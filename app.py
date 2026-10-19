"""Mini PKI JSON API: Registration Authority, admin console, certificate login, audit log.
The React frontend (frontend/) talks to /api/*; in production Flask also serves its built files.

Run:  python app.py init      (create CAs + admin account)
      python app.py           (serve on https://localhost:8443)
"""
import base64
import binascii
import datetime as dt
import getpass
import re
import secrets
import sqlite3
import sys
from functools import wraps
from pathlib import Path

from flask import Flask, Response, abort, g, jsonify, make_response, request, send_from_directory, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash

import pki

DB = pki.DATA / "pki.db"
DIST = Path(__file__).parent / "frontend" / "dist"
app = Flask(__name__, static_folder=DIST, static_url_path="")
app.config.update(SESSION_COOKIE_SECURE=True, SESSION_COOKIE_SAMESITE="Lax",
                  PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=1))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, email TEXT, role TEXT NOT NULL CHECK (role IN ('user','admin')),
    password_hash TEXT, created TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, username TEXT NOT NULL, email TEXT, csr TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')), created TEXT NOT NULL,
    reviewed_by TEXT, note TEXT, serial TEXT);
CREATE TABLE IF NOT EXISTS certs (serial TEXT PRIMARY KEY, username TEXT NOT NULL, pem TEXT NOT NULL,
    not_after TEXT NOT NULL, revoked_at TEXT, reason TEXT);
CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT, action TEXT NOT NULL,
    detail TEXT, ip TEXT);
"""
USERNAME_RE = re.compile(r"^[a-zA-Z0-9._-]{3,32}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    if (conn := g.pop("db", None)) is not None:
        conn.close()


def now_iso():
    return pki.now().isoformat(timespec="seconds")


def body():
    return request.get_json(silent=True) or {}


def fail(msg, code=400):
    abort(make_response(jsonify(error=msg), code))


def audit(action, detail="", actor=None):
    db().execute("INSERT INTO audit (ts, actor, action, detail, ip) VALUES (?,?,?,?,?)",
                 (now_iso(), actor or session.get("user"), action, detail, request.remote_addr))
    db().commit()


def rebuild_crl():
    pki.build_crl([(r["serial"], dt.datetime.fromisoformat(r["revoked_at"]), r["reason"])
                   for r in db().execute("SELECT * FROM certs WHERE revoked_at IS NOT NULL")])


def store_cert(cert, username):
    serial = format(cert.serial_number, "x")
    db().execute("INSERT INTO certs (serial, username, pem, not_after) VALUES (?,?,?,?)",
                 (serial, username, pki.pem(cert), cert.not_valid_after_utc.isoformat(timespec="seconds")))
    return serial


def revoke(serial, reason):
    db().execute("UPDATE certs SET revoked_at=?, reason=? WHERE serial=? AND revoked_at IS NULL",
                 (now_iso(), reason, serial))
    db().commit()
    rebuild_crl()


def cert_json(row):
    if row["revoked_at"]:
        status = "revoked"
    else:
        status = "expired" if dt.datetime.fromisoformat(row["not_after"]) < pki.now() else "valid"
    return {"serial": row["serial"], "username": row["username"], "not_after": row["not_after"],
            "revoked_at": row["revoked_at"], "reason": row["reason"], "status": status}


# ---------- security plumbing ----------

@app.before_request
def csrf_protect():
    session.setdefault("csrf", secrets.token_urlsafe(32))
    if request.method == "POST" and request.headers.get("X-CSRF-Token") != session["csrf"]:
        fail("CSRF token missing or invalid")


@app.errorhandler(HTTPException)
def http_error(e):
    if e.code == 404 and request.method == "GET" and not request.path.startswith("/api/") and (DIST / "index.html").exists():
        return send_from_directory(DIST, "index.html")  # SPA fallback: React Router handles the path
    return jsonify(error=e.description), e.code


def login_required(role=None):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            if "user" not in session:
                fail("Not logged in", 401)
            if role and session.get("role") != role:
                audit("access_denied", request.path)
                fail("Forbidden", 403)
            return f(*a, **kw)
        return wrapper
    return deco


# ---------- public: CA distribution ----------

@app.get("/ca/root.pem")
def root_pem():
    return Response(pki.ROOT_CERT.read_text(), mimetype="application/x-pem-file")


@app.get("/ca/chain.pem")
def chain():
    return Response(pki.chain_pem(), mimetype="application/x-pem-file")


@app.get("/crl.pem")
def crl():
    if pki.crl_is_stale():
        rebuild_crl()
    return Response(pki.CRL_FILE.read_bytes(), mimetype="application/pkix-crl")


@app.get("/cert/<serial>.pem")
def download_cert(serial):
    row = db().execute("SELECT pem FROM certs WHERE serial=?", (serial,)).fetchone() or abort(404)
    return Response(row["pem"], mimetype="application/x-pem-file",
                    headers={"Content-Disposition": f"attachment; filename={serial}.pem"})


@app.get("/api/me")
def me():
    return jsonify(user=session.get("user"), role=session.get("role"), method=session.get("method"),
                   serial=session.get("serial"), csrf=session.setdefault("csrf", secrets.token_urlsafe(32)), reasons=pki.REASONS)


# ---------- Registration Authority: certificate requests ----------

@app.post("/api/requests")
def new_request():
    d = body()
    username, email, csr = d.get("username", "").strip(), d.get("email", "").strip(), d.get("csr", "")
    try:
        if not USERNAME_RE.match(username):
            raise ValueError("Username must be 3-32 chars: letters, digits, . _ -")
        if not EMAIL_RE.match(email):
            raise ValueError("Enter a valid email")
        pki.check_csr(csr)
        if db().execute("SELECT 1 FROM requests WHERE username=? AND status='pending'", (username,)).fetchone():
            raise ValueError("A request for this username is already pending")
        if (u := db().execute("SELECT email FROM users WHERE username=?", (username,)).fetchone()) and u["email"] != email:
            raise ValueError("Username already belongs to another person")
    except ValueError as e:
        fail(str(e))
    rid = secrets.token_urlsafe(16)
    db().execute("INSERT INTO requests (id, username, email, csr, status, created) VALUES (?,?,?,?, 'pending', ?)",
                 (rid, username, email, csr.strip(), now_iso()))
    audit("csr_submitted", f"request for {username} <{email}>", actor=username)
    return jsonify(id=rid), 201


@app.get("/api/requests/<rid>")
def request_status(rid):
    req = db().execute("SELECT * FROM requests WHERE id=?", (rid,)).fetchone() or abort(404)
    cert = req["serial"] and db().execute("SELECT * FROM certs WHERE serial=?", (req["serial"],)).fetchone()
    return jsonify(request={k: req[k] for k in ("username", "status", "created", "reviewed_by", "note")},
                   cert=cert_json(cert) if cert else None)


# ---------- certificate-based login ----------

@app.get("/api/login/challenge")
def challenge():
    session["challenge"] = "minipki-login:" + secrets.token_urlsafe(32)
    return jsonify(challenge=session["challenge"])


@app.post("/api/login")
def login():
    d = body()
    challenge = session.pop("challenge", None)  # one-time: prevents replay
    try:
        if not challenge:
            raise ValueError("Login challenge expired, try again")
        if pki.crl_is_stale():
            rebuild_crl()
        cert = pki.validate_login(d.get("cert_pem", ""), challenge,
                                  base64.b64decode(d.get("signature", ""), validate=True))
        serial = format(cert.serial_number, "x")
        if not db().execute("SELECT 1 FROM certs WHERE serial=?", (serial,)).fetchone():
            raise ValueError("Certificate not found in CA records")
    except (ValueError, binascii.Error) as e:
        audit("login_failed", str(e), actor="anonymous")
        fail(f"Login rejected: {e}", 401)
    username = pki.common_name(cert)
    user = db().execute("SELECT role FROM users WHERE username=?", (username,)).fetchone()
    session.clear()
    session.update(user=username, role=user["role"] if user else "user", serial=serial, method="certificate",
                   csrf=secrets.token_urlsafe(32))
    audit("login_success", f"certificate serial {serial}")
    return me()


@app.post("/api/logout")
def logout():
    if "user" in session:
        audit("logout")
    session.clear()
    return me()


# ---------- protected user portal ----------

@app.get("/api/my/certs")
@login_required()
def my_certs():
    rows = db().execute("SELECT * FROM certs WHERE username=? ORDER BY not_after DESC", (session["user"],))
    return jsonify([cert_json(r) for r in rows])


@app.post("/api/my/renew")
@login_required()
def renew():
    # Identity already proven by a valid cert, so renewal skips RA review; old cert is superseded.
    if session.get("method") != "certificate":
        fail("Renewal requires certificate login", 403)
    try:
        user = db().execute("SELECT email FROM users WHERE username=?", (session["user"],)).fetchone()
        cert = pki.issue(body().get("csr", ""), session["user"], user["email"] if user else None, 365)
    except ValueError as e:
        fail(str(e))
    serial = store_cert(cert, session["user"])
    old = session["serial"]
    revoke(old, "superseded")
    audit("cert_renewed", f"{old} -> {serial}")
    session.clear()
    return jsonify(serial=serial)


@app.post("/api/my/revoke")
@login_required()
def self_revoke():
    serial, reason = body().get("serial"), body().get("reason")
    if reason not in pki.REASONS:
        fail("Unknown reason")
    if not db().execute("SELECT 1 FROM certs WHERE serial=? AND username=?", (serial, session["user"])).fetchone():
        fail("Not your certificate", 403)
    revoke(serial, reason)
    audit("cert_revoked", f"{serial} by owner, reason={reason}")
    logged_out = serial == session.get("serial")
    if logged_out:
        session.clear()
    return jsonify(logged_out=logged_out)


# ---------- admin / RA console ----------

@app.post("/api/admin/login")
def admin_login():
    username, password = body().get("username", ""), body().get("password", "")
    user = db().execute("SELECT * FROM users WHERE username=? AND role='admin'", (username,)).fetchone()
    if not user or not user["password_hash"] or not check_password_hash(user["password_hash"], password):
        audit("admin_login_failed", f"username={username}", actor="anonymous")
        fail("Invalid credentials", 401)
    session.clear()
    session.update(user=username, role="admin", method="password", csrf=secrets.token_urlsafe(32))
    audit("admin_login_success")
    return me()


@app.get("/api/admin/requests")
@login_required("admin")
def pending_requests():
    rows = db().execute("SELECT id, username, email, csr, created FROM requests WHERE status='pending' ORDER BY created")
    return jsonify([dict(r) for r in rows])


@app.get("/api/admin/certs")
@login_required("admin")
def all_certs():
    return jsonify([cert_json(r) for r in db().execute("SELECT * FROM certs ORDER BY rowid DESC")])


@app.post("/api/admin/requests/<rid>")
@login_required("admin")
def review(rid):
    d = body()
    req = db().execute("SELECT * FROM requests WHERE id=? AND status='pending'", (rid,)).fetchone() or abort(404)
    if d.get("action") == "reject":
        db().execute("UPDATE requests SET status='rejected', reviewed_by=?, note=? WHERE id=?",
                     (session["user"], d.get("note", ""), rid))
        db().commit()
        audit("csr_rejected", f"{req['username']}: {d.get('note', '')}")
        return jsonify(ok=True)
    try:
        days = float(d.get("days", 365))
        if not 0.0005 <= days <= 825:  # 0.0005 day ~ 43s, handy for demoing expiry
            raise ValueError("Validity must be between 0.0005 and 825 days")
        cert = pki.issue(req["csr"], req["username"], req["email"], days)
    except (ValueError, TypeError) as e:
        fail(str(e))
    serial = store_cert(cert, req["username"])
    db().execute("INSERT OR IGNORE INTO users (username, email, role, created) VALUES (?,?, 'user', ?)",
                 (req["username"], req["email"], now_iso()))
    db().execute("UPDATE requests SET status='approved', reviewed_by=?, serial=? WHERE id=?", (session["user"], serial, rid))
    db().commit()
    audit("cert_issued", f"{req['username']} serial={serial} days={days}")
    return jsonify(serial=serial)


@app.post("/api/admin/revoke")
@login_required("admin")
def admin_revoke():
    serial, reason = body().get("serial"), body().get("reason")
    if reason not in pki.REASONS:
        fail("Unknown reason")
    revoke(serial, reason)
    audit("cert_revoked", f"{serial} by admin, reason={reason}")
    return jsonify(ok=True)


@app.get("/api/admin/audit")
@login_required("admin")
def audit_log():
    return jsonify([dict(r) for r in db().execute("SELECT * FROM audit ORDER BY id DESC LIMIT 500")])


# ---------- setup ----------

def setup(admin_user, admin_password):
    created = pki.init_ca()
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA)
    conn.execute("INSERT OR REPLACE INTO users (username, email, role, password_hash, created) VALUES (?,?, 'admin', ?, ?)",
                 (admin_user, None, generate_password_hash(admin_password), now_iso()))
    conn.execute("INSERT INTO audit (ts, actor, action, detail) VALUES (?,?,?,?)",
                 (now_iso(), "system", "setup", f"CA created={created}, admin={admin_user}"))
    conn.commit()
    conn.close()
    secret = pki.DATA / "secret_key"
    if not secret.exists():
        secret.write_text(secrets.token_hex(32))
        secret.chmod(0o600)


def load_secret():
    app.secret_key = (pki.DATA / "secret_key").read_text()


if __name__ == "__main__":
    if sys.argv[1:] == ["init"]:
        user = input("Admin username [admin]: ") or "admin"
        pw = getpass.getpass("Admin password (min 8 chars): ")
        if len(pw) < 8:
            sys.exit("Password too short")
        setup(user, pw)
        print(f"Done. Data in {pki.DATA}. Import {pki.ROOT_CERT} into your browser/OS trust store, then run: python app.py")
    else:
        if not pki.ROOT_CERT.exists():
            sys.exit("Run `python app.py init` first")
        load_secret()
        app.run(host="127.0.0.1", port=8443, ssl_context=(str(pki.SRV_CERT), str(pki.SRV_KEY)))
