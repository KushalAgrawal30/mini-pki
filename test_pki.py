"""End-to-end lifecycle check against the JSON API:
request -> approve -> cert login -> renew -> revoke -> expiry -> foreign CA -> audit.
Run: python test_pki.py
"""
import base64
import os
import tempfile
import time

os.environ["PKI_DATA"] = tempfile.mkdtemp()

from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

import app as webapp  # noqa: E402

webapp.setup("admin", "admin-pass-123")
webapp.load_secret()
c = webapp.app.test_client()
c.environ_base["wsgi.url_scheme"] = "https"


def post(url, data=None):
    token = c.get("/api/me").json["csrf"]
    return c.post(url, json=data or {}, headers={"X-CSRF-Token": token})


def new_csr(cn="alice"):
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, cn)]))
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM).decode()


def cert_login(key, cert_pem):
    """Does what the React login page does with WebCrypto: sign the challenge, send raw r||s."""
    challenge = c.get("/api/login/challenge").json["challenge"]
    r, s = decode_dss_signature(key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256())))
    sig = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
    return post("/api/login", {"cert_pem": cert_pem, "signature": sig})


def approve_latest(days=365):
    post("/api/admin/login", {"username": "admin", "password": "admin-pass-123"})
    rid = c.get("/api/admin/requests").json[0]["id"]
    serial = post(f"/api/admin/requests/{rid}", {"action": "approve", "days": days}).json["serial"]
    post("/api/logout")
    return c.get(f"/cert/{serial}.pem").get_data(as_text=True)


# CSRF and RBAC
assert c.post("/api/requests", json={"username": "x"}).status_code == 400
assert c.get("/api/admin/requests").status_code == 401
assert post("/api/admin/login", {"username": "admin", "password": "wrong"}).status_code == 401

# Bad CSR rejected by RA
assert post("/api/requests", {"username": "alice", "email": "a@org.com", "csr": "junk"}).status_code == 400

# 1. Register + RA approval + issuance
key, csr = new_csr()
r = post("/api/requests", {"username": "alice", "email": "a@org.com", "csr": csr})
assert r.status_code == 201
rid = r.json["id"]
assert c.get(f"/api/requests/{rid}").json["request"]["status"] == "pending"
cert_pem = approve_latest()
assert c.get(f"/api/requests/{rid}").json["cert"]["status"] == "valid"
cert = x509.load_pem_x509_certificate(cert_pem.encode())
assert cert.subject.rfc4514_string().startswith("CN=alice")

# 2. Certificate login works; portal accessible; user can't reach admin
assert cert_login(key, cert_pem).json["user"] == "alice"
assert c.get("/api/my/certs").status_code == 200
assert c.get("/api/admin/requests").status_code == 403

# Wrong private key is rejected (proof of possession)
post("/api/logout")
other_key, _ = new_csr()
assert "private key does not match" in cert_login(other_key, cert_pem).json["error"]

# Challenge can't be replayed
assert "challenge expired" in post("/api/login", {"cert_pem": cert_pem, "signature": ""}).json["error"]

# 3. Renewal: new key, old cert superseded (revoked)
cert_login(key, cert_pem)
key2, csr2 = new_csr()
serial2 = post("/api/my/renew", {"csr": csr2}).json["serial"]
cert2_pem = c.get(f"/cert/{serial2}.pem").get_data(as_text=True)
assert "revoked" in cert_login(key, cert_pem).json["error"]
assert cert_login(key2, cert2_pem).json["user"] == "alice"

# 4. Self-revocation -> CRL -> login refused
assert post("/api/my/revoke", {"serial": serial2, "reason": "keyCompromise"}).json["logged_out"]
crl = x509.load_pem_x509_crl(c.get("/crl.pem").data)
assert crl.get_revoked_certificate_by_serial_number(int(serial2, 16)) is not None
assert "revoked" in cert_login(key2, cert2_pem).json["error"]

# 5. Expiry: a ~43s certificate is rejected after it lapses
key3, csr3 = new_csr("bob")
post("/api/requests", {"username": "bob", "email": "b@org.com", "csr": csr3})
cert3_pem = approve_latest(days=0.0005)
time.sleep(45)
assert "expired" in cert_login(key3, cert3_pem).json["error"]

# 6. A cert from a foreign CA is rejected
fk = ec.generate_private_key(ec.SECP256R1())
n = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "alice")])
fake = (x509.CertificateBuilder().subject_name(n).issuer_name(n).public_key(fk.public_key())
        .serial_number(1).not_valid_before(webapp.pki.now()).not_valid_after(webapp.pki.now() + webapp.dt.timedelta(days=1))
        .sign(fk, hashes.SHA256()).public_bytes(serialization.Encoding.PEM).decode())
assert "chain does not lead" in cert_login(fk, fake).json["error"]

# 7. Audit trail captured everything
post("/api/admin/login", {"username": "admin", "password": "admin-pass-123"})
actions = {row["action"] for row in c.get("/api/admin/audit").json}
for action in ["csr_submitted", "cert_issued", "login_success", "login_failed", "cert_renewed", "cert_revoked",
               "admin_login_failed", "access_denied"]:
    assert action in actions, action

print("All PKI lifecycle checks passed.")
