# Mini PKI: Certificate Management and Authentication

A small Public Key Infrastructure for an organization. It has a Root CA, an Intermediate CA and a Registration Authority (RA). The React web interface lets users request, renew and revoke certificates, and log in with a certificate instead of a password.

**Team:** Jeevesh Malhotra (23BKT0048), Kushal Agrawal (23BKT0033), Mayank Balmoori (23BKT0030)

## Architecture

```
MiniPKI Root CA            self-signed trust anchor, ECC P-384, 10 years; key used only to sign the Intermediate
 └── MiniPKI Intermediate CA   ECC P-384, 5 years; issues all end-entity certs and signs the CRL
       ├── localhost           HTTPS certificate of this web server (serverAuth)
       └── users / devices     ECC P-256, 1 year by default (clientAuth, digitalSignature)
```

| Layer | Tech | File |
|---|---|---|
| PKI core (CA, issuance, CRL, validation) | Python `cryptography` | `pki.py` |
| REST API, RA workflow, roles, audit log | Flask + SQLite | `app.py` |
| Web interface | React 18 + Vite + React Router | `frontend/src/` |
| End-to-end lifecycle test | Python | `test_pki.py` |

## Certificate lifecycle

1. **Registration:** the user generates a key pair *locally* with openssl and submits a CSR. The server checks the CSR signature (proof of possession) and requires ECC P-256.
2. **RA verification:** an administrator reviews the pending request and approves (choosing the validity period) or rejects it with a reason.
3. **Issuance:** the Intermediate CA signs an X.509 v3 certificate. The RA sets the subject (the CSR's subject is ignored). Extensions: `basicConstraints CA:FALSE`, `keyUsage digitalSignature`, `extendedKeyUsage clientAuth`, `subjectAltName email`, `cRLDistributionPoints`, SKI/AKI.
4. **Authentication:** the server sends a one-time random challenge. The browser signs it with the user's private key through the WebCrypto API, so **the private key never leaves the user's machine**. The server then checks:
   - the chain: leaf → Intermediate → Root signatures
   - the validity period of the leaf and the Intermediate
   - usage: not a CA, `digitalSignature` set, `clientAuth` in the EKU
   - revocation: the serial is checked against the CRL, whose signature and freshness are verified first
   - proof of possession: the challenge signature (ECDSA-SHA256) is verified against the certificate's public key
   - the challenge is single-use, so a captured login cannot be replayed
5. **Renewal:** a logged-in user submits a CSR for a *new* key. The new certificate is issued and the old one is revoked as `superseded`.
6. **Revocation:** the user or an admin revokes a certificate with an RFC 5280 reason (`keyCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `unspecified`). The CRL is re-signed straight away and published at `/crl.pem`.
7. **Expiration:** expired certificates are rejected by the validity-period check, separately from the CRL.
8. **Audit:** CSR submissions, approvals and rejections, issuance, renewals, revocations, successful and failed logins (with the reason), and denied access attempts are all logged with time, actor and IP.

## Security measures

- ECC P-256/P-384 with SHA-256 signatures, X.509 v3 and RFC 5280 extensions
- CA private keys are stored encrypted (PKCS#8 + AES-256, passphrase from `PKI_PASSPHRASE`) with file mode `0600`
- HTTPS only, served with a certificate from our own CA; session cookies are `Secure`, `HttpOnly`, `SameSite=Lax`
- Role-based access (`user` / `admin`), CSRF token on every state-changing request, admin passwords hashed (PBKDF2 via Werkzeug)
- The CRL is signed by the CA and the login check fails closed if the CRL is invalid or stale

## Setup

Requires Python 3.10+, Node 18+ and OpenSSL.

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd frontend && npm install && npm run build && cd ..

export PKI_PASSPHRASE='choose-a-strong-passphrase'   # protects the CA keys
python app.py init        # creates the Root CA, Intermediate CA, server cert and admin account
python app.py             # https://localhost:8443
```

**Trust the Root CA** so the browser accepts the HTTPS certificate without a warning:
- macOS: `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain data/root.pem`
- Windows: double-click `data/root.pem` → Install → "Trusted Root Certification Authorities"
- Or just click through the browser warning for a demo.

Frontend development with hot reload: run `python app.py` in one terminal and `cd frontend && npm run dev` in another, then open http://localhost:5173. Vite proxies API calls to Flask.

Port 8443 is used because macOS AirPlay Receiver occupies port 5000.

## Demo walkthrough

```bash
# 1. User creates a key pair and CSR (private key stays here)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out alice.key
openssl req -new -key alice.key -subj "/CN=alice" -out alice.csr
```
2. Go to **Request certificate**, enter `alice` and an email, and paste `alice.csr`. Bookmark the status page.
3. Go to **Admin**, log in, and approve the request. To demo expiry, use a validity of `0.001` days (~90 s).
4. On the status page, download the certificate. Open **Certificate login** and pick the certificate and `alice.key`. You are now logged in to the protected portal.
5. Inspect the certificate: `openssl x509 -in <serial>.pem -noout -text`, and verify the chain: `openssl verify -CAfile data/root.pem -untrusted data/intermediate.pem <serial>.pem`.
6. **Renew:** make a new key and CSR and paste it in the portal. The old certificate now shows as revoked (superseded).
7. **Revoke:** revoke the certificate in the portal or the admin page, then try logging in again. It is rejected with "Certificate has been revoked". Check the CRL: `curl -k https://localhost:8443/crl.pem | openssl crl -noout -text`.
8. Try logging in with a different key, an expired certificate, or a self-made certificate. Each is rejected with a specific reason.
9. Open **Audit log** to see every event.

## Tests

```bash
python test_pki.py
```
This runs the whole lifecycle against a temporary CA: CSRF and role checks, bad CSR, issuance, certificate login, wrong private key, challenge replay, renewal, revocation and the CRL, expiry, a certificate from a foreign CA, and audit coverage.

## Limitations / future work

- Users log in by selecting key files. A production deployment would use mutual TLS with keys on smart cards or in the OS keystore.
- The Root CA key would be kept offline or in an HSM. Here it sits encrypted on disk.
- OCSP responder, certificate templates for devices/servers, email notifications to the RA.
- The Flask development server is used. Production would run behind gunicorn or nginx.
