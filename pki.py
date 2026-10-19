"""Mini PKI core: Root CA, Intermediate CA, issuance, CRL and certificate-login validation."""
import datetime as dt
import ipaddress
import os
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

DATA = Path(os.environ.get("PKI_DATA", Path(__file__).parent / "data"))
PASSPHRASE = os.environ.get("PKI_PASSPHRASE", "change-me-in-production").encode()
BASE_URL = os.environ.get("PKI_BASE_URL", "https://localhost:8443")
ORG = "MiniPKI Organization"

ROOT_KEY, ROOT_CERT = DATA / "root.key", DATA / "root.pem"
INT_KEY, INT_CERT = DATA / "intermediate.key", DATA / "intermediate.pem"
SRV_KEY, SRV_CERT = DATA / "server.key", DATA / "server.pem"
CRL_FILE = DATA / "crl.pem"

REASONS = ["keyCompromise", "affiliationChanged", "superseded", "cessationOfOperation", "unspecified"]


def now():
    return dt.datetime.now(dt.timezone.utc)


def name(cn):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "IN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORG),
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])


def common_name(cert):
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def save_key(key, path, encrypt=True):
    enc = serialization.BestAvailableEncryption(PASSPHRASE) if encrypt else serialization.NoEncryption()
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc))
    os.chmod(path, 0o600)


def load_key(path):
    return serialization.load_pem_private_key(path.read_bytes(), PASSPHRASE)


def load_cert(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def sign_cert(subject, public_key, issuer_name, issuer_key, days, extensions):
    b = (x509.CertificateBuilder()
         .subject_name(subject).issuer_name(issuer_name).public_key(public_key)
         .serial_number(x509.random_serial_number())
         .not_valid_before(now() - dt.timedelta(minutes=1))
         .not_valid_after(now() + dt.timedelta(days=days))
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), False))
    for ext, critical in extensions:
        b = b.add_extension(ext, critical)
    return b.sign(issuer_key, hashes.SHA256())


def key_usage(digital_signature=False, cert_sign=False):
    return x509.KeyUsage(digital_signature=digital_signature, content_commitment=False, key_encipherment=False,
                         data_encipherment=False, key_agreement=False, key_cert_sign=cert_sign,
                         crl_sign=cert_sign, encipher_only=False, decipher_only=False)


def init_ca():
    """Create Root CA -> Intermediate CA -> HTTPS server cert, plus an empty CRL. Idempotent."""
    DATA.mkdir(exist_ok=True)
    if ROOT_CERT.exists():
        return False
    # Root CA: self-signed trust anchor, key used only here (to sign the Intermediate).
    root_key = ec.generate_private_key(ec.SECP384R1())
    root = sign_cert(name("MiniPKI Root CA"), root_key.public_key(), name("MiniPKI Root CA"), root_key, 3650, [
        (x509.BasicConstraints(ca=True, path_length=1), True),
        (key_usage(cert_sign=True), True),
    ])
    # Intermediate CA: does day-to-day issuing and CRL signing.
    int_key = ec.generate_private_key(ec.SECP384R1())
    inter = sign_cert(name("MiniPKI Intermediate CA"), int_key.public_key(), root.subject, root_key, 1825, [
        (x509.BasicConstraints(ca=True, path_length=0), True),
        (key_usage(cert_sign=True), True),
    ])
    # TLS cert for the web app itself, issued by the Intermediate.
    srv_key = ec.generate_private_key(ec.SECP256R1())
    srv = sign_cert(name("localhost"), srv_key.public_key(), inter.subject, int_key, 397, [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (key_usage(digital_signature=True), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False),
        (x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                      x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False),
    ])
    save_key(root_key, ROOT_KEY)
    save_key(int_key, INT_KEY)
    save_key(srv_key, SRV_KEY, encrypt=False)  # ponytail: plain key so the TLS server can start unattended; use an HSM/secret store in prod
    ROOT_CERT.write_text(pem(root))
    INT_CERT.write_text(pem(inter))
    SRV_CERT.write_text(pem(srv) + pem(inter))
    build_crl([])
    return True


def chain_pem():
    return INT_CERT.read_text() + ROOT_CERT.read_text()


def check_csr(csr_pem):
    """Parse a CSR and verify its self-signature (proof the requester holds the private key)."""
    try:
        csr = x509.load_pem_x509_csr(csr_pem.strip().encode())
    except ValueError:
        raise ValueError("Not a valid PEM certificate signing request")
    if not csr.is_signature_valid:
        raise ValueError("CSR signature is invalid")
    key = csr.public_key()
    if not (isinstance(key, ec.EllipticCurvePublicKey) and isinstance(key.curve, ec.SECP256R1)):
        raise ValueError("Key must be ECC P-256 (prime256v1)")
    return csr


def issue(csr_pem, username, email, days):
    """Intermediate CA issues an end-entity client-auth certificate. Subject comes from the RA, not the CSR."""
    csr = check_csr(csr_pem)
    san = [x509.RFC822Name(email)] if email else []
    exts = [
        (x509.BasicConstraints(ca=False, path_length=None), True),
        (key_usage(digital_signature=True), True),
        (x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False),
        (x509.CRLDistributionPoints([x509.DistributionPoint(
            [x509.UniformResourceIdentifier(f"{BASE_URL}/crl.pem")], None, None, None)]), False),
    ]
    if san:
        exts.append((x509.SubjectAlternativeName(san), False))
    inter = load_cert(INT_CERT)
    return sign_cert(name(username), csr.public_key(), inter.subject, load_key(INT_KEY), days, exts)


def build_crl(revoked):
    """revoked: iterable of (serial_hex, revoked_at datetime, reason). Signed by the Intermediate CA."""
    inter = load_cert(INT_CERT)
    b = (x509.CertificateRevocationListBuilder().issuer_name(inter.subject)
         .last_update(now()).next_update(now() + dt.timedelta(days=7)))
    for serial, when, reason in revoked:
        b = b.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(int(serial, 16)).revocation_date(when)
            .add_extension(x509.CRLReason(x509.ReasonFlags(reason)), False).build())
    crl = b.sign(load_key(INT_KEY), hashes.SHA256())
    CRL_FILE.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    return crl


def crl_is_stale():
    return x509.load_pem_x509_crl(CRL_FILE.read_bytes()).next_update_utc <= now()


def validate_login(cert_pem, challenge, raw_sig):
    """Full RFC 5280-style check + proof of possession. Returns the cert; raises ValueError with the reason."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.strip().encode())
    except ValueError:
        raise ValueError("Malformed certificate")
    root, inter, t = load_cert(ROOT_CERT), load_cert(INT_CERT), now()

    # 1. Chain: leaf <- Intermediate <- Root (trust anchor)
    try:
        cert.verify_directly_issued_by(inter)
        inter.verify_directly_issued_by(root)
    except (ValueError, TypeError, InvalidSignature):
        raise ValueError("Certificate chain does not lead to the trusted Root CA")
    # 2. Validity period (leaf and intermediate)
    for c in (cert, inter):
        if not (c.not_valid_before_utc <= t <= c.not_valid_after_utc):
            raise ValueError(f"Certificate expired or not yet valid ({common_name(c)})")
    # 3. Intended usage
    try:
        if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("CA certificates cannot be used to log in")
        if not cert.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature:
            raise ValueError("Key usage does not allow digitalSignature")
        if ExtendedKeyUsageOID.CLIENT_AUTH not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
            raise ValueError("Certificate is not issued for client authentication")
    except x509.ExtensionNotFound as e:
        raise ValueError(f"Missing required extension: {e.oid._name}")
    # 4. Revocation via the CA-signed CRL
    crl = x509.load_pem_x509_crl(CRL_FILE.read_bytes())
    if not crl.is_signature_valid(inter.public_key()) or crl.next_update_utc <= t:
        raise ValueError("CRL is invalid or stale; refusing login")
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise ValueError("Certificate has been revoked")
    # 5. Proof of possession: browser signed our one-time challenge (WebCrypto raw r||s format)
    if len(raw_sig) != 64:
        raise ValueError("Bad signature format")
    der = encode_dss_signature(int.from_bytes(raw_sig[:32], "big"), int.from_bytes(raw_sig[32:], "big"))
    try:
        cert.public_key().verify(der, challenge.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise ValueError("Challenge signature invalid: private key does not match certificate")
    return cert
