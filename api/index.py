import base64
import datetime
import hashlib
import io
import json
import os
import struct
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateNumbers, RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
from flask import Flask, jsonify, render_template, request, send_file
import tempfile

_template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "templates")
app = Flask(__name__, template_folder=_template_dir)
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024  # 1 MB


# ── JWK helpers ───────────────────────────────────────────────────────────────

def b64url_to_int(value: str) -> int:
    padding = (4 - len(value) % 4) % 4
    return int.from_bytes(base64.urlsafe_b64decode(value + "=" * padding), "big")


def int_to_b64url(n: int) -> str:
    length = (n.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).rstrip(b"=").decode()


def jwk_to_private_key(jwk: dict):
    required = ["n", "e", "d", "p", "q", "dp", "dq", "qi"]
    missing = [f for f in required if not jwk.get(f)]
    if missing:
        raise ValueError(f"JWK is missing required fields: {', '.join(missing)}")
    pub = RSAPublicNumbers(b64url_to_int(jwk["e"]), b64url_to_int(jwk["n"]))
    priv = RSAPrivateNumbers(
        p=b64url_to_int(jwk["p"]),
        q=b64url_to_int(jwk["q"]),
        d=b64url_to_int(jwk["d"]),
        dmp1=b64url_to_int(jwk["dp"]),
        dmq1=b64url_to_int(jwk["dq"]),
        iqmp=b64url_to_int(jwk["qi"]),
        public_numbers=pub,
    )
    return priv.private_key()


def private_key_to_jwk(private_key, kid: str = "") -> dict:
    priv = private_key.private_numbers()
    pub = priv.public_numbers
    jwk = {
        "kty": "RSA", "alg": "RS256", "use": "sig",
        "n": int_to_b64url(pub.n), "e": int_to_b64url(pub.e),
        "d": int_to_b64url(priv.d), "p": int_to_b64url(priv.p),
        "q": int_to_b64url(priv.q), "dp": int_to_b64url(priv.dmp1),
        "dq": int_to_b64url(priv.dmq1), "qi": int_to_b64url(priv.iqmp),
    }
    if kid:
        jwk["kid"] = kid
    return {"keys": [jwk]}


# ── Pure Python JKS writer ────────────────────────────────────────────────────

def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b

def _der_seq(c: bytes) -> bytes: return b"\x30" + _der_len(len(c)) + c
def _der_oid(b: bytes) -> bytes: return b"\x06" + _der_len(len(b)) + b
def _der_oct(b: bytes) -> bytes: return b"\x04" + _der_len(len(b)) + b

# OID 1.3.6.1.4.1.42.2.17.1.1 — Sun JKS key protector
_JKS_OID = bytes([0x2b, 0x06, 0x01, 0x04, 0x01, 0x2a, 0x02, 0x11, 0x01, 0x01])


def _jks_encrypt_key(password: str, plaintext: bytes) -> bytes:
    """XOR-encrypt a private key using the JKS proprietary cipher."""
    pwd = password.encode("utf-16-be")
    salt = os.urandom(20)
    keystream, h_in = b"", pwd + salt
    while len(keystream) < len(plaintext):
        h = hashlib.sha1(h_in).digest()
        keystream += h
        h_in = pwd + h
    encrypted = bytes(p ^ k for p, k in zip(plaintext, keystream))
    check = hashlib.sha1(pwd + plaintext).digest()
    return salt + encrypted + check


def _make_epki(password: str, pkcs8_der: bytes) -> bytes:
    """Wrap an encrypted key in EncryptedPrivateKeyInfo DER."""
    return _der_seq(_der_seq(_der_oid(_JKS_OID)) + _der_oct(_jks_encrypt_key(password, pkcs8_der)))


def write_jks(alias: str, pkcs8_der: bytes, cert_der: bytes, password: str) -> bytes:
    """Write a JKS keystore (version 2) with a single private key entry."""
    buf = io.BytesIO()
    buf.write(struct.pack(">II", 0xFEEDFEED, 2))   # magic + version
    buf.write(struct.pack(">I", 1))                  # entry count

    buf.write(struct.pack(">I", 1))                  # tag: PrivateKeyEntry
    alias_b = alias.encode("utf-8")
    buf.write(struct.pack(">H", len(alias_b))); buf.write(alias_b)
    buf.write(struct.pack(">q", int(time.time() * 1000)))

    epki = _make_epki(password, pkcs8_der)
    buf.write(struct.pack(">I", len(epki))); buf.write(epki)

    buf.write(struct.pack(">I", 1))                  # cert chain: 1 entry
    ct = b"X.509"
    buf.write(struct.pack(">H", len(ct))); buf.write(ct)
    buf.write(struct.pack(">I", len(cert_der))); buf.write(cert_der)

    data = buf.getvalue()
    integrity = hashlib.sha1(password.encode("utf-16-be") + b"Mighty Aphrodite" + data).digest()
    buf.write(integrity)
    return buf.getvalue()


# ── Conversion logic ──────────────────────────────────────────────────────────

def build_self_signed_cert(private_key, cn: str):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(private_key, hashes.SHA256())
    )


def convert_jwk_to_jks(jwk_json: str, password: str, alias: str) -> bytes:
    data = json.loads(jwk_json)
    key_dict = data["keys"][0] if "keys" in data else data

    private_key = jwk_to_private_key(key_dict)
    cert = build_self_signed_cert(private_key, cn=alias)

    pkcs8_der = private_key.private_bytes(
        serialization.Encoding.DER,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    return write_jks(alias, pkcs8_der, cert_der, password)


def extract_from_p12(p12_bytes: bytes, password: str):
    try:
        private_key, cert, _ = pkcs12.load_key_and_certificates(
            p12_bytes, password.encode()
        )
    except Exception:
        raise ValueError("Could not load .p12 file. Check that the password is correct.")
    if private_key is None:
        raise ValueError("No private key found in the .p12 file.")
    return private_key, cert


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/convert", methods=["POST"])
def convert():
    if "jwk_file" not in request.files or request.files["jwk_file"].filename == "":
        return jsonify({"error": "No JWK file provided."}), 400

    password = request.form.get("password", "").strip()
    alias = request.form.get("alias", "").strip()

    if not password:
        return jsonify({"error": "Password is required."}), 400
    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters (JKS requirement)."}), 400
    if not alias:
        return jsonify({"error": "Alias is required."}), 400

    try:
        jwk_json = request.files["jwk_file"].read().decode("utf-8")
        jks_bytes = convert_jwk_to_jks(jwk_json, password, alias)
    except json.JSONDecodeError as e:
        return jsonify({"error": f"Invalid JSON in JWK file: {e}"}), 400
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".jks")
    tmp.write(jks_bytes); tmp.close()
    return send_file(tmp.name, as_attachment=True, download_name=f"{alias}.jks",
                     mimetype="application/octet-stream")


@app.route("/extract", methods=["POST"])
def extract():
    if "p12_file" not in request.files or request.files["p12_file"].filename == "":
        return jsonify({"error": "No .p12 file provided."}), 400

    password = request.form.get("password", "").strip()
    fmt = request.form.get("format", "pem")
    kid = request.form.get("kid", "").strip()

    if not password:
        return jsonify({"error": "Password is required."}), 400

    try:
        p12_bytes = request.files["p12_file"].read()
        private_key, _ = extract_from_p12(p12_bytes, password)

        if fmt == "jwk":
            output = json.dumps(private_key_to_jwk(private_key, kid=kid), indent=2).encode()
            filename = f"{kid or 'private_key'}.json"
            mimetype = "application/json"
        else:
            output = private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
            filename = "private_key.pem"
            mimetype = "application/x-pem-file"

    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {e}"}), 500

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=os.path.splitext(filename)[1])
    tmp.write(output); tmp.close()
    return send_file(tmp.name, as_attachment=True, download_name=filename, mimetype=mimetype)
