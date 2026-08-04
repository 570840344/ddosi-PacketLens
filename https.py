#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import ssl
import sys
import datetime
import webbrowser

from http.server import HTTPServer, SimpleHTTPRequestHandler

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# 禁止 SSLKEYLOGFILE
os.environ["SSLKEYLOGFILE"] = ""

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"


def create_self_signed_cert():
    """生成自签名 HTTPS 证书"""

    print("🔐 正在生成自签名证书...")

    # RSA 私钥
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Local"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Python HTTPS Server"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.DNSName("127.0.0.1"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    with open(KEY_FILE, "wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption(),
            )
        )

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print("✅ 已生成 cert.pem 和 key.pem")


def ensure_certificate():
    """保证证书存在"""

    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        return

    create_self_signed_cert()


def run_server(port=8443, directory="."):
    os.chdir(directory)

    ensure_certificate()

    handler = SimpleHTTPRequestHandler

    httpd = HTTPServer(("0.0.0.0", port), handler)

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_FILE, KEY_FILE)

    httpd.socket = context.wrap_socket(
        httpd.socket,
        server_side=True,
    )

    url = f"https://localhost:{port}"

    print()
    print("🚀 HTTPS Server Started")
    print("📁 Directory :", os.path.abspath(directory))
    print("🔗 URL       :", url)
    print("⚠️  浏览器会提示自签名证书，请继续访问")
    print("按 Ctrl+C 停止服务器")
    print()

    webbrowser.open(url)

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 已停止服务器")
    finally:
        httpd.server_close()


if __name__ == "__main__":

    port = 8443
    directory = "."

    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            directory = sys.argv[1]

    if len(sys.argv) > 2:
        directory = sys.argv[2]

    run_server(port, directory)
