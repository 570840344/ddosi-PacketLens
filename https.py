#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import datetime
import functools
import ipaddress
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import webbrowser

from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


# Do not persist TLS session secrets from this process.
os.environ.pop("SSLKEYLOGFILE", None)

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"
ALLOWED_METHODS = "GET, HEAD, OPTIONS"


def _safe_log_text(value):
    """Prevent terminal control-character injection from request data."""
    return "".join(ch if ch.isprintable() and ch not in "\r\n\x1b" else "?" for ch in str(value))


class PacketLensHandler(SimpleHTTPRequestHandler):
    """Read-only static handler with browser-compatible hardening headers."""

    protocol_version = "HTTP/1.1"

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", ALLOWED_METHODS)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _method_not_allowed(self):
        # Do not attempt to parse unwanted request bodies on this static server.
        self.close_connection = True
        self.send_response(405, "Method Not Allowed")
        self.send_header("Allow", ALLOWED_METHODS)
        self.send_header("Connection", "close")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_POST = _method_not_allowed
    do_PUT = _method_not_allowed
    do_DELETE = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_TRACE = _method_not_allowed
    do_CONNECT = _method_not_allowed

    def log_message(self, fmt, *args):
        super().log_message(_safe_log_text(fmt), *(_safe_log_text(arg) for arg in args))


def _certificate_names(bind):
    dns_names = {"localhost"}
    ip_names = {ipaddress.ip_address("127.0.0.1"), ipaddress.ip_address("::1")}
    try:
        address = ipaddress.ip_address(bind.split("%", 1)[0])
        if not address.is_unspecified:
            ip_names.add(address)
    except ValueError:
        if bind not in ("", "*"):
            dns_names.add(bind.rstrip(".").lower())
    return dns_names, ip_names


def _atomic_write(path, data, private=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    try:
        if private:
            try:
                os.chmod(temporary, 0o600)
            except OSError:
                pass
        with os.fdopen(fd, "wb") as stream:
            fd = -1
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if private:
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
    finally:
        if fd != -1:
            os.close(fd)
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def create_self_signed_cert(cert_file=CERT_FILE, key_file=KEY_FILE, bind="127.0.0.1"):
    """Generate a self-signed certificate valid for localhost and the bind host."""
    print("🔐 正在生成自签名证书...")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PacketLens Local"),
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
    ])
    dns_names, ip_names = _certificate_names(bind)
    san = [x509.DNSName(name) for name in sorted(dns_names)]
    san.extend(x509.IPAddress(address) for address in sorted(ip_names, key=str))
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    # Replace key first: interruption can only leave a mismatch, detected next run.
    _atomic_write(key_file, key_bytes, private=True)
    _atomic_write(cert_file, cert.public_bytes(serialization.Encoding.PEM))
    print(f"✅ 已生成 {Path(cert_file).name} 和 {Path(key_file).name}")


def _certificate_is_usable(cert_file, key_file, bind):
    try:
        cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
        key = serialization.load_pem_private_key(Path(key_file).read_bytes(), password=None)
        cert_public = cert.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        key_public = key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        if cert_public != key_public:
            return False, "证书与私钥不匹配"
        now = datetime.datetime.now(datetime.timezone.utc)
        if hasattr(cert, "not_valid_before_utc"):
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        else:  # Compatibility with older cryptography releases.
            not_before = cert.not_valid_before.replace(tzinfo=datetime.timezone.utc)
            not_after = cert.not_valid_after.replace(tzinfo=datetime.timezone.utc)
        if not_before > now or not_after <= now + datetime.timedelta(days=1):
            return False, "证书尚未生效、已过期或即将过期"
        dns_names, ip_names = _certificate_names(bind)
        extension = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        cert_dns = {name.rstrip(".").lower() for name in extension.get_values_for_type(x509.DNSName)}
        cert_ips = set(extension.get_values_for_type(x509.IPAddress))
        if not dns_names.issubset(cert_dns) or not ip_names.issubset(cert_ips):
            return False, "证书 SAN 与监听主机不匹配"
        return True, ""
    except (OSError, ValueError, TypeError, x509.ExtensionNotFound) as exc:
        return False, f"证书或私钥无法读取（{type(exc).__name__}）"


def ensure_certificate(cert_file=CERT_FILE, key_file=KEY_FILE, bind="127.0.0.1"):
    usable, reason = _certificate_is_usable(cert_file, key_file, bind)
    if usable:
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
        return
    if Path(cert_file).exists() or Path(key_file).exists():
        print(f"⚠️  {reason}，正在安全重建证书对。", file=sys.stderr)
    create_self_signed_cert(cert_file, key_file, bind)
    usable, reason = _certificate_is_usable(cert_file, key_file, bind)
    if not usable:
        raise RuntimeError(f"新证书验证失败：{reason}")


def _server_class(bind):
    try:
        infos = socket.getaddrinfo(bind, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        infos = []
    family = infos[0][0] if infos else socket.AF_INET
    if family == socket.AF_INET6:
        class IPv6ThreadingHTTPServer(ThreadingHTTPServer):
            address_family = socket.AF_INET6
        return IPv6ThreadingHTTPServer
    return ThreadingHTTPServer


def _is_loopback_bind(bind):
    if bind.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(bind.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _display_url(bind, port):
    shown_host = "localhost" if bind in ("127.0.0.1", "::1") else bind
    if ":" in shown_host and not shown_host.startswith("["):
        shown_host = f"[{shown_host}]"
    return f"https://{shown_host}:{port}"


def run_server(port=8443, directory=".", bind="127.0.0.1", open_browser=True):
    root = Path(directory).resolve(strict=True)
    if not root.is_dir():
        raise NotADirectoryError(root)
    cert_file = str((root / CERT_FILE).resolve())
    key_file = str((root / KEY_FILE).resolve())
    ensure_certificate(cert_file, key_file, bind)

    handler = functools.partial(PacketLensHandler, directory=str(root))
    server_class = _server_class(bind)
    httpd = server_class((bind, port), handler)
    httpd.daemon_threads = True
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert_file, key_file)
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

        url = _display_url(bind, httpd.server_port)
        print("\n🚀 HTTPS Server Started")
        print("📁 Directory :", root)
        print("🔒 Bind      :", bind)
        print("🔗 URL       :", url)
        if not _is_loopback_bind(bind):
            print("⚠️  安全警告：当前监听地址可能对局域网或公网开放；静态文件和自签名私钥将暴露于该主机。", file=sys.stderr)
            print("⚠️  请使用实际主机名/IP 访问；通配监听地址本身不能作为证书主机名。", file=sys.stderr)
        print("⚠️  浏览器会提示自签名证书，请确认指纹后继续访问")
        print("按 Ctrl+C 停止服务器\n")
        if open_browser:
            try:
                if not webbrowser.open(url):
                    print("⚠️  未能自动打开浏览器，请手动访问上面的 URL。", file=sys.stderr)
            except Exception as exc:
                print(f"⚠️  打开浏览器失败：{_safe_log_text(exc)}", file=sys.stderr)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n👋 已停止服务器")
    finally:
        httpd.server_close()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="PacketLens read-only static HTTPS server (TLS 1.2+)",
        epilog="兼容用法: python https.py [port] [directory] --bind ADDRESS --no-open",
    )
    parser.add_argument("port", nargs="?", type=int, default=8443, help="监听端口（默认: 8443）")
    parser.add_argument("directory", nargs="?", default=".", help="静态文件目录（默认: 当前目录）")
    parser.add_argument("--bind", default="127.0.0.1", help="监听地址（默认: 127.0.0.1，仅本机）")
    parser.add_argument("--no-open", action="store_true", help="不自动打开浏览器")
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    return args


def main(argv=None):
    try:
        options = parse_args(argv)
        run_server(options.port, options.directory, options.bind, not options.no_open)
        return 0
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"错误：静态目录无效：{_safe_log_text(exc)}", file=sys.stderr)
        return 2
    except PermissionError as exc:
        print(f"错误：权限不足：{_safe_log_text(exc)}", file=sys.stderr)
        return 3
    except OSError as exc:
        if getattr(exc, "errno", None) in (48, 98, 10048):
            print("错误：端口已被占用，请选择其他端口或停止占用进程。", file=sys.stderr)
        else:
            print(f"错误：无法启动 HTTPS 服务：{_safe_log_text(exc)}", file=sys.stderr)
        return 1
    except (RuntimeError, ValueError, ssl.SSLError) as exc:
        print(f"错误：TLS 初始化失败：{_safe_log_text(exc)}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())