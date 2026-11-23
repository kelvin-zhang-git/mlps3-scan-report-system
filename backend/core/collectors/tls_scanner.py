"""对已经发现的 HTTPS 端口做一次握手，不发送应用层探测以外的流量。"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa


def inspect_endpoints(host: str, ports: list[int]) -> list[dict[str, Any]]:
    rows: list[dict] = []
    seen: set[int] = set()
    for port in ports:
        if port in seen:
            continue
        seen.add(port)
        rows.extend(_one(host, port))
    return rows


def _one(host: str, port: int) -> list[dict]:
    hints = ["8.1.2.2-a"]
    weak_protocols = []
    for version, label in ((getattr(ssl.TLSVersion, "TLSv1", None), "TLS 1.0"), (getattr(ssl.TLSVersion, "TLSv1_1", None), "TLS 1.1")):
        if version is None:
            continue
        if _accepts(host, port, version):
            weak_protocols.append(label)
    try:
        cert_bin, cipher, hsts = _handshake(host, port)
    except Exception as exc:
        return [_fail(host, port, "TLS 握手没有完成", str(exc)[:180], "medium", hints)]
    rows = []
    if weak_protocols:
        rows.append(_fail(host, port, "服务仍接受过时的 TLS 协议", ",".join(weak_protocols), "high", hints))
    else:
        rows.append(_pass(host, port, "未协商到 TLS 1.0 或 TLS 1.1", "已检查", hints))
    cert = x509.load_der_x509_certificate(cert_bin)
    now = datetime.now(timezone.utc)
    expires = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
    days = (expires - now).days
    if days < 0:
        rows.append(_fail(host, port, "证书已经过期", expires.date().isoformat(), "high", hints))
    elif days < 30:
        rows.append(_fail(host, port, "证书将在 30 天内过期", expires.date().isoformat(), "medium", hints))
    else:
        rows.append(_pass(host, port, "证书仍在有效期内", expires.date().isoformat(), hints))
    public = cert.public_key()
    if isinstance(public, rsa.RSAPublicKey) and public.key_size < 2048:
        rows.append(_fail(host, port, "证书公钥长度不足 2048 位", str(public.key_size), "medium", hints))
    else:
        rows.append(_pass(host, port, "证书公钥长度可用", type(public).__name__, hints))
    signature = cert.signature_hash_algorithm.name.lower() if cert.signature_hash_algorithm else ""
    if signature in {"sha1", "md5"}:
        rows.append(_fail(host, port, "证书使用了过时的签名算法", signature, "high", hints))
    else:
        rows.append(_pass(host, port, "证书签名算法可用", signature or "未知", hints))
    if cert.issuer == cert.subject:
        rows.append(_fail(host, port, "证书是自签名的", "subject=issuer", "low", hints))
    else:
        rows.append(_pass(host, port, "证书不是由自己签发", "已检查", hints))
    cipher_name = (cipher or ("", "", 0))[0].lower()
    if any(token in cipher_name for token in ("rc4", "3des", "des", "null")):
        rows.append(_fail(host, port, "协商到了弱加密套件", cipher_name, "high", hints))
    else:
        rows.append(_pass(host, port, "当前协商套件未发现弱算法", cipher_name or "未知", hints))
    if hsts:
        rows.append(_pass(host, port, "HTTPS 响应带有 HSTS", "Strict-Transport-Security", hints))
    else:
        rows.append(_fail(host, port, "HTTPS 响应没有 HSTS", "Strict-Transport-Security", "low", hints))
    return rows


def _accepts(host: str, port: int, version: ssl.TLSVersion) -> bool:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = version
        context.maximum_version = version
    except ValueError:
        return False
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _handshake(host: str, port: int) -> tuple[bytes, tuple | None, bool]:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=6) as sock:
        with context.wrap_socket(sock, server_hostname=host) as wrapped:
            cert = wrapped.getpeercert(binary_form=True) or b""
            cipher = wrapped.cipher()
            hsts = False
            try:
                wrapped.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
                data = wrapped.recv(1024).decode("latin1", errors="replace").lower()
                hsts = "strict-transport-security" in data
            except Exception:
                hsts = False
            return cert, cipher, hsts


def _fail(host: str, port: int, title: str, detail: str, severity: str, hints: list[str]) -> dict:
    return _row(host, port, "BASELINE_FAIL", severity, title, detail, hints)


def _pass(host: str, port: int, title: str, detail: str, hints: list[str]) -> dict:
    return _row(host, port, "BASELINE_PASS", "info", title, detail, hints)


def _row(host: str, port: int, kind: str, severity: str, title: str, detail: str, hints: list[str]) -> dict:
    return {
        "source_tool": "tls_scanner",
        "evidence_type": kind,
        "severity": severity,
        "cve_or_cwe": None,
        "title": f"{title}（{port}）",
        "port": str(port),
        "detail": {"text": f"{host}:{port} {detail}", "clause_hints": hints},
        "origin": "live",
        "clause_hints": hints,
    }
