"""保拓扑可逆脱敏。真实地址只进入本地加密映射，不进入模型请求。"""
from __future__ import annotations

import json
import re
from typing import Any

from cryptography.fernet import Fernet

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}")
AK_RE = re.compile(r"\b(?:AKIA|LTAI|AKID)[A-Za-z0-9]{12,}\b")
PHONE_RE = re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")
IDCARD_RE = re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")
SECRET_HEADER_RE = re.compile(r"(?im)^(authorization|cookie|set-cookie|x-api-key)\s*:.*$")


def build_zone_map(assets: list[dict]) -> dict[str, str]:
    counters: dict[str, int] = {}
    mapping: dict[str, str] = {}
    for asset in assets:
        zone = str(asset.get("security_zone") or "EXT").upper()
        counters[zone] = counters.get(zone, 0) + 1
        mapping[asset["host"]] = f"ZONE_{zone}_HOST_{counters[zone]:02d}"
    return mapping


def redact_text(text: str, zone_map: dict[str, str]) -> str:
    if not text:
        return ""
    output = text
    for host, token in sorted(zone_map.items(), key=lambda item: len(item[0]), reverse=True):
        output = output.replace(host, token)
    output = SECRET_HEADER_RE.sub(r"\1: [REDACTED]", output)
    output = JWT_RE.sub("[JWT]", output)
    output = AK_RE.sub("[ACCESS_KEY]", output)
    output = EMAIL_RE.sub("[EMAIL]", output)
    output = PHONE_RE.sub("[PHONE]", output)
    output = IDCARD_RE.sub("[IDCARD]", output)

    def _ip(match: re.Match) -> str:
        ip = match.group(0)
        # 条款编号 8.1.4.4-a 里的数字不是主机地址。
        if match.end() < len(output) and output[match.end()] == "-":
            return ip
        return zone_map.get(ip, "ZONE_EXT_IP")

    output = IPV4_RE.sub(_ip, output)
    return output


PRIVATE_IP_RE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})\b"
)


def delivery_leak_findings(texts: list[str], secrets: list[str]) -> list[str]:
    """送入外部合规台账前，再扫一遍人工备注和报告正文。"""
    payload = "\n".join(text for text in texts if text)
    found = leak_findings(payload, secrets)
    found.extend(PRIVATE_IP_RE.findall(payload))
    unique: list[str] = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique


def leak_findings(payload: str, secrets: list[str]) -> list[str]:
    found = []
    for secret in secrets:
        if secret and secret in payload:
            found.append(secret)
    if JWT_RE.search(payload) or AK_RE.search(payload) or EMAIL_RE.search(payload):
        found.append("pattern")
    if PHONE_RE.search(payload) or IDCARD_RE.search(payload):
        found.append("pii")
    return found


def _redact_value(value: Any, zone_map: dict[str, str]) -> Any:
    """递归对结构化 detail 中的字符串字段执行脱敏，保留数值与布尔类型。"""
    if isinstance(value, str):
        return redact_text(value, zone_map)
    if isinstance(value, list):
        return [_redact_value(v, zone_map) for v in value]
    if isinstance(value, dict):
        return {str(k): _redact_value(v, zone_map) for k, v in value.items()}
    return value


def sanitize_records(records: list[dict], assets: list[dict], fernet_key: str) -> tuple[list[dict], dict, str, bool]:
    zone_map = build_zone_map(assets)
    secrets = [asset["host"] for asset in assets]
    sanitized: list[dict] = []
    previews = []
    for record in records:
        detail = record.get("detail") or {}
        if isinstance(detail, str):
            text = detail
            hints = list(record.get("clause_hints") or [])
            extra: dict[str, Any] = {}
        else:
            text = str(detail.get("text") or "")
            hints = list(record.get("clause_hints") or detail.get("clause_hints") or [])
            extra = {
                k: _redact_value(v, zone_map)
                for k, v in detail.items()
                if k not in {"text", "clause_hints"}
            }
        if record.get("port") and "port" not in extra:
            extra["port"] = str(record.get("port"))
        clean = redact_text(text, zone_map)
        item = dict(record)
        item["clause_hints"] = hints
        item["detail"] = {**extra, "text": clean, "clause_hints": hints}
        sanitized.append(item)
        previews.append({"title": record.get("title"), "before": text[:500], "after": clean[:500]})
    blob_text = json.dumps({"zone_map": zone_map, "previews": previews}, ensure_ascii=False)
    leaks = leak_findings(json.dumps([item["detail"] for item in sanitized], ensure_ascii=False), secrets)
    passed = not leaks
    token = Fernet(fernet_key.encode("utf-8") if isinstance(fernet_key, str) else fernet_key)
    encrypted = token.encrypt(json.dumps(zone_map, ensure_ascii=False).encode("utf-8")).decode("utf-8")
    preview = {"samples": previews[:8], "leaks": leaks, "zone_map_keys": list(zone_map)}
    return sanitized, preview, encrypted, passed


def _decrypt_zone_map(encrypted: str, fernet_key: str) -> dict[str, str]:
    data = json.loads(Fernet(fernet_key.encode("utf-8")).decrypt(encrypted.encode("utf-8")))
    return {str(host): str(token) for host, token in data.items()}


def restore_token(encrypted: str, fernet_key: str, token_name: str) -> str:
    for host, token in _decrypt_zone_map(encrypted, fernet_key).items():
        if token == token_name:
            return host
    return token_name


def restore_mapping(encrypted: str, fernet_key: str) -> dict[str, str]:
    """把保险库里的代号还原成主机地址，键是代号。"""
    return {token: host for host, token in _decrypt_zone_map(encrypted, fernet_key).items()}
