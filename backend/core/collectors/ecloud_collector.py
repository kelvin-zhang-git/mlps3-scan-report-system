"""移动云只读配置归一化。没有密钥时不发起外呼。"""
from __future__ import annotations

import os
from typing import Any


def normalize_ecloud(snapshot: dict[str, Any], asset_id: str) -> list[dict]:
    rows = []
    if snapshot.get("mfa_enabled") is False:
        rows.append(_cloud(asset_id, "云账号未启用 MFA", "high", "主账号未开启多因素认证", ["cloud.8.1-a"]))
    elif snapshot.get("mfa_enabled") is True:
        rows.append(_cloud(asset_id, "云账号已启用 MFA", "info", "MFA 已开启", ["cloud.8.1-a"], passed=True))
    for rule in snapshot.get("security_groups", []):
        cidr = rule.get("cidr")
        port = str(rule.get("port"))
        if cidr == "0.0.0.0/0" and port in {"22", "3389", "3306", "6379", "9200"}:
            rows.append(_cloud(asset_id, f"安全组对全网开放 {port}", "high", f"{cidr}:{port}", ["cloud.8.2-a"]))
    if snapshot.get("audit_enabled") is False:
        rows.append(_cloud(asset_id, "云操作审计未开启", "high", "审计日志未覆盖", ["cloud.8.3-a"]))
    if snapshot.get("bucket_public") is True:
        rows.append(_cloud(asset_id, "对象存储存在公共读写", "high", "桶 ACL 对匿名用户开放", ["cloud.8.3-a"]))
    return rows


def collector_status() -> dict:
    configured = bool(os.environ.get("ECLOUD_ACCESS_KEY") and os.environ.get("ECLOUD_SECRET_KEY"))
    return {
        "name": "移动云 OpenAPI",
        "configured": configured,
        "mode": "readonly" if configured else "not_configured",
        "detail": "已配置只读密钥" if configured else "未配置密钥，采集器保持关闭",
    }


def _cloud(asset_id: str, title: str, severity: str, text: str, hints: list[str], passed: bool = False) -> dict:
    return {
        "asset_id": asset_id,
        "source_tool": "ecloud",
        "evidence_type": "BASELINE_PASS" if passed else "CLOUD_CONFIG",
        "severity": "info" if passed else severity,
        "cve_or_cwe": None,
        "title": title,
        "port": "",
        "detail": {"text": text, "clause_hints": hints},
        "origin": "import",
        "clause_hints": hints,
    }
