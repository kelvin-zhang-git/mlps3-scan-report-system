"""godlp、Akto、Kubescape、ZAP 结果适配。只消费已有报告，不发起攻击流量。"""
from __future__ import annotations

from typing import Any


def parse_godlp(report: dict, asset_id: str) -> list[dict]:
    leaked = int(report.get("unmasked_count") or 0)
    title = "跨境样本存在未脱敏字段" if leaked else "跨境样本脱敏抽检通过"
    return [{
        "asset_id": asset_id,
        "source_tool": "godlp",
        "evidence_type": "CLOUD_CONFIG" if leaked else "BASELINE_PASS",
        "severity": "high" if leaked else "info",
        "cve_or_cwe": None,
        "title": title,
        "port": "",
        "detail": {"text": f"未脱敏计数 {leaked}", "clause_hints": ["8.1.4.6-a"]},
        "origin": "import",
        "clause_hints": ["8.1.4.6-a"],
    }]


def parse_akto(report: dict, asset_id: str) -> list[dict]:
    rows = []
    for item in report.get("findings", []):
        rows.append({
            "asset_id": asset_id,
            "source_tool": "akto",
            "evidence_type": "VULNERABILITY",
            "severity": item.get("severity", "medium"),
            "cve_or_cwe": item.get("cwe"),
            "title": item.get("title", "API 鉴权缺陷"),
            "port": "443",
            "detail": {"text": item.get("endpoint", ""), "clause_hints": ["8.1.4.2-a"]},
            "origin": "import",
            "clause_hints": ["8.1.4.2-a"],
        })
    return rows


def parse_kubescape(report: dict, asset_id: str) -> list[dict]:
    rows = []
    for item in report.get("controls", []):
        if item.get("status") == "failed":
            rows.append({
                "asset_id": asset_id,
                "source_tool": "kubescape",
                "evidence_type": "BASELINE_FAIL",
                "severity": item.get("severity", "medium"),
                "cve_or_cwe": item.get("id"),
                "title": item.get("name", "集群基线未通过"),
                "port": "",
                "detail": {"text": item.get("name", ""), "clause_hints": ["8.1.4.4-a"]},
                "origin": "import",
                "clause_hints": ["8.1.4.4-a"],
            })
    return rows


def parse_zap(report: dict, asset_id: str) -> list[dict]:
    rows = []
    for site in report.get("site", []):
        for alert in site.get("alerts", []):
            rows.append({
                "asset_id": asset_id,
                "source_tool": "zap",
                "evidence_type": "VULNERABILITY",
                "severity": _zap_risk(alert.get("riskcode")),
                "cve_or_cwe": alert.get("cweid") and f"CWE-{alert.get('cweid')}",
                "title": alert.get("name", "ZAP 告警"),
                "port": "443",
                "detail": {"text": alert.get("desc", "")[:240], "clause_hints": ["8.1.4.4-a"]},
                "origin": "import",
                "clause_hints": ["8.1.4.4-a"],
            })
    return rows


def _zap_risk(code: Any) -> str:
    return {"3": "high", "2": "medium", "1": "low"}.get(str(code), "info")
