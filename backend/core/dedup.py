"""跨工具漏洞二次聚合。"""
from __future__ import annotations

from collections import defaultdict
from typing import Any


def aggregate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """同一资产上的同一 CVE 或同一 CWE+端口只保留一条，并记录检出工具。"""
    grouped: dict[tuple, dict] = {}
    order: list[tuple] = []
    for item in findings:
        cve = (item.get("cve_or_cwe") or "").upper()
        port = str(item.get("port") or item.get("component") or "")
        asset = item["asset_id"]
        if cve.startswith("CVE-"):
            key = (asset, "CVE", cve, port)
        elif cve.startswith("CWE-"):
            key = (asset, "CWE", cve, port)
        else:
            key = (asset, "TITLE", item.get("title"), port, item.get("source_tool"))
        if key not in grouped:
            detail = dict(item.get("detail") or {}) if isinstance(item.get("detail"), dict) else {"text": str(item.get("detail") or "")}
            pkg = detail.get("pkg_name")
            if pkg:
                detail["affected_pkgs"] = [pkg]
            grouped[key] = {
                **item,
                "detail": detail,
                "detected_by": [item.get("source_tool")],
            }
            order.append(key)
        else:
            tools = grouped[key]["detected_by"]
            tool = item.get("source_tool")
            if tool and tool not in tools:
                tools.append(tool)
            if _rank(item.get("severity")) > _rank(grouped[key].get("severity")):
                grouped[key]["severity"] = item.get("severity")
            # 同一资产同一 CVE 影响多个子包时，聚合受影响包名清单
            new_detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
            pkg = new_detail.get("pkg_name")
            if pkg:
                pkgs = grouped[key]["detail"].setdefault("affected_pkgs", [])
                if pkg not in pkgs:
                    pkgs.append(pkg)
            if new_detail.get("fixed_version") and not grouped[key]["detail"].get("fixed_version"):
                grouped[key]["detail"]["fixed_version"] = new_detail["fixed_version"]
            if new_detail.get("cvss_score") is not None:
                prev_cvss = grouped[key]["detail"].get("cvss_score")
                if prev_cvss is None or float(new_detail["cvss_score"]) > float(prev_cvss):
                    grouped[key]["detail"]["cvss_score"] = new_detail["cvss_score"]
                    grouped[key]["detail"]["cvss_vector"] = new_detail.get("cvss_vector") or ""
    return [grouped[key] for key in order]


def _rank(severity: str | None) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get((severity or "").lower(), 0)
