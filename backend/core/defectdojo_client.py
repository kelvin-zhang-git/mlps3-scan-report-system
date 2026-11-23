"""DefectDojo 客户端。未连通时只在本地完成二次去重。"""
from __future__ import annotations

import json
import os
from typing import Any

import httpx

from core.dedup import aggregate_findings

IMPORT_TYPES = {"BASELINE_FAIL", "VULNERABILITY", "CLOUD_CONFIG"}


def deduplicate(findings: list[dict]) -> list[dict]:
    return aggregate_findings(findings)


def _base_url() -> str:
    return os.environ.get("DEFECTDOJO_URL", "").rstrip("/")


def connector_status() -> dict:
    url = _base_url()
    if not url:
        return {"name": "DefectDojo", "configured": False, "reachable": False, "detail": "未配置 DEFECTDOJO_URL"}
    token = ""
    try:
        token = _token()
    except httpx.HTTPError:
        token = ""
    headers = {"Authorization": f"Token {token}"} if token else {}
    try:
        response = httpx.get(f"{url}/api/v2/users/", headers=headers, timeout=8.0)
        ok = response.status_code < 500
        return {"name": "DefectDojo", "configured": True, "reachable": ok, "detail": f"HTTP {response.status_code}"}
    except httpx.HTTPError as exc:
        return {"name": "DefectDojo", "configured": True, "reachable": False, "detail": str(exc)}


def _token() -> str:
    existing = os.environ.get("DEFECTDOJO_API_TOKEN", "").strip()
    if existing:
        return existing
    username = os.environ.get("DEFECTDOJO_ADMIN_USER", "admin")
    password = os.environ.get("DEFECTDOJO_ADMIN_PASSWORD", "")
    if not password:
        return ""
    response = httpx.post(
        f"{_base_url()}/api/v2/api-token-auth/",
        json={"username": username, "password": password},
        timeout=20.0,
    )
    response.raise_for_status()
    return str(response.json().get("token") or "")


def public_dojo_base() -> str:
    host = os.environ.get("SCANNER_HOST", "").strip()
    if host:
        return f"http://{host}:8080"
    return _base_url() or "http://127.0.0.1:8080"


def engagement_name_for(job: dict | None) -> str:
    if not job:
        return os.environ.get("DEFECTDOJO_ENGAGEMENT", "stage1")
    started = str(job.get("started_at") or "")[:10]
    return f"{str(job.get('job_id') or '')[:12]}-{started or 'job'}"


def product_name_for(project: dict | None) -> str:
    if project and project.get("name"):
        return str(project["name"])
    return os.environ.get("DEFECTDOJO_PRODUCT", "等保三级扫描")


def import_findings(findings: list[dict], project: dict | None = None, job: dict | None = None) -> dict[str, Any]:
    status = connector_status()
    product_name = product_name_for(project)
    engagement_name = engagement_name_for(job)
    context = {"product_name": product_name, "engagement_name": engagement_name}
    if not status["reachable"]:
        return {"imported": 0, "mode": "local_dedup", "detail": status["detail"], **context}
    token = _token()
    if not token:
        return {"imported": 0, "mode": "local_dedup", "detail": "DefectDojo 可达，但没有 API Token 或管理员口令", **context}
    selected = [row for row in findings if row.get("evidence_type") in IMPORT_TYPES and not row.get("dojo_finding_id")]
    payload = {"findings": [_generic(row) for row in selected]}
    if not payload["findings"]:
        return {"imported": 0, "mode": "defectdojo", "detail": "没有需要导入的不符合项", **context}
    data = {
        "scan_type": "Generic Findings Import",
        "product_type_name": os.environ.get("DEFECTDOJO_PRODUCT_TYPE", "等保评估"),
        "product_name": product_name,
        "engagement_name": engagement_name,
        "auto_create_context": "true",
        "active": "true",
        "verified": "false",
        "minimum_severity": "Info",
        "close_old_findings": "false",
    }
    try:
        response = httpx.post(
            f"{_base_url()}/api/v2/import-scan/",
            headers={"Authorization": f"Token {token}"},
            data=data,
            files={"file": ("findings.json", json.dumps(payload, ensure_ascii=False), "application/json")},
            timeout=90.0,
        )
    except httpx.HTTPError as exc:
        return {"imported": 0, "mode": "defectdojo", "detail": f"导入失败：{exc}", **context}
    if response.status_code >= 300:
        return {"imported": 0, "mode": "defectdojo", "detail": f"导入失败 HTTP {response.status_code}：{response.text[:240]}", **context}
    body = response.json() if response.content else {}
    product_id, engagement_id, test_id = _import_ids(body)
    if not engagement_id:
        engagement_id = _lookup_engagement(token, engagement_name)
    url = f"{public_dojo_base()}/engagement/{engagement_id}" if engagement_id else public_dojo_base()
    return {
        "imported": len(payload["findings"]),
        "mode": "defectdojo",
        "detail": f"已导入 DefectDojo {len(payload['findings'])} 条",
        "product_id": product_id,
        "engagement_id": engagement_id,
        "test_id": test_id,
        "url": url,
        **context,
    }


def pull_engagement_status(engagement_id: str) -> dict[str, Any]:
    token = _token()
    if not token or not engagement_id:
        return {"findings": [], "detail": "尚未建立对应的 DefectDojo 处置周期"}
    headers = {"Authorization": f"Token {token}"}
    url = f"{_base_url()}/api/v2/findings/?test__engagement={engagement_id}&limit=200"
    rows: list[dict] = []
    while url:
        response = httpx.get(url, headers=headers, timeout=40.0)
        if response.status_code >= 300:
            return {"findings": rows, "detail": f"状态同步失败 HTTP {response.status_code}"}
        body = response.json()
        rows.extend(body.get("results") or [])
        url = body.get("next") or ""
    findings = [_pulled(row) for row in rows]
    return {"findings": findings, "detail": f"已同步 {len(findings)} 条处置状态"}


def _import_ids(body: dict) -> tuple[str, str, str]:
    product = body.get("product_id") or body.get("product") or ""
    engagement = body.get("engagement_id") or body.get("engagement") or ""
    test = body.get("test_id") or body.get("test") or ""
    return _id_of(product), _id_of(engagement), _id_of(test)


def _id_of(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("id") or "")
    return str(value or "")


def _lookup_engagement(token: str, name: str) -> str:
    response = httpx.get(
        f"{_base_url()}/api/v2/engagements/",
        headers={"Authorization": f"Token {token}"},
        params={"name": name},
        timeout=20.0,
    )
    if response.status_code >= 300:
        return ""
    results = response.json().get("results") or []
    return str(results[0]["id"]) if results else ""


def _pulled(row: dict) -> dict:
    if row.get("false_p"):
        status = "false_positive"
    elif row.get("is_mitigated"):
        status = "mitigated"
    else:
        status = "active"
    return {
        "id": row.get("id"),
        "title": row.get("title") or "",
        "cve": row.get("cve") or "",
        "unique_id_from_tool": row.get("unique_id_from_tool") or "",
        "false_p": bool(row.get("false_p")),
        "is_mitigated": bool(row.get("is_mitigated")),
        "status": status,
    }


def _generic(row: dict) -> dict:
    severity = str(row.get("severity") or "Info").capitalize()
    if severity not in {"Info", "Low", "Medium", "High", "Critical"}:
        severity = "Info"
    description = (row.get("detail") or {}).get("text") or row.get("title") or ""
    item: dict[str, Any] = {
        "title": row.get("title") or "未命名发现",
        "severity": severity,
        "description": str(description)[:4000],
        "mitigation": "按等保三级差距项整改后复测。",
        "unique_id_from_tool": str(row.get("evidence_id") or ""),
    }
    cve = row.get("cve_or_cwe")
    if cve and str(cve).upper().startswith("CVE-"):
        item["cve"] = cve
    if row.get("port"):
        item["endpoints"] = [str(row["port"])]
    return item
