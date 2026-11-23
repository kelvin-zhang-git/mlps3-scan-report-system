"""扫描调度：白名单校验、只读采集、去重、脱敏后等待人工放行。"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from core.asset_access import resolve_ssh
from core.collectors.db_mw_baseline import collect_db_mw_over_ssh, parse_db_mw_baseline
from core.collectors.ssh_baseline import collect_over_ssh, collect_rpm_lines, parse_baseline
from core.collectors.tls_scanner import inspect_endpoints
from core.container_scanners import scan_nmap, scan_nuclei, scan_trivy_sbom
from core.defectdojo_client import deduplicate, import_findings
from core.policy import PolicyError, assert_targets_allowed
from core.rpm_sbom import rpm_to_cyclonedx
from core.sanitizer import sanitize_records
from core.settings import vault_key
from database.db_manager import new_id


def run_collection(db, job: dict, assets: list[dict], policy: dict) -> None:
    enabled = [asset for asset in assets if asset.get("is_enabled", True)]
    assert_targets_allowed(enabled, policy["whitelist_cidrs"], policy["forbidden_cidrs"])
    excluded = policy.get("global_limits", {}).get("nuclei_exclude_tags", [])
    workers = max(1, int(policy.get("global_limits", {}).get("max_concurrency") or 2))
    db.add_event(job["job_id"], "policy", f"白名单通过，准备核查 {len(enabled)} 台主机，Nuclei 已排除标签 {', '.join(excluded)}", 10)
    findings: list[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_collect_asset, db, job, asset, policy): asset for asset in enabled}
        for future in as_completed(futures):
            asset = futures[future]
            try:
                findings.extend(future.result())
            except Exception as exc:
                err_msg = f"{type(exc).__name__}: {exc or '执行超时或连接中断'}"
                db.add_event(job["job_id"], "asset", f"{asset.get('host')} 采集失败：{err_msg}", 60)
                findings.append({
                    "asset_id": asset["asset_id"],
                    "source_tool": "runner",
                    "evidence_type": "COLLECT_ERROR",
                    "severity": "info",
                    "cve_or_cwe": None,
                    "title": "主机采集没有完成",
                    "port": "",
                    "detail": {"text": f"采集异常（不计入合规不符合）：{err_msg}"[:300], "clause_hints": []},
                    "origin": "live",
                    "clause_hints": [],
                })
    for row in findings:
        row.setdefault("evidence_id", new_id("ev"))
        detail = row.get("detail") or {}
        row["clause_hints"] = row.get("clause_hints") or detail.get("clause_hints") or []
    merged = deduplicate(findings)
    db.add_event(job["job_id"], "dedup", f"二次去重后保留 {len(merged)} 条证据", 70)
    project = db.get_project(job["project_id"])
    dojo = import_findings(merged, project, job)
    db.add_event(job["job_id"], "defectdojo", dojo.get("detail") or dojo.get("mode") or "已处理", 72)
    if dojo.get("engagement_id") or dojo.get("product_id"):
        fields = {
            "dojo_product_id": dojo.get("product_id") or None,
            "dojo_product_name": dojo.get("product_name"),
            "dojo_engagement_id": dojo.get("engagement_id") or None,
            "dojo_url": dojo.get("url"),
        }
        db.save_integration(job["project_id"], fields)
        db.save_job_delivery(job["job_id"], job["project_id"], fields)
    db.add_sync_record(job["project_id"], job["job_id"], "defectdojo_push", "ok" if dojo.get("mode") == "defectdojo" else "skipped", dojo.get("detail") or "", dojo)
    sanitized, preview, encrypted, passed = sanitize_records(merged, assets, vault_key())
    if not passed:
        db.save_vault(job["job_id"], encrypted, False, preview)
        db.update_job(job["job_id"], status="failed", error_msg="脱敏结果未通过零泄漏检查", finished_at=_now(db))
        db.add_event(job["job_id"], "sanitizer", "发现未脱敏秘密，已拒绝送入模型", 100)
        return
    db.replace_evidences(job["job_id"], sanitized)
    _pull_dojo_status(db, job, dojo)
    db.save_vault(job["job_id"], encrypted, True, preview)
    db.update_job(job["job_id"], status="awaiting_approval", progress_pct=80, current_stage="awaiting_approval")
    db.add_event(job["job_id"], "sanitizer", "脱敏完成，等待人工放行后再调用模型", 80)


def _pull_dojo_status(db, job: dict, dojo: dict) -> None:
    engagement_id = str(dojo.get("engagement_id") or "")
    if not engagement_id:
        return
    try:
        from core.defectdojo_client import pull_engagement_status
        from core.delivery import apply_dojo_pull

        pulled = pull_engagement_status(engagement_id)
        stats = apply_dojo_pull(db, job["job_id"], pulled.get("findings") or [])
        db.add_sync_record(job["project_id"], job["job_id"], "defectdojo_pull", "ok", pulled.get("detail") or "已同步", stats)
    except Exception as exc:
        db.add_event(job["job_id"], "defectdojo", f"处置状态暂未同步：{exc}"[:180], 74)


def _collect_asset(db, job: dict, asset: dict, policy: dict) -> list[dict]:
    findings: list[dict] = []
    scanners = set(asset.get("scanners") or [])
    nmap_rows: list[dict] = []
    if "ssh_baseline" in scanners:
        findings.extend(_baseline(db, job, asset))
    if "db_mw_baseline" in scanners or "ssh_baseline" in scanners or asset.get("object_type") in {"database", "middleware"}:
        findings.extend(_db_mw_baseline(db, job, asset))
    if "nmap" in scanners:
        nmap_rows = _nmap(db, job, asset, policy)
        findings.extend(nmap_rows)
    if "tls_scanner" in scanners or "nmap" in scanners:
        ports = _tls_ports(nmap_rows)
        if ports:
            tls_rows = inspect_endpoints(asset["host"], ports)
            for row in tls_rows:
                row["asset_id"] = asset["asset_id"]
            findings.extend(tls_rows)
            db.add_event(job["job_id"], "tls", f"{asset['host']} TLS 检查 {len(tls_rows)} 条", 58)
    if "nuclei" in scanners:
        local_policy = dict(policy)
        local_policy["web_targets"] = _web_targets(asset["host"], nmap_rows)
        findings.extend(_tool(db, job, asset, "nuclei", scan_nuclei, local_policy))
    if "trivy" in scanners:
        findings.extend(_trivy_os(db, job, asset))
    return findings


def _baseline(db, job: dict, asset: dict) -> list[dict]:
    resolved = resolve_ssh(asset)
    try:
        outputs = collect_over_ssh(
            asset["host"], resolved["port"], resolved["username"], resolved.get("password"), resolved.get("key_path"), resolved.get("key_text")
        )
        rows = parse_baseline(outputs, asset["asset_id"])
        db.add_event(job["job_id"], "ssh_baseline", f"{asset['host']} 只读基线采集 {len(rows)} 条", 40)
        return rows
    except Exception as exc:  # 网络或认证/超时失败留痕为 COLLECT_ERROR，不误算作合规不符合
        err_msg = f"{type(exc).__name__}: {exc or '执行超时或连接中断'}"
        db.add_event(job["job_id"], "ssh_baseline", f"{asset['host']} 基线采集失败：{err_msg}", 40)
        return [{
            "asset_id": asset["asset_id"],
            "source_tool": "ssh_baseline",
            "evidence_type": "COLLECT_ERROR",
            "severity": "info",
            "cve_or_cwe": None,
            "title": "主机基线采集失败",
            "port": "22",
            "detail": {"text": f"采集未完成（不计入合规不符合）：{err_msg}"[:300], "clause_hints": []},
            "origin": "live",
            "clause_hints": [],
        }]


def _db_mw_baseline(db, job: dict, asset: dict) -> list[dict]:
    resolved = resolve_ssh(asset)
    try:
        outputs = collect_db_mw_over_ssh(
            asset["host"], resolved["port"], resolved["username"], resolved.get("password"), resolved.get("key_path"), resolved.get("key_text")
        )
        rows = parse_db_mw_baseline(outputs, asset["asset_id"])
        if rows:
            db_cnt = sum(1 for r in rows if r.get("source_tool") == "db_baseline")
            mw_cnt = sum(1 for r in rows if r.get("source_tool") == "mw_baseline")
            db.add_event(job["job_id"], "db_mw_baseline", f"{asset['host']} 数据库/中间件只读基线采集 {len(rows)} 条（数据库 {db_cnt} · 中间件 {mw_cnt}）", 46)
        return rows
    except Exception as exc:
        db.add_event(job["job_id"], "db_mw_baseline", f"{asset['host']} 数据库/中间件基线跳过：{exc}", 46)
        return []


def _trivy_os(db, job: dict, asset: dict) -> list[dict]:
    try:
        os_name, version, lines = collect_rpm_lines(asset["host"], resolve_ssh(asset))
        message, rows = scan_trivy_sbom(rpm_to_cyclonedx(lines, os_name, version))
    except Exception as exc:
        db.add_event(job["job_id"], "trivy_os", f"{asset['host']} 软件包漏洞扫描失败：{exc}", 62)
        return []
    for row in rows:
        row["asset_id"] = asset["asset_id"]
    db.add_event(job["job_id"], "trivy_os", f"{asset['host']} {message}", 62)
    return rows


def _tls_ports(rows: list[dict]) -> list[int]:
    ports = []
    for row in rows:
        detail = row.get("detail") or {}
        service = str(detail.get("service") or "")
        if detail.get("tunnel") == "ssl" or service in {"https", "ssl", "https-alt"}:
            try:
                ports.append(int(row.get("port") or 0))
            except ValueError:
                continue
    for fallback in (443, 8443):
        if any(str(row.get("port")) == str(fallback) for row in rows) and fallback not in ports:
            ports.append(fallback)
    return [port for port in ports if port > 0]


def _web_targets(host: str, rows: list[dict]) -> list[str]:
    """按 nmap 识别出的协议生成地址。端口号只在服务名未知时兜底，避免对同一端口同时打 http 和 https。"""
    targets = []
    for row in rows:
        detail = row.get("detail") or {}
        service = str(detail.get("service") or "")
        port = str(row.get("port") or "")
        tunnel = str(detail.get("tunnel") or "")
        secure = tunnel == "ssl" or service in {"https", "ssl"}
        plain = service in {"http", "http-proxy", "http-alt"}
        if not secure and not plain and port in {"443", "8443"}:
            secure = True
        if not secure and not plain and port in {"80", "8080", "8000", "3000"}:
            plain = True
        if plain:
            targets.append(f"http://{host}:{port}" if port and port != "80" else f"http://{host}")
        if secure:
            targets.append(f"https://{host}:{port}" if port and port != "443" else f"https://{host}")
    return list(dict.fromkeys(targets)) or [f"http://{host}"]


def _tool(db, job: dict, asset: dict, stage: str, func, policy: dict) -> list[dict]:
    try:
        message, rows = func(asset["host"], policy)
    except Exception as exc:
        db.add_event(job["job_id"], stage, f"{asset['host']} {stage} 失败：{exc}", 55)
        return []
    for row in rows:
        row["asset_id"] = asset["asset_id"]
    progress = {"nmap": 50, "nuclei": 60}.get(stage, 55)
    db.add_event(job["job_id"], stage, message, progress)
    return rows


def _nmap(db, job: dict, asset: dict, policy: dict) -> list[dict]:
    return _tool(db, job, asset, "nmap", scan_nmap, policy)


def parse_nmap_xml(xml_text: str, asset_id: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    rows = []
    for port in root.findall(".//port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        port_id = port.get("portid") or ""
        service = port.find("service")
        name = service.get("name") if service is not None else "unknown"
        product = service.get("product") if service is not None else ""
        tunnel = service.get("tunnel") if service is not None else ""
        severity = "medium" if port_id in {"22", "23", "3389", "3306", "5432", "6379", "9200", "27017"} else "low"
        hints = ["8.1.3.1-a", "8.1.2.2-a"] if tunnel == "ssl" or name in {"https", "ssl"} else ["8.1.3.1-a"]
        rows.append({
            "asset_id": asset_id,
            "source_tool": "nmap",
            "evidence_type": "VULNERABILITY" if severity == "medium" else "BASELINE_PASS",
            "severity": severity,
            "cve_or_cwe": None,
            "title": f"开放端口 {port_id}/{name}",
            "port": port_id,
            "detail": {"text": f"端口 {port_id} 服务 {name} {product}".strip(), "clause_hints": hints, "tunnel": tunnel or "", "service": name},
            "origin": "live",
            "clause_hints": hints,
        })
    return rows


def _now(db) -> str:
    from database.db_manager import utcnow
    return utcnow()
