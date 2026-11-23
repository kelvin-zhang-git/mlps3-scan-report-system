from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from api.deps import current_user, get_db
from api.projects import load_clauses
from core.report_generator import render_docx_report, render_report, render_tickets
from core.report_narrative import (
    asset_display_name,
    build_asset_directory,
    ensure_report_narrative,
    format_beijing,
    replace_asset_refs_in_text,
    rewrite_narrative_assets,
)
from core.sanitizer import restore_mapping
from core.scoring import department_for, priority_for, score_assessments, status_zh
from core.settings import vault_key
from database.db_manager import Database

router = APIRouter(prefix="/api/reports", tags=["reports"])

SEVERITY_ZH = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息"}


_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

_TOOL_LABELS = {
    "ssh_baseline": "主机只读基线（SSH）",
    "db_baseline": "数据库只读基线",
    "mw_baseline": "中间件只读基线",
    "trivy_os": "软件包漏洞扫描（Trivy）",
    "nmap": "端口与服务发现（Nmap）",
    "tls_scanner": "传输加密检测（TLS/HTTPS）",
    "nuclei": "Web 暴露面检测（Nuclei）",
    "netdev_config": "网络/安全设备离线配置核查",
    "cloud_audit": "云平台离线核查",
}


def _departments(assessments: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for row in assessments:
        if row.get("final_status") not in {"non_compliant", "partially_compliant", "pending_manual"}:
            continue
        grouped.setdefault(row.get("department") or "安全管理与合规", []).append(row)
    order = ["系统与主机运维", "网络与边界安全", "应用与研发", "云平台与基础架构", "安全管理与合规"]
    result: list[dict] = []
    for name in order:
        items = grouped.get(name)
        if not items:
            continue
        sorted_items = sorted(
            items,
            key=lambda r: (
                0 if r.get("final_status") in {"non_compliant", "partially_compliant"} else 1,
                _PRIORITY_RANK.get(str(r.get("priority") or "P3"), 3),
                str(r.get("clause_id") or ""),
            ),
        )
        tech_items = [r for r in sorted_items if r.get("final_status") in {"non_compliant", "partially_compliant"}]
        manual_items = [r for r in sorted_items if r.get("final_status") == "pending_manual"]
        result.append({
            "name": name,
            "items": sorted_items,
            "tech_items": tech_items,
            "manual_items": manual_items,
        })
    return result


def _host_summary(
    evidences: list[dict],
    asset_lookup: dict[str, dict[str, str]],
    assets: list[dict] | None = None,
    *,
    variant: str = "masked",
) -> list[dict]:
    grouped: dict[str, dict] = {}
    # 先为全部已启用资产初始化行，避免某台主机采集失败后从汇总表里“静默消失”
    for asset in assets or []:
        if not asset.get("is_enabled", True):
            continue
        aid = str(asset.get("asset_id") or "")
        scanners = set(asset.get("scanners") or [])
        grouped[aid] = {
            "asset_id": aid,
            "asset_display": asset_display_name(aid, asset_lookup, variant=variant),
            "ssh_enabled": "ssh_baseline" in scanners,
            "ssh_error": "",
            "passed": 0,
            "failed": 0,
            "db_mw_passed": 0,
            "db_mw_failed": 0,
        }

    for row in evidences:
        tool = row.get("source_tool")
        if tool not in {"ssh_baseline", "db_baseline", "mw_baseline"}:
            continue
        aid = str(row.get("asset_id") or "")
        bucket = grouped.setdefault(
            aid,
            {
                "asset_id": aid,
                "asset_display": asset_display_name(aid, asset_lookup, variant=variant),
                "ssh_enabled": tool == "ssh_baseline",
                "ssh_error": "",
                "passed": 0,
                "failed": 0,
                "db_mw_passed": 0,
                "db_mw_failed": 0,
            },
        )
        ev_type = row.get("evidence_type")
        if tool == "ssh_baseline":
            bucket["ssh_enabled"] = True
            if ev_type == "BASELINE_PASS":
                bucket["passed"] += 1
            elif ev_type == "BASELINE_FAIL":
                bucket["failed"] += 1
            elif ev_type == "COLLECT_ERROR":
                bucket["ssh_error"] = str((row.get("detail") or {}).get("text") or row.get("title") or "采集失败")
        else:
            if ev_type == "BASELINE_PASS":
                bucket["db_mw_passed"] += 1
            elif ev_type == "BASELINE_FAIL":
                bucket["db_mw_failed"] += 1

    rows: list[dict] = []
    for bucket in grouped.values():
        if bucket["passed"] or bucket["failed"]:
            bucket["ssh_status"] = "已采集"
        elif bucket["ssh_error"]:
            bucket["ssh_status"] = "采集失败"
        elif bucket["ssh_enabled"]:
            bucket["ssh_status"] = "未返回数据"
        else:
            bucket["ssh_status"] = "未启用"
        rows.append(bucket)
    return rows


def _group_remediation_scripts(assessments: list[dict]) -> list[dict]:
    """按脚本正文去重汇总技术加固脚本，标明适用条款清单，避免第八章重复堆砌。"""
    grouped: dict[str, dict] = {}
    for row in assessments:
        script = str(row.get("remediation_script") or "").strip()
        if not script:
            continue
        # 仅保留真正的技术加固脚本（至少包含命令行/注释结构）
        if not ("\n" in script or script.startswith("#")):
            continue
        cid = str(row.get("clause_id") or "")
        cp = str(row.get("control_point") or "")
        label = f"{cid}（{cp}）" if cp else cid
        # 将组合脚本按双换行拆分为独立场景块去重展示
        for block in [b.strip() for b in script.split("\n\n") if b.strip()]:
            first_line = block.splitlines()[0].lstrip("#").strip()
            entry = grouped.setdefault(block, {"title": first_line or "安全加固参考", "clauses": [], "script": block})
            if label and label not in entry["clauses"]:
                entry["clauses"].append(label)
    return list(grouped.values())


def build_report_context(
    db: Database,
    project: dict,
    job: dict,
    *,
    variant: str = "masked",
    refresh_ai: bool = False,
) -> dict[str, Any]:
    """汇总本轮评估事实并调用 AI 研判，生成报告渲染上下文。"""
    job_id = job["job_id"]
    assessments = [dict(row) for row in db.list_assessments(job_id)]
    all_clauses = {item["clause_id"]: item for item in load_clauses(None)}
    active_catalog = load_clauses(project.get("enabled_extensions"))
    for row in assessments:
        clause = all_clauses.get(row["clause_id"], {})
        row["domain"] = clause.get("domain", "") or row.get("domain", "")
        row["control_point"] = clause.get("control_point", "")
        row["requirement_text"] = clause.get("requirement_text", "")
        row["applicable_objects"] = clause.get("applicable_objects") or []
        row["applicable_object_labels"] = clause.get("applicable_object_labels") or []
        row["risk_weight_level"] = clause.get("risk_weight_level", "medium")
        row["high_risk_precedent"] = clause.get("high_risk_precedent")
        row["status_zh"] = status_zh(row.get("final_status") or "")
        row["department"] = department_for(row["domain"])
        row["priority"] = priority_for(row)
    # 若历史任务仍保存了旧版精简条款，则按实际评估记录构建计分目录
    if assessments:
        active_ids = {item["clause_id"] for item in active_catalog}
        row_ids = {row["clause_id"] for row in assessments}
        if len(row_ids) != len(active_ids) or not row_ids.issubset(active_ids):
            score_catalog = [all_clauses.get(row["clause_id"], {"clause_id": row["clause_id"], "domain": row.get("domain") or "未归类"}) for row in assessments]
        else:
            score_catalog = active_catalog
    else:
        score_catalog = active_catalog
    evidences = db.list_evidences(job_id)
    assets = db.list_assets(project["project_id"])
    enriched_assets, asset_lookup = build_asset_directory(assets)
    score = score_assessments(assessments, score_catalog, assets=assets, evidences=evidences)
    stats = db.dashboard(project["project_id"], job_id)
    paths = [dict(p) for p in db.list_paths(job_id)]
    manual_docs = db.list_manual_docs(project["project_id"])

    # AI 研判始终基于脱敏数据执行，确保送出内容不含真实地址。
    narrative = ensure_report_narrative(
        db,
        project,
        job,
        score,
        assessments,
        evidences,
        assets,
        paths,
        manual_docs,
        force_refresh=refresh_ai,
    )

    vault_mapping: dict[str, str] | None = None
    if variant == "restored":
        vault = db.get_vault(job_id)
        if vault:
            vault_mapping = restore_mapping(vault["encrypted_mapping_blob"], vault_key())

    for row in assessments:
        row["ai_rationale"] = replace_asset_refs_in_text(
            str(row.get("ai_rationale") or ""),
            asset_lookup,
            variant=variant,
            vault_mapping=vault_mapping,
        )
    for path in paths:
        path["title"] = replace_asset_refs_in_text(
            str(path.get("title") or ""),
            asset_lookup,
            variant=variant,
            vault_mapping=vault_mapping,
        )
        path["steps"] = [
            replace_asset_refs_in_text(str(step), asset_lookup, variant=variant, vault_mapping=vault_mapping)
            for step in (path.get("steps") or [])
        ]

    direct_high_risk_rows = [
        row for row in assessments
        if row.get("is_high_risk")
        and row.get("final_status") in {"non_compliant", "partially_compliant"}
        and row.get("compensation_status") != "mitigated"
    ]
    mitigated_high_risk_rows = [
        row for row in assessments
        if row.get("is_high_risk")
        and row.get("final_status") in {"non_compliant", "partially_compliant"}
        and row.get("compensation_status") == "mitigated"
    ]

    display_narrative = dict(narrative)
    display_narrative["sections"] = rewrite_narrative_assets(
        narrative.get("sections") or {},
        asset_lookup,
        variant=variant,
        vault_mapping=vault_mapping,
    )

    def _decorate_ev(row: dict) -> dict:
        item = dict(row)
        detail = item.get("detail") if isinstance(item.get("detail"), dict) else {}
        item["asset_display"] = asset_display_name(str(item.get("asset_id") or ""), asset_lookup, variant=variant)
        item["severity_zh"] = SEVERITY_ZH.get(str(item.get("severity") or "").lower(), str(item.get("severity") or ""))
        item["pkg_name"] = detail.get("pkg_name") or ""
        item["affected_pkgs"] = detail.get("affected_pkgs") or ([] if not item["pkg_name"] else [item["pkg_name"]])
        item["installed_version"] = detail.get("installed_version") or ""
        item["fixed_version"] = detail.get("fixed_version") or ""
        item["cvss_score"] = detail.get("cvss_score")
        item["cvss_vector"] = detail.get("cvss_vector") or ""
        item["severity_source"] = detail.get("severity_source") or ""
        item["port"] = item.get("port") or detail.get("port")
        item["detail_text"] = replace_asset_refs_in_text(
            str(detail.get("text") or ""),
            asset_lookup,
            variant=variant,
            vault_mapping=vault_mapping,
        )
        return item

    cves = [
        _decorate_ev(row)
        for row in evidences
        if row.get("source_tool") == "trivy_os" and row.get("severity") in {"high", "critical"}
    ]
    unique_cve_count = len({str(c.get("cve_or_cwe") or "") for c in cves if c.get("cve_or_cwe")})
    tls_rows = [
        _decorate_ev(row)
        for row in evidences
        if row.get("source_tool") == "tls_scanner" and row.get("evidence_type") != "COLLECT_ERROR"
    ]
    db_mw_rows = [
        _decorate_ev(row)
        for row in evidences
        if row.get("source_tool") in {"db_baseline", "mw_baseline"} and row.get("evidence_type") != "COLLECT_ERROR"
    ]
    def _port_of(row: dict) -> int:
        raw = row.get("port") or (row.get("detail") or {}).get("port")
        if raw and str(raw).isdigit():
            return int(raw)
        m = re.search(r"(\d+)", str(row.get("title") or ""))
        return int(m.group(1)) if m else 0

    open_ports = []
    for row in evidences:
        if row.get("source_tool") == "nmap" and row.get("evidence_type") != "COLLECT_ERROR":
            item = _decorate_ev(row)
            if not item.get("port"):
                p_num = _port_of(row)
                item["port"] = str(p_num) if p_num else ""
            open_ports.append(item)
    open_ports.sort(key=lambda r: (str(r.get("asset_display") or ""), int(r.get("port") or 0)))

    # 按受影响软件包统计高危/严重漏洞 Top 10，便于管理层与运维聚焦补丁组件
    pkg_counter: dict[str, dict[str, Any]] = {}
    for row in cves:
        pkg = str(row.get("pkg_name") or "").strip()
        if not pkg:
            continue
        bucket = pkg_counter.setdefault(
            pkg,
            {
                "pkg_name": pkg,
                "critical": 0,
                "high": 0,
                "max_cvss": 0.0,
                "installed_version": row.get("installed_version") or "",
                "fixed_version": row.get("fixed_version") or "",
            },
        )
        if row.get("severity") == "critical":
            bucket["critical"] += 1
        else:
            bucket["high"] += 1
        cvss = float(row.get("cvss_score") or 0.0)
        if cvss > bucket["max_cvss"]:
            bucket["max_cvss"] = cvss
        if not bucket["fixed_version"] and row.get("fixed_version"):
            bucket["fixed_version"] = row.get("fixed_version")
    top_vuln_pkgs = sorted(
        pkg_counter.values(),
        key=lambda x: (-x["critical"], -x["max_cvss"], -x["high"], x["pkg_name"]),
    )[:12]
    collect_errors = [_decorate_ev(row) for row in evidences if row.get("evidence_type") == "COLLECT_ERROR"]

    tools_used = [
        _TOOL_LABELS.get(t, t)
        for t in sorted({str(e.get("source_tool") or "") for e in evidences if e.get("source_tool")})
    ]
    report_meta = {
        "assessed_at": f"{format_beijing(job.get('finished_at') or job.get('started_at'))}（北京时间）",
        "started_at": f"{format_beijing(job.get('started_at'))}（北京时间）",
        "grade_spec": "第三级（建议定级 S3 / A3 / G3，最终以公安机关备案证明为准）",
        "scanner_origin": "内网独立扫描节点只读采集（同网段视角，互联网可达性需结合边界防火墙策略复核）",
        "tools_used": tools_used,
    }

    return {
        "project": project,
        "job_id": job_id,
        "report_meta": report_meta,
        "assessments": assessments,
        "paths": paths,
        "stats": stats,
        "assets": enriched_assets,
        "asset_lookup": asset_lookup,
        "host_summary": _host_summary(evidences, asset_lookup, assets=assets, variant=variant),
        "db_mw_rows": db_mw_rows,
        "open_ports": open_ports,
        "collect_errors": collect_errors,
        "cves": cves,
        "unique_cve_count": unique_cve_count,
        "top_vuln_pkgs": top_vuln_pkgs,
        "tls_rows": tls_rows,
        "score": score,
        "direct_high_risk_rows": direct_high_risk_rows,
        "mitigated_high_risk_rows": mitigated_high_risk_rows,
        "departments": _departments(assessments),
        "remediation_scripts": _group_remediation_scripts(assessments),
        "narrative": display_narrative,
        "masked_narrative": narrative,
    }


class ReportBody(BaseModel):
    variant: str
    refresh_ai: bool = False


@router.post("/{job_id}/generate")
def generate(job_id: str, body: ReportBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if body.variant not in {"masked", "restored"}:
        raise HTTPException(status_code=400, detail="报告版本不合法")
    if body.variant == "restored" and user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="还原版报告由等保负责人或系统管理员导出")
    job = db.get_job(job_id)
    project = db.get_project(job["project_id"]) if job else None
    if not job or not project:
        raise HTTPException(status_code=404, detail="任务不存在")
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，已有报告仍可下载，新的报告要等重新启用之后再生成")
    assessments = db.list_assessments(job_id)
    if job["status"] != "completed" or not assessments:
        raise HTTPException(status_code=400, detail="先完成条款评审，再生成报告")

    context = build_report_context(db, project, job, variant=body.variant, refresh_ai=body.refresh_ai)
    filename, path = render_report(context, body.variant)
    report = db.save_report(job_id, body.variant, filename, str(path))

    docx_variant = "restored_docx" if body.variant == "restored" else "masked_docx"
    docx_name, docx_path = render_docx_report(context, body.variant)
    docx_report = db.save_report(job_id, docx_variant, docx_name, str(docx_path))

    ticket_name, ticket_path = render_tickets(context)
    tickets = db.save_report(job_id, "tickets", ticket_name, str(ticket_path))
    ready = db.has_report_variant(job_id, "masked")
    narrative = context.get("masked_narrative") or {}
    return {
        "report": report,
        "docx_report": docx_report,
        "tickets": tickets,
        "delivery_ready": ready,
        "narrative": {
            "status": narrative.get("status"),
            "model_id": narrative.get("model_id"),
            "prompt_version": narrative.get("prompt_version"),
            "generated_at": narrative.get("generated_at"),
        },
    }


@router.get("/{report_id}/download")
def download(report_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> FileResponse:
    report = db.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="报告不存在")
    if report["variant"] in {"restored", "restored_docx"} and user.get("role") not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="还原版报告由等保负责人或系统管理员下载")
    return FileResponse(report["content_path"], filename=report["filename"])
