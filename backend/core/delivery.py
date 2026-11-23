"""项目内把评审结果送入 DefectDojo，终检并结合 AI 专业研判写入 CISO Assistant 与中文终版报告。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from core.ciso_sync import CisoError, deliver_assessment
from core.defectdojo_client import import_findings, pull_engagement_status
from core.report_generator import render_docx_report, render_report
from core.report_narrative import narrative_plain_texts
from core.report_prompts import DEFAULT_MLPS3_REPORT_PROMPT, REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE
from core.sanitizer import delivery_leak_findings


def push_defectdojo(db, project: dict, job: dict) -> dict[str, Any]:
    findings = db.list_evidences(job["job_id"])
    result = import_findings(findings, project, job)
    if result.get("engagement_id") or result.get("product_id"):
        fields = {
            "dojo_product_id": result.get("product_id") or None,
            "dojo_product_name": result.get("product_name"),
            "dojo_engagement_id": result.get("engagement_id") or None,
            "dojo_url": result.get("url"),
        }
        db.save_integration(project["project_id"], fields)
        db.save_job_delivery(job["job_id"], project["project_id"], fields)
    status = "ok" if result.get("mode") == "defectdojo" else "skipped"
    db.add_sync_record(project["project_id"], job["job_id"], "defectdojo_push", status, result.get("detail") or "", result)
    return result


def pull_defectdojo(db, project: dict, job: dict) -> dict[str, Any]:
    integration = db.get_job_delivery(job["job_id"]) or db.get_integration(project["project_id"]) or {}
    engagement_id = str(integration.get("dojo_engagement_id") or "")
    pulled = pull_engagement_status(engagement_id)
    stats = apply_dojo_pull(db, job["job_id"], pulled.get("findings") or [])
    detail = pulled.get("detail") or stats["summary"]
    db.add_sync_record(project["project_id"], job["job_id"], "defectdojo_pull", "ok" if engagement_id else "skipped", detail, stats)
    stats["detail"] = detail
    stats["url"] = integration.get("dojo_url") or ""
    return stats


def apply_dojo_pull(db, job_id: str, findings: list[dict]) -> dict[str, Any]:
    evidences = db.list_evidences(job_id)
    by_id = {row["evidence_id"]: row for row in evidences}
    counts = {"active": 0, "mitigated": 0, "false_positive": 0, "matched": 0}
    for item in findings:
        status = item.get("status") or "active"
        target = by_id.get(str(item.get("unique_id_from_tool") or ""))
        if target is None:
            target = next(
                (
                    row for row in evidences
                    if row.get("title") == item.get("title")
                    and (not item.get("cve") or row.get("cve_or_cwe") == item.get("cve"))
                ),
                None,
            )
        if target is None or not item.get("id"):
            continue
        db.set_evidence_dojo(target["evidence_id"], str(item["id"]), status)
        counts["matched"] += 1
        if status in counts:
            counts[status] += 1
    counts["summary"] = f"活跃 {counts['active']}，已修复 {counts['mitigated']}，误报 {counts['false_positive']}"
    return counts


def _ciso_control_items(assessments: list[dict]) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for row in assessments:
        status = row.get("final_status")
        if status not in {"non_compliant", "partially_compliant"}:
            continue
        priority_num = 1 if row.get("is_high_risk") and status == "non_compliant" else 2
        point = row.get("control_point") or row.get("clause_id")
        items.append({
            "clause_id": row["clause_id"],
            "name": f"[{row['clause_id']}] {point} 整改加固",
            "description": f"{row.get('ai_rationale') or ''}\n\n整改参考：\n{row.get('remediation_script') or ''}".strip(),
            "priority_num": priority_num,
            "category": "technical" if "管理" not in str(row.get("domain") or "") else "process",
        })
    items.sort(key=lambda x: (x["priority_num"], x["clause_id"]))
    return items[:20]


def _ciso_observation_text(score: dict, sections: dict[str, Any]) -> str:
    parts = []
    if sections.get("ciso_summary"):
        parts.append(str(sections["ciso_summary"]).strip())
    elif sections.get("executive_summary"):
        parts.append(str(sections["executive_summary"]).strip())
    roadmap = sections.get("remediation_roadmap") or []
    if roadmap:
        lines = ["【分阶段整改路线】"]
        for step in roadmap[:3]:
            actions = "；".join(str(a) for a in (step.get("actions") or [])[:3])
            lines.append(f"- {step.get('phase', '')}（{step.get('owner_department', '')}）：{actions}")
        parts.append("\n".join(lines))
    return "\n\n".join(parts)


def deliver_ciso(db, project: dict, job: dict, report_path: str | None) -> dict[str, Any]:
    from api.reports import build_report_context

    context = build_report_context(db, project, job, variant="masked", refresh_ai=False)
    assessments = context["assessments"]
    docs = db.list_manual_docs(project["project_id"])
    assets = context["assets"]
    narrative = context.get("masked_narrative") or {}
    sections = narrative.get("sections") or {}

    # 同步前保证中文终版报告（HTML + Word .docx）已按最新研判刷新落盘。
    html_name, html_path = render_report(context, "masked")
    db.save_report(job["job_id"], "masked", html_name, str(html_path))
    docx_name, docx_path = render_docx_report(context, "masked")
    docx_report = db.save_report(job["job_id"], "masked_docx", docx_name, str(docx_path))

    leaks = final_leak_check(assessments, docs, assets, str(html_path), extra_texts=narrative_plain_texts(sections))
    if leaks:
        detail = {"leaks": leaks, "passed": False}
        db.add_sync_record(project["project_id"], job["job_id"], "ciso_push", "blocked", "二次脱敏终检未通过", detail)
        return {"synced": False, "passed": False, "leaks": leaks, "detail": "二次脱敏终检发现未脱敏内容，已停止写入 CISO Assistant"}

    score = context["score"]
    assessment_description = (
        f"GB/T 22239-2019 等保三级预评估｜纳管资产 {len(assets)} 台｜"
        f"结论：{score.get('verdict_label', '')}｜已核查得分 {score.get('checked_score', 0)} 分｜"
        f"全量保守得分 {score.get('conservative_score', 0)} 分｜完备度 {score.get('completeness', 0)}%"
    )
    assessment_observation = _ciso_observation_text(score, sections)
    control_items = _ciso_control_items(assessments)

    try:
        result = deliver_assessment(
            project,
            job,
            assessments,
            docs,
            db.get_integration(project["project_id"]),
            assessment_description=assessment_description,
            assessment_observation=assessment_observation,
            control_items=control_items,
        )
    except CisoError as exc:
        db.add_sync_record(project["project_id"], job["job_id"], "ciso_push", "failed", str(exc), {"passed": True})
        raise
    fields = {
        "ciso_folder_id": result["folder_id"],
        "ciso_perimeter_id": result["perimeter_id"],
        "ciso_framework_id": result["framework_id"],
        "ciso_assessment_id": result["assessment_id"],
        "ciso_url": result["url"],
    }
    db.save_integration(project["project_id"], fields)
    db.save_job_delivery(job["job_id"], project["project_id"], {
        "ciso_assessment_id": result["assessment_id"],
        "ciso_url": result["url"],
        "leak_passed": 1,
    })
    report = db.save_report(job["job_id"], "ciso_final", result["filename"], result["report_path"])
    db.add_sync_record(
        project["project_id"],
        job["job_id"],
        "ciso_push",
        "ok",
        result["detail"],
        {"written": result["written"], "controls_written": result.get("controls_written", 0), "passed": True},
    )
    db.add_sync_record(
        project["project_id"],
        job["job_id"],
        "ciso_report",
        "ok",
        "已归档 CISO 台账快照并更新中文 Word 终版报告",
        {"report_id": report["report_id"], "docx_report_id": docx_report["report_id"]},
    )
    result["report"] = report
    result["docx_report"] = docx_report
    result["passed"] = True
    result["leaks"] = []
    return result


def final_leak_check(
    assessments: list[dict],
    docs: list[dict],
    assets: list[dict],
    report_path: str | None,
    *,
    extra_texts: list[str] | None = None,
) -> list[str]:
    texts = [str(row.get("ai_rationale") or "") for row in assessments]
    texts.extend(str(row.get("remediation_script") or "") for row in assessments)
    texts.extend(str(doc.get("note") or "") for doc in docs)
    if extra_texts:
        texts.extend(extra_texts)
    if report_path and Path(report_path).exists():
        texts.append(Path(report_path).read_bytes().decode("utf-8", "ignore"))
    secrets = [str(asset.get("host") or "") for asset in assets if asset.get("host")]
    found = delivery_leak_findings(texts, secrets)
    visible = []
    for item in found:
        if item in {"pattern", "pii"}:
            label = "发现口令、令牌或个人信息样式" if item == "pattern" else "发现电话或证件号样式"
            if label not in visible:
                visible.append(label)
        elif item not in visible:
            visible.append(item)
    return visible


def delivery_snapshot(db, project: dict, job: dict | None) -> dict[str, Any]:
    project_integration = db.get_integration(project["project_id"]) if project else None
    job_integration = db.get_job_delivery(job["job_id"]) if job else None
    integration = dict(project_integration or {})
    if job:
        # 本轮没有自己的外部编号时，不沿用上一轮的评估或测试周期。
        for key in ("dojo_engagement_id", "dojo_url", "ciso_assessment_id", "ciso_url"):
            integration[key] = (job_integration or {}).get(key) or ""
        if job_integration and job_integration.get("dojo_product_name"):
            integration["dojo_product_name"] = job_integration["dojo_product_name"]
            integration["dojo_product_id"] = job_integration.get("dojo_product_id") or integration.get("dojo_product_id")
    reports = db.list_reports(job["job_id"]) if job else []
    masked = [row for row in reports if row["variant"] == "masked"]
    evidences = db.list_evidences(job["job_id"]) if job else []
    stats = {"active": 0, "mitigated": 0, "false_positive": 0, "pushed": 0}
    for row in evidences:
        if row.get("dojo_finding_id"):
            stats["pushed"] += 1
        status = row.get("dojo_status")
        if status in stats:
            stats[status] += 1
    history = db.list_sync_records(project["project_id"], job["job_id"] if job else None)
    if job and not integration.get("dojo_engagement_id") and stats["pushed"] > 0:
        # 兼容 job_delivery 表建立前已推送的历史轮次：从本轮同步记录或项目集成回填周期号，避免语义矛盾。
        latest_dojo = next((row for row in history if row["target"] == "defectdojo_push" and row["status"] == "ok"), None)
        detail = (latest_dojo or {}).get("detail") or {}
        integration["dojo_engagement_id"] = str(detail.get("engagement_id") or (project_integration or {}).get("dojo_engagement_id") or "")
        integration["dojo_url"] = str(detail.get("url") or (project_integration or {}).get("dojo_url") or "")
    latest_leak = next((row for row in history if row["target"] == "ciso_push"), None)
    latest_controls = int(((latest_leak or {}).get("detail") or {}).get("controls_written") or 0)
    latest_written = int(((latest_leak or {}).get("detail") or {}).get("written") or 0)

    prompt_row = db.ensure_system_prompt(REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE, DEFAULT_MLPS3_REPORT_PROMPT)
    narrative = db.get_report_narrative(job["job_id"]) if job else None
    latest_prompt_version = int(prompt_row.get("version") or 1)
    used_prompt_version = int(narrative.get("prompt_version") or 0) if narrative else 0
    has_docx = any(row["variant"] in {"masked_docx", "restored_docx"} for row in reports)

    return {
        "delivery_ready": bool(masked) and bool(job) and job.get("status") == "completed",
        "reports": reports,
        "ai_report": {
            "generated": bool(narrative),
            "status": (narrative or {}).get("status") or "pending",
            "model_id": (narrative or {}).get("model_id") or "",
            "prompt_version": used_prompt_version,
            "latest_prompt_version": latest_prompt_version,
            "prompt_outdated": bool(narrative) and used_prompt_version < latest_prompt_version,
            "generated_at": (narrative or {}).get("generated_at") or "",
            "executive_preview": str(((narrative or {}).get("sections") or {}).get("executive_summary") or "")[:240],
        },
        "steps": {
            "remediation": "done" if stats["pushed"] > 0 else "ready",
            "ciso_archive": "done" if integration.get("ciso_assessment_id") and (not latest_leak or latest_leak["status"] != "blocked") else ("blocked" if latest_leak and latest_leak["status"] == "blocked" else "ready"),
            "artifacts": "done" if (has_docx or bool(masked)) else "pending",
        },
        "defectdojo": {
            "product_id": (integration or {}).get("dojo_product_id") or "",
            "product_name": (integration or {}).get("dojo_product_name") or project.get("name") or "",
            "engagement_id": (integration or {}).get("dojo_engagement_id") or "",
            "url": (integration or {}).get("dojo_url") or "",
            **stats,
        },
        "ciso": {
            "folder_id": (integration or {}).get("ciso_folder_id") or "",
            "perimeter_id": (integration or {}).get("ciso_perimeter_id") or "",
            "framework_id": (integration or {}).get("ciso_framework_id") or "",
            "assessment_id": (integration or {}).get("ciso_assessment_id") or "",
            "url": (integration or {}).get("ciso_url") or "",
            "written": latest_written,
            "controls_written": latest_controls,
            "leak_passed": None if not latest_leak else latest_leak["status"] != "blocked",
            "leak_detail": (latest_leak or {}).get("detail") or {},
        },
        "history": history,
    }
