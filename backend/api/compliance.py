from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.deps import current_user, get_db
from api.projects import PROJECT_ID, load_clauses
from core.ciso_sync import sync_assessments
from core.llm_assessor import assert_manual_not_auto_passed, assess_clauses
from core.policy import CompliancePolicyError
from core.settings import load_yaml
from database.db_manager import Database, new_id

router = APIRouter(prefix="/api", tags=["compliance"])


class ReviewBody(BaseModel):
    manual_status: str
    note: str = ""
    compensation_status: str | None = None
    compensation_note: str | None = None


class ImportBody(BaseModel):
    source: str
    payload: dict
    job_id: str | None = None


@router.post("/compliance/{job_id}/assess")
def assess(job_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="发起 AI 评审由等保负责人或系统管理员操作")
    job = db.get_job(job_id)
    vault = db.get_vault(job_id)
    if not job or not vault:
        raise HTTPException(status_code=404, detail="任务不存在")
    project = db.get_project(job["project_id"])
    if project and project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能发起评审")
    if not vault.get("approved_by"):
        raise HTTPException(status_code=400, detail="脱敏结果尚未人工放行")
    clauses = load_clauses(project.get("enabled_extensions") if project else ["GENERAL"])
    evidences = db.list_evidences(job_id)
    profiles = db.gateway_profiles() or load_yaml("config.yaml")["llm_profiles"]
    try:
        assessments, paths, audit = assess_clauses(clauses, evidences, job["env_tier"], job["llm_profile"], profiles)
        assert_manual_not_auto_passed(assessments, clauses)
    except CompliancePolicyError as exc:
        db.add_llm_log({"job_id": job_id, "stage": "route_guard", "model_id": job["llm_profile"], "status": "blocked", "error_detail": str(exc)})
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    db.replace_assessments(job_id, assessments)
    db.replace_paths(job_id, paths)
    audit["job_id"] = job_id
    audit["log_id"] = new_id("llm")
    db.add_llm_log(audit)
    db.update_job(job_id, status="completed", progress_pct=100, current_stage="completed")
    return {"assessments": len(assessments), "paths": len(paths), "reviewer": user["email"]}


@router.get("/compliance/{job_id}/clauses")
def clause_rows(job_id: str, db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    clauses = {item["clause_id"]: item for item in load_clauses()}
    rows = []
    for row in db.list_assessments(job_id):
        clause = clauses.get(row["clause_id"], {})
        rows.append({
            **row,
            "domain": clause.get("domain"),
            "control_point": clause.get("control_point"),
            "extension_type": clause.get("extension_type", "GENERAL"),
            "auto_level": clause.get("auto_level"),
            "requirement_text": clause.get("requirement_text"),
            "manual_check_guide": clause.get("manual_check_guide"),
            "applicable_objects": clause.get("applicable_objects") or [],
            "applicable_object_labels": clause.get("applicable_object_labels") or [],
            "risk_weight_level": clause.get("risk_weight_level", "medium"),
            "risk_weight": clause.get("risk_weight", 2.0),
            "high_risk_precedent": clause.get("high_risk_precedent"),
        })
    return rows


@router.patch("/compliance/clauses/{assessment_id}")
def review(assessment_id: str, body: ReviewBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="修改条款结论由等保负责人或系统管理员操作")
    allowed = {"compliant", "partially_compliant", "non_compliant", "not_applicable", "pending_manual"}
    if body.manual_status not in allowed:
        raise HTTPException(status_code=400, detail="状态不合法")
    if body.compensation_status is not None and body.compensation_status not in {"none", "mitigated"}:
        raise HTTPException(status_code=400, detail="补偿控制状态不合法")
    updated = db.update_assessment(
        assessment_id,
        user["email"],
        body.manual_status,
        body.note,
        compensation_status=body.compensation_status,
        compensation_note=body.compensation_note,
    )
    if not updated:
        raise HTTPException(status_code=404, detail="条款不存在")
    return updated


@router.get("/compliance/{job_id}/attack-paths")
def paths(job_id: str, db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_paths(job_id)


@router.post("/compliance/{job_id}/ciso-sync")
def ciso(job_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="同步外部平台由等保负责人或系统管理员操作")
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="任务不存在")
    project = db.get_project(job["project_id"])
    if project and project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能同步外部平台")
    return sync_assessments(db.list_assessments(job_id), db.list_manual_docs(job["project_id"]))


@router.get("/llm/audit")
def llm_audit(db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_llm_logs()


@router.get("/imports/templates")
def import_templates(_: dict = Depends(current_user)) -> dict:
    from core.collectors import SAMPLE_CLOUD_AUDIT, SAMPLE_NETDEV_CONFIG

    return {
        "netdev_config": {
            "device_name": "FW-BORDER-01",
            "device_role": "security_device",
            "config_text": SAMPLE_NETDEV_CONFIG,
        },
        "cloud_audit": SAMPLE_CLOUD_AUDIT,
    }


@router.post("/imports/{project_id}")
def import_extra(project_id: str, body: ImportBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    from core.collectors import (
        normalize_ecloud,
        parse_akto,
        parse_cloud_audit,
        parse_godlp,
        parse_kubescape,
        parse_netdev_config,
        parse_zap,
    )
    from core.sanitizer import sanitize_records
    from core.settings import vault_key

    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="导入外部或离线核查证据由等保负责人或系统管理员操作")
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能导入证据")

    job = db.get_job(body.job_id) if body.job_id else db.latest_job(project_id)
    if not job:
        job = db.create_job(project)
        db.update_job(job["job_id"], status="awaiting_approval", progress_pct=80, current_stage="awaiting_approval")

    assets = db.list_assets(project_id)
    default_asset_id = assets[0]["asset_id"] if assets else f"imp_{body.source}"

    if body.source == "netdev_config":
        cfg_text = str((body.payload or {}).get("config_text") or "").strip()
        if not cfg_text:
            raise HTTPException(status_code=400, detail="请提供网络或安全设备的脱敏配置文本")
        dev_name = str((body.payload or {}).get("device_name") or "边界网络/安全设备").strip()
        dev_role = str((body.payload or {}).get("device_role") or "security_device").strip()
        rows = parse_netdev_config(cfg_text, f"netdev_{dev_name}", device_name=dev_name, device_role=dev_role)
    elif body.source == "cloud_audit":
        rows = parse_cloud_audit(body.payload or {}, f"cloud_{str((body.payload or {}).get('provider') or 'platform').lower()}")
    else:
        parsers = {
            "ecloud": normalize_ecloud,
            "godlp": parse_godlp,
            "akto": parse_akto,
            "kubescape": parse_kubescape,
            "zap": parse_zap,
        }
        parser = parsers.get(body.source)
        if not parser:
            raise HTTPException(status_code=400, detail="未知数据源")
        rows = parser(body.payload, default_asset_id)

    if not rows:
        raise HTTPException(status_code=400, detail="未能从导入内容解析出有效核查证据，请检查格式")

    for row in rows:
        row["evidence_id"] = new_id("ev")
    sanitized_new, preview, encrypted, passed = sanitize_records(rows, assets, vault_key())
    if not passed:
        raise HTTPException(status_code=400, detail="导入内容包含未脱敏敏感凭据或密钥，请先脱敏后再导入")

    existing = db.list_evidences(job["job_id"])
    for item in existing:
        item["clause_hints"] = (item.get("detail") or {}).get("clause_hints") or []
    db.replace_evidences(job["job_id"], existing + sanitized_new)
    if not db.get_vault(job["job_id"]):
        db.save_vault(job["job_id"], encrypted, True, preview)
    db.add_event(job["job_id"], "import", f"已导入 {body.source} 核查证据 {len(sanitized_new)} 条", 80)
    passed_cnt = sum(1 for r in sanitized_new if r.get("evidence_type") == "BASELINE_PASS")
    failed_cnt = sum(1 for r in sanitized_new if r.get("evidence_type") == "BASELINE_FAIL")
    return {
        "imported": len(sanitized_new),
        "passed": passed_cnt,
        "failed": failed_cnt,
        "job_id": job["job_id"],
        "source": body.source,
    }
