from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import current_user, get_db
from core.sanitizer import restore_token
from core.settings import vault_key
from database.db_manager import Database

router = APIRouter(prefix="/api/sanitization", tags=["sanitization"])


@router.get("/{job_id}/diff")
def diff(job_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    vault = db.get_vault(job_id)
    if not vault:
        raise HTTPException(status_code=404, detail="还没有脱敏结果")
    samples = []
    for sample in vault["preview"].get("samples", []):
        item = {"title": sample["title"], "after": sample["after"]}
        if user["role"] in {"admin", "security_lead"}:
            item["before"] = sample["before"]
        samples.append(item)
    return {
        "leak_check_passed": vault["leak_check_passed"],
        "approved_by": vault.get("approved_by"),
        "samples": samples,
        "leaks": vault["preview"].get("leaks", []),
    }


@router.post("/{job_id}/approve")
def approve(job_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] == "auditor":
        raise HTTPException(status_code=403, detail="确认脱敏结果由等保负责人或系统管理员操作")
    job = db.get_job(job_id)
    project = db.get_project(job["project_id"]) if job else None
    if project and project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能确认脱敏")
    vault = db.get_vault(job_id)
    if not vault or not vault["leak_check_passed"]:
        raise HTTPException(status_code=400, detail="脱敏结果尚未通过零泄漏检查，确认要等检查通过之后")
    db.approve_vault(job_id, user["email"])
    return {"approved": True, "reviewer": user["email"]}


@router.get("/{job_id}/restore/{token_name}")
def restore(job_id: str, token_name: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="还原真实地址由等保负责人或系统管理员操作")
    vault = db.get_vault(job_id)
    if not vault:
        raise HTTPException(status_code=404, detail="没有映射")
    return {"token": token_name, "host": restore_token(vault["encrypted_mapping_blob"], vault_key(), token_name)}
