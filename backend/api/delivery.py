"""项目内 DefectDojo 与 CISO Assistant 协同交付。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from api.deps import current_user, get_db
from core.ciso_sync import CisoError
from core.delivery import deliver_ciso, delivery_snapshot, pull_defectdojo, push_defectdojo
from database.db_manager import Database

router = APIRouter(prefix="/api/projects", tags=["delivery"])


def _operators(user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="协同交付由等保负责人或系统管理员操作")
    return user


def _context(project_id: str, job_id: str, db: Database) -> tuple[dict, dict]:
    project = db.get_project(project_id)
    job = db.get_job(job_id) if job_id else None
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if not job or job["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="任务不属于该项目")
    return project, job


@router.get("/{project_id}/delivery")
def delivery_status(project_id: str, job_id: str = "", db: Database = Depends(get_db), _: dict = Depends(current_user)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    job = db.get_job(job_id) if job_id else None
    if job and job["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="任务不属于该项目")
    return delivery_snapshot(db, project, job)


@router.post("/{project_id}/delivery/defectdojo-push")
def defectdojo_push(project_id: str, job_id: str = "", db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project, job = _context(project_id, job_id, db)
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档。重新启用之后才能继续推送")
    return push_defectdojo(db, project, job)


@router.post("/{project_id}/delivery/defectdojo-pull")
def defectdojo_pull(project_id: str, job_id: str = "", db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project, job = _context(project_id, job_id, db)
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档。重新启用之后才能回拉处置状态")
    return pull_defectdojo(db, project, job)


@router.post("/{project_id}/delivery/ciso-deliver")
def ciso_deliver(project_id: str, job_id: str = "", db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project, job = _context(project_id, job_id, db)
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档。重新启用之后才能写入 CISO Assistant")
    if job["status"] != "completed" or not db.count_assessments(job["job_id"]):
        raise HTTPException(status_code=400, detail="先完成条款评审，再写入 CISO Assistant")
    reports = [row for row in db.list_reports(job["job_id"]) if row["variant"] == "masked"]
    if not reports:
        raise HTTPException(status_code=400, detail="先在报告制品里生成本轮脱敏版报告")
    try:
        return deliver_ciso(db, project, job, reports[0]["content_path"])
    except CisoError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
