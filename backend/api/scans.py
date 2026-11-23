from __future__ import annotations

import asyncio
import json
import threading

from fastapi import APIRouter, Body, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from api.deps import current_user, get_db
from api.projects import PROJECT_ID
from core.asset_access import scan_policy
from core.policy import PolicyError, assert_targets_allowed
from core.runner import run_collection
from database.db_manager import Database

router = APIRouter(prefix="/api", tags=["scans"])


class ScanBody(BaseModel):
    asset_ids: list[str] = []
    project_id: str = ""


def scan_context(db: Database, project_id: str, asset_ids: list[str] | None = None) -> tuple[dict, list[dict]]:
    project = db.get_project(project_id)
    if not project:
        return {}, []
    assets = db.list_assets(project_id, include_secret=True)
    if asset_ids:
        chosen = set(asset_ids)
        assets = [asset for asset in assets if asset["asset_id"] in chosen]
    assets = [asset for asset in assets if asset.get("is_enabled", True)]
    return scan_policy(project), assets


def _start_scan(project_id: str, asset_ids: list[str] | None, db: Database, user: dict) -> dict:
    if user["role"] == "auditor":
        raise HTTPException(status_code=403, detail="发起扫描由等保负责人或系统管理员操作")
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目未初始化")
    if project.get("status") != "active":
        raise HTTPException(status_code=400, detail="先启动项目，再发起核查")
    raw, assets = scan_context(db, project_id, asset_ids)
    if not assets:
        raise HTTPException(status_code=400, detail="先在资产白名单中启用至少一台主机")
    if any(asset["scan_mode"] == "ACTIVE_SCAN" for asset in assets) and user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="主动扫描由等保负责人或系统管理员发起")
    try:
        assert_targets_allowed(assets, raw.get("whitelist_cidrs") or [], raw.get("forbidden_cidrs") or [])
    except PolicyError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    job = db.create_job(project)

    def worker() -> None:
        try:
            run_collection(db, job, assets, raw)
        except PolicyError as exc:
            db.update_job(job["job_id"], status="failed", error_msg=str(exc), current_stage="policy")
            db.add_event(job["job_id"], "policy", str(exc), 100)
        except Exception as exc:
            db.update_job(job["job_id"], status="failed", error_msg=str(exc), current_stage="failed")
            db.add_event(job["job_id"], "failed", str(exc), 100)

    db.update_job(job["job_id"], status="running", current_stage="policy")
    threading.Thread(target=worker, daemon=True).start()
    return db.get_job(job["job_id"])


@router.post("/scans/run")
def run_scan(body: ScanBody | None = Body(default=None), db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    project_id = (body.project_id if body and body.project_id else "") or PROJECT_ID
    asset_ids = body.asset_ids if body else None
    return _start_scan(project_id, asset_ids, db, user)


@router.post("/projects/{project_id}/scans/run")
def run_project_scan(
    project_id: str,
    body: ScanBody | None = Body(default=None),
    db: Database = Depends(get_db),
    user: dict = Depends(current_user),
) -> dict:
    return _start_scan(project_id, body.asset_ids if body else None, db, user)


@router.get("/scans/{job_id}")
def job_detail(job_id: str, db: Database = Depends(get_db), _: dict = Depends(current_user)) -> dict:
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="任务不存在")
    return {"job": job, "events": db.list_events(job_id)}


@router.get("/scans/{job_id}/stream")
async def stream(job_id: str, db: Database = Depends(get_db), _: dict = Depends(current_user)) -> StreamingResponse:
    if not db.get_job(job_id):
        raise HTTPException(status_code=404, detail="任务不存在")

    async def events():
        last = 0
        for _ in range(120):
            job = db.get_job(job_id)
            for event in db.list_events(job_id, last):
                last = event["id"]
                yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
            if job and job["status"] in {"awaiting_approval", "completed", "failed"}:
                yield f"data: {json.dumps({'type': 'end', 'status': job['status']}, ensure_ascii=False)}\n\n"
                break
            await asyncio.sleep(0.4)

    return StreamingResponse(events(), media_type="text/event-stream")


@router.get("/evidences/{job_id}")
def evidences(job_id: str, db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_evidences(job_id)
