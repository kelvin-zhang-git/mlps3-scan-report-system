from __future__ import annotations

import json

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import current_user, get_db, require_roles
from core.sanitizer import build_zone_map
from core.settings import ROOT
from core.workflow import build_workflow
from database.db_manager import Database, new_id

router = APIRouter(prefix="/api", tags=["projects"])
PROJECT_ID = "prj_stage1"


class ModeBody(BaseModel):
    scan_mode: str


def _present_assets(assets: list[dict], role: str) -> list[dict]:
    mapping = build_zone_map(assets)
    shown = []
    for asset in assets:
        item = dict(asset)
        item.pop("ssh_secret_encrypted", None)
        item["zone_token"] = mapping.get(asset["host"], "ZONE_EXT_HOST_01")
        item["host_visible"] = asset["host"] if role in {"admin", "security_lead"} else item["zone_token"]
        shown.append(item)
    return shown


def load_clauses(extensions: list[str] | None = None) -> list[dict]:
    from core.clause_catalog import load_clauses as _load_clauses

    return _load_clauses(extensions)


class ProjectBody(BaseModel):
    name: str
    summary: str = ""
    env_tier: str = "L1_TEST"
    llm_profile: str = "local_rules"
    stage_label: str = "进场前差距核查"
    classification: str = "内部"
    whitelist_cidrs: list[str] = Field(default_factory=list)
    enabled_extensions: list[str] = Field(default_factory=lambda: ["GENERAL"])


ENV_TIERS = {"L1_TEST", "L2_INTERNAL", "L3_CROSSBORDER_APPROVED"}
SCANNER_NET = ipaddress.ip_network("192.168.1.250/32")


def _operators(user: dict = Depends(require_roles("admin", "security_lead"))) -> dict:
    return user


def _clean_cidrs(cidrs: list[str]) -> list[str]:
    cleaned = []
    for raw in cidrs:
        item = raw.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"网段无法解析：{item}") from exc
        if SCANNER_NET.subnet_of(network) or network.subnet_of(SCANNER_NET) or SCANNER_NET == network:
            raise HTTPException(status_code=400, detail="白名单不能覆盖扫描机 192.168.1.250")
        cleaned.append(str(network))
    return cleaned


def _check_profile(db: Database, profile_key: str) -> None:
    profile = db.get_llm_profile(profile_key)
    if profile and not profile["is_enabled"]:
        raise HTTPException(status_code=400, detail="先启用模型通道，再把它设为项目默认")


@router.get("/projects")
def projects(db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_project_cards()


@router.post("/projects")
def create_project(body: ProjectBody, db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="项目名称不能为空")
    if body.env_tier not in ENV_TIERS:
        raise HTTPException(status_code=400, detail="密级不合法")
    _check_profile(db, body.llm_profile)
    project = db.create_project({
        "project_id": new_id("prj"),
        "name": name,
        "summary": body.summary.strip(),
        "env_tier": body.env_tier,
        "llm_profile": body.llm_profile,
        "stage_label": body.stage_label.strip() or "进场前差距核查",
        "classification": body.classification.strip() or "内部",
        "whitelist_cidrs": _clean_cidrs(body.whitelist_cidrs),
        "enabled_extensions": body.enabled_extensions,
    })
    return project


@router.put("/projects/{project_id}")
def update_project(project_id: str, body: ProjectBody, db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能修改")
    if body.env_tier not in ENV_TIERS:
        raise HTTPException(status_code=400, detail="密级不合法")
    _check_profile(db, body.llm_profile)
    updated = db.update_project(project_id, {
        "name": body.name.strip() or project["name"],
        "summary": body.summary.strip(),
        "env_tier": body.env_tier,
        "llm_profile": body.llm_profile,
        "stage_label": body.stage_label.strip() or project.get("stage_label") or "",
        "classification": body.classification.strip() or project.get("classification") or "",
        "whitelist_cidrs": _clean_cidrs(body.whitelist_cidrs),
        "enabled_extensions": body.enabled_extensions,
    })
    return updated or {}


@router.post("/projects/{project_id}/start")
def start_project(project_id: str, db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") == "active":
        return project
    if project.get("status") not in {"draft", "archived"}:
        raise HTTPException(status_code=400, detail="当前状态不能启动")
    return db.set_project_status(project_id, "active") or {}


@router.post("/projects/{project_id}/archive")
def archive_project(project_id: str, db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") == "archived":
        return project
    if project.get("status") != "active":
        raise HTTPException(status_code=400, detail="草稿还没有作业，可以直接删除；已启动的项目才归档")
    return db.set_project_status(project_id, "archived") or {}


@router.delete("/projects/{project_id}")
def delete_project(project_id: str, db: Database = Depends(get_db), _: dict = Depends(_operators)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") != "draft":
        raise HTTPException(status_code=400, detail="只有草稿可以删除。已启动的项目请改为归档")
    try:
        db.delete_project_if_empty(project_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"deleted": project_id}


@router.get("/projects/{project_id}/overview")
def overview(project_id: str, job_id: str | None = None, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    stats = db.dashboard(project_id, job_id)
    selected = db.get_job(job_id) if job_id else (stats.get("effective_job") or stats.get("job"))
    if selected and selected["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="任务不属于该项目")
    assets = _present_assets(db.list_assets(project_id), user["role"])
    vault = db.get_vault(selected["job_id"]) if selected else None
    assessment_count = db.count_assessments(selected["job_id"]) if selected else 0
    report_ready = db.has_report_variant(selected["job_id"], "masked") if selected else False
    return {
        "project": project,
        "assets": assets,
        "stats": stats,
        "selected_job": selected,
        "jobs": db.list_jobs(project_id),
        "reports": db.list_reports(selected["job_id"]) if selected else [],
        "clauses": load_clauses(project.get("enabled_extensions")),
        "workflow": build_workflow(project, assets, selected, vault, assessment_count, report_ready),
    }


@router.get("/projects/{project_id}/analytics")
def analytics(project_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if not db.get_project(project_id):
        raise HTTPException(status_code=404, detail="项目不存在")
    payload = db.dashboard_analytics(project_id)
    payload["project"] = db.get_project(project_id)
    payload["assets"] = _present_assets(db.list_assets(project_id), user["role"])
    return payload


class ProfileBind(BaseModel):
    profile_key: str


@router.patch("/projects/{project_id}/llm-profile")
def bind_profile(project_id: str, body: ProfileBind, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="切换默认模型通道由系统管理员操作")
    project = db.get_project(project_id)
    if project and project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能更换默认通道")
    profile = db.get_llm_profile(body.profile_key)
    if not project or not profile:
        raise HTTPException(status_code=404, detail="项目或通道不存在")
    if not profile["is_enabled"]:
        raise HTTPException(status_code=400, detail="先启用通道，再把它设为项目默认")
    db.set_project_llm_profile(project_id, body.profile_key)
    return {"project_id": project_id, "llm_profile": body.profile_key}


@router.patch("/assets/{asset_id}/mode")
def set_mode(asset_id: str, body: ModeBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if body.scan_mode not in {"READONLY_AUDIT", "ACTIVE_SCAN"}:
        raise HTTPException(status_code=400, detail="扫描模式不合法")
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="修改扫描模式由等保负责人或系统管理员操作")
    asset = db.get_asset(asset_id)
    project = db.get_project(asset["project_id"]) if asset else None
    if not asset or not project:
        raise HTTPException(status_code=404, detail="资产不存在")
    if project.get("status") != "active":
        raise HTTPException(status_code=400, detail="只有已启动的项目可以修改扫描模式")
    db.update_asset_mode(asset_id, body.scan_mode)
    return {"asset_id": asset_id, "scan_mode": body.scan_mode}


@router.get("/clauses")
def clauses(
    extension: str | None = None,
    object_type: str | None = None,
    _: dict = Depends(current_user),
) -> list[dict]:
    rows = load_clauses(None)
    if extension:
        ext = extension.strip().upper()
        rows = [row for row in rows if str(row.get("extension_type") or "GENERAL").upper() == ext]
    if object_type:
        obj = object_type.strip()
        rows = [row for row in rows if obj in (row.get("applicable_objects") or [])]
    return rows
