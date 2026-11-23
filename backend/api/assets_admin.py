"""工作台里的虚拟机、白名单和项目密级。"""
from __future__ import annotations

import ipaddress
import time

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import get_db, require_roles
from core.asset_access import resolve_ssh
from core.clause_metadata import TECH_OBJECT_KEYS
from core.collectors.ssh_baseline import probe_os
from core.policy import host_decision
from core.secrets import encrypt_secret
from database.db_manager import Database, new_id

router = APIRouter(prefix="/api", tags=["assets"])

SCANNER_CIDR = "192.168.1.250/32"
OS_TYPES = {"rocky_linux", "centos"}
AUTH_MODES = {"env_ref", "encrypted_password", "encrypted_key"}
DEFAULT_SCANNERS = ["nmap", "nuclei", "trivy", "ssh_baseline", "db_mw_baseline"]


class AssetBody(BaseModel):
    asset_id: str = ""
    host: str
    security_zone: str = "APP"
    os_type: str = "rocky_linux"
    object_type: str = "host_os"
    scan_mode: str = "READONLY_AUDIT"
    scanners: list[str] = Field(default_factory=lambda: list(DEFAULT_SCANNERS))
    ssh_port: int = 22
    ssh_user: str = ""
    ssh_auth_mode: str = "env_ref"
    ssh_secret_env: str = ""
    ssh_key_env: str = ""
    ssh_secret: str = ""
    is_enabled: bool = True
    notes: str = ""


class ScopeBody(BaseModel):
    env_tier: str
    whitelist_cidrs: list[str]
    max_concurrency: int = Field(default=2, ge=1, le=8)
    nuclei_rate_limit: int = Field(default=50, ge=1, le=500)
    enabled_extensions: list[str] | None = None


def _roles(user: dict = Depends(require_roles("admin", "security_lead"))) -> dict:
    return user


def _require_active_project(project: dict) -> None:
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，重新启用之后才能修改资产和范围")
    if project.get("status") != "active":
        raise HTTPException(status_code=400, detail="先启动项目，再配置远程主机")


def _validate_host(host: str, project: dict) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="主机地址需要写成 IPv4") from exc
    whitelist = project.get("whitelist_cidrs") or []
    if not whitelist:
        raise HTTPException(status_code=400, detail="项目白名单还是空的。先在「白名单与密级」里写下这台虚拟机的网段，或在这个窗口里选择「加入白名单并保存」。")
    ok, reason = host_decision(host, whitelist, project.get("forbidden_cidrs") or [SCANNER_CIDR])
    if ok:
        return
    if reason == "目标不在白名单内":
        raise HTTPException(status_code=400, detail="这个地址不在白名单里。先把所在网段写入「白名单与密级」，或选择「加入白名单并保存」。")
    raise HTTPException(status_code=400, detail=reason)


def _validate_cidrs(cidrs: list[str]) -> list[str]:
    cleaned = []
    scanner = ipaddress.ip_network(SCANNER_CIDR)
    for raw in cidrs:
        item = raw.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=f"网段无法解析：{item}") from exc
        if scanner.subnet_of(network) or network.subnet_of(scanner) or scanner == network:
            raise HTTPException(status_code=400, detail="白名单不能覆盖扫描机 192.168.1.250")
        cleaned.append(str(network))
    if not cleaned:
        raise HTTPException(status_code=400, detail="至少保留一个白名单网段")
    return cleaned


def _payload(body: AssetBody, existing: dict | None) -> dict:
    if body.os_type not in OS_TYPES:
        raise HTTPException(status_code=400, detail="系统类型目前支持 rocky_linux 和 centos")
    object_type = (body.object_type or "host_os").strip()
    if object_type not in TECH_OBJECT_KEYS:
        raise HTTPException(status_code=400, detail="测评对象类别不合法")
    if body.scan_mode not in {"READONLY_AUDIT", "ACTIVE_SCAN"}:
        raise HTTPException(status_code=400, detail="扫描模式不合法")
    if body.ssh_auth_mode not in AUTH_MODES:
        raise HTTPException(status_code=400, detail="SSH 认证方式不合法")
    secret = ""
    if body.ssh_secret.strip():
        secret = encrypt_secret(body.ssh_secret.strip())
    elif existing:
        secret = ""
    if body.ssh_auth_mode != "env_ref" and not secret and not (existing or {}).get("ssh_configured"):
        raise HTTPException(status_code=400, detail="加密方式需要填写口令或私钥")
    return {
        "asset_id": body.asset_id or (existing or {}).get("asset_id") or new_id("ast"),
        "host": body.host.strip(),
        "security_zone": body.security_zone.strip() or "APP",
        "os_type": body.os_type,
        "object_type": object_type,
        "scan_mode": body.scan_mode,
        "scanners": body.scanners or list(DEFAULT_SCANNERS),
        "ssh_port": body.ssh_port,
        "ssh_user": body.ssh_user.strip(),
        "ssh_auth_mode": body.ssh_auth_mode,
        "ssh_secret_env": body.ssh_secret_env.strip(),
        "ssh_key_env": body.ssh_key_env.strip(),
        "ssh_secret_encrypted": secret,
        "is_enabled": body.is_enabled,
        "notes": body.notes.strip(),
    }


@router.post("/projects/{project_id}/assets")
def create_asset(project_id: str, body: AssetBody, db: Database = Depends(get_db), _: dict = Depends(_roles)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    _require_active_project(project)
    _validate_host(body.host.strip(), project)
    payload = _payload(body, None)
    if db.get_asset(payload["asset_id"]):
        raise HTTPException(status_code=409, detail="资产标识已存在")
    db.save_asset(project_id, payload, creating=True)
    return db.get_asset(payload["asset_id"]) or {}


@router.put("/projects/{project_id}/assets/{asset_id}")
def update_asset(project_id: str, asset_id: str, body: AssetBody, db: Database = Depends(get_db), _: dict = Depends(_roles)) -> dict:
    project = db.get_project(project_id)
    existing = db.get_asset(asset_id)
    if not project or not existing or existing["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="资产不存在")
    _require_active_project(project)
    _validate_host(body.host.strip(), project)
    body.asset_id = asset_id
    db.save_asset(project_id, _payload(body, existing), creating=False)
    return db.get_asset(asset_id) or {}


@router.delete("/projects/{project_id}/assets/{asset_id}")
def remove_asset(project_id: str, asset_id: str, db: Database = Depends(get_db), _: dict = Depends(_roles)) -> dict:
    project = db.get_project(project_id)
    existing = db.get_asset(asset_id)
    if not project or not existing or existing["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="资产不存在")
    _require_active_project(project)
    db.delete_asset(project_id, asset_id)
    return {"deleted": asset_id}


@router.post("/assets/{asset_id}/test-ssh")
def test_ssh(asset_id: str, db: Database = Depends(get_db), _: dict = Depends(_roles)) -> dict:
    asset = db.get_asset(asset_id, include_secret=True)
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    started = time.perf_counter()
    try:
        info = probe_os(asset["host"], resolve_ssh(asset))
    except Exception as exc:
        return {"ok": False, "detail": str(exc), "latency_ms": int((time.perf_counter() - started) * 1000)}
    return {"ok": True, "detail": info, "latency_ms": int((time.perf_counter() - started) * 1000)}


@router.patch("/projects/{project_id}/scope")
def update_scope(project_id: str, body: ScopeBody, db: Database = Depends(get_db), _: dict = Depends(_roles)) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    _require_active_project(project)
    if body.env_tier not in {"L1_TEST", "L2_INTERNAL", "L3_CROSSBORDER_APPROVED"}:
        raise HTTPException(status_code=400, detail="密级不合法")
    whitelist = _validate_cidrs(body.whitelist_cidrs)
    db.update_project_scope(
        project_id,
        body.env_tier,
        whitelist,
        body.max_concurrency,
        body.nuclei_rate_limit,
        enabled_extensions=body.enabled_extensions,
    )
    updated = db.get_project(project_id) or {}
    warning = ""
    profile = db.get_llm_profile(updated.get("llm_profile") or "")
    if body.env_tier == "L2_INTERNAL" and profile and profile.get("is_cross_border"):
        warning = "当前默认通道会出境。内网资产请改绑国内模型或本地模型后再做评审。"
    return {"project": updated, "warning": warning}
