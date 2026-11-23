"""模型通道的增删改查。密钥只加密保存，响应里只出现掩码。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import get_db, require_roles
from api.projects import PROJECT_ID
from core.llm_gateway import test_profile
from core.secrets import decrypt_secret, encrypt_secret, mask_secret
from database.db_manager import Database

router = APIRouter(prefix="/api/admin/llm-profiles", tags=["llm-admin"])

PROVIDERS = {"gemini", "openai_compatible", "local_rules"}
AUTH_MODES = {"env_ref", "encrypted_key"}
TIERS = {"L1_TEST", "L2_INTERNAL", "L3_CROSSBORDER", "L3_CROSSBORDER_APPROVED"}


class ProfileBody(BaseModel):
    profile_key: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=1, max_length=80)
    provider: str
    is_cross_border: bool = False
    allowed_env_tiers: list[str] = Field(default_factory=list)
    fast_mapper_model: str
    deep_reasoner_model: str = ""
    api_base: str = ""
    proxy_env: str = ""
    auth_mode: str = "env_ref"
    api_key_env: str = ""
    api_key: str = ""
    enable_context_caching: bool = False
    inject_block_none_safety: bool = False
    is_enabled: bool = True


def _check(body: ProfileBody) -> None:
    if body.provider not in PROVIDERS:
        raise HTTPException(status_code=400, detail="厂商类型不合法")
    if body.auth_mode not in AUTH_MODES:
        raise HTTPException(status_code=400, detail="密钥模式不合法")
    unknown = [item for item in body.allowed_env_tiers if item not in TIERS]
    if unknown:
        raise HTTPException(status_code=400, detail=f"未知密级 {unknown[0]}")
    if body.is_cross_border and not body.proxy_env:
        raise HTTPException(status_code=400, detail="跨境通道必须指定代理环境变量")
    if body.provider == "gemini" and body.inject_block_none_safety is False:
        raise HTTPException(status_code=400, detail="Gemini 作为裁判时要注入 BLOCK_NONE，否则会因为内容敏感而拒答")
    if not body.profile_key.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="通道标识只允许字母、数字、下划线和短横线")


def _present(db: Database, profile_key: str) -> dict:
    row = db.get_llm_profile(profile_key)
    if not row:
        raise HTTPException(status_code=404, detail="模型通道不存在")
    public = db._public_profile(row)
    plain = decrypt_secret(row.get("api_key_encrypted") or "")
    public["api_key_masked"] = mask_secret(plain) if plain else ""
    public["has_api_key"] = bool(plain) or (row["auth_mode"] == "env_ref" and bool(row["api_key_env"]))
    return public


def _store(db: Database, body: ProfileBody, keep_secret: bool) -> dict:
    _check(body)
    encrypted = ""
    if body.auth_mode == "encrypted_key" and body.api_key.strip():
        encrypted = encrypt_secret(body.api_key.strip())
        keep_secret = False
    if body.auth_mode == "env_ref":
        encrypted = ""
        keep_secret = False
    saved = db.save_llm_profile({
        "profile_key": body.profile_key.strip(),
        "display_name": body.display_name.strip(),
        "provider": body.provider,
        "is_cross_border": body.is_cross_border,
        "allowed_env_tiers": body.allowed_env_tiers,
        "fast_mapper_model": body.fast_mapper_model.strip(),
        "deep_reasoner_model": body.deep_reasoner_model.strip() or body.fast_mapper_model.strip(),
        "api_base": body.api_base.strip(),
        "proxy_env": body.proxy_env.strip(),
        "auth_mode": body.auth_mode,
        "api_key_env": body.api_key_env.strip(),
        "api_key_encrypted": encrypted,
        "keep_secret": keep_secret,
        "enable_context_caching": body.enable_context_caching,
        "inject_block_none_safety": body.inject_block_none_safety or body.provider == "gemini",
        "is_enabled": body.is_enabled,
    })
    return _present(db, saved["profile_key"])


@router.get("")
def list_profiles(db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> list[dict]:
    return [_present(db, row["profile_key"]) for row in db.list_llm_profiles()]


@router.post("")
def create_profile(body: ProfileBody, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    if db.get_llm_profile(body.profile_key):
        raise HTTPException(status_code=409, detail="通道标识已存在")
    if body.auth_mode == "encrypted_key" and not body.api_key.strip():
        raise HTTPException(status_code=400, detail="加密模式需要填写 API Key")
    return _store(db, body, keep_secret=False)


@router.put("/{profile_key}")
def update_profile(profile_key: str, body: ProfileBody, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    if not db.get_llm_profile(profile_key):
        raise HTTPException(status_code=404, detail="模型通道不存在")
    if body.profile_key != profile_key:
        raise HTTPException(status_code=400, detail="通道标识在创建后保持不变")
    return _store(db, body, keep_secret=not body.api_key.strip())


@router.delete("/{profile_key}")
def delete_profile(profile_key: str, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    if not db.get_llm_profile(profile_key):
        raise HTTPException(status_code=404, detail="模型通道不存在")
    used = db.projects_using_profile(profile_key)
    if used:
        names = "、".join(item["name"] for item in used)
        raise HTTPException(status_code=409, detail=f"通道仍被项目使用：{names}")
    db.delete_llm_profile(profile_key)
    return {"deleted": profile_key}


@router.post("/{profile_key}/test")
def probe(profile_key: str, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    stored = db.gateway_profiles().get(profile_key)
    if not stored:
        raise HTTPException(status_code=404, detail="模型通道不存在")
    return test_profile(stored)


@router.patch("/project/{project_id}")
def bind_project(project_id: str, body: dict, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    profile_key = str(body.get("profile_key") or "")
    project = db.get_project(project_id or PROJECT_ID)
    profile = db.get_llm_profile(profile_key)
    if not project or not profile:
        raise HTTPException(status_code=404, detail="项目或通道不存在")
    if not profile["is_enabled"]:
        raise HTTPException(status_code=400, detail="先启用通道，再把它设为项目默认")
    db.set_project_llm_profile(project["project_id"], profile_key)
    return {"project_id": project["project_id"], "llm_profile": profile_key}
