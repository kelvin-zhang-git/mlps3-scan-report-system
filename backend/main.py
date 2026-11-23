"""等保三级扫描与报告系统 API。"""
from __future__ import annotations

import os

import yaml
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import api.deps as deps
from api import assets_admin, auth, compliance, delivery, llm_admin, projects, prompts_admin, reports, sanitization, scans, system, users_admin
from core.report_prompts import DEFAULT_MLPS3_REPORT_PROMPT, REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE
from core.security import hash_password
from core.settings import ROOT, db_path, env, load_yaml
from database.db_manager import Database

app = FastAPI(title="等保三级扫描与报告系统", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def bootstrap(database: Database) -> None:
    raw = yaml.safe_load((ROOT / "config" / "targets.yaml").read_text(encoding="utf-8"))
    project = raw["project"]
    assets = []
    for asset in raw.get("assets") or []:
        item = dict(asset)
        ssh = item.get("ssh_config") or {}
        user_env = ssh.get("user_env") or "STAGE1_TARGET_SSH_USER"
        item["ssh_user"] = os.environ.get(user_env, item.get("ssh_user") or "")
        item["ssh_auth_mode"] = "env_ref"
        assets.append(item)
    database.upsert_project({
        "project_id": "prj_stage1",
        "name": project["name"],
        "summary": project["summary"],
        "env_tier": project["env_tier"],
        "llm_profile": project["llm_profile"],
        "stage_label": project["stage_label"],
        "classification": project["classification"],
        "whitelist_cidrs": raw.get("whitelist_cidrs") or [],
        "forbidden_cidrs": raw.get("forbidden_cidrs") or ["192.168.1.250/32"],
        "max_concurrency": (raw.get("global_limits") or {}).get("max_concurrency") or 2,
        "nuclei_rate_limit": (raw.get("global_limits") or {}).get("nuclei_rate_limit") or 50,
        "assets": assets,
    })
    email = env("ADMIN_EMAIL", "security@company.com")
    if database.user_count() == 0:
        password = env("ADMIN_PASSWORD")
        if not password:
            raise RuntimeError("首次启动需要 ADMIN_PASSWORD")
        database.create_user(email, hash_password(password), "系统管理员", "admin")
    database.promote_bootstrap_admin(email)
    seed_llm_profiles(database)
    database.ensure_system_prompt(REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE, DEFAULT_MLPS3_REPORT_PROMPT)


def seed_llm_profiles(database: Database) -> None:
    if database.llm_profile_count():
        return
    raw = load_yaml("config.yaml").get("llm_profiles") or {}
    presets = {
        "gemini_paid": ("Gemini 跨境通道", "gemini", "GEMINI_API_KEY"),
        "domestic_cn": ("国内模型通道", "openai_compatible", "DEEPSEEK_API_KEY"),
        "local_vllm": ("本地 vLLM", "openai_compatible", "VLLM_API_KEY"),
        "local_rules": ("本地规则映射", "local_rules", ""),
    }
    for key, profile in raw.items():
        display, provider, key_env = presets.get(key, (key, "openai_compatible", ""))
        model = str(profile.get("fast_mapper_model") or "")
        if "gemini" in model:
            provider = "gemini"
        database.save_llm_profile({
            "profile_key": key,
            "display_name": display,
            "provider": provider,
            "is_cross_border": bool(profile.get("is_cross_border")),
            "allowed_env_tiers": profile.get("allowed_env_tiers") or [],
            "fast_mapper_model": model,
            "deep_reasoner_model": profile.get("deep_reasoner_model") or model,
            "api_base": profile.get("api_base") or "",
            "proxy_env": profile.get("proxy_env") or "",
            "auth_mode": "env_ref",
            "api_key_env": key_env,
            "api_key_encrypted": "",
            "enable_context_caching": bool(profile.get("enable_context_caching")),
            "inject_block_none_safety": bool(profile.get("inject_block_none_safety")) or provider == "gemini",
            "is_enabled": True,
        })


@app.on_event("startup")
def startup() -> None:
    database = Database(db_path())
    deps.db = database
    bootstrap(database)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok"}


app.include_router(auth.router)
app.include_router(assets_admin.router)
app.include_router(projects.router)
app.include_router(scans.router)
app.include_router(sanitization.router)
app.include_router(compliance.router)
app.include_router(reports.router)
app.include_router(delivery.router)
app.include_router(system.router)
app.include_router(llm_admin.router)
app.include_router(prompts_admin.router)
app.include_router(users_admin.router)
