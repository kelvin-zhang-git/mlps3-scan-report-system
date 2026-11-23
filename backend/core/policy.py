"""扫描目标白名单与模型出境路由。"""
from __future__ import annotations

import ipaddress
from typing import Any


class PolicyError(Exception):
    """扫描或模型路由违反安全策略。"""


class CompliancePolicyError(PolicyError):
    """涉敏资产试图走未授权的境外模型通道。"""


def host_decision(host: str, whitelist: list[str], forbidden: list[str]) -> tuple[bool, str]:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False, "目标不是合法 IP，已拒绝"
    for cidr in forbidden:
        if ip in ipaddress.ip_network(cidr, strict=False):
            return False, f"目标在排除网段 {cidr} 内，本次扫描不会发往该地址"
    for cidr in whitelist:
        if ip in ipaddress.ip_network(cidr, strict=False):
            return True, "白名单通过"
    return False, "目标不在白名单内"


def assert_targets_allowed(assets: list[dict], whitelist: list[str], forbidden: list[str]) -> None:
    if not assets:
        raise PolicyError("没有可扫描资产")
    for asset in assets:
        ok, reason = host_decision(asset["host"], whitelist, forbidden)
        if not ok:
            raise PolicyError(f"{asset['host']}：{reason}")
        if asset.get("scan_mode") == "READONLY_AUDIT":
            blocked = {"zap_active", "openvas"}
            chosen = set(asset.get("scanners") or [])
            if chosen & blocked:
                raise PolicyError("只读核查使用基线和模板检查；主动侵入式扫描器要切换到主动扫描之后再启用")


def filter_nuclei_tags(tags: list[str], excluded: list[str]) -> list[str]:
    banned = {item.lower() for item in excluded}
    return [tag for tag in tags if tag.lower() not in banned]


def assert_llm_route(env_tier: str, profile_name: str, profiles: dict[str, Any]) -> dict:
    profile = profiles.get(profile_name)
    if not profile:
        raise CompliancePolicyError(f"未知模型通道 {profile_name}")
    allowed = profile.get("allowed_env_tiers") or []
    if env_tier not in allowed:
        raise CompliancePolicyError(
            f"资产密级 {env_tier} 不允许使用模型通道 {profile_name}"
        )
    return profile


def gemini_safety_settings(profile: dict) -> list[dict] | None:
    model = str(profile.get("fast_mapper_model", ""))
    if not profile.get("inject_block_none_safety"):
        return None
    if "gemini" not in model:
        return None
    categories = [
        "HARM_CATEGORY_HARASSMENT",
        "HARM_CATEGORY_HATE_SPEECH",
        "HARM_CATEGORY_SEXUALLY_EXPLICIT",
        "HARM_CATEGORY_DANGEROUS_CONTENT",
    ]
    return [{"category": name, "threshold": "BLOCK_NONE"} for name in categories]
