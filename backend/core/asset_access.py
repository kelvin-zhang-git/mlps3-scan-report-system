"""把数据库里的资产整理成采集器能直接使用的连接参数。"""
from __future__ import annotations

import os
from typing import Any

from core.secrets import decrypt_secret


def resolve_ssh(asset: dict) -> dict[str, Any]:
    """口令只在采集进程内解密，不写回数据库，也不进入日志。"""
    mode = asset.get("ssh_auth_mode") or "env_ref"
    username = (asset.get("ssh_user") or "").strip() or os.environ.get("STAGE1_TARGET_SSH_USER", "root")
    password = None
    key_path = None
    key_text = None
    if mode == "encrypted_password":
        password = decrypt_secret(asset.get("ssh_secret_encrypted") or "")
    elif mode == "encrypted_key":
        key_text = decrypt_secret(asset.get("ssh_secret_encrypted") or "")
    else:
        secret_env = (asset.get("ssh_secret_env") or "STAGE1_TARGET_SSH_PASSWORD").strip()
        key_env = (asset.get("ssh_key_env") or "STAGE1_TARGET_SSH_KEY_PATH").strip()
        password = os.environ.get(secret_env, "").strip() or None
        key_path = os.environ.get(key_env, "").strip() or None
    return {
        "port": int(asset.get("ssh_port") or 22),
        "username": username,
        "password": password or None,
        "key_path": key_path,
        "key_text": key_text or None,
    }


def scan_policy(project: dict) -> dict:
    forbidden = list(project.get("forbidden_cidrs") or [])
    if "192.168.1.250/32" not in forbidden:
        forbidden.append("192.168.1.250/32")
    return {
        "whitelist_cidrs": list(project.get("whitelist_cidrs") or []),
        "forbidden_cidrs": forbidden,
        "global_limits": {
            "max_concurrency": int(project.get("max_concurrency") or 2),
            "nuclei_rate_limit": int(project.get("nuclei_rate_limit") or 50),
            "nuclei_exclude_tags": ["dos", "fuzz", "intrusive", "bruteforce"],
            "task_timeout_sec": 1800,
        },
    }
