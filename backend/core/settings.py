"""运行配置。模型 ID 与密钥只从配置文件和环境变量读取。"""
from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def load_dotenv(path: Path) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


load_dotenv(ROOT / ".env")


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


@lru_cache(maxsize=1)
def load_yaml(name: str) -> dict:
    return yaml.safe_load((ROOT / "config" / name).read_text(encoding="utf-8")) or {}


def db_path() -> Path:
    return ROOT / "backend" / "data" / "mlps.db"


def report_dir() -> Path:
    path = ROOT / "backend" / "data" / "reports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def jwt_secret() -> str:
    secret = env("JWT_SECRET")
    if not secret:
        raise RuntimeError("缺少 JWT_SECRET")
    return secret


def vault_key() -> str:
    key = env("VAULT_FERNET_KEY")
    if not key:
        raise RuntimeError("缺少 VAULT_FERNET_KEY")
    return key
