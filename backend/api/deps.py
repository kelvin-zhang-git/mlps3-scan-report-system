from __future__ import annotations

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from core.security import decode_token
from database.db_manager import Database

security = HTTPBearer(auto_error=False)
db: Database | None = None

ROLES = ("admin", "security_lead", "auditor")


def get_db() -> Database:
    assert db is not None
    return db


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    database: Database = Depends(get_db),
) -> dict:
    if credentials is None:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        payload = decode_token(credentials.credentials)
    except Exception as exc:
        raise HTTPException(status_code=401, detail="登录已失效") from exc
    user = database.get_user(payload["sub"])
    if not user:
        raise HTTPException(status_code=401, detail="用户不存在")
    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="账号已停用")
    user.pop("password_hash", None)
    user["is_active"] = bool(user.get("is_active", 1))
    return user


def require_roles(*roles: str):
    def checker(user: dict = Depends(current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="这项操作由具备相应角色的账号来做")
        return user

    return checker
