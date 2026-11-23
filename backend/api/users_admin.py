"""账户与角色。停用或删除时至少保留一个启用中的管理员。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import ROLES, get_db, require_roles
from core.security import hash_password
from database.db_manager import Database

router = APIRouter(prefix="/api/admin", tags=["users-admin"])

ROLE_MATRIX = [
    {
        "role": "admin",
        "label": "系统管理员",
        "summary": "管理模型通道、账户和全部评估动作。",
        "permissions": ["查看全部数据", "发起扫描", "切换扫描模式", "确认脱敏结果", "AI 评审", "条款复核", "导出还原报告", "外部平台同步", "模型通道管理", "账户与角色管理"],
    },
    {
        "role": "security_lead",
        "label": "等保负责人",
        "summary": "负责扫描、确认脱敏、复核和报告。系统配置由系统管理员维护。",
        "permissions": ["查看全部数据", "发起扫描", "切换扫描模式", "确认脱敏结果", "AI 评审", "条款复核", "导出还原报告", "外部平台同步"],
    },
    {
        "role": "auditor",
        "label": "只读审计员",
        "summary": "查看评估结果，并导出脱敏报告。",
        "permissions": ["查看全部数据", "导出脱敏报告"],
    },
]


class UserBody(BaseModel):
    email: str
    display_name: str = Field(min_length=1, max_length=40)
    role: str
    password: str = Field(min_length=8)
    is_active: bool = True


class UserPatch(BaseModel):
    display_name: str = Field(min_length=1, max_length=40)
    role: str
    is_active: bool = True


class PasswordBody(BaseModel):
    password: str = Field(min_length=8)


def _public(user: dict) -> dict:
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "role": user["role"],
        "theme_preference": user.get("theme_preference") or "classic_red",
        "is_active": bool(user.get("is_active", 1)),
        "created_at": user.get("created_at"),
        "updated_at": user.get("updated_at"),
    }


def _guard_last_admin(db: Database, user_id: str, next_role: str, next_active: bool) -> None:
    current = db.get_user(user_id)
    if not current or current["role"] != "admin" or not current.get("is_active", 1):
        return
    still_admin = next_role == "admin" and next_active
    if still_admin:
        return
    if db.count_active_admins(exclude_user_id=user_id) < 1:
        raise HTTPException(status_code=400, detail="必须保留至少一个启用中的系统管理员")


@router.get("/roles")
def roles(_: dict = Depends(require_roles("admin", "security_lead", "auditor"))) -> list[dict]:
    return ROLE_MATRIX


@router.get("/users")
def users(db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> list[dict]:
    return db.list_users()


@router.post("/users")
def create_user(body: UserBody, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail="角色不合法")
    if db.get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="邮箱已存在")
    created = db.create_user(body.email, hash_password(body.password), body.display_name.strip(), body.role)
    if not body.is_active:
        created = db.update_user(created["user_id"], body.display_name.strip(), body.role, False)
    return _public(created)


@router.patch("/users/{user_id}")
def update_user(user_id: str, body: UserPatch, db: Database = Depends(get_db), actor: dict = Depends(require_roles("admin"))) -> dict:
    if body.role not in ROLES:
        raise HTTPException(status_code=400, detail="角色不合法")
    if not db.get_user(user_id):
        raise HTTPException(status_code=404, detail="用户不存在")
    _guard_last_admin(db, user_id, body.role, body.is_active)
    if actor["user_id"] == user_id and (body.role != "admin" or not body.is_active):
        raise HTTPException(status_code=400, detail="当前登录的管理员账号要保留管理员角色")
    updated = db.update_user(user_id, body.display_name.strip(), body.role, body.is_active)
    return _public(updated or {})


@router.post("/users/{user_id}/reset-password")
def reset_password(user_id: str, body: PasswordBody, db: Database = Depends(get_db), _: dict = Depends(require_roles("admin"))) -> dict:
    if not db.get_user(user_id):
        raise HTTPException(status_code=404, detail="用户不存在")
    db.set_password(user_id, hash_password(body.password))
    return {"reset": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: str, db: Database = Depends(get_db), actor: dict = Depends(require_roles("admin"))) -> dict:
    if actor["user_id"] == user_id:
        raise HTTPException(status_code=400, detail="当前登录的账号留在系统里，删除请换另一个管理员操作")
    if not db.get_user(user_id):
        raise HTTPException(status_code=404, detail="用户不存在")
    _guard_last_admin(db, user_id, "auditor", False)
    db.delete_user(user_id)
    return {"deleted": user_id}
