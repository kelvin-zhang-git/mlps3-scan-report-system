from __future__ import annotations

from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException

from api.deps import current_user, get_db
from core.security import create_token, hash_password, verify_password
from database.db_manager import Database

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginBody(BaseModel):
    email: str
    password: str


class RegisterBody(BaseModel):
    email: str
    password: str = Field(min_length=8)
    display_name: str


class ThemeBody(BaseModel):
    theme: str


def public_user(user: dict) -> dict:
    return {
        "user_id": user["user_id"],
        "email": user["email"],
        "display_name": user["display_name"],
        "role": user["role"],
        "theme_preference": user["theme_preference"],
        "is_active": bool(user.get("is_active", 1)),
    }


@router.post("/login")
def login(body: LoginBody, db: Database = Depends(get_db)) -> dict:
    user = db.get_user_by_email(body.email)
    if not user or not verify_password(body.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="邮箱或口令不正确")
    if not user.get("is_active", 1):
        raise HTTPException(status_code=403, detail="账号已停用")
    return {"access_token": create_token(user), "user": public_user(user)}


@router.post("/register")
def register(body: RegisterBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="只有管理员可以创建账号")
    if db.get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="邮箱已存在")
    created = db.create_user(body.email, hash_password(body.password), body.display_name, "auditor")
    return public_user(created)


@router.get("/me")
def me(user: dict = Depends(current_user)) -> dict:
    return user


@router.patch("/theme")
def theme(body: ThemeBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    allowed = {"classic_red", "arctic_blue", "midnight_dark"}
    if body.theme not in allowed:
        raise HTTPException(status_code=400, detail="未知主题")
    db.update_theme(user["user_id"], body.theme)
    user["theme_preference"] = body.theme
    return user
