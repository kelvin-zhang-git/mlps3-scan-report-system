"""等保三级报告 AI System Prompt 的读取、编辑与恢复默认接口。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.deps import current_user, get_db, require_roles
from core.report_prompts import (
    DEFAULT_MLPS3_REPORT_PROMPT,
    PROMPT_SECTION_HINTS,
    REPORT_PROMPT_KEY,
    REPORT_PROMPT_TITLE,
)
from database.db_manager import Database

router = APIRouter(prefix="/api/admin/prompts", tags=["prompts-admin"])


class PromptUpdateBody(BaseModel):
    title: str = Field(default=REPORT_PROMPT_TITLE, min_length=1, max_length=120)
    content: str = Field(min_length=20, max_length=20000)


def _present(row: dict) -> dict:
    return {
        "prompt_key": row["prompt_key"],
        "title": row["title"],
        "content": row["content"],
        "version": int(row.get("version") or 1),
        "updated_by": row.get("updated_by") or "系统内置",
        "updated_at": row.get("updated_at") or "",
        "is_default": row["content"].strip() == DEFAULT_MLPS3_REPORT_PROMPT.strip(),
        "default_content": DEFAULT_MLPS3_REPORT_PROMPT,
        "section_hints": [{"key": key, "label": label} for key, label in PROMPT_SECTION_HINTS],
    }


@router.get("/mlps3_final_report")
def get_report_prompt(db: Database = Depends(get_db), _: dict = Depends(current_user)) -> dict:
    row = db.ensure_system_prompt(REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE, DEFAULT_MLPS3_REPORT_PROMPT)
    return _present(row)


@router.put("/mlps3_final_report")
def update_report_prompt(
    body: PromptUpdateBody,
    db: Database = Depends(get_db),
    user: dict = Depends(require_roles("admin")),
) -> dict:
    content = body.content.strip()
    if len(content) < 20:
        raise HTTPException(status_code=400, detail="系统提示词内容过短，请保留完整的角色与输出要求")
    editor = user.get("display_name") or user.get("email") or "系统管理员"
    saved = db.save_system_prompt(REPORT_PROMPT_KEY, body.title.strip() or REPORT_PROMPT_TITLE, content, editor)
    return _present(saved)


@router.post("/mlps3_final_report/reset")
def reset_report_prompt(
    db: Database = Depends(get_db),
    user: dict = Depends(require_roles("admin")),
) -> dict:
    editor = user.get("display_name") or user.get("email") or "系统管理员"
    saved = db.save_system_prompt(REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE, DEFAULT_MLPS3_REPORT_PROMPT, f"{editor}（恢复默认）")
    return _present(saved)
