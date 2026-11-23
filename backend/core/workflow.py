"""根据项目和当前作业计算工作台五个阶段是否可以进入。"""
from __future__ import annotations

from typing import Any

FLOW = [
    ("assets", "范围与资产", 1),
    ("collect", "采集与脱敏", 2),
    ("review", "漏洞与条款", 3),
    ("reports", "报告生成", 4),
    ("delivery", "协同交付", 5),
]
ALWAYS = [
    ("overview", "概览"),
]


def build_workflow(
    project: dict,
    assets: list[dict],
    selected_job: dict | None,
    vault: dict | None,
    assessment_count: int,
    report_ready: bool = False,
) -> dict[str, Any]:
    status = project.get("status") or "active"
    enabled_assets = [item for item in assets if item.get("is_enabled", True)]
    job_status = (selected_job or {}).get("status") or ""
    in_progress = job_status in {"queued", "running"}
    collected = bool(selected_job) and job_status in {"awaiting_approval", "completed"} and vault is not None
    reviewed = bool(selected_job) and job_status == "completed" and assessment_count > 0
    pending_scan = "这一轮核查还在进行。采集完成之后，这一步才会打开。"
    reasons = {
        "assets": "" if status != "draft" else "请先启动项目，再配置远程主机",
        "collect": _scan_reason(status, len(enabled_assets)),
        "review": "" if reviewed else (pending_scan if in_progress else "先在采集与脱敏里确认零泄漏并完成条款评审"),
        "reports": "" if reviewed else "先完成条款评审，再生成报告",
        "delivery": "" if reviewed and report_ready else ("先在报告生成里生成本轮脱敏版报告" if reviewed else "先完成条款评审，并生成本轮脱敏版报告"),
    }
    enabled = {
        "overview": True,
        "assets": status != "draft",
        "collect": (status == "active" and len(enabled_assets) >= 1) or bool(selected_job),
        "review": reviewed,
        "reports": reviewed,
        "delivery": reviewed and bool(report_ready),
    }
    if status == "archived" and not selected_job:
        enabled["collect"] = False
        reasons["collect"] = "项目已归档，没有可回看的核查作业"
    next_step = _next_step(status, len(enabled_assets), collected, reviewed, bool(report_ready), job_status)
    tabs: dict[str, dict] = {}
    for key, label in ALWAYS:
        tabs[key] = {
            "key": key,
            "label": label,
            "step": None,
            "enabled": True,
            "state": "current" if next_step["key"] == key else "open",
            "reason": "",
        }
    for key, label, step in FLOW:
        open_now = enabled[key]
        tabs[key] = {
            "key": key,
            "label": label,
            "step": step,
            "enabled": open_now,
            "state": "locked" if not open_now else ("current" if next_step["key"] == key else "done"),
            "reason": "" if open_now else reasons[key],
        }
    return {
        "project_status": status,
        "writable": status == "active",
        "manual_writable": status != "archived",
        "next_step": next_step,
        "tabs": tabs,
    }


def _scan_reason(status: str, enabled_count: int) -> str:
    if status == "draft":
        return "先启动项目，再发起核查"
    if status == "archived":
        return "项目已归档，重新启用之后才能发起新的核查"
    if enabled_count < 1:
        return "先在范围与资产中启用至少 1 台远程主机"
    return ""


def _next_step(status: str, enabled_count: int, collected: bool, reviewed: bool, report_ready: bool, job_status: str = "") -> dict[str, str]:
    if status == "draft":
        return {"key": "overview", "label": "启动项目", "reason": "项目还是草稿。启动之后才能配置主机并发起核查。"}
    if status == "archived":
        return {"key": "overview", "label": "已归档", "reason": "项目已归档，历史结果可以查看。重新启用之后才能继续修改。"}
    if enabled_count < 1:
        return {"key": "assets", "label": "范围与资产", "reason": "先配置白名单和远程主机，并至少启用一台。"}
    if job_status in {"queued", "running"}:
        return {"key": "collect", "label": "采集与脱敏", "reason": "这一轮核查还在进行。采集完成之后，才能核对脱敏并进入条款复核。"}
    if job_status == "failed":
        return {"key": "collect", "label": "采集与脱敏", "reason": "这一轮核查没有完成。可以查看记录，再重新发起。"}
    if not collected:
        return {"key": "collect", "label": "采集与脱敏", "reason": "主机已经启用。下一步是发起这一轮只读核查。"}
    if not reviewed:
        return {"key": "collect", "label": "采集与脱敏", "reason": "采集已经完成。核对脱敏结果并确认后，才会开始条款评审。"}
    if not report_ready:
        return {"key": "reports", "label": "报告生成", "reason": "条款评审已经完成。生成本轮脱敏版报告后，才能进入协同交付。"}
    return {"key": "delivery", "label": "协同交付", "reason": "脱敏版报告已经生成，可同步最新整改状态并归档至 CISO Assistant。"}
