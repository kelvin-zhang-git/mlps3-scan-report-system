from __future__ import annotations

import os

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.deps import current_user, get_db
from api.projects import PROJECT_ID
from core.ciso_sync import connector_status as ciso_status
from core.collectors.ecloud_collector import collector_status
from core.defectdojo_client import connector_status as dojo_status
from core.llm_gateway import proxy_for_profile
from database.db_manager import Database

router = APIRouter(prefix="/api", tags=["system"])


class ManualBody(BaseModel):
    clause_id: str
    filename: str
    note: str
    project_id: str = ""


def _host() -> str:
    return os.environ.get("SCANNER_HOST", "192.168.1.250")


def _catalog() -> list[dict]:
    host = _host()
    ecloud = collector_status()
    dojo = dojo_status()
    ciso = ciso_status()
    return [
        {
            "key": "nmap",
            "name": "Nmap",
            "category": "upstream_scanner",
            "role": "发现白名单主机的开放端口和服务，供边界防护条款取证。",
            "flow": "扫描机容器 → 本系统证据库",
            "configured": True,
            "reachable": True,
            "external_url": "",
            "actions": [],
            "detail": "只扫描白名单，使用 TCP connect 和常见端口。",
        },
        {
            "key": "nuclei",
            "name": "Nuclei",
            "category": "upstream_scanner",
            "role": "按模板检查错误配置和暴露面，不执行拒绝服务或爆破。",
            "flow": "扫描机容器 → 本系统证据库",
            "configured": True,
            "reachable": True,
            "external_url": "",
            "actions": [],
            "detail": "已排除 dos、fuzz、intrusive、bruteforce，并关闭 interactsh。",
        },
        {
            "key": "trivy",
            "name": "Trivy",
            "category": "upstream_scanner",
            "role": "检查靶机上的业务镜像漏洞，不扫描扫描机自身系统。",
            "flow": "本地镜像 → 本系统证据库",
            "configured": True,
            "reachable": True,
            "external_url": "",
            "actions": [],
            "detail": "当前检查 juice-shop 镜像的高危和严重漏洞。",
        },
        {
            "key": "ssh_baseline",
            "name": "Rocky SSH 基线",
            "category": "upstream_scanner",
            "role": "只读核查 SSH、SELinux、审计、防火墙和时间同步。",
            "flow": "靶机 SSH → 本系统证据库",
            "configured": bool(os.environ.get("STAGE1_TARGET_SSH_PASSWORD") or os.environ.get("STAGE1_TARGET_SSH_KEY")),
            "reachable": True,
            "external_url": "",
            "actions": [],
            "detail": "采集失败时记为基线不符合，结论要等重新取到证据后再改。",
        },
        {
            **dojo,
            "key": "defectdojo",
            "category": "downstream_platform",
            "role": "接收去重后的漏洞和基线不符合项，并在 DefectDojo 里继续跟踪。",
            "flow": "本系统 → DefectDojo 产品「等保三级扫描」",
            "external_url": f"http://{host}:8080",
            "actions": ["test", "sync"],
        },
        {
            **ciso,
            "key": "ciso",
            "category": "downstream_platform",
            "role": "承载等保条款台账和整改跟踪。条款写入需要先配置访问令牌。",
            "flow": "本系统条款结论 → CISO Assistant",
            "external_url": f"https://{host}:8443",
            "actions": ["test", "sync"],
        },
        {
            "key": "ecloud",
            "name": ecloud["name"],
            "category": "cloud_and_import",
            "role": "读取移动云安全组和审计配置。密钥还没配好时，采集器保持关闭。",
            "flow": "移动云 OpenAPI → 本系统证据库",
            "configured": ecloud["configured"],
            "reachable": ecloud["configured"],
            "external_url": "",
            "actions": ["import"],
            "detail": ecloud["detail"],
        },
        {
            "key": "kubescape",
            "name": "Kubescape",
            "category": "cloud_and_import",
            "role": "导入 Kubernetes 基线结果。当前不在扫描机上主动采集。",
            "flow": "JSON 报告 → 本系统证据库",
            "configured": False,
            "reachable": False,
            "external_url": "",
            "actions": ["import"],
            "detail": "在页面上传 Kubescape JSON。",
        },
        {
            "key": "zap",
            "name": "OWASP ZAP",
            "category": "cloud_and_import",
            "role": "导入主动 Web 扫描告警。只读核查阶段先用导入的结果，ZAP 要等切换到主动扫描之后再启动。",
            "flow": "JSON 报告 → 本系统证据库",
            "configured": False,
            "reachable": False,
            "external_url": "",
            "actions": ["import"],
            "detail": "在页面上传 ZAP 告警 JSON。",
        },
        {
            "key": "godlp",
            "name": "godlp",
            "category": "cloud_and_import",
            "role": "导入数据泄露扫描的未脱敏计数。",
            "flow": "JSON 报告 → 本系统证据库",
            "configured": False,
            "reachable": False,
            "external_url": "",
            "actions": ["import"],
            "detail": "在页面上传 godlp JSON。",
        },
        {
            "key": "akto",
            "name": "Akto",
            "category": "cloud_and_import",
            "role": "导入 API 安全测试发现。",
            "flow": "JSON 报告 → 本系统证据库",
            "configured": False,
            "reachable": False,
            "external_url": "",
            "actions": ["import"],
            "detail": "在页面上传 Akto JSON。",
        },
        {
            "key": "gemini",
            "name": "Gemini 跨境通道",
            "category": "downstream_platform",
            "role": "对已经确认过的脱敏证据做条款映射。涉敏资产改走国内或本地通道。",
            "flow": "脱敏证据 → 指定代理 → Gemini",
            "configured": bool(os.environ.get("OUTBOUND_PROXY")),
            "reachable": bool(os.environ.get("GEMINI_API_KEY") and os.environ.get("OUTBOUND_PROXY")),
            "external_url": "",
            "actions": [],
            "detail": _gemini_detail(),
        },
    ]


@router.get("/connectors")
def connectors(_: dict = Depends(current_user)) -> list[dict]:
    return _catalog()


class SyncBody(BaseModel):
    job_id: str = ""
    project_id: str = ""


@router.post("/connectors/{key}/test")
def test_connector(key: str, user: dict = Depends(current_user)) -> dict:
    if user["role"] == "auditor":
        raise HTTPException(status_code=403, detail="探测外部平台由等保负责人或系统管理员操作")
    found = next((item for item in _catalog() if item["key"] == key), None)
    if not found:
        raise HTTPException(status_code=404, detail="未知连接器")
    return found


@router.post("/connectors/{key}/sync")
def sync_connector(key: str, body: SyncBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="同步外部平台由等保负责人或系统管理员操作")
    from core.defectdojo_client import import_findings

    job = db.get_job(body.job_id) if body.job_id else None
    if not job and body.project_id:
        job = db.latest_job(body.project_id)
    if not job:
        job = db.latest_job(PROJECT_ID)
    if not job:
        raise HTTPException(status_code=400, detail="没有可同步的扫描任务")
    project_id = job["project_id"]
    if key == "defectdojo":
        return import_findings(db.list_evidences(job["job_id"]))
    if key == "ciso":
        from core.ciso_sync import sync_assessments

        return sync_assessments(db.list_assessments(job["job_id"]), db.list_manual_docs(project_id))
    raise HTTPException(status_code=400, detail="该连接器不支持同步")


def _gemini_detail() -> str:
    try:
        proxy = proxy_for_profile({"is_cross_border": True, "proxy_env": "OUTBOUND_PROXY"})
    except Exception as exc:
        return str(exc)
    if not os.environ.get("GEMINI_API_KEY"):
        return f"跨境请求经过 {proxy}。还缺少 GEMINI_API_KEY，当前仍用本地规则。"
    return f"跨境请求经过 {proxy}。"


def _active_projects(db: Database, project_id: str = "") -> list[dict]:
    if project_id:
        project = db.get_project(project_id)
        return [project] if project else []
    return [item for item in db.list_projects() if item.get("status") == "active"]


@router.get("/todos")
def todos(project_id: str = "", db: Database = Depends(get_db), _: dict = Depends(current_user)) -> dict:
    pending = []
    waiting_jobs = []
    docs = []
    for project in _active_projects(db, project_id):
        job = db.latest_job(project["project_id"])
        if job and job["status"] == "awaiting_approval":
            waiting_jobs.append({**job, "project_name": project["name"]})
        effective = db._effective_job(project["project_id"])
        if effective:
            for row in db.list_assessments(effective["job_id"]):
                if row["final_status"] == "pending_manual":
                    pending.append({**row, "project_id": project["project_id"], "project_name": project["name"]})
        for doc in db.list_manual_docs(project["project_id"]):
            item = dict(doc)
            item["project_name"] = project["name"]
            docs.append(item)
    waiting = waiting_jobs[0] if waiting_jobs else None
    return {
        "pending_clauses": pending,
        "awaiting_approval": waiting,
        "awaiting_jobs": waiting_jobs,
        "manual_docs": docs,
    }


def _writable_project(db: Database, project_id: str) -> dict:
    project = db.get_project(project_id)
    if not project:
        raise HTTPException(status_code=404, detail="项目不存在")
    if project.get("status") == "archived":
        raise HTTPException(status_code=400, detail="项目已归档，历史证据仍可查看，新的登记要等重新启用之后")
    return project


@router.post("/manual-evidence")
def add_doc(body: ManualBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    if user["role"] not in {"admin", "security_lead"}:
        raise HTTPException(status_code=403, detail="登记证据由等保负责人或系统管理员操作")
    project_id = body.project_id or PROJECT_ID
    _writable_project(db, project_id)
    return db.add_manual_doc(project_id, body.clause_id, body.filename, body.note, user["email"])


@router.get("/manual-evidence")
def list_docs(project_id: str = "", db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_manual_docs(project_id or PROJECT_ID)


@router.post("/projects/{project_id}/manual-evidence")
def add_project_doc(project_id: str, body: ManualBody, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> dict:
    body.project_id = project_id
    return add_doc(body, db, user)


@router.get("/projects/{project_id}/manual-evidence")
def list_project_docs(project_id: str, db: Database = Depends(get_db), user: dict = Depends(current_user)) -> list[dict]:
    return list_docs(project_id, db, user)


@router.get("/users")
def users(db: Database = Depends(get_db), _: dict = Depends(current_user)) -> list[dict]:
    return db.list_users()
