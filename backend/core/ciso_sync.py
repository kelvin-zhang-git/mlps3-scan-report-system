"""把脱敏后的条款结论、AI 评估总述与关键整改控制项写入 CISO Assistant，并拉回原生归档件。"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import httpx

from core.ciso_framework import build_library_yaml, framework_spec, load_clauses
from core.settings import report_dir

RESULT_MAP = {
    "compliant": ("compliant", "done"),
    "partially_compliant": ("partially_compliant", "done"),
    "non_compliant": ("non_compliant", "done"),
    "not_applicable": ("not_applicable", "done"),
}


def _base_url() -> str:
    return os.environ.get("CISO_ASSISTANT_URL", "").rstrip("/")


def public_ciso_base() -> str:
    host = os.environ.get("SCANNER_HOST", "").strip() or "192.168.1.250"
    return f"https://{host}:8443"


def connector_status() -> dict:
    url = _base_url()
    if not url:
        return {"name": "CISO Assistant", "configured": False, "reachable": False, "detail": "未配置 CISO_ASSISTANT_URL"}
    try:
        response = httpx.get(f"{url}/api/health/", timeout=8.0)
        return {
            "name": "CISO Assistant",
            "configured": True,
            "reachable": response.status_code < 500,
            "detail": f"HTTP {response.status_code}",
        }
    except httpx.HTTPError as exc:
        return {"name": "CISO Assistant", "configured": True, "reachable": False, "detail": str(exc)}


def sync_assessments(assessments: list[dict], manual_docs: list[dict]) -> dict[str, Any]:
    """集成页的旧入口。项目内协同交付走 deliver_assessment。"""
    status = connector_status()
    payload = {
        "technical": [
            {"clause_id": row["clause_id"], "status": row["final_status"]}
            for row in assessments
            if row["final_status"] != "pending_manual"
        ],
        "manual_documents": [
            {"clause_id": doc.get("clause_id"), "filename": doc.get("filename"), "note": doc.get("note")}
            for doc in manual_docs
        ],
    }
    if not status["reachable"]:
        return {"synced": False, "mode": "local", "payload": payload, "detail": status["detail"]}
    if not _token():
        return {
            "synced": False,
            "mode": "remote_unauthenticated",
            "payload": payload,
            "detail": "CISO Assistant 已连通。配置令牌或管理员口令后，在项目的协同交付里写入评估。",
        }
    return {
        "synced": False,
        "mode": "remote",
        "payload": payload,
        "detail": "请到该项目的「协同交付」写入 CISO Assistant。这一页只检查平台是否连通。",
    }


class CisoError(RuntimeError):
    pass


def deliver_assessment(
    project: dict,
    job: dict,
    assessments: list[dict],
    manual_docs: list[dict],
    integration: dict | None,
    *,
    assessment_description: str = "",
    assessment_observation: str = "",
    control_items: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    token = _token()
    if not token:
        raise CisoError("CISO Assistant 已连通，但还没有可用的访问令牌")
    client = _Client(_base_url(), token)
    extensions = project.get("enabled_extensions") or ["GENERAL"]
    if any(str(row.get("clause_id") or "").startswith("8.2.") for row in assessments):
        if "CLOUD" not in extensions:
            extensions = [*extensions, "CLOUD"]
    framework_id = client.ensure_framework(extensions)
    folder_name = project["name"]
    folder_id = (
        _reuse(client, "folders", (integration or {}).get("ciso_folder_id"))
        or client.find_named("folders", folder_name)
        or _object_id(client.create("folders", {"name": folder_name}))
    )
    perimeter_name = f"{project['name']} 评估范围"
    perimeter_id = (
        _reuse(client, "perimeters", (integration or {}).get("ciso_perimeter_id"))
        or client.find_named("perimeters", perimeter_name)
        or _object_id(client.create(
            "perimeters",
            {"name": perimeter_name, "folder": folder_id, "description": str(project.get("summary") or "")[:500]},
        ))
    )
    assessment_name = f"{project['name']} {str(job.get('job_id') or '')[:12]}"
    assessment_id = (
        _reuse(client, "compliance-assessments", (integration or {}).get("ciso_assessment_id"))
        or client.find_named("compliance-assessments", assessment_name)
    )
    desc_text = (assessment_description or str(project.get("summary") or "")).strip()[:2000]
    obs_text = assessment_observation.strip()[:4000]
    if not assessment_id:
        created = client.create("compliance-assessments", {
            "name": assessment_name,
            "framework": framework_id,
            "perimeter": perimeter_id,
            "folder": folder_id,
            "status": "in_progress",
            "description": desc_text,
            "observation": obs_text,
        })
        assessment_id = _object_id(created)
    if not assessment_id:
        raise CisoError("CISO Assistant 没有返回评估项目编号")

    meta_patch: dict[str, Any] = {"status": "in_progress"}
    if desc_text:
        meta_patch["description"] = desc_text
    if obs_text:
        meta_patch["observation"] = obs_text
    client.patch(f"/api/compliance-assessments/{assessment_id}/", meta_patch)

    controls_by_clause: dict[str, list[str]] = {}
    controls_written = 0
    if control_items:
        controls_by_clause, controls_written = client.sync_applied_controls(folder_id, control_items)

    written = client.write_requirements(
        assessment_id,
        framework_id,
        assessments,
        manual_docs,
        controls_by_clause=controls_by_clause,
    )
    final_patch: dict[str, Any] = {"status": "in_review"}
    if desc_text:
        final_patch["description"] = desc_text
    if obs_text:
        final_patch["observation"] = obs_text
    client.patch(f"/api/compliance-assessments/{assessment_id}/", final_patch)
    report_path, filename = client.export_report(assessment_id, str(job["job_id"]))
    url = f"{public_ciso_base()}/compliance-assessments/{assessment_id}"
    control_note = f"、{controls_written} 项整改控制措施" if controls_written else ""
    return {
        "synced": True,
        "framework_id": framework_id,
        "folder_id": folder_id,
        "perimeter_id": perimeter_id,
        "assessment_id": assessment_id,
        "written": written,
        "controls_written": controls_written,
        "url": url,
        "report_path": str(report_path),
        "filename": filename,
        "detail": f"已写入 CISO Assistant {written} 条条款{control_note}及 AI 评估总述，并归档平台台账快照",
    }


def _token() -> str:
    existing = os.environ.get("CISO_ASSISTANT_TOKEN", "").strip()
    if existing:
        return existing
    email = os.environ.get("CISO_ASSISTANT_EMAIL", "").strip() or os.environ.get("ADMIN_EMAIL", "").strip()
    password = os.environ.get("CISO_ASSISTANT_PASSWORD", "") or os.environ.get("ADMIN_PASSWORD", "")
    if not email or not password or not _base_url():
        return ""
    try:
        response = httpx.post(
            f"{_base_url()}/api/_allauth/app/v1/auth/login",
            json={"email": email, "password": password},
            timeout=20.0,
        )
    except httpx.HTTPError:
        return ""
    if response.status_code >= 300:
        return ""
    meta = (response.json() or {}).get("meta") or {}
    return str(meta.get("access_token") or "")


def _same_host(base: str, url: str) -> str:
    if not url:
        return ""
    if url.startswith("/"):
        return base + url
    if url.startswith(base):
        return url
    if url.startswith("http://") or url.startswith("https://"):
        marker = url.find("/api/")
        if marker >= 0:
            return base + url[marker:]
    return url


def _object_id(body: dict) -> str:
    return str(body.get("id") or "")


def _reuse(client: "_Client", collection: str, object_id: str | None) -> str:
    if not object_id:
        return ""
    row = client.get(f"/api/{collection}/{object_id}/")
    return str(row.get("id") or "") if row else ""


class _Client:
    def __init__(self, base: str, token: str) -> None:
        self.base = base
        self.headers = {"Authorization": f"Token {token}"}

    def get(self, path: str, params: dict | None = None) -> dict:
        response = httpx.get(f"{self.base}{path}", headers=self.headers, params=params, timeout=40.0)
        if response.status_code == 404:
            return {}
        if response.status_code >= 300:
            raise CisoError(f"读取 {path} 失败 HTTP {response.status_code}")
        body = response.json()
        return body if isinstance(body, dict) else {}

    def find_named(self, collection: str, name: str) -> str:
        for row in self._pages(f"/api/{collection}/", {}):
            if row.get("name") == name:
                return str(row.get("id") or "")
        return ""

    def patch(self, path: str, payload: dict) -> None:
        response = httpx.patch(f"{self.base}{path}", headers=self.headers, json=payload, timeout=30.0)
        if response.status_code >= 300:
            raise CisoError(f"更新 {path} 失败 HTTP {response.status_code}：{response.text[:240]}")

    def create(self, collection: str, payload: dict) -> dict:
        response = httpx.post(f"{self.base}/api/{collection}/", headers=self.headers, json=payload, timeout=40.0)
        if response.status_code >= 300:
            raise CisoError(f"创建 {collection} 失败 HTTP {response.status_code}：{response.text[:240]}")
        return response.json()

    def ensure_framework(self, extensions: list[str] | None = None) -> str:
        spec = framework_spec(extensions)
        found = self._find_framework(spec)
        if found:
            return found
        clauses = load_clauses(extensions or ["GENERAL"])
        yaml_text = build_library_yaml(clauses, extensions=extensions or ["GENERAL"])
        response = httpx.post(
            f"{self.base}/api/stored-libraries/upload/",
            headers={
                **self.headers,
                "Content-Type": "application/yaml",
                "Content-Disposition": f'attachment; filename="{spec["filename"]}"',
            },
            content=yaml_text.encode("utf-8"),
            timeout=60.0,
        )
        if response.status_code >= 300:
            raise CisoError(f"导入等保框架失败 HTTP {response.status_code}：{response.text[:240]}")
        body = response.json() if response.content else {}
        library_id = str(body.get("id") or "")
        if not library_id:
            library_id = self._library_id_by_urn(spec["library_urn"])
        if not library_id:
            raise CisoError("框架包已上传，但没有返回库编号")
        loaded = httpx.post(f"{self.base}/api/stored-libraries/{library_id}/import/", headers=self.headers, timeout=90.0)
        if loaded.status_code >= 300 and "already been loaded" not in loaded.text:
            raise CisoError(f"加载等保框架失败 HTTP {loaded.status_code}：{loaded.text[:240]}")
        found = self._find_framework(spec)
        if not found:
            raise CisoError("框架已加载，但评估框架列表里还没有等保三级")
        return found

    def sync_applied_controls(self, folder_id: str, control_items: list[dict[str, Any]]) -> tuple[dict[str, list[str]], int]:
        """为本轮高风险差距条款创建或复用 CISO Applied Controls，避免行动计划表为空。"""
        by_clause: dict[str, list[str]] = {}
        existing_by_name: dict[str, str] = {}
        try:
            for row in self._pages("/api/applied-controls/", {"folder": folder_id}):
                if row.get("name") and row.get("id"):
                    existing_by_name[str(row["name"])] = str(row["id"])
        except Exception:
            existing_by_name = {}

        created_or_matched = 0
        for item in control_items[:20]:
            name = str(item.get("name") or "").strip()[:180]
            clause_id = str(item.get("clause_id") or "").strip()
            if not name or not clause_id:
                continue
            ctrl_id = existing_by_name.get(name)
            if not ctrl_id:
                payload = {
                    "name": name,
                    "description": str(item.get("description") or "")[:2000],
                    "folder": folder_id,
                    "status": "to_do",
                    "priority": int(item.get("priority_num") or 2),
                    "category": str(item.get("category") or "technical"),
                }
                try:
                    resp = httpx.post(f"{self.base}/api/applied-controls/", headers=self.headers, json=payload, timeout=30.0)
                    if resp.status_code < 300:
                        ctrl_id = str((resp.json() or {}).get("id") or "")
                        if ctrl_id:
                            existing_by_name[name] = ctrl_id
                except httpx.HTTPError:
                    ctrl_id = ""
            if ctrl_id:
                by_clause.setdefault(clause_id, []).append(ctrl_id)
                created_or_matched += 1
        return by_clause, created_or_matched

    def write_requirements(
        self,
        assessment_id: str,
        framework_id: str,
        assessments: list[dict],
        manual_docs: list[dict],
        *,
        controls_by_clause: dict[str, list[str]] | None = None,
    ) -> int:
        by_clause = {row["clause_id"]: row for row in assessments}
        notes: dict[str, list[str]] = {}
        for doc in manual_docs:
            notes.setdefault(str(doc.get("clause_id") or ""), []).append(
                f"{doc.get('filename') or '证据'}：{doc.get('note') or ''}".strip()
            )
        ref_by_requirement = self._requirement_refs(framework_id)
        written = 0
        for item in self._pages("/api/requirement-assessments/", {"compliance_assessment": assessment_id}):
            requirement = item.get("requirement")
            requirement_id = requirement.get("id") if isinstance(requirement, dict) else requirement
            ref_id = item.get("ref_id") or ref_by_requirement.get(str(requirement_id or ""))
            source = by_clause.get(str(ref_id or ""))
            if not source:
                continue
            result, progress = RESULT_MAP.get(source.get("final_status") or "", ("not_assessed", "in_progress"))
            observation = _observation(source, notes.get(str(ref_id), []))
            patch_body: dict[str, Any] = {"result": result, "status": progress, "observation": observation[:4000]}
            linked = (controls_by_clause or {}).get(str(ref_id))
            if linked:
                patch_body["applied_controls"] = linked
            response = httpx.patch(
                f"{self.base}/api/requirement-assessments/{item['id']}/",
                headers=self.headers,
                json=patch_body,
                timeout=30.0,
            )
            if response.status_code >= 300 and "applied_controls" in patch_body:
                # 若当前版本 CISO 拒绝 applied_controls 关联字段，降级重试确保条款结论正常写入。
                patch_body.pop("applied_controls", None)
                response = httpx.patch(
                    f"{self.base}/api/requirement-assessments/{item['id']}/",
                    headers=self.headers,
                    json=patch_body,
                    timeout=30.0,
                )
            if response.status_code >= 300:
                raise CisoError(f"写入条款 {ref_id} 失败 HTTP {response.status_code}：{response.text[:300]}")
            written += 1
        return written

    def export_report(self, assessment_id: str, job_id: str) -> tuple[Path, str]:
        for suffix, path in (("docx", "word_report"), ("xlsx", "xlsx")):
            response = httpx.get(
                f"{self.base}/api/compliance-assessments/{assessment_id}/{path}/",
                headers=self.headers,
                timeout=90.0,
            )
            if response.status_code < 300 and response.content and not _looks_like_error(response):
                filename = f"{job_id}-ciso_final.{suffix}"
                target = report_dir() / filename
                target.write_bytes(response.content)
                return target, filename
        raise CisoError("CISO Assistant 没有返回可保存的评估报告")

    def _pages(self, path: str, params: dict) -> list[dict]:
        rows: list[dict] = []
        query = dict(params)
        query["limit"] = 100
        url = f"{self.base}{path}"
        while url:
            response = httpx.get(url, headers=self.headers, params=query, timeout=40.0)
            if response.status_code >= 300:
                raise CisoError(f"读取条款评估失败 HTTP {response.status_code}")
            body = response.json()
            rows.extend(body.get("results") or [])
            url = _same_host(self.base, body.get("next") or "")
            query = None
        return rows

    def _requirement_refs(self, framework_id: str) -> dict[str, str]:
        mapping: dict[str, str] = {}
        for row in self._pages("/api/requirement-nodes/", {"framework": framework_id}):
            if row.get("ref_id"):
                mapping[str(row.get("id"))] = str(row["ref_id"])
        return mapping

    def _find_framework(self, spec: dict[str, str]) -> str:
        for row in self._pages("/api/frameworks/", {}):
            if row.get("urn") == spec["framework_urn"] or row.get("ref_id") == spec["framework_ref"]:
                return str(row["id"])
        return ""

    def _library_id_by_urn(self, library_urn: str) -> str:
        for row in self._pages("/api/stored-libraries/", {}):
            if str(row.get("urn") or "") == library_urn:
                return str(row["id"])
        return ""


def _observation(row: dict, notes: list[str]) -> str:
    parts = [str(row.get("ai_rationale") or "").strip(), str(row.get("remediation_script") or "").strip()]
    parts.extend(note for note in notes if note)
    return "\n".join(part for part in parts if part)


def _looks_like_error(response: httpx.Response) -> bool:
    content_type = response.headers.get("content-type", "")
    return "application/json" in content_type and len(response.content) < 800
