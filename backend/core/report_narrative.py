"""结合管理员可配置的等保三级 System Prompt，生成结构化中文专业报告研判。"""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any

from core.clause_metadata import OBJECT_LABELS
from core.llm_gateway import model_id_of, review_with_profile
from core.policy import CompliancePolicyError, assert_llm_route
from core.report_prompts import (
    DEFAULT_MLPS3_REPORT_PROMPT,
    REPORT_PROMPT_KEY,
    REPORT_PROMPT_TITLE,
)
from core.scoring import department_for, status_zh
from database.db_manager import Database

_BEIJING = timezone(timedelta(hours=8))


def format_beijing(value: str | None) -> str:
    """把库存的 UTC 时间显示成北京时间。"""
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        moment = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return raw[:16].replace("T", " ")
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(_BEIJING).strftime("%Y-%m-%d %H:%M")


ZONE_LABELS: dict[str, str] = {
    "DMZ": "边界DMZ域",
    "APP": "应用域",
    "DB": "数据库域",
    "MGMT": "运维管理域",
    "CORE": "核心业务域",
    "CLOUD": "云平台域",
    "NET": "网络边界域",
    "OFFICE": "办公网域",
    "EXT": "外部区域",
}

OBJECT_SHORT_LABELS: dict[str, str] = {
    "host_os": "主机",
    "database": "数据库主机",
    "middleware": "中间件主机",
    "network_device": "网络设备",
    "security_device": "安全设备",
    "application": "业务应用节点",
    "cloud_platform": "云平台节点",
}

OS_LABELS: dict[str, str] = {
    "rocky_linux": "Rocky Linux",
    "centos": "CentOS",
    "ubuntu": "Ubuntu",
    "debian": "Debian",
    "kylin": "银河麒麟",
    "openeuler": "openEuler",
    "windows": "Windows Server",
}

SCAN_MODE_LABELS: dict[str, str] = {
    "READONLY_AUDIT": "只读核查",
    "ACTIVE_SCAN": "主动扫描",
}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _zone_label(zone: str) -> str:
    raw = (zone or "").strip()
    if not raw:
        return "默认安全域"
    upper = raw.upper()
    if upper in ZONE_LABELS:
        return ZONE_LABELS[upper]
    return raw if raw.endswith("域") else f"{raw}域"


def _mask_note_ips(note: str) -> str:
    return _IPV4_RE.sub("[已脱敏地址]", (note or "").strip())


def build_asset_directory(assets: list[dict]) -> tuple[list[dict[str, Any]], dict[str, dict[str, str]]]:
    """为纳管资产生成人类可读的中文代号（脱敏版不含真实 IP，受控还原版附带真实地址）。"""
    counters: dict[tuple[str, str], int] = {}
    enriched: list[dict[str, Any]] = []
    lookup: dict[str, dict[str, str]] = {}
    for asset in assets:
        item = dict(asset)
        aid = str(item.get("asset_id") or "")
        zone_raw = str(item.get("security_zone") or "APP")
        obj_type = str(item.get("object_type") or "host_os")
        z_label = _zone_label(zone_raw)
        obj_label = OBJECT_LABELS.get(obj_type, "主机操作系统")
        short_obj = OBJECT_SHORT_LABELS.get(obj_type, "主机")
        key = (z_label, short_obj)
        counters[key] = counters.get(key, 0) + 1
        seq = f"{counters[key]:02d}"
        masked_label = f"{z_label}-{short_obj}{seq}"
        host = str(item.get("host") or "").strip()
        restored_label = f"{masked_label}（{host}）" if host else masked_label
        os_raw = str(item.get("os_type") or "")
        os_label = OS_LABELS.get(os_raw.lower(), os_raw or "未知系统")
        mode_raw = str(item.get("scan_mode") or "READONLY_AUDIT")
        mode_label = SCAN_MODE_LABELS.get(mode_raw, mode_raw)
        note_raw = str(item.get("notes") or "").strip()
        role_note_masked = _mask_note_ips(note_raw) or f"{z_label}{obj_label}资产"
        role_note_restored = note_raw or f"{z_label}{obj_label}资产"

        item.update({
            "zone_label": z_label,
            "object_label": obj_label,
            "os_label": os_label,
            "scan_mode_label": mode_label,
            "masked_label": masked_label,
            "restored_label": restored_label,
            "masked_host_placeholder": f"已脱敏（{masked_label}）",
            "role_note_masked": role_note_masked,
            "role_note_restored": role_note_restored,
        })
        enriched.append(item)
        if aid:
            lookup[aid] = {
                "masked": masked_label,
                "restored": restored_label,
                "host": host,
                "zone_label": z_label,
                "object_label": obj_label,
            }
    return enriched, lookup


def asset_display_name(asset_id: str, lookup: dict[str, dict[str, str]], *, variant: str = "masked") -> str:
    """将资产内部 ID 转换为面向读者的中文名称。"""
    aid = str(asset_id or "").strip()
    if not aid:
        return "未标注资产"
    entry = lookup.get(aid)
    if entry:
        return entry["restored"] if variant == "restored" else entry["masked"]
    # 离线导入的边界设备/云平台账号可能自带可读标识（如 FW-BORDER-01 / CLOUD-PROD-01）
    return aid


def replace_asset_refs_in_text(
    text: str,
    lookup: dict[str, dict[str, str]],
    *,
    variant: str = "masked",
    vault_mapping: dict[str, str] | None = None,
) -> str:
    """将正文中裸露的 ast_xxx 内部编号和脱敏占位符替换为读者可读名称。"""
    if not text:
        return text
    out = str(text)
    if variant == "restored":
        # 1. 先把裸 ast_xxx 替换为完整受控还原名（如：应用域-主机01（192.168.1.220））
        for aid, info in lookup.items():
            if aid and aid in out:
                out = out.replace(aid, info["restored"])
        # 2. 若 AI 正文已使用脱敏可读代号（如：应用域-主机01），避免重复追加括号，补全真实地址
        for info in lookup.values():
            masked = info["masked"]
            restored = info["restored"]
            if masked and restored != masked and masked in out and restored not in out:
                out = out.replace(masked, restored)
        # 3. 还原 Vault 中的 ZONE_APP_HOST_01 等拓扑占位符，优先带可读前缀
        host_to_restored = {info["host"]: info["restored"] for info in lookup.values() if info.get("host")}
        for token, host in (vault_mapping or {}).items():
            if token and host and token in out:
                out = out.replace(token, host_to_restored.get(host, host))
    else:
        for aid, info in lookup.items():
            if aid and aid in out:
                out = out.replace(aid, info["masked"])
    return out


def rewrite_narrative_assets(
    sections: dict[str, Any],
    lookup: dict[str, dict[str, str]],
    *,
    variant: str = "masked",
    vault_mapping: dict[str, str] | None = None,
) -> dict[str, Any]:
    """统一将报告叙事 JSON 中的资产编号转换为对应版本的读者可读表达。"""
    if not sections:
        return sections

    def _walk(node: Any) -> Any:
        if isinstance(node, str):
            return replace_asset_refs_in_text(node, lookup, variant=variant, vault_mapping=vault_mapping)
        if isinstance(node, list):
            return [_walk(x) for x in node]
        if isinstance(node, dict):
            return {k: _walk(v) for k, v in node.items()}
        return node

    return _walk(sections)


def ensure_report_narrative(
    db: Database,
    project: dict,
    job: dict,
    score: dict,
    assessments: list[dict],
    evidences: list[dict],
    assets: list[dict],
    paths: list[dict],
    manual_docs: list[dict],
    *,
    force_refresh: bool = False,
) -> dict[str, Any]:
    """返回本轮任务的 AI 专业研判，默认按最新 Prompt 版本缓存复用。"""
    prompt_row = db.ensure_system_prompt(REPORT_PROMPT_KEY, REPORT_PROMPT_TITLE, DEFAULT_MLPS3_REPORT_PROMPT)
    prompt_version = int(prompt_row.get("version") or 1)
    cached = db.get_report_narrative(job["job_id"])
    if cached and not force_refresh and int(cached.get("prompt_version") or 0) == prompt_version:
        return cached

    fallback = _build_fallback_narrative(project, score, assessments, evidences, assets, paths, manual_docs)
    user_payload = _build_user_prompt(project, job, score, assessments, evidences, assets, paths, manual_docs)

    profiles = db.gateway_profiles()
    profile_key = project.get("llm_profile") or job.get("llm_profile") or "local_rules"
    env_tier = project.get("env_tier") or job.get("env_tier") or "L1_TEST"
    model_id = "rule_synthesizer"
    status = "fallback"
    error_detail: str | None = None
    started = time.perf_counter()
    sections = fallback

    try:
        profile = assert_llm_route(env_tier, profile_key, profiles)
        if profile.get("is_enabled") is False:
            raise CompliancePolicyError(f"模型通道 {profile_key} 已停用")
        model_id = model_id_of(profile, "deep") or profile_key
        remote = review_with_profile(
            profile,
            user_payload,
            system_prompt=prompt_row["content"],
            model_slot="deep",
            timeout=90.0,
            temperature=0.2,
        )
        status = "ai" if remote.get("status") == "ok" else "fallback"
        error_detail = remote.get("error_detail")
        if remote.get("status") == "ok" and isinstance(remote.get("parsed"), dict):
            sections = _normalize_sections(remote["parsed"], fallback)
            model_id = str(remote.get("model_id") or model_id)
    except Exception as exc:
        status = "fallback"
        error_detail = str(exc)

    latency_ms = int((time.perf_counter() - started) * 1000)
    db.add_llm_log({
        "job_id": job["job_id"],
        "stage": "report_synthesis",
        "model_id": model_id,
        "prompt_tokens": max(200, len(user_payload) // 3),
        "completion_tokens": max(200, len(json.dumps(sections, ensure_ascii=False)) // 3),
        "cached_tokens": 0,
        "latency_ms": latency_ms,
        "status": "ok" if status == "ai" else "fallback",
        "error_detail": error_detail,
    })
    return db.save_report_narrative(
        job["job_id"],
        REPORT_PROMPT_KEY,
        prompt_version,
        model_id,
        status,
        sections,
    )


def narrative_plain_texts(sections: dict[str, Any] | None) -> list[str]:
    """提取研判结构里的全部正文，用于二次脱敏终检。"""
    if not sections:
        return []
    texts: list[str] = []
    for key in ("executive_summary", "scope_and_methodology", "ciso_summary"):
        if sections.get(key):
            texts.append(str(sections[key]))
    for item in sections.get("domain_insights") or []:
        if isinstance(item, dict):
            texts.extend(str(item.get(k) or "") for k in ("domain", "status_summary", "key_gaps", "priority_action"))
    for item in sections.get("critical_risk_analysis") or []:
        if isinstance(item, dict):
            texts.extend(
                str(item.get(k) or "")
                for k in ("risk_title", "severity", "affected_scope", "business_impact", "remediation_advice")
            )
    for item in sections.get("remediation_roadmap") or []:
        if isinstance(item, dict):
            texts.extend(str(item.get(k) or "") for k in ("phase", "owner_department", "acceptance_criteria"))
            texts.extend(str(a) for a in (item.get("actions") or []))
    for item in sections.get("manual_readiness_checklist") or []:
        texts.append(str(item))
    return [t for t in texts if t.strip()]


def restore_narrative(sections: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    """受控还原版报告把 AI 解读正文里的占位符替换回真实资产标识。"""
    if not mapping or not sections:
        return sections
    blob = json.dumps(sections, ensure_ascii=False)
    for token, host in mapping.items():
        if token and host:
            blob = blob.replace(token, host)
    return json.loads(blob)


def _build_user_prompt(
    project: dict,
    job: dict,
    score: dict,
    assessments: list[dict],
    evidences: list[dict],
    assets: list[dict],
    paths: list[dict],
    manual_docs: list[dict],
) -> str:
    # 严禁向模型传入真实主机 IP，仅传递可读中文代号、安全域与测评对象角色。
    enriched_assets, lookup = build_asset_directory(assets)

    def _alias(aid: Any) -> str:
        return asset_display_name(str(aid or ""), lookup, variant="masked")

    safe_assets = [
        {
            "asset_alias": a.get("masked_label"),
            "zone_label": a.get("zone_label"),
            "object_label": a.get("object_label"),
            "os_label": a.get("os_label"),
            "scan_mode_label": a.get("scan_mode_label"),
            "role_note": a.get("role_note_masked"),
            "scanners": a.get("scanners") or [],
        }
        for a in enriched_assets
    ]
    baseline_fails = [
        {"asset_alias": _alias(e.get("asset_id")), "severity": e.get("severity"), "title": e.get("title")}
        for e in evidences
        if e.get("source_tool") == "ssh_baseline" and e.get("evidence_type") == "BASELINE_FAIL"
    ][:24]
    baseline_pass_items = [
        e for e in evidences if e.get("source_tool") == "ssh_baseline" and e.get("evidence_type") == "BASELINE_PASS"
    ]
    baseline_pass_count = len(baseline_pass_items)
    db_mw_fails = [
        {
            "asset_alias": _alias(e.get("asset_id")),
            "source": "数据库基线" if e.get("source_tool") == "db_baseline" else "中间件基线",
            "severity": e.get("severity"),
            "title": e.get("title"),
        }
        for e in evidences
        if e.get("source_tool") in {"db_baseline", "mw_baseline"} and e.get("evidence_type") == "BASELINE_FAIL"
    ][:24]
    db_mw_pass_items = [
        e for e in evidences if e.get("source_tool") in {"db_baseline", "mw_baseline"} and e.get("evidence_type") == "BASELINE_PASS"
    ]
    db_mw_pass_count = len(db_mw_pass_items)
    # 汇总已通过的主机与数据库/中间件基线项，供大模型避开“对已通过项重复提整改”
    baseline_pass_titles = [
        f"{_alias(e.get('asset_id'))}：{e.get('title')}"
        for e in (db_mw_pass_items + baseline_pass_items)
    ][:35]
    collect_errors = [
        {
            "asset_alias": _alias(e.get("asset_id")),
            "source_tool": e.get("source_tool"),
            "title": e.get("title"),
            "detail": str((e.get("detail") or {}).get("text") or "")[:160],
        }
        for e in evidences
        if e.get("evidence_type") == "COLLECT_ERROR"
    ]
    netdev_cloud_fails = [
        {
            "asset_alias": _alias(e.get("asset_id")),
            "source": "网络/安全设备配置" if e.get("source_tool") == "netdev_config" else "云平台核查",
            "severity": e.get("severity"),
            "title": e.get("title"),
        }
        for e in evidences
        if e.get("source_tool") in {"netdev_config", "cloud_audit"}
        and e.get("evidence_type") not in {"BASELINE_PASS", "COLLECT_ERROR"}
    ][:20]
    all_high_critical_cves = [
        e for e in evidences
        if e.get("source_tool") == "trivy_os" and e.get("severity") in {"critical", "high"}
    ]
    unique_high_critical_cves = sorted({
        str(e.get("cve_or_cwe") or "")
        for e in all_high_critical_cves
        if e.get("cve_or_cwe")
    })
    top_cves = [
        {
            "asset_alias": _alias(e.get("asset_id")),
            "severity": e.get("severity"),
            "cve": e.get("cve_or_cwe"),
            "pkg_name": (e.get("detail") or {}).get("pkg_name") or "",
            "affected_pkgs": (e.get("detail") or {}).get("affected_pkgs") or [],
            "installed_version": (e.get("detail") or {}).get("installed_version") or "",
            "fixed_version": (e.get("detail") or {}).get("fixed_version") or "",
            "cvss_score": (e.get("detail") or {}).get("cvss_score"),
            "cvss_vector": (e.get("detail") or {}).get("cvss_vector") or "",
            "severity_source": (e.get("detail") or {}).get("severity_source") or "",
            "title": e.get("title"),
        }
        for e in all_high_critical_cves[:30]
    ]
    tls_fails = [
        {"asset_alias": _alias(e.get("asset_id")), "severity": e.get("severity"), "title": e.get("title")}
        for e in evidences
        if e.get("source_tool") == "tls_scanner" and e.get("evidence_type") not in {"BASELINE_PASS", "COLLECT_ERROR"}
    ][:12]
    open_ports = [
        {
            "asset_alias": _alias(e.get("asset_id")),
            "port": e.get("port") or (e.get("detail") or {}).get("port") or (re.search(r"(\d+)", str(e.get("title") or "")).group(1) if re.search(r"(\d+)", str(e.get("title") or "")) else ""),
            "title": e.get("title"),
        }
        for e in evidences
        if e.get("source_tool") == "nmap" and e.get("evidence_type") != "COLLECT_ERROR"
    ][:40]
    web_hits = [
        {"asset_alias": _alias(e.get("asset_id")), "severity": e.get("severity"), "title": e.get("title")}
        for e in evidences
        if e.get("source_tool") == "nuclei" and e.get("evidence_type") not in {"BASELINE_PASS", "COLLECT_ERROR"}
    ][:12]
    gap_clauses = [
        {
            "clause_id": row.get("clause_id"),
            "domain": row.get("domain"),
            "control_point": row.get("control_point"),
            "status": row.get("final_status"),
            "status_zh": status_zh(row.get("final_status") or ""),
            "is_high_risk": bool(row.get("is_high_risk")),
            "compensation_status": row.get("compensation_status") or "none",
            "compensation_note": str(row.get("compensation_note") or "")[:160],
            "applicable_objects": row.get("applicable_object_labels") or [],
            "precedent_category": (row.get("high_risk_precedent") or {}).get("category") or "",
            "rationale": replace_asset_refs_in_text(str(row.get("ai_rationale") or "")[:240], lookup, variant="masked"),
        }
        for row in assessments
        if row.get("final_status") in {"non_compliant", "partially_compliant"}
    ][:35]
    pending_count = sum(1 for row in assessments if row.get("final_status") in {"pending_manual", "not_assessed"})

    fact_pack = {
        "project": {
            "name": project.get("name"),
            "summary": project.get("summary"),
            "classification": project.get("classification"),
            "stage_label": project.get("stage_label"),
            "job_id": job.get("job_id"),
            "started_at": f"{format_beijing(job.get('started_at'))}（北京时间）",
        },
        "score": {
            "verdict_label": score.get("verdict_label"),
            "verdict_advice": score.get("verdict_advice"),
            "clause_total": score.get("clause_total"),
            "completeness_pct": score.get("completeness"),
            "checked_score": score.get("checked_score"),
            "conservative_score": score.get("conservative_score"),
            "weighted_checked_score": score.get("weighted_checked_score"),
            "weighted_conservative_score": score.get("weighted_conservative_score"),
            "high_fail": score.get("high_fail"),
            "direct_high_fail": score.get("direct_high_fail"),
            "mitigated_high_count": score.get("mitigated_high_count"),
            "high_open": score.get("high_open"),
            "counts": score.get("counts"),
            "risk_breakdown": score.get("risk_breakdown"),
            "object_coverage": score.get("object_coverage"),
            "domains": score.get("domains"),
        },
        "assets": safe_assets,
        "evidence_overview": {
            "total": len(evidences),
            "baseline_passed": baseline_pass_count,
            "baseline_failed_count": len(baseline_fails),
            "baseline_fails": baseline_fails,
            "db_mw_passed": db_mw_pass_count,
            "db_mw_failed_count": len(db_mw_fails),
            "db_mw_fails": db_mw_fails,
            "total_baseline_passed": baseline_pass_count + db_mw_pass_count,
            "baseline_pass_titles": baseline_pass_titles,
            "collect_errors": collect_errors,
            "netdev_cloud_failed_count": len(netdev_cloud_fails),
            "netdev_cloud_fails": netdev_cloud_fails,
            "unique_high_critical_cve_count": len(unique_high_critical_cves),
            "high_critical_cve_total": len(all_high_critical_cves),
            "top_cves": top_cves,
            "tls_fails": tls_fails,
            "open_ports": open_ports,
            "web_risks": web_hits,
        },
        "gap_clauses": gap_clauses,
        "pending_or_unassessed_clauses": pending_count,
        "attack_paths": paths[:5],
        "manual_docs": [
            {"clause_id": d.get("clause_id"), "filename": d.get("filename"), "note": str(d.get("note") or "")[:160]}
            for d in manual_docs[:15]
        ],
    }
    return (
        "请基于以下已经过脱敏处理的等保三级预评估实测事实包，严格按照系统提示词规定的 JSON 结构输出专业报告研判。"
        "注意：文中提及具体资产时请使用 assets 中的 asset_alias（中文可读代号）与角色说明，不要输出内部随机编号。\n"
        f"实测事实包：\n{json.dumps(fact_pack, ensure_ascii=False)}"
    )


def _normalize_sections(parsed: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    result = dict(fallback)
    for key in ("executive_summary", "scope_and_methodology", "ciso_summary"):
        val = parsed.get(key)
        if isinstance(val, str) and len(val.strip()) >= 20:
            result[key] = val.strip()

    if isinstance(parsed.get("domain_insights"), list) and parsed["domain_insights"]:
        cleaned = []
        for item in parsed["domain_insights"]:
            if isinstance(item, dict) and item.get("domain"):
                cleaned.append({
                    "domain": str(item.get("domain") or ""),
                    "status_summary": str(item.get("status_summary") or ""),
                    "key_gaps": str(item.get("key_gaps") or ""),
                    "priority_action": str(item.get("priority_action") or ""),
                })
        if cleaned:
            result["domain_insights"] = cleaned

    if isinstance(parsed.get("critical_risk_analysis"), list) and parsed["critical_risk_analysis"]:
        cleaned = []
        for item in parsed["critical_risk_analysis"]:
            if isinstance(item, dict) and item.get("risk_title"):
                cleaned.append({
                    "risk_title": str(item.get("risk_title") or ""),
                    "severity": str(item.get("severity") or "高风险"),
                    "affected_scope": str(item.get("affected_scope") or ""),
                    "business_impact": str(item.get("business_impact") or ""),
                    "remediation_advice": str(item.get("remediation_advice") or ""),
                })
        if cleaned:
            result["critical_risk_analysis"] = cleaned

    if isinstance(parsed.get("remediation_roadmap"), list) and parsed["remediation_roadmap"]:
        cleaned = []
        for item in parsed["remediation_roadmap"]:
            if isinstance(item, dict) and item.get("phase"):
                actions = item.get("actions") or []
                if isinstance(actions, str):
                    actions = [actions]
                cleaned.append({
                    "phase": str(item.get("phase") or ""),
                    "owner_department": str(item.get("owner_department") or "安全管理与合规"),
                    "actions": [str(a) for a in actions if str(a).strip()],
                    "acceptance_criteria": str(item.get("acceptance_criteria") or ""),
                })
        if cleaned:
            result["remediation_roadmap"] = cleaned

    if isinstance(parsed.get("manual_readiness_checklist"), list) and parsed["manual_readiness_checklist"]:
        items = [str(x).strip() for x in parsed["manual_readiness_checklist"] if str(x).strip()]
        if items:
            result["manual_readiness_checklist"] = items

    return result


def _build_fallback_narrative(
    project: dict,
    score: dict,
    assessments: list[dict],
    evidences: list[dict],
    assets: list[dict],
    paths: list[dict],
    manual_docs: list[dict],
) -> dict[str, Any]:
    """当通道为本地规则或远端模型不可用时，基于实测数据生成完整的专业中文研判。"""
    counts = score.get("counts") or {}
    total = score.get("clause_total") or len(assessments)
    completeness = score.get("completeness") or 0
    checked_score = score.get("checked_score") or 0
    conservative_score = score.get("conservative_score") or 0
    weighted_checked = score.get("weighted_checked_score") or checked_score
    weighted_conservative = score.get("weighted_conservative_score") or conservative_score
    high_fail = score.get("high_fail") or 0
    direct_high_fail = score.get("direct_high_fail") if score.get("direct_high_fail") is not None else high_fail
    mitigated_high = score.get("mitigated_high_count") or 0
    high_open = score.get("high_open") or 0
    obj_cov = score.get("object_coverage") or {}
    obj_summary = obj_cov.get("summary") or ""
    verdict = score.get("verdict_label") or "核查未完成"
    advice = score.get("verdict_advice") or ""

    enriched_assets, lookup = build_asset_directory(assets)
    asset_briefs = "、".join(
        f"{a['masked_label']}（{a['object_label']} / {a['os_label']}）" for a in enriched_assets
    )

    baseline_fails = [
        e for e in evidences if e.get("source_tool") == "ssh_baseline" and e.get("evidence_type") == "BASELINE_FAIL"
    ]
    baseline_pass = sum(
        1 for e in evidences if e.get("source_tool") == "ssh_baseline" and e.get("evidence_type") == "BASELINE_PASS"
    )
    db_mw_fails = [
        e for e in evidences if e.get("source_tool") in {"db_baseline", "mw_baseline"} and e.get("evidence_type") == "BASELINE_FAIL"
    ]
    db_mw_pass = sum(
        1 for e in evidences if e.get("source_tool") in {"db_baseline", "mw_baseline"} and e.get("evidence_type") == "BASELINE_PASS"
    )
    high_cves = [
        e for e in evidences if e.get("source_tool") == "trivy_os" and e.get("severity") in {"critical", "high"}
    ]
    unique_high_cves = sorted({str(e.get("cve_or_cwe") or "") for e in high_cves if e.get("cve_or_cwe")})
    critical_cves = [e for e in high_cves if e.get("severity") == "critical"]
    unique_crit_cves = sorted({str(e.get("cve_or_cwe") or "") for e in critical_cves if e.get("cve_or_cwe")})
    tls_fails = [
        e for e in evidences
        if e.get("source_tool") == "tls_scanner" and e.get("evidence_type") not in {"BASELINE_PASS", "COLLECT_ERROR"}
    ]
    collect_errors = [e for e in evidences if e.get("evidence_type") == "COLLECT_ERROR"]

    db_mw_clause = f"、{len(db_mw_fails)} 项数据库与中间件基线未通过" if db_mw_fails else ""
    collect_err_clause = (
        f"需要特别说明的是，本轮有 {len(collect_errors)} 项采集任务因超时或连接异常未能完成"
        f"（涉及：{'、'.join(sorted({asset_display_name(str(e.get('asset_id') or ''), lookup, variant='masked') for e in collect_errors}))}），相关对象存在局部盲区。"
        if collect_errors
        else ""
    )
    asset_scope_desc = f"（包括：{asset_briefs}）" if asset_briefs else ""
    executive_summary = (
        f"本次针对「{project.get('name')}」开展了 GB/T 22239-2019 等级保护第三级预评估差距核查，覆盖 {len(assets)} 台纳管资产{asset_scope_desc}，"
        f"归集去重后的技术证据共 {len(evidences)} 条，并对 {total} 条等保三级要求完成了自动映射与状态汇总。"
        f"当前综合研判结论为「{verdict}」：按高/中/低风险权重加权后，已核查条款得分 {weighted_checked} 分（等权 {checked_score} 分），"
        f"全量保守得分 {weighted_conservative} 分（等权 {conservative_score} 分），核查完备度 {completeness}%。\n\n"
        f"从条款与高风险判例分布来看，目前符合 {counts.get('compliant', 0)} 条、部分符合 {counts.get('partially_compliant', 0)} 条、"
        f"不符合 {counts.get('non_compliant', 0)} 条、不适用 {counts.get('not_applicable', 0)} 条，"
        f"另有待人工核查 {counts.get('pending_manual', 0)} 条、未评估 {counts.get('not_assessed', 0)} 条。"
        f"对照 T/ISEAA 001-2020 高风险判定指引，存在直接高风险不符合 {direct_high_fail} 项、已登记补偿控制降级 {mitigated_high} 项、高风险未关闭共 {high_open} 项。"
        f"技术侧重点暴露出 {len(baseline_fails)} 项主机基线未通过{db_mw_clause}、{len(high_cves)} 条操作系统高危/严重软件包漏洞实例"
        f"（去重 {len(unique_high_cves)} 个 CVE，含去重 {len(unique_crit_cves)} 个严重级 CVE）以及 {len(tls_fails)} 项传输加密薄弱点。{collect_err_clause}{advice}"
    )

    db_mw_method = (
        f"、数据库与中间件只读基线核查（通过 {db_mw_pass} 项、未通过 {len(db_mw_fails)} 项）"
        if (db_mw_pass or db_mw_fails)
        else ""
    )
    scope_and_methodology = (
        f"本报告用于等保三级正式测评前的差距自查与整改准备，正式等级测评报告仍由具备资质的测评机构出具。"
        f"本轮技术核查以只读方式开展主机基线核对（通过 {baseline_pass} 项、未通过 {len(baseline_fails)} 项）{db_mw_method}、"
        f"端口与服务识别、HTTPS 传输加密检测、非侵入式 Web 模板核查以及软件包 CVE 比对。"
        f"从测评对象覆盖维度来看，{obj_summary}{collect_err_clause}"
        f"涉及物理机房门禁、安全管理制度、人员培训与应急演练等人工核查类条款，在相关制度文件与现场记录核对完成之前暂保持待人工复核状态"
        f"（当前已登记人工证据 {len(manual_docs)} 份）。"
    )

    domain_insights = []
    for d in score.get("domains") or []:
        name = d.get("domain") or "未分类安全域"
        d_comp = d.get("completeness") or 0
        d_score = d.get("checked_score") or d.get("score") or 0
        d_pending = d.get("pending") or 0
        d_high = d.get("high_open") or 0
        domain_gaps = [
            row for row in assessments
            if row.get("domain") == name and row.get("final_status") in {"non_compliant", "partially_compliant"}
        ]
        gap_points = "、".join(
            sorted({str(row.get("control_point") or row.get("clause_id")) for row in domain_gaps})[:4]
        )
        if d_comp == 0:
            status_summary = f"核查完备度 0%，{d_pending} 条要求全部等待人工复核与佐证登记。"
            key_gaps = "尚未登记对应的制度文件、记录台账或现场核查结论，在全量保守口径下暂不计分。"
            priority_action = f"由{department_for(name)}牵头整理该域制度与运行记录，并在工作台逐项完成复核。"
        elif d_high > 0 or domain_gaps:
            status_summary = f"已核查得分 {d_score} 分（完备度 {d_comp}%），存在 {d_high} 项高风险未关闭缺口。"
            key_gaps = f"差距集中在：{gap_points or '部分技术配置与漏洞治理未达标'}。"
            priority_action = f"优先关闭该域高风险不符合项，由{department_for(name)}完成加固后复测闭环。"
        else:
            status_summary = f"已核查得分 {d_score} 分（完备度 {d_comp}%），当前已检条款整体达标。"
            key_gaps = f"仍有 {d_pending} 条待人工复核项需补充台账留痕。" if d_pending else "暂无明显技术短板。"
            priority_action = "保持现有配置基线，补齐剩余佐证材料即可。"
        domain_insights.append({
            "domain": name,
            "status_summary": status_summary,
            "key_gaps": key_gaps,
            "priority_action": priority_action,
        })

    critical_risk_analysis = []
    if high_cves:
        sample_cves = "、".join(
            [str(e.get("cve_or_cwe") or e.get("title")) for e in high_cves[:5] if e.get("cve_or_cwe") or e.get("title")]
        )
        critical_risk_analysis.append({
            "risk_title": f"操作系统存在 {len(high_cves)} 个高危及严重级软件包漏洞",
            "severity": "高风险",
            "affected_scope": f"代表性漏洞：{sample_cves}（涉及条款 8.1.4.4-e、8.1.10.5-a）",
            "business_impact": "未修补的操作系统及基础运行库漏洞易被攻击者用于提权或远程代码执行，在等保三级「恶意代码防范」与「漏洞和风险管理」测评中会触发明显扣分。",
            "remediation_advice": "在变更窗口通过受信任软件源执行安全补丁升级（如 dnf upgrade --security），重点优先修复严重级组件并保留更新记录以便复测核销。",
        })
    if db_mw_fails:
        affected_db_assets = "、".join(
            sorted({asset_display_name(str(e.get("asset_id") or ""), lookup, variant="masked") for e in db_mw_fails})
        )
        sample_db = "；".join(str(e.get("title") or "") for e in db_mw_fails[:4])
        critical_risk_analysis.append({
            "risk_title": f"数据库与中间件安全基线存在 {len(db_mw_fails)} 项未通过配置",
            "severity": "高风险",
            "affected_scope": f"涉及资产：{affected_db_assets}；典型问题：{sample_db}",
            "business_impact": "数据库免密认证（如 PostgreSQL trust）、全网监听暴露、缺少 SSL 传输加密或未开启审计插件会直接触发等保三级安全计算环境「身份鉴别」「访问控制」「安全审计」与「数据保密性」高风险扣分。",
            "remediation_advice": "收窄数据库与 Redis 监听地址至内网业务网段、禁用免密认证并统一采用强口令算法、强制启用 TLS/SSL 通信加密及审计日志留存，同时隐藏 Nginx 等中间件版本信息。",
        })
    if baseline_fails:
        affected_os_assets = "、".join(
            sorted({asset_display_name(str(e.get("asset_id") or ""), lookup, variant="masked") for e in baseline_fails})
        )
        sample_base = "；".join(str(e.get("title") or "") for e in baseline_fails[:4])
        critical_risk_analysis.append({
            "risk_title": f"主机安全基线存在 {len(baseline_fails)} 项未通过配置",
            "severity": "高风险",
            "affected_scope": f"涉及资产：{affected_os_assets}；典型问题：{sample_base}",
            "business_impact": "远程 root 登录、弱加密算法、缺少登录失败锁定或宽泛防火墙规则会直接拉低「身份鉴别」「访问控制」与「安全审计」等高风险条款得分。",
            "remediation_advice": "按分部门整改工单中的加固脚本逐项收紧 SSH、PAM 锁定、sudo 授权、auditd 与 firewalld 策略，并在业务低峰验证管理连通性。",
        })
    if tls_fails:
        sample_tls = "；".join(str(e.get("title") or "") for e in tls_fails[:3])
        critical_risk_analysis.append({
            "risk_title": f"HTTPS 传输加密配置存在 {len(tls_fails)} 项薄弱点",
            "severity": "中风险",
            "affected_scope": f"典型问题：{sample_tls}（涉及通信传输保密性与完整性条款）",
            "business_impact": "弱协议、弱密码套件或缺失 HSTS/可信证书可能导致中间人劫持，影响「安全通信网络」与「数据保密性」评定。",
            "remediation_advice": "禁用 TLS 1.0/1.1 与弱套件，启用 TLS 1.2/1.3 与合规证书链，并在反向代理层开启 HSTS 响应头。",
        })
    if not critical_risk_analysis:
        critical_risk_analysis.append({
            "risk_title": "自动化技术面暂未发现严重阻断项，重点关注人工条款完备度",
            "severity": "中风险",
            "affected_scope": f"当前待人工与未评估条款共 {counts.get('pending_manual', 0) + counts.get('not_assessed', 0)} 条",
            "business_impact": "在正式等保测评中，管理制度、运行台账与物理环境同样占重要分值，缺证会导致保守得分偏低。",
            "remediation_advice": "按下方人工核查清单逐项补充制度、演练与审批记录并在工作台完成复核。",
        })

    remediation_roadmap = [
        {
            "phase": "P0 立即阻断（1~3 天）",
            "owner_department": "系统与主机运维 / 网络与边界安全",
            "actions": [
                "优先处理高风险不符合条款对应的主机基线项（禁止 root 远程直连、启用登录失败锁定、收紧 sudo 与防火墙暴露端口）。",
                f"对 {len(critical_cves)} 个严重级及边界暴露相关高危 CVE 安排紧急补丁窗口或在 DefectDojo 中核实受控缓解措施。",
            ],
            "acceptance_criteria": "复测后高风险不符合条款清零，高危暴露端口按最小权限收敛。",
        },
        {
            "phase": "P1 进场前必改（1~2 周）",
            "owner_department": "系统与主机运维 / 应用与研发",
            "actions": [
                "批量完成剩余操作系统高危软件包的补丁升级与服务重启验证，并在漏洞平台闭环处置状态。",
                "完成 HTTPS/TLS 加密协议与证书加固，确保审计日志（auditd/rsyslog）集中留存不少于 180 天。",
            ],
            "acceptance_criteria": "已核查技术条款得分达到 85 分以上，DefectDojo 中高危活跃项基本清零或完成误报核销。",
        },
        {
            "phase": "P2 迎检准备与持续加固（正式测评前）",
            "owner_department": "安全管理与合规",
            "actions": [
                f"完成剩余 {counts.get('pending_manual', 0) + counts.get('not_assessed', 0)} 条人工/未评估条款的线下核对与制度佐证登记。",
                "将最终复测结果同步归档至 CISO Assistant 合规台账，形成迎检备查证据包。",
            ],
            "acceptance_criteria": f"全部 {total} 条条款核查完备度达到 100%，全量保守得分稳定在 80 分以上。",
        },
    ]

    manual_readiness_checklist = [
        "准备网络安全等级保护定级报告、备案证明及最新网络拓扑图（标注安全域与边界防护设备）。",
        "整理安全管理制度体系汇编、年度修订评审记录及信息安全领导小组任命文件。",
        "归集近 6 个月的账号权限审批单、特权操作审计记录、日志备份与留存截图（满足至少 180 天留存）。",
        "准备漏洞扫描、渗透测试与高危漏洞整改闭环工单（可直接附本系统 DefectDojo 导出与分部门工单）。",
        "汇总应急预案、年度应急演练方案与演练总结报告，以及数据备份恢复测试记录。",
        "确认机房物理访问控制、门禁刷卡记录、视频监控留存与消防/供电巡检台账齐备。",
    ]

    path_hint = f"已识别 {len(paths)} 条潜在攻击路径，最高优先级为 {paths[0].get('mitigation_priority', 'P1')}。" if paths else ""
    ciso_summary = (
        f"【等保三级预评估总述】项目「{project.get('name')}」本轮共纳管 {len(assets)} 台资产，覆盖 {total} 条 GB/T 22239-2019 第三级要求。"
        f"当前结论：{verdict}；已核查得分 {checked_score} 分，全量保守得分 {conservative_score} 分，核查完备度 {completeness}%；"
        f"高风险不符合 {high_fail} 项，高风险未关闭 {high_open} 项。"
        f"技术侧发现主机基线未通过 {len(baseline_fails)} 项、操作系统高危/严重 CVE {len(high_cves)} 个、TLS 薄弱项 {len(tls_fails)} 项。{path_hint}"
        f"建议优先由系统运维与网络边界团队在 1~3 天内完成 P0 高风险基线与严重漏洞处置，随后在一两周内完成高危补丁与人工制度佐证补齐，复测达标后再进入正式测评。"
    )

    return {
        "executive_summary": executive_summary,
        "scope_and_methodology": scope_and_methodology,
        "domain_insights": domain_insights,
        "critical_risk_analysis": critical_risk_analysis,
        "remediation_roadmap": remediation_roadmap,
        "manual_readiness_checklist": manual_readiness_checklist,
        "ciso_summary": ciso_summary,
    }
