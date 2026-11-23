"""等保三级预评估计分：测评对象覆盖矩阵、加权双口径得分、高风险判例降级与责任部门。"""
from __future__ import annotations

from typing import Any

from core.clause_metadata import OBJECT_LABELS, RISK_WEIGHTS, TECH_OBJECTS

WEIGHT = {
    "compliant": 1.0,
    "partially_compliant": 0.5,
    "non_compliant": 0.0,
}
STATUS_ZH = {
    "compliant": "符合",
    "partially_compliant": "部分符合",
    "non_compliant": "不符合",
    "not_applicable": "不适用",
    "pending_manual": "待人工",
    "not_assessed": "未评估",
}
DEPT_BY_DOMAIN = {
    "安全计算环境": "系统与主机运维",
    "安全通信网络": "网络与边界安全",
    "安全区域边界": "网络与边界安全",
    "云计算安全扩展": "云平台与基础架构",
}
# 不同采集工具能够实测覆盖的技术测评对象类别
TOOL_OBJECT_HINTS: dict[str, tuple[str, ...]] = {
    "ssh_baseline": ("host_os",),
    "trivy_os": ("host_os",),
    "db_baseline": ("database",),
    "mw_baseline": ("middleware",),
    "netdev_config": ("network_device", "security_device"),
    "cloud_audit": ("cloud_platform", "security_device"),
    "nmap": ("host_os", "network_device"),
    "tls_scanner": ("middleware", "application"),
    "nuclei": ("application", "middleware"),
    "ecloud": ("cloud_platform", "security_device"),
    "kubescape": ("cloud_platform",),
    "zap": ("application",),
    "akto": ("application",),
}
# 具备对象层直接配置/基线实测深度的采集器（区别于仅外部端口侧向探测）
DIRECT_EVIDENCE_TOOLS: dict[str, set[str]] = {
    "host_os": {"ssh_baseline", "trivy_os"},
    "database": {"db_baseline"},
    "middleware": {"mw_baseline"},
    "network_device": {"netdev_config"},
    "security_device": {"netdev_config", "cloud_audit", "ecloud"},
    "application": {"nuclei", "zap", "akto"},
    "cloud_platform": {"cloud_audit", "ecloud", "kubescape"},
}


def department_for(domain: str, source_tool: str = "") -> str:
    if source_tool in {"nuclei"}:
        return "应用与研发"
    if domain in DEPT_BY_DOMAIN:
        return DEPT_BY_DOMAIN[domain]
    if "云" in (domain or ""):
        return "云平台与基础架构"
    return "安全管理与合规"


def status_zh(value: str) -> str:
    return STATUS_ZH.get(value or "", value or "未评估")


def compute_object_coverage(
    catalog: list[dict] | None,
    assessments: list[dict],
    assets: list[dict] | None = None,
    evidences: list[dict] | None = None,
) -> dict[str, Any]:
    """按 7 类标准技术测评对象计算资产纳管情况与条款覆盖度，直观揭示单机抽样盲区。"""
    managed_by_obj: dict[str, set[str]] = {k: set() for k, _ in TECH_OBJECTS}
    scanned_by_obj: dict[str, set[str]] = {k: set() for k, _ in TECH_OBJECTS}
    probe_tools_by_obj: dict[str, set[str]] = {k: set() for k, _ in TECH_OBJECTS}
    direct_ev_by_obj: dict[str, int] = {k: 0 for k, _ in TECH_OBJECTS}
    direct_tools_by_obj: dict[str, set[str]] = {k: set() for k, _ in TECH_OBJECTS}

    enabled_assets = [a for a in (assets or []) if a.get("is_enabled", True)]
    asset_obj_map: dict[str, str] = {}
    for asset in enabled_assets:
        obj_type = str(asset.get("object_type") or "host_os")
        if obj_type not in managed_by_obj:
            obj_type = "host_os"
        aid = str(asset.get("asset_id") or "")
        asset_obj_map[aid] = obj_type
        managed_by_obj[obj_type].add(aid)
        # 若数据库/中间件等宿主机资产启用了主机 OS 基线或软件包扫描，同时计入主机操作系统层纳管范围
        scanners = set(asset.get("scanners") or [])
        if obj_type != "host_os" and scanners.intersection({"ssh_baseline", "trivy"}):
            managed_by_obj["host_os"].add(aid)

    direct_assets_by_obj: dict[str, set[str]] = {k: set() for k, _ in TECH_OBJECTS}
    for ev in evidences or []:
        # 采集失败占位记录不计入实测覆盖
        if str(ev.get("evidence_type") or "") == "COLLECT_ERROR":
            continue
        aid = str(ev.get("asset_id") or "")
        tool = str(ev.get("source_tool") or "")
        if aid in asset_obj_map:
            obj_of_asset = asset_obj_map[aid]
            if tool in DIRECT_EVIDENCE_TOOLS.get(obj_of_asset, set()) or obj_of_asset in TOOL_OBJECT_HINTS.get(tool, ()):
                scanned_by_obj[obj_of_asset].add(aid)
        for hinted in TOOL_OBJECT_HINTS.get(tool, ()):
            if hinted in probe_tools_by_obj:
                probe_tools_by_obj[hinted].add(tool)
            if tool in DIRECT_EVIDENCE_TOOLS.get(hinted, set()):
                direct_ev_by_obj[hinted] += 1
                direct_tools_by_obj[hinted].add(tool)
                if aid:
                    direct_assets_by_obj[hinted].add(aid)
                    if aid in managed_by_obj[hinted]:
                        scanned_by_obj[hinted].add(aid)

    assessment_by_clause = {row.get("clause_id"): row for row in assessments}
    items: list[dict[str, Any]] = []
    managed_covered_labels: list[str] = []
    imported_covered_labels: list[str] = []
    partial_labels: list[str] = []
    unmanaged_labels: list[str] = []

    for obj_key, obj_label in TECH_OBJECTS:
        relevant_clauses = [
            c for c in (catalog or [])
            if obj_key in (c.get("applicable_objects") or [])
        ]
        if not relevant_clauses:
            continue
        decided_clauses = 0
        non_compliant_clauses = 0
        for clause in relevant_clauses:
            row = assessment_by_clause.get(clause.get("clause_id"))
            status = (row or {}).get("final_status") or "not_assessed"
            if status in {"compliant", "partially_compliant", "non_compliant", "not_applicable"}:
                decided_clauses += 1
            if status == "non_compliant":
                non_compliant_clauses += 1

        managed_cnt = len(managed_by_obj[obj_key])
        scanned_cnt = len(scanned_by_obj[obj_key])
        probe_tools = sorted(probe_tools_by_obj[obj_key])
        direct_ev_cnt = direct_ev_by_obj[obj_key]
        direct_tools = sorted(direct_tools_by_obj[obj_key])

        # 业务应用类条款达 35 条，若未独立纳管且仅获得 1~2 条零星 Web 模板命中，不判定为“已覆盖”
        weak_unmanaged_app = obj_key == "application" and managed_cnt == 0 and 0 < direct_ev_cnt < 3

        if scanned_cnt > 0:
            status_code = "covered"
            status_label = "已纳管实测"
            if direct_ev_cnt > 0:
                note = f"已纳管 {managed_cnt} 个对象（实测 {scanned_cnt} 个），通过 {'/'.join(direct_tools)} 采集 {direct_ev_cnt} 条实测基线/漏洞证据（涉及 {len(relevant_clauses)} 条要求）。"
            else:
                note = f"已纳管 {managed_cnt} 个对象并采集实测证据（本类涉及 {len(relevant_clauses)} 条要求）。"
            managed_covered_labels.append(obj_label)
        elif direct_ev_cnt > 0 and not weak_unmanaged_app:
            status_code = "covered"
            status_label = "已采集/导入（未独立纳管）"
            note = f"未独立登记该类资产，但已通过 {'/'.join(direct_tools)} 获取 {direct_ev_cnt} 条对象层配置/基线证据（涉及 {len(relevant_clauses)} 条要求），建议后续补充独立资产台账。"
            imported_covered_labels.append(obj_label)
        elif weak_unmanaged_app:
            status_code = "partial"
            status_label = "覆盖不足（少量扫描线索）"
            note = f"未独立纳管业务应用，仅通过 {'/'.join(direct_tools)} 命中 {direct_ev_cnt} 条外部扫描线索，远不足以覆盖所涉 {len(relevant_clauses)} 条要求，存在明显盲区。"
            partial_labels.append(obj_label)
        elif managed_cnt > 0:
            status_code = "partial"
            status_label = "已纳管待采集"
            note = f"已登记 {managed_cnt} 个资产，但本轮尚未形成该对象的有效实测证据。"
            partial_labels.append(obj_label)
        elif probe_tools:
            status_code = "partial"
            status_label = "仅侧向探测"
            note = f"未独立纳管该类资产，仅通过 {'/'.join(probe_tools)} 获取少量外部探测线索，存在覆盖盲区。"
            partial_labels.append(obj_label)
        else:
            status_code = "unmanaged"
            status_label = "尚未纳管"
            note = f"尚未纳管{obj_label}，涉及的 {len(relevant_clauses)} 条要求目前缺少该对象层实测证据。"
            unmanaged_labels.append(obj_label)

        items.append({
            "object_key": obj_key,
            "object_label": obj_label,
            "managed_assets": managed_cnt,
            "scanned_assets": scanned_cnt,
            "applicable_clauses": len(relevant_clauses),
            "decided_clauses": decided_clauses,
            "non_compliant_clauses": non_compliant_clauses,
            "probe_tools": probe_tools,
            "direct_evidence_count": direct_ev_cnt,
            "status": status_code,
            "status_label": status_label,
            "note": note,
        })

    parts: list[str] = []
    if managed_covered_labels:
        parts.append(f"已纳管实测：{'、'.join(managed_covered_labels)}")
    if imported_covered_labels:
        parts.append(f"已采集/导入（未独立纳管）：{'、'.join(imported_covered_labels)}")
    if partial_labels:
        parts.append(f"覆盖不足/仅侧向探测：{'、'.join(partial_labels)}")
    if unmanaged_labels:
        parts.append(f"尚未纳管（存在盲区）：{'、'.join(unmanaged_labels)}")
    summary = "；".join(parts) + "。" if parts else "当前项目尚未纳管技术测评对象。"
    return {
        "items": items,
        "covered_count": len(managed_covered_labels) + len(imported_covered_labels),
        "partial_count": len(partial_labels),
        "unmanaged_count": len(unmanaged_labels),
        "total_object_types": len(items),
        "summary": summary,
    }


def score_assessments(
    rows: list[dict],
    catalog: list[dict] | None = None,
    *,
    assets: list[dict] | None = None,
    evidences: list[dict] | None = None,
) -> dict[str, Any]:
    by_id = {item.get("clause_id"): item for item in (catalog or [])}
    counts = {key: 0 for key in ("compliant", "partially_compliant", "non_compliant", "not_applicable", "pending_manual", "not_assessed")}
    high_fail = 0
    high_open = 0
    direct_high_fail = 0
    direct_high_open = 0
    mitigated_high_count = 0

    weighted_earned = 0.0
    weighted_done_total = 0.0
    weighted_all_applicable = 0.0
    risk_breakdown: dict[str, dict[str, Any]] = {
        level: {
            "level": level,
            "label": {"high": "高风险（权重 3）", "medium": "中风险（权重 2）", "low": "低风险（权重 1）"}[level],
            "weight": RISK_WEIGHTS[level],
            "total": 0,
            "compliant": 0,
            "partially_compliant": 0,
            "non_compliant": 0,
            "pending": 0,
            "mitigated": 0,
        }
        for level in ("high", "medium", "low")
    }

    domains: dict[str, dict] = {}
    for clause in catalog or []:
        bucket = domains.setdefault(clause.get("domain") or "未归类", _empty_domain(clause.get("domain") or "未归类"))
        bucket["total"] += 1

    seen_clause_ids: set[str] = set()
    for row in rows:
        cid = row.get("clause_id") or ""
        seen_clause_ids.add(cid)
        status = row.get("final_status") or "not_assessed"
        if status not in counts:
            status = "not_assessed"
        counts[status] += 1
        meta = by_id.get(cid, {})
        domain = meta.get("domain") or row.get("domain") or "未归类"
        bucket = domains.setdefault(domain, _empty_domain(domain))
        if catalog is None:
            bucket["total"] += 1
        bucket[status] = bucket.get(status, 0) + 1

        is_high = bool(row.get("is_high_risk") or meta.get("high_risk"))
        comp_status = str(row.get("compensation_status") or "none")
        is_mitigated = is_high and comp_status == "mitigated" and status in {"non_compliant", "partially_compliant"}
        if is_mitigated:
            mitigated_high_count += 1
            bucket["mitigated_high"] += 1

        weight_level = str(meta.get("risk_weight_level") or ("high" if is_high else "medium"))
        if weight_level not in risk_breakdown:
            weight_level = "medium"
        # 高风险项经有效补偿控制降级后，扣分权重按中风险（2.0）折算，贴近测评机构判例缓解规则
        effective_weight = RISK_WEIGHTS["medium"] if is_mitigated else float(meta.get("risk_weight") or RISK_WEIGHTS[weight_level])

        rb = risk_breakdown[weight_level]
        rb["total"] += 1
        if status in {"compliant", "partially_compliant", "non_compliant"}:
            rb[status] += 1
            weighted_done_total += effective_weight
            weighted_earned += effective_weight * WEIGHT[status]
            weighted_all_applicable += effective_weight
            bucket["weighted_done"] += effective_weight
            bucket["weighted_earned"] += effective_weight * WEIGHT[status]
            bucket["weighted_applicable"] += effective_weight
        elif status in {"pending_manual", "not_assessed"}:
            rb["pending"] += 1
            weighted_all_applicable += effective_weight
            bucket["weighted_applicable"] += effective_weight
        if is_mitigated:
            rb["mitigated"] += 1

        if is_high:
            bucket["high_total"] += 1
            if status in {"non_compliant", "partially_compliant", "pending_manual", "not_assessed"}:
                high_open += 1
                bucket["high_open"] += 1
                if not is_mitigated:
                    direct_high_open += 1
            if status == "non_compliant":
                high_fail += 1
                if not is_mitigated:
                    direct_high_fail += 1
                    bucket["direct_high_fail"] += 1

    # 当尚无评估行但提供了 catalog 时，补齐未评估条款的加权分母
    if catalog and not rows:
        for clause in catalog:
            wl = str(clause.get("risk_weight_level") or ("high" if clause.get("high_risk") else "medium"))
            if wl not in risk_breakdown:
                wl = "medium"
            risk_breakdown[wl]["total"] += 1
            risk_breakdown[wl]["pending"] += 1
            weighted_all_applicable += float(clause.get("risk_weight") or RISK_WEIGHTS[wl])

    total = len(rows) or sum(item["total"] for item in domains.values()) or 0
    decided = counts["compliant"] + counts["partially_compliant"] + counts["non_compliant"] + counts["not_applicable"]
    applicable_done = counts["compliant"] + counts["partially_compliant"] + counts["non_compliant"]
    earned = counts["compliant"] * 1.0 + counts["partially_compliant"] * 0.5
    applicable_all = max(total - counts["not_applicable"], 0)

    checked_score = round(earned / applicable_done * 100, 1) if applicable_done else 0.0
    conservative = round(earned / applicable_all * 100, 1) if applicable_all else 0.0
    weighted_checked_score = round(weighted_earned / weighted_done_total * 100, 1) if weighted_done_total else 0.0
    weighted_conservative_score = round(weighted_earned / weighted_all_applicable * 100, 1) if weighted_all_applicable else 0.0
    completeness = round(decided / total * 100, 1) if total else 0.0
    verdict = _verdict(completeness, weighted_conservative_score, direct_high_fail, mitigated_high_count)

    for bucket in domains.values():
        done = bucket["compliant"] + bucket["partially_compliant"] + bucket["non_compliant"]
        points = bucket["compliant"] + bucket["partially_compliant"] * 0.5
        applicable = max(bucket["total"] - bucket["not_applicable"], 0)
        decided_d = done + bucket["not_applicable"]
        bucket["pending"] = bucket["pending_manual"] + bucket["not_assessed"]
        bucket["completeness"] = round(decided_d / bucket["total"] * 100, 1) if bucket["total"] else 0.0
        bucket["score"] = round(points / applicable * 100, 1) if applicable else 0.0
        bucket["checked_score"] = round(points / done * 100, 1) if done else 0.0
        bucket["weighted_checked_score"] = (
            round(bucket["weighted_earned"] / bucket["weighted_done"] * 100, 1)
            if bucket["weighted_done"] else 0.0
        )
        bucket["weighted_score"] = (
            round(bucket["weighted_earned"] / bucket["weighted_applicable"] * 100, 1)
            if bucket["weighted_applicable"] else 0.0
        )

    object_coverage = compute_object_coverage(catalog, rows, assets, evidences)

    return {
        "counts": counts,
        "clause_total": total,
        "completeness": completeness,
        "checked_score": checked_score,
        "conservative_score": conservative,
        "weighted_checked_score": weighted_checked_score,
        "weighted_conservative_score": weighted_conservative_score,
        "coverage": completeness,
        "pending_manual": counts["pending_manual"] + counts["not_assessed"],
        "compliant": counts["compliant"],
        "high_open": high_open,
        "high_fail": high_fail,
        "direct_high_fail": direct_high_fail,
        "direct_high_open": direct_high_open,
        "mitigated_high_count": mitigated_high_count,
        "risk_breakdown": list(risk_breakdown.values()),
        "object_coverage": object_coverage,
        "verdict": verdict["code"],
        "verdict_label": verdict["label"],
        "verdict_advice": verdict["advice"],
        "domains": list(domains.values()),
    }


def priority_for(row: dict) -> str:
    status = row.get("final_status") or ""
    severity = (row.get("severity") or "").lower()
    comp_status = str(row.get("compensation_status") or "none")
    if row.get("is_high_risk") and status == "non_compliant" and comp_status != "mitigated":
        return "P0"
    if severity in {"critical", "high"} or status == "non_compliant":
        return "P1"
    if status == "partially_compliant" or severity in {"medium", "low"}:
        return "P2"
    return "P3"


def _verdict(
    completeness: float,
    weighted_conservative: float,
    direct_high_fail: int,
    mitigated_high_count: int = 0,
) -> dict[str, str]:
    mitigated_tip = f"（另有 {mitigated_high_count} 项高风险已登记补偿控制降级，仍建议在正式测评前完成根本整改）" if mitigated_high_count else ""
    if completeness < 100:
        return {
            "code": "incomplete",
            "label": "核查未完成",
            "advice": f"当前仍有待人工或未评估条款，需补齐证据后再形成最终迎检结论{mitigated_tip}。",
        }
    if weighted_conservative < 70 or direct_high_fail > 0:
        return {
            "code": "not_ready",
            "label": "暂未达到等保三级要求",
            "advice": f"存在 {direct_high_fail} 项直接高风险不符合项，需优先关闭阻断项并完成复测{mitigated_tip}。",
        }
    if weighted_conservative < 80:
        return {
            "code": "needs_retest",
            "label": "基本接近，需整改后复测",
            "advice": f"直接高风险不符合项已清零，建议将风险加权得分提升至 80 分以上再安排进场{mitigated_tip}。",
        }
    label = "达到预评估进场条件" if weighted_conservative < 90 else "预评估结果优良"
    return {"code": "ready", "label": label, "advice": f"可以整理证据包，进入正式测评准备{mitigated_tip}。"}


def _empty_domain(name: str) -> dict[str, Any]:
    return {
        "domain": name,
        "total": 0,
        "compliant": 0,
        "partially_compliant": 0,
        "non_compliant": 0,
        "not_applicable": 0,
        "pending_manual": 0,
        "not_assessed": 0,
        "high_total": 0,
        "high_open": 0,
        "direct_high_fail": 0,
        "mitigated_high": 0,
        "weighted_earned": 0.0,
        "weighted_done": 0.0,
        "weighted_applicable": 0.0,
    }
