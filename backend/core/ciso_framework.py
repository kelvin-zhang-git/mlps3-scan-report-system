"""将 GB/T 22239-2019 第三级全量条款库打成 CISO Assistant 可导入的框架包。"""
from __future__ import annotations

import json
from typing import Iterable

from core.clause_catalog import load_clauses as _load_catalog
from core.clause_catalog import normalize_extensions

# 默认常量（通用要求 211 项 v2 框架），供向后兼容引用
LIBRARY_URN = "urn:mlps:risk:library:gbt22239-2019-l3-v2"
FRAMEWORK_URN = "urn:mlps:risk:framework:gbt22239-2019-l3-v2"
FRAMEWORK_REF = "GB-T-22239-2019-L3-V2"


def load_clauses(extensions: Iterable[str] | None = None) -> list[dict]:
    return _load_catalog(extensions)


def framework_spec(extensions: Iterable[str] | None = None) -> dict[str, str]:
    exts = normalize_extensions(extensions)
    has_cloud = "CLOUD" in exts
    suffix = "cloud-v2" if has_cloud else "v2"
    ref_suffix = "CLOUD-V2" if has_cloud else "V2"
    title = (
        "GB/T 22239-2019 第三级（通用 211 项 + 云计算扩展 46 项）"
        if has_cloud
        else "GB/T 22239-2019 第三级（通用要求 211 项）"
    )
    return {
        "library_urn": f"urn:mlps:risk:library:gbt22239-2019-l3-{suffix}",
        "framework_urn": f"urn:mlps:risk:framework:gbt22239-2019-l3-{suffix}",
        "framework_ref": f"GB-T-22239-2019-L3-{ref_suffix}",
        "node_prefix": f"urn:mlps:risk:req_node:gbt22239-2019-l3-{suffix}",
        "filename": f"gbt22239-2019-l3-{suffix}.yaml",
        "title": title,
    }


def build_library_yaml(
    clauses: list[dict] | None = None,
    extensions: Iterable[str] | None = None,
) -> str:
    exts = normalize_extensions(extensions)
    if clauses is None:
        rows = load_clauses(exts if extensions is not None else None)
    else:
        rows = clauses
        if extensions is None and any(str(r.get("extension_type") or "").upper() == "CLOUD" for r in rows):
            exts = normalize_extensions(["GENERAL", "CLOUD"])
    spec = framework_spec(exts)
    node_prefix = spec["node_prefix"]
    lines = [
        f"urn: {spec['library_urn']}",
        "locale: zh",
        f"ref_id: {spec['framework_ref']}",
        "name: " + _q(spec["title"]),
        "description: " + _q(f"对齐 GB/T 22239-2019 第三级标准构建的合规框架（共 {len(rows)} 项要求），条款编号与工作台条款库一致。"),
        "copyright: " + _q("GB/T 22239-2019"),
        "version: 2",
        "publication_date: 2019-05-13",
        "provider: " + _q("等保预评估工作台"),
        "packager: mlps",
        "objects:",
        "  framework:",
        f"    urn: {spec['framework_urn']}",
        f"    ref_id: {spec['framework_ref']}",
        "    name: " + _q(spec["title"]),
        "    description: " + _q(f"按安全域组织的 GB/T 22239-2019 第三级要求（共 {len(rows)} 项）。"),
        "    requirement_nodes:",
        f"    - urn: {node_prefix}:root",
        "      name: " + _q("等保三级"),
        "      assessable: false",
    ]
    domains: dict[str, str] = {}
    for row in rows:
        domain = str(row.get("domain") or "未分类")
        if domain not in domains:
            slug = f"d{len(domains) + 1:02d}"
            domains[domain] = slug
            lines.extend([
                f"    - urn: {node_prefix}:{slug}",
                "      assessable: false",
                "      depth: 1",
                f"      parent_urn: {node_prefix}:root",
                f"      ref_id: {slug}",
                "      name: " + _q(domain),
            ])
        clause_id = str(row["clause_id"])
        node = clause_id.replace(".", "_")
        lines.extend([
            f"    - urn: {node_prefix}:{node}",
            "      assessable: true",
            "      depth: 2",
            f"      parent_urn: {node_prefix}:{domains[domain]}",
            "      ref_id: " + _q(clause_id),
            "      name: " + _q(str(row.get("control_point") or clause_id)),
            "      description: " + _q(str(row.get("requirement_text") or "")),
        ])
    return "\n".join(lines) + "\n"


def _q(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)
