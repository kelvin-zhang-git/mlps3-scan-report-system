"""差距报告渲染：HTML/PDF、中文 Word 终版（.docx）与分部门整改工单。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor
from jinja2 import Environment, FileSystemLoader, select_autoescape

from core.cve_links import linkify_cves_html, linkify_cves_md
from core.settings import report_dir

BRAND_RED = RGBColor(0xC8, 0x10, 0x2E)
DARK_TEXT = RGBColor(0x11, 0x18, 0x27)
MUTED_TEXT = RGBColor(0x4B, 0x55, 0x63)


def render_report(context: dict, variant: str) -> tuple[str, Path]:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape(["html"]))
    env.filters["cve_links"] = linkify_cves_html
    html = env.get_template("gap_report.html.j2").render(**context, variant=variant)
    filename = f"{context['job_id']}-{variant}.html"
    path = report_dir() / filename
    path.write_text(html, encoding="utf-8")
    pdf_name = filename.replace(".html", ".pdf")
    pdf_path = report_dir() / pdf_name
    try:
        from weasyprint import HTML

        HTML(string=html, base_url=str(template_dir)).write_pdf(pdf_path)
        return pdf_name, pdf_path
    except Exception:
        return filename, path


def render_tickets(context: dict) -> tuple[str, Path]:
    template_dir = Path(__file__).resolve().parents[1] / "templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=False)
    env.filters["cve_links_md"] = linkify_cves_md
    text = env.get_template("remediation_tickets.md.j2").render(**context)
    filename = f"{context['job_id']}-tickets.md"
    path = report_dir() / filename
    path.write_text(text, encoding="utf-8")
    return filename, path


def render_docx_report(context: dict[str, Any], variant: str) -> tuple[str, Path]:
    """生成带 AI 专业解读、双口径评分、安全域剖析与分阶段整改路线的中文 Word 报告。"""
    doc = Document()
    _configure_styles(doc)

    project = context["project"]
    score = context["score"]
    narrative = context.get("narrative") or {}
    sections = narrative.get("sections") or {}
    assets = context.get("assets") or []
    host_summary = context.get("host_summary") or []
    db_mw_rows = context.get("db_mw_rows") or []
    cves = context.get("cves") or []
    tls_rows = context.get("tls_rows") or []
    departments = context.get("departments") or []
    assessments = context.get("assessments") or []
    paths = context.get("paths") or []
    counts = score.get("counts") or {}
    variant_label = "受控还原版（限内部运维使用）" if variant == "restored" else "脱敏对外汇报版"

    # 封面标题区
    eyebrow = doc.add_paragraph()
    run_eye = eyebrow.add_run(f"GB/T 22239-2019 网络安全等级保护第三级 · {variant_label}")
    run_eye.font.size = Pt(10)
    run_eye.font.bold = True
    run_eye.font.color.rgb = BRAND_RED

    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(4)
    title_p.paragraph_format.space_after = Pt(6)
    run_title = title_p.add_run(f"{project.get('name', '等保三级评估项目')} — 预评估差距与专业研判报告")
    run_title.font.size = Pt(20)
    run_title.font.bold = True
    run_title.font.color.rgb = DARK_TEXT

    if project.get("summary"):
        sub_p = doc.add_paragraph(str(project["summary"]))
        sub_p.runs[0].font.color.rgb = MUTED_TEXT

    # 项目元信息概览表
    report_meta = context.get("report_meta") or {}
    ai_source = (
        f"AI 专业研判（模型：{narrative.get('model_id') or '未记录'}，提示词 v{narrative.get('prompt_version') or 1}）"
        if narrative.get("status") == "ai"
        else f"规则研判（提示词 v{narrative.get('prompt_version') or 1}）"
    )
    meta_rows = [
        ("项目名称", str(project.get("name") or "")),
        ("任务批次", str(context.get("job_id") or "")),
        ("报告版本", variant_label),
        ("定级与密级", f"{report_meta.get('grade_spec') or project.get('classification') or '等保三级'} / {project.get('env_tier') or ''}"),
        ("评估时间", str(report_meta.get("assessed_at") or "—")),
        ("采集视角与范围", str(report_meta.get("scanner_origin") or "内网只读采集")),
        ("预评估结论", f"{score.get('verdict_label') or ''}（已核查 {score.get('checked_score', 0)} 分 / 全量保守 {score.get('conservative_score', 0)} 分）"),
        ("研判引擎", ai_source),
    ]
    if report_meta.get("tools_used"):
        meta_rows.append(("本轮采集工具", "、".join(report_meta["tools_used"])))
    _add_kv_table(doc, meta_rows)

    # 一、管理层执行摘要与专业研判
    _add_heading(doc, "一、管理层执行摘要与迎检研判", level=1)
    _add_paragraphs(doc, str(sections.get("executive_summary") or score.get("verdict_advice") or ""))

    # 双口径与风险加权指标摘要表
    direct_high_fail = score.get("direct_high_fail") if score.get("direct_high_fail") is not None else score.get("high_fail", 0)
    mitigated_high = score.get("mitigated_high_count", 0)
    hr_note = "对照 T/ISEAA 001-2020 区分直接高风险阻断项与存在有效补偿措施的降级项"
    if float(score.get("completeness") or 0) < 100:
        hr_note += "（直接高风险仅统计已判定条款）"
    _add_styled_table(
        doc,
        ["核心指标", "当前结果", "指标说明"],
        [
            ["预评估结论", str(score.get("verdict_label") or ""), str(score.get("verdict_advice") or "")],
            ["核查完备度", f"{score.get('completeness', 0)}%", f"共 {score.get('clause_total', 0)} 条要求，待人工 {counts.get('pending_manual', 0)} 条、未评估 {counts.get('not_assessed', 0)} 条"],
            ["风险加权得分（对标测评扣分）", f"已核查 {score.get('weighted_checked_score', score.get('checked_score', 0))} 分 / 保守 {score.get('weighted_conservative_score', score.get('conservative_score', 0))} 分", "按高风险（权重 3）、中风险（权重 2）、低风险（权重 1）折算；高风险补偿降级项按权重 2 计扣"],
            ["等权双口径得分（参考）", f"已核查 {score.get('checked_score', 0)} 分 / 保守 {score.get('conservative_score', 0)} 分", f"符合 {counts.get('compliant', 0)} / 部分符合 {counts.get('partially_compliant', 0)} / 不符合 {counts.get('non_compliant', 0)} / 不适用 {counts.get('not_applicable', 0)}"],
            ["高风险判例态势", f"直接高风险不符合 {direct_high_fail} 项 · 已补偿降级 {mitigated_high} 项 · 未关闭 {score.get('high_open', 0)} 项", hr_note],
        ],
    )
    _add_paragraphs(
        doc,
        "严重度与风险口径说明：本报告采用三层标准口径——① 技术证据采用 5 级严重度（严重/高危/中危/低危/信息，漏洞参照 CVSS 与发行版公告）；② 第 4 章风险研判卡采用综合研判等级（高风险/中风险）；③ 等保高风险判例严格对照 T/ISEAA 001-2020 认定（经补偿控制降级后按中风险计扣）。",
    )

    # 二、核查范围、方法与边界声明
    _add_heading(doc, "二、核查范围、采集手段与边界声明", level=1)
    _add_paragraphs(doc, str(sections.get("scope_and_methodology") or ""))
    obj_cov = score.get("object_coverage") or {}
    obj_items = obj_cov.get("items") or []
    if obj_items:
        _add_heading(doc, "2.1 测评对象覆盖矩阵（防止单机抽样假象）", level=2)
        if obj_cov.get("summary"):
            _add_paragraphs(doc, str(obj_cov["summary"]))
        _add_styled_table(
            doc,
            ["测评对象类别", "纳管/实测资产", "涉及条款", "覆盖状态", "边界与盲区说明"],
            [
                [
                    str(item.get("object_label") or ""),
                    f"{item.get('managed_assets', 0)} / {item.get('scanned_assets', 0)}",
                    f"{item.get('decided_clauses', 0)} / {item.get('applicable_clauses', 0)}",
                    str(item.get("status_label") or ""),
                    str(item.get("note") or ""),
                ]
                for item in obj_items
            ],
        )
    if assets:
        _add_heading(doc, "2.2 本轮纳管资产对照表", level=2)
        if variant == "restored":
            _add_paragraphs(
                doc,
                "说明：本报告为受控还原版（仅限内部运维与等保整改团队使用），下表已将脱敏可读代号还原为真实主机地址，正文及明细表均按「可读代号（真实地址）」标注。",
            )
        else:
            _add_paragraphs(
                doc,
                "说明：本报告为对外脱敏汇报版，已隐藏真实内网 IP 地址；正文及附表统一采用「安全域-对象序号」可读代号（如「应用域-主机01」「数据库域-数据库主机01」）。内部运维定位与整改请查阅受控还原版。",
            )
        from core.clause_metadata import OBJECT_LABELS

        _add_styled_table(
            doc,
            ["可读代号", "测评对象类别", "主机地址 / 占位", "所属安全域", "操作系统与用途说明", "核查模式", "系统编号"],
            [
                [
                    str(a.get("restored_label") if variant == "restored" else a.get("masked_label") or a.get("asset_id") or ""),
                    str(a.get("object_label") or OBJECT_LABELS.get(str(a.get("object_type") or "host_os"), "主机操作系统")),
                    str(a.get("host") if variant == "restored" else a.get("masked_host_placeholder") or "已脱敏"),
                    str(a.get("zone_label") or a.get("security_zone") or ""),
                    f"{a.get('os_label') or a.get('os_type') or ''}；{a.get('role_note_restored') if variant == 'restored' else a.get('role_note_masked') or ''}".strip("；"),
                    str(a.get("scan_mode_label") or a.get("scan_mode") or ""),
                    str(a.get("asset_id") or ""),
                ]
                for a in assets
            ],
        )

    # 三、各安全域核查进度与深度剖析
    _add_heading(doc, "三、各安全域核查进度与差距剖析", level=1)
    domain_rows = [
        [
            str(d.get("domain") or ""),
            str(d.get("total") or 0),
            f"{d.get('completeness', 0)}%",
            f"{d.get('checked_score', d.get('score', 0))} 分",
            str(d.get("pending_manual") if d.get("pending_manual") is not None else d.get("pending", 0)),
            str(d.get("not_assessed") or 0),
            str(d.get("high_open") or 0),
        ]
        for d in (score.get("domains") or [])
    ]
    if domain_rows:
        _add_styled_table(doc, ["安全域", "条款数", "核查完备度", "已核查得分", "待人工", "未评估", "高风险未关闭"], domain_rows)

    domain_insights = sections.get("domain_insights") or []
    if domain_insights:
        _add_heading(doc, "3.1 安全域专业研判", level=2)
        for item in domain_insights:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(6)
            p.paragraph_format.space_after = Pt(2)
            r_head = p.add_run(f"【{item.get('domain', '')}】{item.get('status_summary', '')}")
            r_head.bold = True
            r_head.font.color.rgb = DARK_TEXT
            _add_bullet(doc, f"主要缺口：{item.get('key_gaps', '')}")
            _add_bullet(doc, f"优先动作：{item.get('priority_action', '')}")

    # 四、关键高危风险与技术核查发现解读
    _add_heading(doc, "四、关键高危风险与技术发现解读", level=1)
    direct_hr = context.get("direct_high_risk_rows") or []
    mitigated_hr = context.get("mitigated_high_risk_rows") or []
    if direct_hr or mitigated_hr:
        _add_heading(doc, "4.0 高风险判例分类与补偿控制评估（对照 T/ISEAA 001-2020）", level=2)
        hr_rows = []
        for item in direct_hr[:25]:
            prec = item.get("high_risk_precedent") or {}
            hr_rows.append([
                str(item.get("clause_id") or ""),
                "直接高风险（阻断）",
                str(prec.get("category") or item.get("control_point") or ""),
                "、".join(item.get("applicable_object_labels") or []),
                str(item.get("status_zh") or ""),
                str(prec.get("trigger_condition") or item.get("ai_rationale") or "")[:120],
            ])
        for item in mitigated_hr[:20]:
            prec = item.get("high_risk_precedent") or {}
            hr_rows.append([
                str(item.get("clause_id") or ""),
                "已补偿降级",
                str(prec.get("category") or item.get("control_point") or ""),
                "、".join(item.get("applicable_object_labels") or []),
                str(item.get("status_zh") or ""),
                str(item.get("compensation_note") or "已登记有效补偿控制措施并按中风险跟踪")[:120],
            ])
        _add_styled_table(
            doc,
            ["条款编号", "判例性质", "T/ISEAA 判例类别", "适用对象", "结论", "判定/补偿说明"],
            hr_rows,
        )
    for risk in sections.get("critical_risk_analysis") or []:
        p = doc.add_paragraph()
        p.paragraph_format.space_before = Pt(6)
        p.paragraph_format.space_after = Pt(2)
        r_title = p.add_run(f"[{risk.get('severity', '高风险')}] {risk.get('risk_title', '')}")
        r_title.bold = True
        r_title.font.color.rgb = BRAND_RED if "高" in str(risk.get("severity") or "") else DARK_TEXT
        if risk.get("affected_scope"):
            _add_bullet(doc, f"影响范围与依据：{risk['affected_scope']}")
        if risk.get("business_impact"):
            _add_bullet(doc, f"安全与测评影响：{risk['business_impact']}")
        if risk.get("remediation_advice"):
            _add_bullet(doc, f"整改建议：{risk['remediation_advice']}")

    _add_heading(doc, "4.1 主机、数据库与中间件安全基线汇总", level=2)
    if host_summary:
        _add_styled_table(
            doc,
            ["受测资产", "主机基线状态", "主机基线通过", "主机基线未通过", "数据库/中间件通过", "数据库/中间件未通过"],
            [
                [
                    str(h.get("asset_display") or h.get("asset_id") or ""),
                    str(h.get("ssh_status") or "已采集"),
                    str(h.get("passed", 0)),
                    str(h.get("failed", 0)),
                    str(h.get("db_mw_passed", 0)),
                    str(h.get("db_mw_failed", 0)),
                ]
                for h in host_summary
            ],
        )
    else:
        doc.add_paragraph("本轮未采集到主机或数据库/中间件只读基线结果。")

    collect_errors = context.get("collect_errors") or []
    if collect_errors:
        _add_paragraphs(doc, "采集异常提示（局部盲区，不计入通过或基线失败）：")
        for err in collect_errors:
            _add_bullet(
                doc,
                f"{err.get('asset_display') or err.get('asset_id', '')}（{err.get('source_tool', '')}）：{err.get('title', '')} {err.get('detail_text') or ''}".strip(),
            )

    if db_mw_rows:
        _add_heading(doc, f"4.1.1 数据库与中间件基线核查明细（共 {len(db_mw_rows)} 条）", level=2)
        _add_styled_table(
            doc,
            ["受测资产", "对象层", "严重度", "核查结果", "检查项"],
            [
                [
                    str(r.get("asset_display") or r.get("asset_id") or ""),
                    "数据库" if r.get("source_tool") == "db_baseline" else "中间件",
                    str(r.get("severity_zh") or r.get("severity") or ""),
                    "通过" if r.get("evidence_type") == "BASELINE_PASS" else "未通过",
                    str(r.get("title") or ""),
                ]
                for r in db_mw_rows[:40]
            ],
        )

    open_ports = context.get("open_ports") or []
    if open_ports:
        _add_heading(doc, f"4.1.2 开放端口与服务暴露清单（Nmap，共 {len(open_ports)} 项）", level=2)
        _add_styled_table(
            doc,
            ["受测资产", "端口", "识别服务与暴露说明"],
            [
                [
                    str(p.get("asset_display") or p.get("asset_id") or ""),
                    str(p.get("port") or "—"),
                    str(p.get("title") or ""),
                ]
                for p in open_ports[:40]
            ],
        )

    if tls_rows:
        _add_heading(doc, "4.2 传输加密（TLS/HTTPS）检测明细", level=2)
        for row in tls_rows[:20]:
            _add_bullet(
                doc,
                f"{row.get('asset_display') or row.get('asset_id', '')} · [{row.get('severity_zh') or row.get('severity', '')}] {row.get('title', '')}",
            )

    unique_cve_count = context.get("unique_cve_count") or len({str(c.get("cve_or_cwe") or "") for c in cves if c.get("cve_or_cwe")})
    _add_heading(
        doc,
        f"4.3 操作系统高危及严重漏洞清单（共 {len(cves)} 条实例，去重 {unique_cve_count} 个 CVE，展示前 40 条）",
        level=2,
    )
    if cves:
        _add_styled_table(
            doc,
            ["受测资产", "受影响软件包", "已装版本 / 修复版本", "CVE 编号", "CVSS / 严重度"],
            [
                [
                    str(c.get("asset_display") or c.get("asset_id") or ""),
                    ", ".join(c.get("affected_pkgs") or []) or str(c.get("pkg_name") or c.get("title") or ""),
                    f"{c.get('installed_version') or '—'} → {c.get('fixed_version') or '暂无修复'}",
                    str(c.get("cve_or_cwe") or "—"),
                    f"{c.get('cvss_score') if c.get('cvss_score') is not None else '—'} / {c.get('severity_zh') or c.get('severity') or ''}",
                ]
                for c in cves[:40]
            ],
        )
    else:
        doc.add_paragraph("本轮未归集到高危或严重级别的操作系统软件包漏洞。")

    if paths:
        _add_heading(doc, "4.4 潜在攻击路径推演", level=2)
        for path in paths:
            p = doc.add_paragraph()
            p.paragraph_format.space_before = Pt(4)
            run = p.add_run(f"{path.get('mitigation_priority', '')} · {path.get('title', '')}")
            run.bold = True
            if path.get("precondition"):
                _add_paragraphs(doc, f"推演前提：{path['precondition']}")
            for idx, step in enumerate(path.get("steps") or [], start=1):
                _add_bullet(doc, f"步骤 {idx}：{step}")

    # 五、分阶段整改路线图与责任分工
    _add_heading(doc, "五、分阶段整改路线图与迎检准备", level=1)
    roadmap = sections.get("remediation_roadmap") or []
    if roadmap:
        _add_styled_table(
            doc,
            ["阶段与周期", "牵头部门", "关键整改动作", "复测验收标准"],
            [
                [
                    str(r.get("phase") or ""),
                    str(r.get("owner_department") or ""),
                    "\n".join(f"• {a}" for a in (r.get("actions") or [])),
                    str(r.get("acceptance_criteria") or ""),
                ]
                for r in roadmap
            ],
        )

    checklist = sections.get("manual_readiness_checklist") or []
    if checklist:
        _add_heading(doc, "5.1 人工核查与迎检材料准备清单", level=2)
        for item in checklist:
            _add_bullet(doc, str(item))

    # 六、分部门差距与加固指引
    _add_heading(doc, "六、分部门差距明细与整改建议", level=1)
    if departments:
        for dept in departments:
            tech_list = dept.get("tech_items") if dept.get("tech_items") is not None else (dept.get("items") or [])
            manual_list = dept.get("manual_items") or []
            _add_heading(
                doc,
                f"{dept.get('name') or '未分配部门'}（技术差距 {len(tech_list)} 项"
                + (f" · 待人工 {len(manual_list)} 项" if manual_list else "")
                + "）",
                level=2,
            )
            if tech_list:
                _add_styled_table(
                    doc,
                    ["优先级", "条款与控制点", "结论状态", "差距说明"],
                    [
                        [
                            str(row.get("priority") or ""),
                            f"{row.get('clause_id', '')} {row.get('control_point', '')}".strip(),
                            str(row.get("status_zh") or ""),
                            str(row.get("ai_rationale") or "")[:320],
                        ]
                        for row in tech_list
                    ],
                )
            if manual_list:
                sample = "、".join(
                    f"{row.get('clause_id', '')}（{row.get('control_point', '')}）" for row in manual_list[:20]
                )
                suffix_txt = f" 等共 {len(manual_list)} 条（详见附录全表）。" if len(manual_list) > 20 else "。"
                _add_paragraphs(doc, f"待人工线下核查条款（P3）：{sample}{suffix_txt}")
    else:
        doc.add_paragraph("当前没有待分派的不符合、部分符合或待人工条款。")

    # 附录：GB/T 22239-2019 第三级条款评估全表
    _add_heading(doc, f"附录一：GB/T 22239-2019 第三级条款评估明细（共 {len(assessments)} 条）", level=1)
    _add_styled_table(
        doc,
        ["条款编号", "安全域 / 控制点", "评定状态", "核查依据与说明", "关联证据"],
        [
            [
                f"{row.get('clause_id', '')}{'（高风险）' if row.get('is_high_risk') else ''}",
                f"{row.get('domain', '')} / {row.get('control_point', '')}".strip(" /"),
                str(row.get("status_zh") or ""),
                str(row.get("ai_rationale") or "")[:240],
                ", ".join((row.get("evidence_ids") or [])[:4]) or "—",
            ]
            for row in assessments
        ],
    )

    rem_scripts = context.get("remediation_scripts") or []
    if rem_scripts:
        _add_heading(doc, "附录二：技术加固参考脚本（含前置检查与回滚说明）", level=1)
        for item in rem_scripts:
            clauses_str = "、".join((item.get("clauses") or [])[:8])
            _add_heading(doc, f"{item.get('title', '安全加固参考')}（关联条款：{clauses_str}）", level=2)
            _add_paragraphs(doc, str(item.get("script") or ""))

    suffix = "restored" if variant == "restored" else "masked"
    filename = f"{context['job_id']}-mlps3-report-{suffix}.docx"
    path = report_dir() / filename
    doc.save(path)
    return filename, path


def _configure_styles(doc: Document) -> None:
    for section in doc.sections:
        section.top_margin = Inches(0.8)
        section.bottom_margin = Inches(0.8)
        section.left_margin = Inches(0.75)
        section.right_margin = Inches(0.75)
    normal = doc.styles["Normal"]
    normal.font.name = "Microsoft YaHei"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = DARK_TEXT
    rpr = normal.element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.append(rfonts)
    rfonts.set(qn("w:eastAsia"), "Microsoft YaHei")


def _add_heading(doc: Document, text: str, level: int = 1) -> None:
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12 if level == 1 else 8)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold = True
    run.font.size = Pt(14 if level == 1 else 11.5)
    run.font.color.rgb = BRAND_RED if level == 1 else DARK_TEXT


def _add_paragraphs(doc: Document, text: str) -> None:
    for block in (text or "").split("\n"):
        cleaned = block.strip()
        if cleaned:
            p = doc.add_paragraph(cleaned)
            p.paragraph_format.space_after = Pt(4)
            p.paragraph_format.line_spacing = 1.3


def _add_bullet(doc: Document, text: str) -> None:
    p = doc.add_paragraph(f"• {text}")
    p.paragraph_format.left_indent = Inches(0.2)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.line_spacing = 1.25


def _set_cell_shading(cell, fill_hex: str) -> None:
    tc_pr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), fill_hex)
    tc_pr.append(shd)


def _add_kv_table(doc: Document, pairs: list[tuple[str, str]]) -> None:
    table = doc.add_table(rows=len(pairs), cols=2)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    for idx, (k, v) in enumerate(pairs):
        row = table.rows[idx]
        row.cells[0].text = k
        row.cells[1].text = v
        _set_cell_shading(row.cells[0], "F3F4F6")
        if row.cells[0].paragraphs and row.cells[0].paragraphs[0].runs:
            row.cells[0].paragraphs[0].runs[0].bold = True


def _add_styled_table(doc: Document, headers: list[str], rows: list[list[str]]) -> None:
    table = doc.add_table(rows=1 + len(rows), cols=len(headers))
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.style = "Table Grid"
    hdr_cells = table.rows[0].cells
    for col_idx, text in enumerate(headers):
        hdr_cells[col_idx].text = text
        _set_cell_shading(hdr_cells[col_idx], "F3F4F6")
        for run in hdr_cells[col_idx].paragraphs[0].runs:
            run.bold = True
            run.font.size = Pt(9.5)
    for row_idx, row_values in enumerate(rows, start=1):
        cells = table.rows[row_idx].cells
        for col_idx, val in enumerate(row_values):
            cells[col_idx].text = val
            for run in cells[col_idx].paragraphs[0].runs:
                run.font.size = Pt(9)
