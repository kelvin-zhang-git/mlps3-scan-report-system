import { useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Download, ExternalLink, FileSpreadsheet, FileText, RefreshCw, ShieldAlert, ShieldCheck, Sparkles, Wrench } from "lucide-react";
import { download } from "../api";
import { formatBeijing } from "../time";

export type ReportItem = {
  report_id: string;
  filename: string;
  variant: string;
  created_at?: string;
};

export type DeliveryData = {
  delivery_ready: boolean;
  reports: ReportItem[];
  ai_report?: {
    generated: boolean;
    status: string;
    model_id: string;
    prompt_version: number;
    latest_prompt_version: number;
    prompt_outdated: boolean;
    generated_at: string;
    executive_preview: string;
  };
  steps?: {
    remediation: string;
    ciso_archive: string;
    artifacts: string;
  };
  defectdojo: {
    product_name: string;
    engagement_id: string;
    url: string;
    pushed: number;
    active: number;
    mitigated: number;
    false_positive: number;
  };
  ciso: {
    url: string;
    assessment_id: string;
    written?: number;
    controls_written?: number;
    leak_passed: boolean | null;
    leak_detail?: { leaks?: string[] };
  };
  history: Array<{ sync_id: string; target: string; status: string; summary: string; created_at: string }>;
};

const TARGET_LABEL: Record<string, string> = {
  defectdojo_push: "漏洞推送至整改台",
  defectdojo_pull: "同步最新整改状态",
  ciso_push: "二次脱敏复核与合规归档",
  ciso_report: "交付报告制品归档",
};

const SYNC_STATUS_LABEL: Record<string, [string, string]> = {
  ok: ["成功", "ok"],
  blocked: ["已暂停", "danger"],
  failed: ["失败", "danger"],
  skipped: ["已跳过", "warn"],
};

function formatTime(iso?: string): string {
  return formatBeijing(iso);
}

export default function DeliveryCenter({
  projectName,
  clauseTotal,
  delivery,
  reports,
  writable,
  isAdmin,
  deliveryEnabled,
  pushing,
  pulling,
  delivering,
  regenerating,
  onPushDojo,
  onPullDojo,
  onDeliverCiso,
  onGenerateReport,
}: {
  projectName: string;
  clauseTotal: number;
  delivery: DeliveryData | null;
  reports: ReportItem[];
  writable: boolean;
  isAdmin: boolean;
  deliveryEnabled: boolean;
  pushing: boolean;
  pulling: boolean;
  delivering: boolean;
  regenerating: boolean;
  onPushDojo: () => void;
  onPullDojo: () => void;
  onDeliverCiso: () => void;
  onGenerateReport: (variant: "masked" | "restored", refreshAi: boolean) => void;
}) {
  const [showAllLogs, setShowAllLogs] = useState(false);

  const dojo = delivery?.defectdojo;
  const ciso = delivery?.ciso;
  const ai = delivery?.ai_report;
  const allReports = delivery?.reports?.length ? delivery.reports : reports;

  const pushed = dojo?.pushed || 0;
  const active = dojo?.active || 0;
  const mitigated = dojo?.mitigated || 0;
  const falsePositive = dojo?.false_positive || 0;
  const closedCount = mitigated + falsePositive;
  const closeRate = pushed > 0 ? Math.round((closedCount / pushed) * 100) : 0;

  const maskedDocx = allReports.find((r) => r.variant === "masked_docx");
  const restoredDocx = allReports.find((r) => r.variant === "restored_docx");
  const maskedHtml = allReports.find((r) => r.variant === "masked");
  const restoredHtml = allReports.find((r) => r.variant === "restored");
  const ticketsReport = allReports.find((r) => r.variant === "tickets");
  const cisoSnapshot = allReports.find((r) => r.variant === "ciso_final");

  const step1Done = pushed > 0;
  const step2Blocked = ciso?.leak_passed === false;
  const step2Done = Boolean(ciso?.assessment_id) && !step2Blocked;
  const step3Done = Boolean(maskedDocx || maskedHtml);

  const history = delivery?.history || [];
  const visibleLogs = showAllLogs ? history : history.slice(0, 5);

  return (
    <div className="delivery-center">
      {/* 顶部三步闭环导引条 */}
      <section className="card card-pad delivery-stepper-card">
        <div className="delivery-intro-head">
          <div>
            <h2>整改闭环与合规交付中心</h2>
            <p className="muted">
              将本轮核查发现转化为可跟踪的整改工单，完成对外输出前的敏感信息复核并归档至合规台账，最终导出包含 AI 专业研判的中文等保三级预评估报告。
            </p>
          </div>
          {ai && (
            <div className="prompt-chip">
              <Sparkles size={14} />
              <span>报告 AI 提示词 v{ai.latest_prompt_version || 1}</span>
              {isAdmin && <Link to="/admin?tab=prompt">编辑提示词</Link>}
            </div>
          )}
        </div>
        <div className="delivery-stepper">
          <div className={`stepper-item ${step1Done ? "done" : "current"}`}>
            <div className="stepper-top">
              <span className="stepper-num">1</span>
              <strong>漏洞整改派发与跟踪</strong>
              <span className={`badge ${step1Done ? "ok" : "warn"}`}>{step1Done ? `已纳管 ${pushed} 项` : "尚未派发"}</span>
            </div>
            <p className="muted">将软件漏洞与主机基线问题分发给运维和研发团队处理，并在修复或确认误报后随时同步最新进度。</p>
          </div>
          <div className={`stepper-item ${step2Blocked ? "blocked" : step2Done ? "done" : step1Done ? "current" : ""}`}>
            <div className="stepper-top">
              <span className="stepper-num">2</span>
              <strong>脱敏终检与合规归档</strong>
              <span className={`badge ${step2Blocked ? "danger" : step2Done ? "ok" : "warn"}`}>
                {step2Blocked ? "终检未通过" : step2Done ? "已归档台账" : "待归档"}
              </span>
            </div>
            <p className="muted">在对外归档前复核脱敏结果，确认无敏感信息外泄后再将全部 {clauseTotal || 211} 条条款结论、评估总述与整改措施存入合规台账。</p>
          </div>
          <div className={`stepper-item ${step3Done ? "done" : ""}`}>
            <div className="stepper-top">
              <span className="stepper-num">3</span>
              <strong>终版报告与工单交付</strong>
              <span className={`badge ${maskedDocx ? "ok" : "warn"}`}>{maskedDocx ? "中文终版已就绪" : "待生成终版"}</span>
            </div>
            <p className="muted">按照阅读对象与密级要求，下载中文 Word 专业研判报告、网页打印版、分部门整改工单以及台账归档快照。</p>
          </div>
        </div>
      </section>

      {/* 第一步与第二步双栏操作区 */}
      <div className="delivery-two-col">
        <article className="card card-pad delivery-step-card">
          <div className="step-card-head">
            <div>
              <span className="step-tag">第一步 · 整改派发</span>
              <h3>漏洞整改派发与闭环跟踪</h3>
            </div>
            <span className="tool-pill"><Wrench size={13} /> DefectDojo</span>
          </div>
          <p className="step-desc">
            将本轮检出的软件漏洞与主机基线缺陷推送至漏洞管理平台，便于运维与研发团队认领修复或核销误报，并把最新处置状态同步回当前工作台。
          </p>

          <div className="delivery-kpis">
            <div className="dkpi"><span>已纳管</span><b>{pushed}</b></div>
            <div className="dkpi"><span className="dkpi-warn">待整改</span><b>{active}</b></div>
            <div className="dkpi"><span className="dkpi-ok">已修复</span><b>{mitigated}</b></div>
            <div className="dkpi"><span>已核销误报</span><b>{falsePositive}</b></div>
          </div>

          <div className="closure-bar">
            <div className="closure-head">
              <span className="muted">本轮漏洞闭环率（已修复与已核销误报之和）</span>
              <strong>{closeRate}%（{closedCount} / {pushed}）</strong>
            </div>
            <div className="scan-progress-track">
              <div className="scan-progress-fill" style={{ width: `${Math.max(pushed ? 4 : 0, closeRate)}%` }} />
            </div>
          </div>

          <p className="meta-line muted">
            关联产品：<b>{dojo?.product_name || projectName}</b> · 处置周期：<b>{dojo?.engagement_id ? `#${dojo.engagement_id}` : "首次推送后自动建立"}</b>
          </p>

          <div className="filters step-actions">
            {pushed > 0 ? (
              <>
                <button className="btn" disabled={!writable || pulling} onClick={onPullDojo}>
                  <RefreshCw size={14} /> {pulling ? "正在同步状态…" : "同步最新整改状态"}
                </button>
                <button className="btn-ghost" disabled={!writable || pushing} onClick={onPushDojo}>
                  {pushing ? "正在补充推送…" : "补充推送新增项"}
                </button>
              </>
            ) : (
              <button className="btn" disabled={!writable || pushing} onClick={onPushDojo}>
                {pushing ? "正在推送…" : "推送技术漏洞到整改台"}
              </button>
            )}
            {dojo?.url && (
              <a className="btn-ghost" href={dojo.url} target="_blank" rel="noreferrer">
                打开漏洞平台 <ExternalLink size={13} />
              </a>
            )}
          </div>
        </article>

        <article className="card card-pad delivery-step-card">
          <div className="step-card-head">
            <div>
              <span className="step-tag">第二步 · 合规归档</span>
              <h3>脱敏终检与合规台账归档</h3>
            </div>
            <span className="tool-pill"><ShieldCheck size={13} /> CISO Assistant</span>
          </div>
          <p className="step-desc">
            对外交付前会对待输出内容执行二次敏感信息复核；确认无泄漏后，结合系统管理的等保三级 AI 提示词生成专业解读，并将全部 {clauseTotal || 211} 条条款结论、执行摘要与高危整改控制项归档至长期合规台账。
          </p>

          <div className="gate-list">
            <div className="gate-row">
              <div className="gate-label">
                {ciso?.leak_passed === false ? <ShieldAlert size={16} className="icon-danger" /> : <CheckCircle2 size={16} className={ciso?.leak_passed ? "icon-ok" : "icon-muted"} />}
                <span>对外输出二次脱敏复核</span>
              </div>
              <span className={`badge ${ciso?.leak_passed === true ? "ok" : ciso?.leak_passed === false ? "danger" : "warn"}`}>
                {ciso?.leak_passed === true ? "已通过复核" : ciso?.leak_passed === false ? "暂停：检出未脱敏内容" : "待执行复核"}
              </span>
            </div>
            {ciso?.leak_passed === false && (ciso.leak_detail?.leaks || []).length > 0 && (
              <div className="error" style={{ margin: 0 }}>检出待处理内容：{(ciso.leak_detail?.leaks || []).join("，")}</div>
            )}

            <div className="gate-row">
              <div className="gate-label">
                <Sparkles size={16} className={ai?.generated ? "icon-ok" : "icon-muted"} />
                <span>AI 专业报告研判</span>
              </div>
              <div className="gate-right">
                {ai?.generated ? (
                  <span className={`badge ${ai.prompt_outdated ? "warn" : "ok"}`}>
                    {ai.status === "ai" ? `AI 已生成 · ${ai.model_id}` : "规则研判已生成"}（v{ai.prompt_version}）
                  </span>
                ) : (
                  <span className="badge warn">将在归档或生成报告时自动撰写</span>
                )}
              </div>
            </div>

            <div className="gate-row">
              <div className="gate-label">
                <ShieldCheck size={16} className={ciso?.assessment_id ? "icon-ok" : "icon-muted"} />
                <span>合规台账归档状态</span>
              </div>
              <span className="muted">
                {ciso?.assessment_id
                  ? `已归档${ciso.written ? ` ${ciso.written} 条条款` : ""}${ciso.controls_written ? ` · ${ciso.controls_written} 项整改控制措施` : ""}`
                  : "复核通过后自动建立本轮台账"}
              </span>
            </div>
          </div>

          {ai?.executive_preview && (
            <div className="ai-preview-box">
              <div className="ai-preview-title">
                <span>AI 执行摘要预览</span>
                {ai.prompt_outdated && <span className="badge warn">提示词已更新至 v{ai.latest_prompt_version}，建议重新生成</span>}
              </div>
              <p>{ai.executive_preview}{ai.executive_preview.length >= 235 ? "…" : ""}</p>
            </div>
          )}

          <div className="filters step-actions">
            <button className="btn" disabled={!writable || delivering || !deliveryEnabled} onClick={onDeliverCiso}>
              {delivering ? "正在复核、研判并归档…" : "复核脱敏、AI 研判并归档台账"}
            </button>
            {ciso?.url && (
              <a className="btn-ghost" href={ciso.url} target="_blank" rel="noreferrer">
                打开合规台账 <ExternalLink size={13} />
              </a>
            )}
          </div>
        </article>
      </div>

      {/* 第三步：最终交付物下载中心 */}
      <article className="card card-pad">
        <div className="step-card-head" style={{ marginBottom: 12 }}>
          <div>
            <span className="step-tag">第三步 · 交付物中心</span>
            <h3>最终专业报告与整改工单下载</h3>
            <p className="muted" style={{ marginTop: 4 }}>
              以下交付物分别对应不同的阅读对象与密级要求；中文 Word 终版报告由系统管理的等保三级 AI 提示词驱动生成，涵盖管理摘要、各安全域差距剖析与分阶段整改路线。
            </p>
          </div>
          <div className="filters">
            <button
              className={ai?.prompt_outdated || !maskedDocx ? "btn" : "btn-ghost"}
              disabled={!writable || regenerating}
              onClick={() => onGenerateReport("masked", true)}
            >
              <Sparkles size={14} /> {regenerating ? "正在调用 AI 生成报告…" : "按最新提示词重新生成终版报告"}
            </button>
            <button
              className="btn-ghost"
              disabled={!writable || regenerating}
              onClick={() => onGenerateReport("restored", false)}
            >
              生成内部受控还原版
            </button>
          </div>
        </div>

        <div className="artifact-grid">
          <div className="artifact-card featured">
            <div className="artifact-top">
              <div className="artifact-title">
                <FileText size={18} />
                <strong>中文等保三级预评估终版报告（Word）</strong>
              </div>
              <span className="badge ok">推荐用于正式汇报</span>
            </div>
            <p className="artifact-audience">适用对象：管理层、迎检小组及合规评审人员</p>
            <p className="muted">
              汇总 AI 管理层执行摘要、双口径得分表、各安全域差距剖析、重点漏洞与主机基线风险分析、P0/P1/P2 整改路线图以及 {clauseTotal || 211} 条条款核查明细。
            </p>
            <div className="artifact-actions">
              {maskedDocx ? (
                <button className="btn" onClick={() => download(`/api/reports/${maskedDocx.report_id}/download`, maskedDocx.filename)}>
                  <Download size={14} /> 下载脱敏版（.docx）
                </button>
              ) : (
                <button className="btn" disabled={!writable || regenerating} onClick={() => onGenerateReport("masked", false)}>
                  立即生成脱敏 Word 终版
                </button>
              )}
              {restoredDocx && (
                <button className="btn-ghost" onClick={() => download(`/api/reports/${restoredDocx.report_id}/download`, restoredDocx.filename)}>
                  <Download size={14} /> 下载受控还原版（含真实地址）
                </button>
              )}
            </div>
            {(maskedDocx || restoredDocx) && (
              <div className="artifact-meta muted">
                {maskedDocx && <span>脱敏版：{maskedDocx.filename}（{formatTime(maskedDocx.created_at)}）</span>}
                {restoredDocx && <span>还原版：{restoredDocx.filename}（{formatTime(restoredDocx.created_at)}）</span>}
              </div>
            )}
          </div>

          <div className="artifact-card">
            <div className="artifact-top">
              <div className="artifact-title">
                <FileText size={18} />
                <strong>中文预评估网页 / 打印版报告</strong>
              </div>
              <span className="badge">浏览器直读</span>
            </div>
            <p className="artifact-audience">适用对象：浏览器审阅及打印签字归档</p>
            <p className="muted">
              与 Word 终版共享同一份 AI 研判正文与条款数据，正文中的 CVE 编号可直接点击查阅官方漏洞记录。
            </p>
            <div className="artifact-actions">
              {maskedHtml && (
                <button className="btn-ghost" onClick={() => download(`/api/reports/${maskedHtml.report_id}/download`, maskedHtml.filename)}>
                  <Download size={14} /> 脱敏版 · {maskedHtml.filename}
                </button>
              )}
              {restoredHtml && (
                <button className="btn-ghost" onClick={() => download(`/api/reports/${restoredHtml.report_id}/download`, restoredHtml.filename)}>
                  <Download size={14} /> 还原版 · {restoredHtml.filename}
                </button>
              )}
              {!maskedHtml && !restoredHtml && <span className="muted">尚未生成，点击上方按钮即可产出。</span>}
            </div>
          </div>

          <div className="artifact-card">
            <div className="artifact-top">
              <div className="artifact-title">
                <FileSpreadsheet size={18} />
                <strong>分部门整改工单包（Markdown）</strong>
              </div>
              <span className="badge">运维与研发执行</span>
            </div>
            <p className="artifact-audience">适用对象：主机运维、网络边界、应用研发与云架构团队</p>
            <p className="muted">
              按照责任部门与 P0/P1/P2 优先级拆分不符合与待核查条款，随附加固参考命令及 CVE 链接，便于直接分发跟进。
            </p>
            <div className="artifact-actions">
              {ticketsReport ? (
                <button className="btn-ghost" onClick={() => download(`/api/reports/${ticketsReport.report_id}/download`, ticketsReport.filename)}>
                  <Download size={14} /> 下载整改工单 · {ticketsReport.filename}
                </button>
              ) : (
                <span className="muted">生成报告后会自动产出对应的分部门工单。</span>
              )}
            </div>
          </div>

          <div className="artifact-card">
            <div className="artifact-top">
              <div className="artifact-title">
                <ShieldCheck size={18} />
                <strong>CISO Assistant 台账归档快照</strong>
              </div>
              <span className="badge">台账审计附件</span>
            </div>
            <p className="artifact-audience">适用对象：合规台账审计与第三方 GRC 平台备查</p>
            <p className="muted">
              由 CISO Assistant 按平台内置英文骨架导出，其中已同步回填 AI 评估总述与高危整改控制措施。面向管理层汇报时，建议优先使用「中文等保三级预评估终版报告」。
            </p>
            <div className="artifact-actions">
              {cisoSnapshot ? (
                <button className="btn-ghost" onClick={() => download(`/api/reports/${cisoSnapshot.report_id}/download`, cisoSnapshot.filename)}>
                  <Download size={14} /> 下载台账快照 · {cisoSnapshot.filename}
                </button>
              ) : (
                <span className="muted">完成第二步合规台账归档后，系统会自动拉回并保存快照。</span>
              )}
            </div>
          </div>
        </div>
      </article>

      {/* 底部：中文业务化交付审计轨迹 */}
      <article className="card card-pad">
        <div className="section-title" style={{ padding: 0, borderBottom: "none", marginBottom: 10 }}>
          <h3>交付审计轨迹</h3>
          {history.length > 5 && (
            <button className="btn-ghost" onClick={() => setShowAllLogs((prev) => !prev)}>
              {showAllLogs ? "仅看最近 5 条" : `展开全部（共 ${history.length} 条）`}
            </button>
          )}
        </div>
        {visibleLogs.length === 0 ? (
          <p className="muted">本轮尚未执行外部协同同步操作。</p>
        ) : (
          <div className="audit-timeline">
            {visibleLogs.map((row) => {
              const [statusLabel, tone] = SYNC_STATUS_LABEL[row.status] || [row.status, ""];
              return (
                <div className="audit-row" key={row.sync_id}>
                  <span className="audit-time mono">{formatTime(row.created_at)}</span>
                  <span className={`badge ${tone}`}>{statusLabel}</span>
                  <strong className="audit-action">{TARGET_LABEL[row.target] || row.target}</strong>
                  <span className="audit-summary muted">{row.summary}</span>
                </div>
              );
            })}
          </div>
        )}
      </article>
    </div>
  );
}
