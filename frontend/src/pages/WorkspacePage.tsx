import { useEffect, useRef, useState } from "react";
import { useParams, useSearchParams } from "react-router-dom";
import { api, download, savedUser } from "../api";
import { CveField, CveText } from "../components/CveText";
import DataTable from "../components/DataTable";
import DeliveryCenter, { type DeliveryData } from "../components/DeliveryCenter";
import Drawer from "../components/Drawer";
import Modal from "../components/Modal";
import OfflineImportPanel from "../components/OfflineImportPanel";
import { formatBeijing } from "../time";
import StatusBadge from "../components/StatusBadge";
import { AUTO_LABEL, OBJECT_TYPE_LABEL, RISK_WEIGHT_LABEL, TECH_OBJECT_OPTIONS, canOperate, statusText } from "../labels";
import { rememberProject } from "../project";

type Job = { job_id: string; status: string; started_at: string; progress_pct: number };
type ScanEvent = { id?: number; stage: string; message: string; progress_pct?: number };
type Asset = {
  asset_id: string; host: string; host_visible: string; zone_token: string; security_zone: string; os_type: string;
  object_type?: string; scan_mode: string; scanners: string[]; ssh_port?: number; ssh_user?: string; ssh_auth_mode?: string;
  ssh_secret_env?: string; ssh_key_env?: string; ssh_configured?: boolean; is_enabled?: boolean; notes?: string;
};
type Evidence = {
  evidence_id: string; asset_id?: string; title: string; evidence_type: string; severity: string; source_tool: string; cve_or_cwe?: string;
  detail?: { text?: string; clause_hints?: string[] } | string;
};
type HighRiskPrecedent = {
  standard_ref: string;
  precedent_code: string;
  category: string;
  direct_high_risk: boolean;
  can_downgrade_with_compensation: boolean;
  trigger_condition: string;
  compensating_controls: string[];
};
type ObjectCoverageItem = {
  object_key: string;
  object_label: string;
  managed_assets: number;
  scanned_assets: number;
  applicable_clauses: number;
  decided_clauses: number;
  non_compliant_clauses: number;
  probe_tools: string[];
  status: "covered" | "partial" | "unmanaged";
  status_label: string;
  note: string;
};
type RiskBreakdownItem = {
  level: string;
  label: string;
  weight: number;
  total: number;
  compliant: number;
  partially_compliant: number;
  non_compliant: number;
  pending: number;
  mitigated: number;
};
type Assessment = {
  assessment_id: string;
  clause_id: string;
  domain?: string;
  control_point?: string;
  auto_level?: string;
  requirement_text?: string;
  manual_check_guide?: string;
  final_status: string;
  ai_rationale: string;
  remediation_script?: string;
  is_high_risk?: boolean;
  applicable_objects?: string[];
  applicable_object_labels?: string[];
  risk_weight_level?: string;
  compensation_status?: "none" | "mitigated";
  compensation_note?: string;
  high_risk_precedent?: HighRiskPrecedent | null;
};
type Overview = {
  project: { name: string; summary: string; stage_label: string; classification: string; llm_profile: string; status?: string; env_tier?: string; whitelist_cidrs?: string[]; enabled_extensions?: string[]; clause_count?: number; max_concurrency?: number; nuclei_rate_limit?: number };
  workflow?: {
    writable: boolean;
    manual_writable: boolean;
    next_step: { key: string; label: string; reason: string };
    tabs: Record<string, { key: string; label: string; step: number | null; enabled: boolean; state: string; reason: string }>;
  };
  assets: Asset[];
  stats: {
    coverage: number;
    high_open: number;
    pending_manual: number;
    completeness?: number;
    checked_score?: number;
    conservative_score?: number;
    weighted_checked_score?: number;
    weighted_conservative_score?: number;
    direct_high_fail?: number;
    direct_high_open?: number;
    mitigated_high_count?: number;
    risk_breakdown?: RiskBreakdownItem[];
    object_coverage?: {
      items: ObjectCoverageItem[];
      covered_count: number;
      partial_count: number;
      unmanaged_count: number;
      total_object_types: number;
      summary: string;
    };
    verdict_label?: string;
    verdict_advice?: string;
    high_fail?: number;
    job?: Job | null;
    effective_job?: Job | null;
  };
  selected_job?: Job | null;
  jobs: Job[];
  reports: Array<{ report_id: string; filename: string; variant: string; created_at?: string }>;
  clauses: Array<{ clause_id: string; control_point: string }>;
};

const TABS = [
  ["overview", "概览"],
  ["assets", "资产白名单"],
  ["scan", "扫描采集"],
  ["findings", "漏洞与基线"],
  ["sanitize", "脱敏审计"],
  ["clauses", "AI 条款映射"],
  ["paths", "攻击路径"],
  ["manual", "人工证据"],
  ["reports", "报告制品"],
  ["delivery", "协同交付"],
] as const;

const TAB_HELP: Record<string, string> = {
  overview: "查看本轮核查是否满足等保三级预评估的进场条件，包括核查完备度、双口径得分与高风险不符合项。",
  assets: "配置项目密级、扫描白名单与受测主机；至少启用一台主机并通过 SSH 连通测试后，方可发起技术核查，扫描机地址保持在排除网段内。",
  collect: "对已启用主机发起只读采集，并在完成后核对脱敏前后样本；确认无敏感信息外泄后，系统进入条款评审阶段。",
  review: "核对漏洞与主机基线，复核当前项目启用的全部等保三级条款，登记管理与现场类人工证据并审阅攻击路径；后续报告将依据这里的结论汇总达标态势与整改清单。",
  reports: "生成本轮中文等保三级预评估报告；脱敏版用于对外沟通汇报，受控还原版保留真实地址供内部定位，生成脱敏版后即可进入协同交付。",
  delivery: "面向本轮任务推进漏洞整改派发、同步最新处置状态，完成二次脱敏复核后归档至合规台账，并下载中文终版报告与分部门整改工单。",
};

const LATER_TABS = ["review", "reports", "delivery"];
const LEGACY_TAB: Record<string, string> = {
  scan: "collect",
  sanitize: "collect",
  findings: "review",
  clauses: "review",
  paths: "review",
  manual: "review",
};

type Delivery = DeliveryData;

const SCAN_STAGE: Record<string, string> = {
  policy: "核对范围",
  ssh_baseline: "主机基线",
  db_mw_baseline: "数据库/中间件基线",
  nmap: "端口与服务",
  tls: "传输加密",
  nuclei: "Web 模板",
  trivy_os: "软件包漏洞",
  dedup: "证据去重",
  defectdojo: "导入处置平台",
  sanitizer: "脱敏",
  import: "离线与云导入",
  asset: "主机采集",
};

function findingCopy(detail?: Evidence["detail"]) {
  let text = "";
  let hints: string[] = [];
  if (typeof detail === "string") text = detail;
  else if (detail) {
    text = detail.text || "";
    hints = detail.clause_hints || [];
  }
  const trimmed = text.trim();
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed = JSON.parse(trimmed) as { text?: string; clause_hints?: string[] };
      if (parsed && typeof parsed === "object") {
        text = String(parsed.text || "");
        if (!hints.length && Array.isArray(parsed.clause_hints)) hints = parsed.clause_hints.map(String);
      }
    } catch {
      /* 不是 JSON 时按原文展示 */
    }
  }
  const readable = Array.from(new Set(hints.filter((item) => item && !item.includes("ZONE_EXT_IP"))));
  return {
    text: text || "这条发现没有附带更多说明。",
    hints: readable,
    maskedHints: hints.length > 0 && readable.length === 0,
  };
}

function ScanProgress({ status, events }: { status: string; events: ScanEvent[] }) {
  if (!events.length && !["queued", "running"].includes(status)) return null;
  const latest = events[events.length - 1];
  const running = status === "queued" || status === "running";
  const failed = status === "failed";
  const done = status === "awaiting_approval" || status === "completed";
  const width = done ? 100 : Math.max(8, latest?.progress_pct || (status === "queued" ? 5 : 12));
  const headline = failed
    ? "这一轮没有完成"
    : done
      ? (status === "completed" ? "这一轮核查已经结束" : "采集已经结束，等待确认脱敏")
      : `正在进行：${SCAN_STAGE[latest?.stage || ""] || "准备采集"}`;
  return (
    <section className="scan-progress" aria-live="polite">
      <div className="scan-progress-head">
        <b>{headline}</b>
        <span className="muted">{running ? "进行中" : failed ? "已停止" : "已结束"}</span>
      </div>
      <div className="scan-progress-track" aria-valuenow={width} aria-valuemin={0} aria-valuemax={100} role="progressbar">
        <div className={`scan-progress-fill${running ? " active" : ""}`} style={{ width: `${width}%` }} />
      </div>
      <div className="scan-steps">
        {events.map((event, index) => (
          <div className={`scan-step${index === events.length - 1 && running ? " current" : ""}`} key={event.id || `${event.stage}-${index}`}>
            <span>{index === events.length - 1 && running ? "…" : "✓"}</span>
            <span><b>{SCAN_STAGE[event.stage] || event.stage}</b> · {event.message}</span>
          </div>
        ))}
        {!events.length && <div className="muted">任务已提交，正在等待第一条进度。</div>}
      </div>
    </section>
  );
}

export default function WorkspacePage() {
  const { projectId = "prj_stage1" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "overview";
  const [jobId, setJobId] = useState(params.get("job") || "");
  const [data, setData] = useState<Overview | null>(null);
  const [evidences, setEvidences] = useState<Evidence[]>([]);
  const [clauses, setClauses] = useState<Assessment[]>([]);
  const [paths, setPaths] = useState<Array<{ path_id: string; title: string; mitigation_priority: string; steps: string[] }>>([]);
  const [docs, setDocs] = useState<Array<{ evidence_doc_id: string; clause_id: string; filename: string; note: string }>>([]);
  const [diff, setDiff] = useState<{ leak_check_passed?: boolean; samples?: Array<{ title: string; before?: string; after: string }> } | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("");
  const [tool, setTool] = useState("");
  const [assetFilter, setAssetFilter] = useState("");
  const [text, setText] = useState("");
  const [assetOpen, setAssetOpen] = useState(false);
  const [scopeOpen, setScopeOpen] = useState(false);
  const [assetError, setAssetError] = useState("");
  const [scopeError, setScopeError] = useState("");
  const [savingAsset, setSavingAsset] = useState(false);
  const [notice, setNotice] = useState("");
  const emptyAsset = { asset_id: "", host: "", security_zone: "APP", os_type: "rocky_linux", object_type: "host_os", scan_mode: "READONLY_AUDIT", ssh_port: 22, ssh_user: "root", ssh_auth_mode: "env_ref", ssh_secret_env: "STAGE1_TARGET_SSH_PASSWORD", ssh_key_env: "STAGE1_TARGET_SSH_KEY_PATH", ssh_secret: "", notes: "", is_enabled: true };
  const [assetForm, setAssetForm] = useState(emptyAsset);
  const [scopeForm, setScopeForm] = useState({ env_tier: "L1_TEST", whitelist: "192.168.1.220/32", max_concurrency: 2, nuclei_rate_limit: 50, include_cloud: false });
  const [clauseStatus, setClauseStatus] = useState("");
  const [clauseObjectFilter, setClauseObjectFilter] = useState("");
  const [clauseHighOnly, setClauseHighOnly] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Evidence | null>(null);
  const [selectedClause, setSelectedClause] = useState<Assessment | null>(null);
  const [compMitigated, setCompMitigated] = useState(false);
  const [compNote, setCompNote] = useState("");
  const [reviewing, setReviewing] = useState(false);
  const reviewingRef = useRef(false);
  const [delivery, setDelivery] = useState<Delivery | null>(null);
  const [delivering, setDelivering] = useState(false);
  const deliveringRef = useRef(false);
  const [helpKey, setHelpKey] = useState("");
  const [reviewView, setReviewView] = useState("clauses");
  const [pushing, setPushing] = useState(false);
  const [pulling, setPulling] = useState(false);
  const [regenerating, setRegenerating] = useState(false);
  const [activeScanId, setActiveScanId] = useState("");
  const scanTimer = useRef<number | null>(null);
  const [note, setNote] = useState("");
  const [manual, setManual] = useState({ clause_id: "8.1.6.1-a", filename: "安全策略.pdf", note: "" });
  const allowed = canOperate(savedUser()?.role);

  function selectTab(next: string) {
    const query = new URLSearchParams(params);
    query.set("tab", next);
    setParams(query);
  }

  async function reload(nextJob = jobId) {
    const query = nextJob ? `?job_id=${nextJob}` : "";
    const overview = await api<Overview>(`/api/projects/${projectId}/overview${query}`);
    setData(overview);
    const selected = nextJob || overview.selected_job?.job_id || overview.stats.job?.job_id || "";
    if (!nextJob && selected) setJobId(selected);
    if (selected) {
      const [evidenceRows, clauseRows, pathRows, diffResult] = await Promise.all([
        api<Evidence[]>(`/api/evidences/${selected}`),
        api<Assessment[]>(`/api/compliance/${selected}/clauses`),
        api<Array<{ path_id: string; title: string; mitigation_priority: string; steps: string[] }>>(`/api/compliance/${selected}/attack-paths`),
        api<typeof diff>(`/api/sanitization/${selected}/diff`).catch(() => null),
      ]);
      setEvidences(evidenceRows);
      setClauses(clauseRows);
      setPaths(pathRows);
      setDiff(diffResult);
      setDelivery(await api<Delivery>(`/api/projects/${projectId}/delivery?job_id=${selected}`).catch(() => null));
      const scan = await api<{ job: Job; events: ScanEvent[] }>(`/api/scans/${selected}`).catch(() => null);
      setEvents(scan?.events || []);
    } else {
      setDelivery(null);
      setEvents([]);
    }
    setDocs(await api(`/api/projects/${projectId}/manual-evidence`));
  }

  useEffect(() => {
    rememberProject(projectId);
    reload().catch((err: Error) => setError(err.message));
  }, [projectId]);

  useEffect(() => () => {
    if (scanTimer.current) window.clearInterval(scanTimer.current);
  }, []);

  useEffect(() => {
    const current = data?.selected_job;
    if (!current || !["queued", "running"].includes(current.status)) return;
    if (scanTimer.current) return;
    const watched = current.job_id;
    scanTimer.current = window.setInterval(async () => {
      try {
        const detail = await api<{ job: Job; events: ScanEvent[] }>(`/api/scans/${watched}`);
        setEvents(detail.events);
        if (["awaiting_approval", "completed", "failed"].includes(detail.job.status)) {
          if (scanTimer.current) window.clearInterval(scanTimer.current);
          scanTimer.current = null;
          await reload(watched);
        }
      } catch (err) {
        if (scanTimer.current) window.clearInterval(scanTimer.current);
        scanTimer.current = null;
        setError(err instanceof Error ? err.message : "核查状态没有刷新");
      }
    }, 1500);
  }, [data?.selected_job?.job_id, data?.selected_job?.status]);

  useEffect(() => {
    if (!helpKey) return;
    const close = (event: MouseEvent) => {
      const target = event.target as HTMLElement | null;
      if (target?.closest(".tab-help")) return;
      setHelpKey("");
    };
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setHelpKey("");
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", onKey);
    };
  }, [helpKey]);

  async function startReview() {
    const target = jobId || data?.selected_job?.job_id || data?.stats.job?.job_id || "";
    if (!target || reviewingRef.current) return;
    reviewingRef.current = true;
    setError("");
    setReviewing(true);
    try {
      await api(`/api/sanitization/${target}/approve`, { method: "POST" });
      await api(`/api/compliance/${target}/assess`, { method: "POST" });
      setJobId(target);
      await reload(target);
      setReviewView("clauses");
      selectTab("review");
    } catch (err) {
      setError(err instanceof Error ? err.message : "评审没有开始");
    } finally {
      reviewingRef.current = false;
      setReviewing(false);
    }
  }

  async function runScan() {
    setError("");
    const job = await api<Job>(`/api/projects/${projectId}/scans/run`, { method: "POST" });
    // 立刻切到本轮进行中的任务，后续页签按这一轮的状态关闭，不再沿用上一轮已完成任务。
    setActiveScanId(job.job_id);
    setJobId(job.job_id);
    selectTab("collect");
    await reload(job.job_id);
    setActiveScanId("");
    if (scanTimer.current) window.clearInterval(scanTimer.current);
    scanTimer.current = window.setInterval(async () => {
      try {
        const detail = await api<{ job: Job; events: ScanEvent[] }>(`/api/scans/${job.job_id}`);
        setEvents(detail.events);
        if (["awaiting_approval", "completed", "failed"].includes(detail.job.status)) {
          if (scanTimer.current) window.clearInterval(scanTimer.current);
          scanTimer.current = null;
          await reload(job.job_id);
          if (detail.job.status === "awaiting_approval") selectTab("collect");
        }
      } catch (err) {
        if (scanTimer.current) window.clearInterval(scanTimer.current);
        scanTimer.current = null;
        setError(err instanceof Error ? err.message : "核查状态没有刷新");
      }
    }, 1500);
  }

  const baselineSummary = Object.values(evidences.reduce<Record<string, { asset_id: string; passed: number; failed: number }>>((grouped, row) => {
    if (row.source_tool !== "ssh_baseline") return grouped;
    if (assetFilter && row.asset_id !== assetFilter) return grouped;
    const assetId = row.asset_id || "未归类资产";
    const bucket = grouped[assetId] || { asset_id: assetId, passed: 0, failed: 0 };
    if (row.evidence_type === "BASELINE_PASS") bucket.passed += 1;
    if (row.evidence_type === "BASELINE_FAIL") bucket.failed += 1;
    grouped[assetId] = bucket;
    return grouped;
  }, {}));
  const findings = evidences.filter((row) => {
    if (severity && row.severity !== severity) return false;
    if (tool && row.source_tool !== tool) return false;
    if (assetFilter && row.asset_id !== assetFilter) return false;
    if (text && !`${row.title} ${row.cve_or_cwe || ""}`.toLowerCase().includes(text.toLowerCase())) return false;
    return true;
  });
  const clauseRows = clauses.filter((row) => {
    if (clauseStatus && row.final_status !== clauseStatus) return false;
    if (clauseObjectFilter && !(row.applicable_objects || []).includes(clauseObjectFilter)) return false;
    if (clauseHighOnly && !row.is_high_risk) return false;
    return true;
  });

  function openClauseDrawer(row: Assessment) {
    setSelectedClause(row);
    setNote("");
    setCompMitigated(row.compensation_status === "mitigated");
    setCompNote(row.compensation_note || "");
  }
  const tools = Array.from(new Set(evidences.map((row) => row.source_tool)));

  const workflowTab = data?.workflow?.tabs?.[tab];
  useEffect(() => {
    if (!data?.workflow) return;
    // 旧链接先映射到新五阶段，再进入门控校验，避免旧键不在 workflow.tabs 中被提前跳过。
    if (LEGACY_TAB[tab]) {
      if (tab === "findings") setReviewView("findings");
      if (tab === "paths") setReviewView("paths");
      if (tab === "manual") setReviewView("manual");
      if (tab === "clauses") setReviewView("clauses");
      selectTab(LEGACY_TAB[tab]);
      return;
    }
    if (!workflowTab) return;
    const jobStatus = data.selected_job?.status || "";
    const scanning = jobStatus === "queued" || jobStatus === "running" || Boolean(activeScanId && data.selected_job?.job_id !== activeScanId);
    if (scanning && LATER_TABS.includes(tab)) {
      setNotice("这一轮核查还在进行。采集完成之后，这一步才会打开。");
      selectTab("collect");
      return;
    }
    if (workflowTab.enabled) return;
    const fallback = data.workflow.next_step?.key && data.workflow.tabs[data.workflow.next_step.key]?.enabled
      ? data.workflow.next_step.key
      : "overview";
    if (fallback !== tab) {
      setNotice(workflowTab.reason || "这一步还不能进入");
      selectTab(fallback);
    }
  }, [data, tab, activeScanId]);

  if (!data) return <div className="card card-pad">{error || "正在加载评估项目..."}</div>;
  const page = data;
  const selected = page.jobs.find((job) => job.job_id === jobId) || page.selected_job;
  const writable = allowed && data.workflow?.writable !== false;
  const manualWritable = allowed && data.workflow?.manual_writable !== false;
  const flowTabs = ["assets", "collect", "review", "reports", "delivery"] as const;
  const alwaysTabs = ["overview"] as const;
  const scanningNow = Boolean(activeScanId) && (page.selected_job?.job_id !== activeScanId || ["queued", "running"].includes(page.selected_job?.status || ""));

  async function saveAsset(includeHost: boolean) {
    if (savingAsset) return;
    setSavingAsset(true);
    setAssetError("");
    try {
      const host = assetForm.host.trim();
      if (includeHost) {
        const cidr = `${host}/32`;
        const current = page.project.whitelist_cidrs || [];
        if (!current.includes(cidr)) {
          await api(`/api/projects/${projectId}/scope`, {
            method: "PATCH",
            body: JSON.stringify({
              env_tier: page.project.env_tier || "L1_TEST",
              whitelist_cidrs: [...current, cidr],
              max_concurrency: page.project.max_concurrency || 2,
              nuclei_rate_limit: page.project.nuclei_rate_limit || 50,
            }),
          });
        }
      }
      const exists = page.assets.some((item) => item.asset_id && item.asset_id === assetForm.asset_id);
      const path = exists ? `/api/projects/${projectId}/assets/${assetForm.asset_id}` : `/api/projects/${projectId}/assets`;
      await api(path, { method: exists ? "PUT" : "POST", body: JSON.stringify({ ...assetForm, host, scanners: ["nmap", "nuclei", "trivy", "ssh_baseline", "db_mw_baseline"] }) });
      setAssetOpen(false);
      setNotice(includeHost ? "虚拟机已保存，并把这个地址写进了白名单" : "虚拟机已保存");
      await reload();
    } catch (err) {
      setAssetError(err instanceof Error ? err.message : "虚拟机没有保存");
    } finally {
      setSavingAsset(false);
    }
  }

  function tabGate(id: string) {
    const item = page.workflow?.tabs?.[id];
    if (scanningNow && LATER_TABS.includes(id)) {
      return { enabled: false, reason: "这一轮核查还在进行。采集完成之后，这一步才会打开。" };
    }
    return { enabled: Boolean(item?.enabled), reason: item?.enabled ? "" : (item?.reason || "这一步还没有打开") };
  }

  function renderTab(id: string, index: number) {
    const item = page.workflow?.tabs?.[id];
    const gate = tabGate(id);
    const label = item?.label || TABS.find(([key]) => key === id)?.[1] || id;
    const title = item?.step ? `${item.step} ${label}` : label;
    return (
      <span className="tab-item" key={id}>
        <button
          role="tab"
          aria-selected={tab === id}
          className={`${tab === id ? "on" : ""} ${item?.state || ""}`}
          disabled={!gate.enabled}
          title={gate.enabled ? "" : gate.reason}
          onClick={() => selectTab(id)}
        >{title}</button>
        <span className="tab-help">
          <button
            type="button"
            className="tab-help-btn"
            aria-expanded={helpKey === id}
            aria-label={`${label}说明`}
            onClick={(event) => {
              event.stopPropagation();
              setHelpKey((current) => current === id ? "" : id);
            }}
          >?</button>
          {helpKey === id && (
            <div className={`tab-help-pop ${index >= 5 ? "align-end" : ""}`} role="dialog" aria-label={label}>
              <strong>{title}</strong>
              <p>{TAB_HELP[id]}</p>
            </div>
          )}
        </span>
      </span>
    );
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>{data.project.name}</h1>
          <p>{data.project.summary}</p>
          <p className="muted">密级 {data.project.env_tier || "未设置"} · 状态 {statusText(data.project.status || "active")} · 适用条款 {data.project.clause_count || data.clauses.length} 项{(data.project.enabled_extensions || []).includes("CLOUD") ? "（含云扩展）" : "（通用要求）"} · 启用主机 {data.assets.filter((item) => item.is_enabled !== false).length} 台 · 白名单 {(data.project.whitelist_cidrs || []).join("，") || "尚未配置"}</p>
        </div>
        <div className="filters">
          <select value={jobId} onChange={(event) => { setNotice(""); setError(""); setJobId(event.target.value); reload(event.target.value).catch((err: Error) => setError(err.message)); }}>
            {data.jobs.map((job) => <option key={job.job_id} value={job.job_id}>{formatBeijing(job.started_at)} · {statusText(job.status)}</option>)}
          </select>
          <StatusBadge value={selected?.status || "queued"} />
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}
      {data.project.status === "draft" && (
        <div className="banner">
          <span>这个项目还是草稿。启动之后才能配置远程主机，并按顺序发起核查。</span>
          <button className="btn" disabled={!allowed} onClick={() => api(`/api/projects/${projectId}/start`, { method: "POST" }).then(() => reload()).then(() => selectTab("assets")).catch((err: Error) => setError(err.message))}>启动项目</button>
        </div>
      )}
      {data.project.status === "archived" && (
        <div className="banner">
          <span>项目已归档，历史结果可以查看。重新启用之后才能继续修改或发起新的核查。</span>
          <button className="btn" disabled={!allowed} onClick={() => api(`/api/projects/${projectId}/start`, { method: "POST" }).then(() => reload()).catch((err: Error) => setError(err.message))}>重新启用</button>
        </div>
      )}
      <div className="tabbar">
        <div className="tabbar-label">常驻视图</div>
        <div className="tabs" role="tablist">
          {alwaysTabs.map((id, index) => renderTab(id, index))}
        </div>
        <div className="tabbar-label">按顺序推进</div>
        <div className="tabs" role="tablist">
          {flowTabs.map((id, index) => renderTab(id, index))}
        </div>
        {data.workflow?.next_step && <p className="muted step-note">{data.workflow.next_step.reason}</p>}
      </div>
      {tab === "overview" && (
        <>
          <section className="kpi-grid">
            <article className="kpi">
              <div className="label">当前快照</div>
              <div className="value" style={{ fontSize: 16 }}>{selected ? statusText(selected.status) : "无"}</div>
              <div className="muted">模型通道 {data.project.llm_profile} · {data.project.env_tier}</div>
            </article>
            <article className="kpi orange">
              <div className="label">核查完备度</div>
              <div className="value">{data.stats.completeness ?? data.stats.coverage}%</div>
              <div className="muted">适用条款 {data.project.clause_count ?? data.clauses.length} 项 · 待人工 {data.stats.pending_manual} 项</div>
            </article>
            <article className="kpi blue">
              <div className="label">加权已核查 / 保守得分</div>
              <div className="value" style={{ fontSize: 22 }}>
                {data.stats.weighted_checked_score ?? data.stats.checked_score ?? "—"} / {data.stats.weighted_conservative_score ?? data.stats.conservative_score ?? "—"}
              </div>
              <div className="muted">高3/中2/低1 加权 · 等权参考 {data.stats.checked_score ?? "—"} / {data.stats.conservative_score ?? "—"} 分</div>
            </article>
            <article className="kpi">
              <div className="label">{data.stats.verdict_label || "高风险态势"}</div>
              <div className="value">{data.stats.direct_high_fail ?? data.stats.high_fail ?? data.stats.high_open}</div>
              <div className="muted">
                直接高风险不符合 {data.stats.direct_high_fail ?? data.stats.high_fail ?? 0} · 已补偿降级 {data.stats.mitigated_high_count ?? 0} · 未关闭 {data.stats.high_open}
              </div>
            </article>
          </section>

          {data.stats.object_coverage && data.stats.object_coverage.items.length > 0 && (
            <article className="card" style={{ marginTop: 14 }}>
              <div className="section-title">
                <h2>测评对象覆盖矩阵（防止单机抽样假象）</h2>
                <span className="badge ok">已实测 {data.stats.object_coverage.covered_count} 类</span>
                {data.stats.object_coverage.partial_count > 0 && (
                  <span className="badge info">侧向/部分 {data.stats.object_coverage.partial_count} 类</span>
                )}
                {data.stats.object_coverage.unmanaged_count > 0 && (
                  <span className="badge danger">尚未纳管 {data.stats.object_coverage.unmanaged_count} 类</span>
                )}
              </div>
              <div className="card-pad" style={{ paddingTop: 0 }}>
                <p className="muted" style={{ marginTop: 0, marginBottom: 10 }}>{data.stats.object_coverage.summary}</p>
              </div>
              <DataTable
                rows={data.stats.object_coverage.items}
                columns={[
                  { key: "label", title: "测评对象类别", render: (row) => <b>{row.object_label}</b> },
                  { key: "assets", title: "纳管 / 实测资产", render: (row) => `${row.managed_assets} / ${row.scanned_assets}` },
                  { key: "clauses", title: "涉及条款（已决 / 总数）", render: (row) => `${row.decided_clauses} / ${row.applicable_clauses}` },
                  {
                    key: "status",
                    title: "覆盖状态",
                    render: (row) => (
                      <span className={`badge ${row.status === "covered" ? "ok" : row.status === "partial" ? "info" : "danger"}`}>
                        {row.status_label}
                      </span>
                    ),
                  },
                  { key: "note", title: "边界与盲区说明", render: (row) => row.note },
                ]}
              />
            </article>
          )}
        </>
      )}
      {tab === "assets" && (
        <article className="card">
          <div className="section-title">
            <h2>扫描范围以白名单为准</h2>
            <span className="badge danger">扫描机 192.168.1.250 不在范围内</span>
            {writable && <button className="btn-ghost" onClick={() => { setScopeError(""); setScopeForm({ env_tier: data.project.env_tier || "L1_TEST", whitelist: (data.project.whitelist_cidrs || []).join("\n"), max_concurrency: data.project.max_concurrency || 2, nuclei_rate_limit: data.project.nuclei_rate_limit || 50, include_cloud: (data.project.enabled_extensions || []).includes("CLOUD") }); setScopeOpen(true); }}>白名单与密级</button>}
            {writable && <button className="btn" onClick={() => { setAssetError(""); setAssetForm(emptyAsset); setAssetOpen(true); }}>新建虚拟机</button>}
          </div>
          {notice && <div className="banner">{notice}</div>}
          <DataTable
            rows={data.assets}
            columns={[
              { key: "id", title: "资产", render: (row) => row.asset_id },
              { key: "obj", title: "测评对象", render: (row) => <span className="badge info">{OBJECT_TYPE_LABEL[row.object_type || "host_os"] || "主机操作系统"}</span> },
              { key: "host", title: "地址", render: (row) => <span title={row.zone_token}>{row.host_visible}</span> },
              { key: "zone", title: "安全域", render: (row) => row.security_zone },
              { key: "os", title: "系统", render: (row) => row.os_type },
              { key: "mode", title: "模式", render: (row) => (
                <select disabled={!writable} value={row.scan_mode} onClick={(event) => event.stopPropagation()} onChange={async (event) => {
                  await api(`/api/assets/${row.asset_id}/mode`, { method: "PATCH", body: JSON.stringify({ scan_mode: event.target.value }) });
                  await reload();
                }}>
                  <option value="READONLY_AUDIT">只读核查</option>
                  <option value="ACTIVE_SCAN">主动扫描</option>
                </select>
              ) },
              { key: "tools", title: "采集器", render: (row) => row.scanners.join("、") },
              { key: "ops", title: "操作", render: (row) => writable ? (
                <span className="filters">
                  <button className="btn-ghost" onClick={async (event) => { event.stopPropagation(); const result = await api<{ ok: boolean; detail: string }>(`/api/assets/${row.asset_id}/test-ssh`, { method: "POST" }); setNotice(`${row.asset_id}：${result.ok ? "已连通" : "未连通"} ${typeof result.detail === "string" ? result.detail : ""}`); }}>测试 SSH</button>
                  <button className="btn-ghost" onClick={(event) => { event.stopPropagation(); setAssetError(""); setAssetForm({ ...emptyAsset, ...row, ssh_secret: "", host: row.host_visible }); setAssetOpen(true); }}>编辑</button>
                </span>
              ) : null },
            ]}
          />
        </article>
      )}
      {(tab === "scan" || tab === "collect") && (
        <>
          <article className="card card-pad">
            <button className="btn" disabled={!writable || data.workflow?.tabs?.scan?.enabled === false} onClick={() => runScan().catch((err: Error) => setError(err.message))}>发起核查（{data.assets.filter((item) => item.is_enabled !== false).length} 台）</button>
            <p className="muted" style={{ marginTop: 8 }}>这一轮会做 Rocky/CentOS 只读基线、数据库与中间件只读基线（MySQL/MariaDB/PostgreSQL/Redis/Nginx/Tomcat）、软件包漏洞，以及已发现 HTTPS 端口的传输加密检查。Nuclei 排除拒绝服务、模糊测试、侵入和爆破。</p>
            <ScanProgress status={selected?.status || ""} events={events} />
          </article>
          <OfflineImportPanel
            projectId={projectId}
            jobId={jobId}
            writable={writable}
            onImported={async (res) => {
              await reload(res.job_id);
            }}
          />
        </>
      )}
      {tab === "review" && (
        <div className="stage-sub">
          {[["findings", "漏洞与基线"], ["clauses", "条款复核"], ["manual", "人工证据"], ["paths", "攻击路径"]].map(([id, label]) => (
            <button key={id} className={reviewView === id ? "btn" : "btn-ghost"} onClick={() => setReviewView(id)}>{label}</button>
          ))}
        </div>
      )}
      {(tab === "findings" || (tab === "review" && reviewView === "findings")) && (
        <article className="card">
          <div className="card-pad baseline-summary">
            <div className="tabbar-label">当前任务的主机基线</div>
            {baselineSummary.length === 0 && <p className="muted">这一轮还没有主机基线结果。</p>}
            {baselineSummary.map((row) => (
              <p key={row.asset_id}>
                <b>{row.asset_id}</b>
                <span className="badge">共 {row.passed + row.failed} 项</span>
                <span className="badge ok">通过 {row.passed}</span>
                <span className="badge danger">未通过 {row.failed}</span>
              </p>
            ))}
          </div>
          <div className="card-pad filters">
            <input placeholder="搜索标题或 CVE" value={text} onChange={(event) => setText(event.target.value)} />
            <select value={severity} onChange={(event) => setSeverity(event.target.value)}>
              <option value="">全部严重度</option>
              {["critical", "high", "medium", "low", "info"].map((item) => <option key={item} value={item}>{statusText(item)}</option>)}
            </select>
            <select value={assetFilter} onChange={(event) => setAssetFilter(event.target.value)}>
              <option value="">全部资产</option>
              {data.assets.map((item) => <option key={item.asset_id} value={item.asset_id}>{item.asset_id}</option>)}
            </select>
            <select value={tool} onChange={(event) => setTool(event.target.value)}>
              <option value="">全部工具</option>
              {Array.from(new Set(["ssh_baseline", "db_baseline", "mw_baseline", "netdev_config", "cloud_audit", "trivy_os", "tls_scanner", "nmap", "nuclei", ...tools])).map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </div>
          <DataTable rows={findings} onRow={setSelectedFinding} columns={[
            { key: "title", title: "标题", render: (row) => row.title },
            { key: "sev", title: "严重度", render: (row) => <StatusBadge value={row.severity} /> },
            { key: "type", title: "类型", render: (row) => statusText(row.evidence_type) },
            { key: "tool", title: "来源", render: (row) => row.source_tool },
            { key: "cve", title: "CVE", render: (row) => <CveField value={row.cve_or_cwe} /> },
          ]} />
        </article>
      )}
      {(tab === "sanitize" || tab === "collect") && (
        <article className="card card-pad">
          <div className="filters">
            <span className={`badge ${diff?.leak_check_passed ? "ok" : "danger"}`}>{diff?.leak_check_passed ? "零泄漏检查已通过" : "尚未通过零泄漏检查"}</span>
            <button className="btn" disabled={!writable || !diff?.leak_check_passed || reviewing} onClick={() => { void startReview(); }}>{reviewing ? "正在确认并开始评审…" : "确认脱敏结果并开始评审"}</button>
            {reviewing && <p className="muted">模型正在按条款做映射，这一步通常要一两分钟。完成后会自动打开「3 漏洞与条款」。</p>}
          </div>
          <div className="split" style={{ marginTop: 12 }}>
            {(diff?.samples || []).map((sample) => (
              <div key={sample.title}>
                <b>{sample.title}</b>
                {sample.before && <pre className="muted"><CveText text={sample.before} /></pre>}
                <pre><CveText text={sample.after} /></pre>
              </div>
            ))}
          </div>
        </article>
      )}
      {(tab === "clauses" || (tab === "review" && reviewView === "clauses")) && (
        <article className="card">
          <div className="card-pad filters">
            <select value={clauseStatus} onChange={(event) => setClauseStatus(event.target.value)}>
              <option value="">全部状态</option>
              {["compliant", "partially_compliant", "non_compliant", "not_applicable", "pending_manual", "not_assessed"].map((item) => <option key={item} value={item}>{statusText(item)}</option>)}
            </select>
            <select value={clauseObjectFilter} onChange={(event) => setClauseObjectFilter(event.target.value)}>
              <option value="">全部测评对象</option>
              {Object.entries(OBJECT_TYPE_LABEL).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
            </select>
            <label className="check">
              <input type="checkbox" checked={clauseHighOnly} onChange={(event) => setClauseHighOnly(event.target.checked)} />
              只看高风险判例项
            </label>
          </div>
          <DataTable rows={clauseRows} onRow={openClauseDrawer} columns={[
            { key: "id", title: "条款", render: (row) => <span className="mono">{row.clause_id}</span> },
            { key: "point", title: "控制点", render: (row) => row.control_point || "" },
            {
              key: "objects",
              title: "适用对象",
              render: (row) => (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {(row.applicable_object_labels || []).slice(0, 3).map((label) => (
                    <span key={label} className="badge">{label}</span>
                  ))}
                  {(row.applicable_object_labels || []).length > 3 && (
                    <span className="muted">+{(row.applicable_object_labels || []).length - 3}</span>
                  )}
                </div>
              ),
            },
            {
              key: "risk",
              title: "风险 / 补偿",
              render: (row) => {
                if (!row.is_high_risk) return <span className="muted">{RISK_WEIGHT_LABEL[row.risk_weight_level || "medium"]?.split("（")[0] || "中风险"}</span>;
                if (row.compensation_status === "mitigated") return <span className="badge info">高风险 · 已补偿降级</span>;
                return <span className="badge danger">直接高风险</span>;
              },
            },
            { key: "level", title: "级别", render: (row) => AUTO_LABEL[row.auto_level || ""] || row.auto_level || "" },
            { key: "status", title: "状态", render: (row) => <StatusBadge value={row.final_status} /> },
            { key: "note", title: "说明", render: (row) => <CveText text={row.ai_rationale} /> },
          ]} />
        </article>
      )}
      {(tab === "paths" || (tab === "review" && reviewView === "paths")) && (
        <article className="card card-pad">
          {paths.length === 0 && <div className="empty">条款评估完成之后，这里会列出根据证据整理出的攻击路径。</div>}
          {paths.map((path) => (
            <section key={path.path_id} style={{ marginBottom: 16 }}>
              <b>{path.mitigation_priority} · {path.title}</b>
              <ol>{path.steps.map((step) => <li key={step}><CveText text={step} /></li>)}</ol>
            </section>
          ))}
        </article>
      )}
      {(tab === "manual" || (tab === "review" && reviewView === "manual")) && (
        <article className="card card-pad">
          <div className="filters">
            <select value={manual.clause_id} onChange={(event) => setManual({ ...manual, clause_id: event.target.value })}>
              {data.clauses.map((clause) => <option key={clause.clause_id} value={clause.clause_id}>{clause.clause_id} {clause.control_point}</option>)}
            </select>
            <input className="inline-input" value={manual.filename} onChange={(event) => setManual({ ...manual, filename: event.target.value })} />
            <input className="inline-input" placeholder="证据说明" value={manual.note} onChange={(event) => setManual({ ...manual, note: event.target.value })} />
            <button className="btn" disabled={!manualWritable} onClick={async () => { await api(`/api/projects/${projectId}/manual-evidence`, { method: "POST", body: JSON.stringify(manual) }); setDocs(await api(`/api/projects/${projectId}/manual-evidence`)); }}>登记</button>
          </div>
          <ul>{docs.map((doc) => <li key={doc.evidence_doc_id}>{doc.clause_id} · {doc.filename} · {doc.note}</li>)}</ul>
        </article>
      )}
      {tab === "reports" && (
        <article className="card card-pad">
          <div className="filters">
            <button className="btn" disabled={!writable || regenerating || data.workflow?.tabs?.reports?.enabled === false} onClick={async () => {
              setRegenerating(true); setError("");
              try {
                const result = await api<{ delivery_ready?: boolean; narrative?: { prompt_version?: number } }>(`/api/reports/${jobId}/generate`, { method: "POST", body: JSON.stringify({ variant: "masked", refresh_ai: true }) });
                await reload(jobId);
                if (result.delivery_ready) setNotice(`脱敏版中文 Word 终版报告、网页版与整改工单已生成（AI 提示词 v${result.narrative?.prompt_version || 1}），可以进入协同交付。`);
              } catch (err) {
                setError(err instanceof Error ? err.message : "生成报告没有完成");
              } finally {
                setRegenerating(false);
              }
            }}>{regenerating ? "正在生成 AI 专业报告…" : "生成脱敏版（含 AI 专业解读与 Word 终版）"}</button>
            <button className="btn-ghost" disabled={!writable || regenerating || data.workflow?.tabs?.reports?.enabled === false} onClick={async () => {
              setRegenerating(true); setError("");
              try {
                await api(`/api/reports/${jobId}/generate`, { method: "POST", body: JSON.stringify({ variant: "restored" }) });
                await reload(jobId);
                setNotice("受控还原版中文 Word 报告与网页版已生成。");
              } catch (err) {
                setError(err instanceof Error ? err.message : "生成还原版报告没有完成");
              } finally {
                setRegenerating(false);
              }
            }}>生成受控还原版</button>
            {data.workflow?.tabs?.delivery?.enabled && <button className="btn" onClick={() => selectTab("delivery")}>前往 {data.workflow.tabs.delivery.step} {data.workflow.tabs.delivery.label}</button>}
          </div>
          <p className="muted" style={{ marginTop: 10 }}>
            生成报告时，系统会依据「系统管理 → 报告 AI 提示词」中的等保三级系统提示词撰写管理摘要、各安全域差距剖析与分阶段整改路线，并同步输出中文 Word 终版（.docx）、网页打印版与分部门整改工单。
          </p>
          <ul>{data.reports.map((report) => <li key={report.report_id}><button className="btn-ghost" onClick={() => download(`/api/reports/${report.report_id}/download`, report.filename)}>{report.filename}</button></li>)}</ul>
        </article>
      )}
      {tab === "delivery" && (
        <DeliveryCenter
          projectName={data.project.name}
          clauseTotal={clauses.length || data.project.clause_count || data.clauses.length}
          delivery={delivery}
          reports={data.reports}
          writable={writable}
          isAdmin={savedUser()?.role === "admin"}
          deliveryEnabled={data.workflow?.tabs?.delivery?.enabled !== false}
          pushing={pushing}
          pulling={pulling}
          delivering={delivering}
          regenerating={regenerating}
          onPushDojo={async () => {
            setPushing(true); setError("");
            try {
              const result = await api<{ detail?: string }>(`/api/projects/${projectId}/delivery/defectdojo-push?job_id=${jobId}`, { method: "POST" });
              setNotice(result.detail || "已完成漏洞推送");
              await reload(jobId);
            } catch (err) { setError(err instanceof Error ? err.message : "推送没有完成"); }
            finally { setPushing(false); }
          }}
          onPullDojo={async () => {
            setPulling(true); setError("");
            try {
              const result = await api<{ detail?: string; summary?: string }>(`/api/projects/${projectId}/delivery/defectdojo-pull?job_id=${jobId}`, { method: "POST" });
              setNotice(result.detail || result.summary || "已同步最新整改状态");
              await reload(jobId);
            } catch (err) { setError(err instanceof Error ? err.message : "同步状态没有完成"); }
            finally { setPulling(false); }
          }}
          onDeliverCiso={async () => {
            if (deliveringRef.current) return;
            deliveringRef.current = true;
            setDelivering(true);
            setError("");
            try {
              const result = await api<{ passed?: boolean; leaks?: string[]; detail?: string }>(`/api/projects/${projectId}/delivery/ciso-deliver?job_id=${jobId}`, { method: "POST" });
              if (result.passed === false) setError(result.detail || "二次脱敏终检未通过");
              else setNotice(result.detail || "已写入 CISO Assistant 并更新中文终版报告");
              await reload(jobId);
            } catch (err) {
              setError(err instanceof Error ? err.message : "写入 CISO Assistant 没有完成");
            } finally {
              deliveringRef.current = false;
              setDelivering(false);
            }
          }}
          onGenerateReport={async (variant, refreshAi) => {
            setRegenerating(true); setError("");
            try {
              const result = await api<{ narrative?: { status?: string; prompt_version?: number } }>(`/api/reports/${jobId}/generate`, {
                method: "POST",
                body: JSON.stringify({ variant, refresh_ai: refreshAi }),
              });
              await reload(jobId);
              const label = variant === "restored" ? "内部受控还原版" : "脱敏版中文 Word 终版与网页报告";
              setNotice(`${label}已更新（提示词 v${result.narrative?.prompt_version || 1}）。`);
            } catch (err) {
              setError(err instanceof Error ? err.message : "重新生成报告没有完成");
            } finally {
              setRegenerating(false);
            }
          }}
        />
      )}
      <Drawer open={!!selectedFinding} title={selectedFinding?.title || ""} onClose={() => setSelectedFinding(null)}>
        {selectedFinding && (() => {
          const copy = findingCopy(selectedFinding.detail);
          return (
            <dl className="finding-detail">
              <div><dt>说明</dt><dd><CveText text={copy.text} /></dd></div>
              <div><dt>严重度</dt><dd><StatusBadge value={selectedFinding.severity} /></dd></div>
              <div><dt>类型</dt><dd>{statusText(selectedFinding.evidence_type)}</dd></div>
              <div><dt>来源</dt><dd>{selectedFinding.source_tool}</dd></div>
              <div><dt>CVE</dt><dd><CveField value={selectedFinding.cve_or_cwe} /></dd></div>
              {copy.hints.length > 0 && <div><dt>关联条款</dt><dd>{copy.hints.join("、")}</dd></div>}
              {copy.maskedHints && <div><dt>关联条款</dt><dd className="muted">这轮脱敏把条款编号里的数字当成了地址。重新采集后，这里会显示原来的条款编号。</dd></div>}
            </dl>
          );
        })()}
      </Drawer>
      <Drawer open={!!selectedClause} title={selectedClause?.clause_id || "条款复核"} onClose={() => setSelectedClause(null)}>
        {selectedClause && (
          <>
            <p style={{ marginTop: 0 }}>
              <b>{selectedClause.domain || ""}</b>{selectedClause.control_point ? ` · ${selectedClause.control_point}` : ""}{" "}
              <span className="badge">{RISK_WEIGHT_LABEL[selectedClause.risk_weight_level || "medium"] || "中风险（权重 2）"}</span>
              {selectedClause.compensation_status === "mitigated" && <span className="badge info" style={{ marginLeft: 6 }}>已补偿降级</span>}
            </p>
            {selectedClause.requirement_text && <p style={{ margin: "8px 0" }}>{selectedClause.requirement_text}</p>}
            {(selectedClause.applicable_object_labels || []).length > 0 && (
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6, marginBottom: 10 }}>
                <span className="muted">适用测评对象：</span>
                {(selectedClause.applicable_object_labels || []).map((label) => (
                  <span key={label} className="badge info">{label}</span>
                ))}
              </div>
            )}
            <div className="muted">当前评审依据</div>
            <p><CveText text={selectedClause.ai_rationale} /></p>
            {selectedClause.remediation_script && <pre><CveText text={selectedClause.remediation_script} /></pre>}
            {selectedClause.high_risk_precedent && (
              <div style={{ border: "1px solid var(--border)", borderLeft: "3px solid var(--accent)", borderRadius: 6, padding: "10px 12px", margin: "12px 0" }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>
                  高风险判例参考（{selectedClause.high_risk_precedent.standard_ref} · {selectedClause.high_risk_precedent.precedent_code}）
                </div>
                <p style={{ margin: "4px 0" }}>
                  <b>判例类别：</b>{selectedClause.high_risk_precedent.category}{" "}
                  <span className={`badge ${selectedClause.high_risk_precedent.can_downgrade_with_compensation ? "info" : "danger"}`}>
                    {selectedClause.high_risk_precedent.can_downgrade_with_compensation ? "存在有效补偿措施可评估降级" : "核心底线 · 建议优先直接整改"}
                  </span>
                </p>
                <p style={{ margin: "4px 0" }}><b>高风险触发情形：</b>{selectedClause.high_risk_precedent.trigger_condition}</p>
                {selectedClause.high_risk_precedent.compensating_controls.length > 0 && (
                  <ul style={{ margin: "6px 0 0 18px", padding: 0 }}>
                    {selectedClause.high_risk_precedent.compensating_controls.map((item) => (
                      <li key={item} style={{ marginBottom: 4 }}>{item}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
            {selectedClause.is_high_risk && (
              <div style={{ margin: "12px 0", padding: "10px 12px", border: "1px dashed var(--border)", borderRadius: 6 }}>
                <label className="check" style={{ marginBottom: 8 }}>
                  <input
                    type="checkbox"
                    disabled={!writable}
                    checked={compMitigated}
                    onChange={(event) => setCompMitigated(event.target.checked)}
                  />
                  已采纳有效补偿控制并申请高风险降级（按中风险权重折算，不计入直接高风险阻断红线）
                </label>
                {compMitigated && (
                  <label className="field">
                    补偿控制措施与佐证说明
                    <textarea
                      disabled={!writable}
                      placeholder="请简述已落地的补偿控制措施（例如：经堡垒机双因子跳转+网络白名单隔离）及留痕材料"
                      value={compNote}
                      onChange={(event) => setCompNote(event.target.value)}
                    />
                  </label>
                )}
              </div>
            )}
            <label className="field">复核说明<textarea value={note} onChange={(event) => setNote(event.target.value)} /></label>
            <div className="filters">
              {["compliant", "partially_compliant", "non_compliant", "not_applicable", "pending_manual"].map((item) => (
                <button key={item} className="btn-ghost" disabled={!writable} onClick={async () => {
                  await api(`/api/compliance/clauses/${selectedClause.assessment_id}`, {
                    method: "PATCH",
                    body: JSON.stringify({
                      manual_status: item,
                      note,
                      compensation_status: selectedClause.is_high_risk && compMitigated ? "mitigated" : "none",
                      compensation_note: selectedClause.is_high_risk && compMitigated ? compNote : "",
                    }),
                  });
                  setSelectedClause(null);
                  await reload(jobId);
                }}>{statusText(item)}</button>
              ))}
            </div>
          </>
        )}
      </Drawer>
      <Modal open={assetOpen} title={data.assets.some((item) => item.asset_id === assetForm.asset_id) ? "编辑虚拟机" : "新建虚拟机"} onClose={() => setAssetOpen(false)}>
        <label className="field">地址<input value={assetForm.host} onChange={(event) => setAssetForm({ ...assetForm, host: event.target.value })} /></label>
        <label className="field">测评对象类别
          <select value={assetForm.object_type || "host_os"} onChange={(event) => setAssetForm({ ...assetForm, object_type: event.target.value })}>
            {TECH_OBJECT_OPTIONS.map(([key, label]) => (
              <option key={key} value={key}>{label}</option>
            ))}
          </select>
        </label>
        <label className="field">安全域<input value={assetForm.security_zone} onChange={(event) => setAssetForm({ ...assetForm, security_zone: event.target.value })} /></label>
        <label className="field">系统
          <select value={assetForm.os_type} onChange={(event) => setAssetForm({ ...assetForm, os_type: event.target.value })}>
            <option value="rocky_linux">Rocky Linux</option>
            <option value="centos">CentOS</option>
          </select>
        </label>
        <label className="field">SSH 端口<input type="number" value={assetForm.ssh_port} onChange={(event) => setAssetForm({ ...assetForm, ssh_port: Number(event.target.value) })} /></label>
        <label className="field">SSH 用户<input value={assetForm.ssh_user} onChange={(event) => setAssetForm({ ...assetForm, ssh_user: event.target.value })} /></label>
        <label className="field">认证方式
          <select value={assetForm.ssh_auth_mode} onChange={(event) => setAssetForm({ ...assetForm, ssh_auth_mode: event.target.value })}>
            <option value="env_ref">引用环境变量</option>
            <option value="encrypted_password">加密保存口令</option>
            <option value="encrypted_key">加密保存私钥</option>
          </select>
        </label>
        {assetForm.ssh_auth_mode === "env_ref" ? (
          <>
            <label className="field">口令变量名<input value={assetForm.ssh_secret_env} onChange={(event) => setAssetForm({ ...assetForm, ssh_secret_env: event.target.value })} /></label>
            <label className="field">私钥路径变量名<input value={assetForm.ssh_key_env} onChange={(event) => setAssetForm({ ...assetForm, ssh_key_env: event.target.value })} /></label>
          </>
        ) : (
          <label className="field">口令或私钥<textarea value={assetForm.ssh_secret} onChange={(event) => setAssetForm({ ...assetForm, ssh_secret: event.target.value })} placeholder="留空则保留已保存的凭据" /></label>
        )}
        <label className="field">备注<input value={assetForm.notes} onChange={(event) => setAssetForm({ ...assetForm, notes: event.target.value })} /></label>
        {assetError && <div className="error" style={{ marginBottom: 12 }}>{assetError}</div>}
        <div className="filters">
          <button className="btn" disabled={savingAsset} onClick={() => { void saveAsset(false); }}>{savingAsset ? "正在保存…" : "保存"}</button>
          {assetError.includes("白名单") && (
            <button className="btn-ghost" disabled={savingAsset} onClick={() => { void saveAsset(true); }}>加入白名单并保存</button>
          )}
        </div>
      </Modal>
      <Modal open={scopeOpen} title="白名单与密级" onClose={() => setScopeOpen(false)}>
        <label className="field">密级
          <select value={scopeForm.env_tier} onChange={(event) => setScopeForm({ ...scopeForm, env_tier: event.target.value })}>
            <option value="L1_TEST">L1_TEST 测试环境</option>
            <option value="L2_INTERNAL">L2_INTERNAL 内网</option>
            <option value="L3_CROSSBORDER_APPROVED">L3_CROSSBORDER_APPROVED 已批准跨境</option>
          </select>
        </label>
        <label className="field">白名单网段，一行一个<textarea value={scopeForm.whitelist} onChange={(event) => setScopeForm({ ...scopeForm, whitelist: event.target.value })} /></label>
        <label className="field">同时核查的主机数<input type="number" value={scopeForm.max_concurrency} onChange={(event) => setScopeForm({ ...scopeForm, max_concurrency: Number(event.target.value) })} /></label>
        <label className="field">Nuclei 速率<input type="number" value={scopeForm.nuclei_rate_limit} onChange={(event) => setScopeForm({ ...scopeForm, nuclei_rate_limit: Number(event.target.value) })} /></label>
        <div className="field">
          <span>适用标准条款</span>
          <label className="check" style={{ marginTop: 6 }}>
            <input type="checkbox" checked disabled />
            安全通用要求（GB/T 22239-2019 第三级必选，211 项）
          </label>
          <label className="check" style={{ marginTop: 6 }}>
            <input
              type="checkbox"
              checked={scopeForm.include_cloud}
              onChange={(event) => setScopeForm({ ...scopeForm, include_cloud: event.target.checked })}
            />
            云计算安全扩展要求（叠加 46 项，合计 257 项；修改后下一轮评审生效）
          </label>
        </div>
        {scopeError && <div className="error" style={{ marginBottom: 12 }}>{scopeError}</div>}
        <button className="btn" onClick={async () => {
          setScopeError("");
          try {
            const result = await api<{ warning?: string }>(`/api/projects/${projectId}/scope`, { method: "PATCH", body: JSON.stringify({ env_tier: scopeForm.env_tier, whitelist_cidrs: scopeForm.whitelist.split(/\s+/).filter(Boolean), max_concurrency: scopeForm.max_concurrency, nuclei_rate_limit: scopeForm.nuclei_rate_limit, enabled_extensions: scopeForm.include_cloud ? ["GENERAL", "CLOUD"] : ["GENERAL"] }) });
            setScopeOpen(false);
            setNotice(result.warning || "范围已保存");
            await reload();
          } catch (err) {
            setScopeError(err instanceof Error ? err.message : "范围没有保存");
          }
        }}>保存</button>
      </Modal>
    </>
  );
}
