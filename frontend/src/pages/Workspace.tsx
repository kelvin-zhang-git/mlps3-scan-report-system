import { useEffect, useMemo, useState } from "react";
import { api, download } from "../api";
import { formatBeijing } from "../time";

type Overview = {
  project: { name: string; summary: string; stage_label: string; classification: string; env_tier: string; llm_profile: string; project_id: string };
  assets: Array<{ asset_id: string; host: string; security_zone: string; os_type: string; scan_mode: string; scanners: string[] }>;
  stats: { job: { job_id: string; status: string; progress_pct: number } | null; clause_total: number; coverage: number; high_open: number; high_total: number; high_closed_rate: number; pending_manual: number };
  jobs: Array<{ job_id: string; status: string; started_at: string; progress_pct: number }>;
  reports: Array<{ report_id: string; filename: string; variant: string }>;
  clauses: Array<{ clause_id: string; domain: string; auto_level: string; high_risk: boolean; control_point: string; requirement_text: string }>;
};

const TABS = ["概览", "资产白名单", "扫描采集", "漏洞与基线", "脱敏审计", "AI 条款映射", "攻击路径", "人工证据", "报告制品"] as const;

export default function Workspace() {
  const [data, setData] = useState<Overview | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("概览");
  const [error, setError] = useState("");
  const [events, setEvents] = useState<Array<{ message: string; stage: string }>>([]);
  const [evidences, setEvidences] = useState<Array<Record<string, unknown>>>([]);
  const [diff, setDiff] = useState<Record<string, unknown> | null>(null);
  const [clauses, setClauses] = useState<Array<Record<string, unknown>>>([]);
  const [paths, setPaths] = useState<Array<Record<string, unknown>>>([]);
  const [docs, setDocs] = useState<Array<Record<string, string>>>([]);
  const [note, setNote] = useState("机房与制度证据待补充");

  const jobId = data?.stats.job?.job_id || "";

  async function reload() {
    const overview = await api<Overview>("/api/projects/prj_stage1/overview");
    setData(overview);
    if (overview.stats.job) {
      const id = overview.stats.job.job_id;
      setEvidences(await api(`/api/evidences/${id}`));
      setClauses(await api(`/api/compliance/${id}/clauses`));
      setPaths(await api(`/api/compliance/${id}/attack-paths`));
      try { setDiff(await api(`/api/sanitization/${id}/diff`)); } catch { setDiff(null); }
    }
    setDocs(await api("/api/manual-evidence"));
  }

  useEffect(() => { reload().catch((err: Error) => setError(err.message)); }, []);

  async function runScan() {
    setError("");
    setEvents([]);
    const job = await api<{ job_id: string }>("/api/scans/run", { method: "POST" });
    const timer = window.setInterval(async () => {
      const detail = await api<{ job: { status: string }; events: Array<{ message: string; stage: string }> }>(`/api/scans/${job.job_id}`);
      setEvents(detail.events);
      if (["awaiting_approval", "completed", "failed"].includes(detail.job.status)) {
        window.clearInterval(timer);
        await reload();
      }
    }, 800);
  }

  async function approve() {
    if (!jobId) return;
    await api(`/api/sanitization/${jobId}/approve`, { method: "POST" });
    await api(`/api/compliance/${jobId}/assess`, { method: "POST" });
    await reload();
    setTab("AI 条款映射");
  }

  async function generate(variant: "masked" | "restored") {
    if (!jobId) return;
    await api(`/api/reports/${jobId}/generate`, { method: "POST", body: JSON.stringify({ variant }) });
    await reload();
  }

  const domains = useMemo(() => Array.from(new Set((data?.clauses || []).map((item) => item.domain))), [data]);

  if (!data) return <div className="card" style={{ padding: 16 }}>{error || "正在加载评估项目..."}</div>;

  return (
    <>
      <section className="card header">
        <div>
          <div className="eyebrow">ASSESSMENT WORKSPACE</div>
          <h1>{data.project.name}</h1>
          <p>{data.project.summary}</p>
        </div>
        <div className="badges">
          <span className="pill danger">{data.project.stage_label}</span>
          <span className="pill">{data.project.classification}</span>
        </div>
      </section>
      <div className="tabs">
        {TABS.map((item) => <button key={item} className={tab === item ? "on" : ""} onClick={() => setTab(item)}>{item}</button>)}
      </div>
      {error && <div className="toast">{error}</div>}
      {tab === "概览" && (
        <>
          <section className="card strip">
            <div><div className="eyebrow">LIFECYCLE · 评估阶段</div><strong>{data.stats.job?.status || "未开始"}</strong></div>
            <div><div className="eyebrow">BASELINE · 测评基线</div><strong>GB/T 22239-2019</strong></div>
            <div><div className="eyebrow">LLM ROUTE · 合规通道</div><strong>{data.project.llm_profile}</strong></div>
            <div><div className="eyebrow">PII REDACTION · 敏感脱敏</div><strong>{diff ? "已开启" : "待采集"}</strong></div>
          </section>
          <section className="card">
            <div className="header"><strong>评估版本</strong><span className="eyebrow">ASSESSMENT TIMELINE</span></div>
            {data.jobs.length === 0 ? <p style={{ padding: "0 16px 16px" }}>还没有评估快照。请到「扫描采集」发起只读核查。</p> : (
              <table><tbody>{data.jobs.map((job) => <tr key={job.job_id}><td>{formatBeijing(job.started_at)}</td><td>{job.job_id}</td><td>{job.status}</td><td>{job.progress_pct}%</td></tr>)}</tbody></table>
            )}
          </section>
          <section className="card metrics">
            <div><div className="eyebrow">条款覆盖率</div><div className="kpi">{data.stats.coverage}%</div><div className="sub">待人工 {data.stats.pending_manual}</div></div>
            <div><div className="eyebrow">高风险未关闭</div><div className="kpi">{data.stats.high_open}</div><div className="sub">共 {data.stats.high_total} 项</div></div>
            <div><div className="eyebrow">高风险关闭率</div><div className="kpi">{data.stats.high_closed_rate}%</div></div>
            <div><div className="eyebrow">安全域</div><div className="kpi">{domains.length}</div><div className="sub">含云计算扩展</div></div>
          </section>
        </>
      )}
      {tab === "资产白名单" && (
        <section className="card">
          <div className="header"><strong>扫描范围是 192.168.1.220/32</strong><span className="pill danger">192.168.1.250 不在范围内</span></div>
          <table>
            <thead><tr><th>资产</th><th>地址</th><th>安全域</th><th>模式</th><th>采集器</th></tr></thead>
            <tbody>{data.assets.map((asset) => (
              <tr key={asset.asset_id}><td>{asset.asset_id}</td><td>ZONE_DMZ_HOST_01</td><td>{asset.security_zone}</td><td>{asset.scan_mode}</td><td>{asset.scanners.join(", ")}</td></tr>
            ))}</tbody>
          </table>
        </section>
      )}
      {tab === "扫描采集" && (
        <section className="card" style={{ padding: 16 }}>
          <div className="row-actions"><button className="btn" onClick={() => runScan().catch((err: Error) => setError(err.message))}>发起只读核查</button><span className="sub">Nuclei 排除 dos / fuzz / intrusive / bruteforce</span></div>
          <div style={{ marginTop: 12 }}>{events.map((event, index) => <div key={index} className="sub">{event.stage} · {event.message}</div>)}</div>
        </section>
      )}
      {tab === "漏洞与基线" && (
        <section className="card">
          <table>
            <thead><tr><th>标题</th><th>类型</th><th>严重度</th><th>来源</th><th>检出</th></tr></thead>
            <tbody>{evidences.map((item) => (
              <tr key={String(item.evidence_id)}><td>{String(item.title)}</td><td>{String(item.evidence_type)}</td><td>{String(item.severity)}</td><td>{String(item.source_tool)}</td><td>{Array.isArray(item.detected_by) ? (item.detected_by as string[]).join(" + ") : String(item.source_tool)}</td></tr>
            ))}</tbody>
          </table>
        </section>
      )}
      {tab === "脱敏审计" && (
        <section className="card" style={{ padding: 16 }}>
          <div className="row-actions"><span className="pill">{diff && diff.leak_check_passed ? "零泄漏检查已通过" : "尚未通过零泄漏检查"}</span><button className="btn" onClick={() => approve().catch((err: Error) => setError(err.message))}>确认脱敏结果并开始评审</button></div>
          <div className="split" style={{ marginTop: 12 }}>
            {((diff?.samples as Array<Record<string, string>>) || []).map((sample) => (
              <div key={sample.title}>
                <div className="eyebrow">{sample.title}</div>
                {sample.before && <div className="diff">{sample.before}</div>}
                <div className="diff">{sample.after}</div>
              </div>
            ))}
          </div>
        </section>
      )}
      {tab === "AI 条款映射" && (
        <section className="card">
          <table>
            <thead><tr><th>条款</th><th>控制点</th><th>级别</th><th>状态</th><th>说明</th></tr></thead>
            <tbody>{clauses.map((row) => (
              <tr key={String(row.assessment_id)}>
                <td>{String(row.clause_id)}{row.is_high_risk ? " · 高风险" : ""}</td>
                <td>{String(row.control_point || "")}</td>
                <td>{String(row.auto_level || "")}</td>
                <td>{String(row.final_status)}</td>
                <td>{String(row.ai_rationale)}</td>
              </tr>
            ))}</tbody>
          </table>
        </section>
      )}
      {tab === "攻击路径" && (
        <section className="card" style={{ padding: 16 }}>
          {paths.map((path) => (
            <article key={String(path.path_id)} style={{ marginBottom: 12 }}>
              <strong>{String(path.mitigation_priority)} · {String(path.title)}</strong>
              <ol>{(path.steps as string[]).map((step) => <li key={step}>{step}</li>)}</ol>
            </article>
          ))}
        </section>
      )}
      {tab === "人工证据" && (
        <section className="card" style={{ padding: 16 }}>
          <div className="row-actions">
            <input value={note} onChange={(event) => setNote(event.target.value)} />
            <button className="btn" onClick={async () => { await api("/api/manual-evidence", { method: "POST", body: JSON.stringify({ clause_id: "8.1.6.1-a", filename: "安全策略.pdf", note }) }); setDocs(await api("/api/manual-evidence")); }}>登记制度证据</button>
            <button className="btn ghost" onClick={async () => setError(JSON.stringify(await api(`/api/compliance/${jobId}/ciso-sync`, { method: "POST" })))}>同步 CISO</button>
          </div>
          <ul>{docs.map((doc) => <li key={doc.evidence_doc_id}>{doc.clause_id} · {doc.filename} · {doc.note}</li>)}</ul>
        </section>
      )}
      {tab === "报告制品" && (
        <section className="card" style={{ padding: 16 }}>
          <div className="row-actions">
            <button className="btn" onClick={() => generate("masked").catch((err: Error) => setError(err.message))}>生成脱敏版</button>
            <button className="btn ghost" onClick={() => generate("restored").catch((err: Error) => setError(err.message))}>生成受控还原版</button>
          </div>
          <ul>{data.reports.map((report) => <li key={report.report_id}><button className="btn ghost" onClick={() => download(`/api/reports/${report.report_id}/download`, report.filename)}>{report.filename}</button></li>)}</ul>
        </section>
      )}
    </>
  );
}
