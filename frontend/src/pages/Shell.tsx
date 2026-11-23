import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, clearSession, savedUser, type User } from "../api";
import Workspace from "./Workspace";

const THEMES = [
  ["classic_red", "经典红白"],
  ["arctic_blue", "极地蓝白"],
  ["midnight_dark", "暗夜深空"],
];

const NAV = [
  ["workspace", "评估项目"],
  ["dashboard", "全局大盘"],
  ["todos", "我的待办"],
  ["clauses", "等保条款库"],
  ["engine", "AI 评审引擎"],
  ["connectors", "工具连接器"],
  ["admin", "系统管理"],
];

function ModulePage({ name, payload, error, query }: { name: string; payload: unknown; error: string; query: string }) {
  const rows = Array.isArray(payload) ? payload as Array<Record<string, unknown>> : [];
  return (
    <section className="card" style={{ padding: 16 }}>
      <div className="eyebrow">{name}</div>
      {error && <div className="toast">{error}</div>}
      {name === "connectors" && (
        <table>
          <thead><tr><th>连接器</th><th>已配置</th><th>可达</th><th>说明</th></tr></thead>
          <tbody>{rows.map((row) => (
            <tr key={String(row.name)}>
              <td>{String(row.name)}</td>
              <td>{row.configured ? "是" : "否"}</td>
              <td>{row.reachable ? "是" : "否"}</td>
              <td>{String(row.detail || "")}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {name === "clauses" && (
        <table>
          <thead><tr><th>条款</th><th>安全域</th><th>控制点</th><th>自动化</th><th>要求</th></tr></thead>
          <tbody>{rows.filter((row) => JSON.stringify(row).includes(query)).map((row) => (
            <tr key={String(row.clause_id)}>
              <td>{String(row.clause_id)}{row.high_risk ? " · 高风险" : ""}</td>
              <td>{String(row.domain)}</td>
              <td>{String(row.control_point)}</td>
              <td>{String(row.auto_level)}</td>
              <td>{String(row.requirement_text)}</td>
            </tr>
          ))}</tbody>
        </table>
      )}
      {name === "admin" && (
        <table>
          <thead><tr><th>姓名</th><th>邮箱</th><th>角色</th><th>主题</th></tr></thead>
          <tbody>{rows.map((row) => (
            <tr key={String(row.user_id)}><td>{String(row.display_name)}</td><td>{String(row.email)}</td><td>{String(row.role)}</td><td>{String(row.theme_preference)}</td></tr>
          ))}</tbody>
        </table>
      )}
      {name === "engine" && (
        rows.length === 0 ? <p>脱敏结果确认之后，调用记录会出现在这里。</p> : (
          <table>
            <thead><tr><th>阶段</th><th>模型</th><th>状态</th><th>耗时</th><th>说明</th></tr></thead>
            <tbody>{rows.map((row, index) => (
              <tr key={String(row.log_id || index)}><td>{String(row.stage)}</td><td>{String(row.model_id)}</td><td>{String(row.status)}</td><td>{String(row.latency_ms || "")}</td><td>{String(row.error_detail || "")}</td></tr>
            ))}</tbody>
          </table>
        )
      )}
      {name === "todos" && <TodoView payload={payload} />}
      {name === "dashboard" && <Dashboard payload={payload} />}
    </section>
  );
}

function Dashboard({ payload }: { payload: unknown }) {
  const data = (payload || {}) as {
    project?: { name: string; summary: string; llm_profile: string; stage_label: string };
    stats?: { coverage: number; high_open: number; pending_manual: number; job: { status: string } | null };
    assets?: Array<{ asset_id: string; security_zone: string; scan_mode: string }>;
  };
  if (!data.project) return <p>正在读取评估项目。</p>;
  return (
    <>
      <h1>{data.project.name}</h1>
      <p>{data.project.summary}</p>
      <section className="metrics">
        <div><div className="eyebrow">任务状态</div><div className="kpi">{data.stats?.job?.status || "未开始"}</div></div>
        <div><div className="eyebrow">条款覆盖率</div><div className="kpi">{data.stats?.coverage ?? 0}%</div></div>
        <div><div className="eyebrow">高风险未关闭</div><div className="kpi">{data.stats?.high_open ?? 0}</div></div>
        <div><div className="eyebrow">待人工</div><div className="kpi">{data.stats?.pending_manual ?? 0}</div></div>
      </section>
      <p className="sub">模型通道 {data.project.llm_profile} · {data.project.stage_label}</p>
      <ul>{(data.assets || []).map((asset) => <li key={asset.asset_id}>{asset.asset_id} · {asset.security_zone} · {asset.scan_mode}</li>)}</ul>
    </>
  );
}

function TodoView({ payload }: { payload: unknown }) {
  const data = (payload || {}) as { pending_clauses?: Array<Record<string, string>>; awaiting_approval?: { job_id: string } | null; manual_docs?: Array<Record<string, string>> };
  return (
    <>
      <p>{data.awaiting_approval ? `任务 ${data.awaiting_approval.job_id} 还等人工确认脱敏结果` : "目前没有等待确认的脱敏结果。"}</p>
      <div className="eyebrow">待人工条款</div>
      <ul>{(data.pending_clauses || []).map((row) => <li key={row.assessment_id || row.clause_id}>{row.clause_id} · {row.final_status}</li>)}</ul>
      <div className="eyebrow">已登记证据</div>
      <ul>{(data.manual_docs || []).map((row) => <li key={row.evidence_doc_id}>{row.clause_id} · {row.filename}</li>)}</ul>
    </>
  );
}

export default function Shell() {
  const navigate = useNavigate();
  const [page, setPage] = useState("workspace");
  const [user, setUser] = useState<User | null>(savedUser());
  const [query, setQuery] = useState("");
  const [payload, setPayload] = useState<unknown>(null);
  const [error, setError] = useState("");
  const theme = document.documentElement.dataset.theme || user?.theme_preference || "classic_red";

  useEffect(() => {
    api<User>("/api/auth/me").then(setUser).catch(() => {
      clearSession();
      navigate("/login");
    });
  }, [navigate]);

  async function applyTheme(next: string) {
    document.documentElement.dataset.theme = next;
    localStorage.setItem("mlps_theme", next);
    await api("/api/auth/theme", { method: "PATCH", body: JSON.stringify({ theme: next }) });
  }

  async function load(kind: string) {
    setError("");
    try {
      if (kind === "dashboard") setPayload(await api("/api/projects/prj_stage1/overview"));
      if (kind === "todos") setPayload(await api("/api/todos"));
      if (kind === "clauses") setPayload(await api("/api/clauses"));
      if (kind === "engine") setPayload(await api("/api/llm/audit"));
      if (kind === "connectors") setPayload(await api("/api/connectors"));
      if (kind === "admin") setPayload(await api("/api/users"));
    } catch (err) {
      setError(err instanceof Error ? err.message : "加载失败");
    }
  }

  useEffect(() => { if (page !== "workspace") void load(page); }, [page]);

  const filtered = Array.isArray(payload)
    ? payload.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase()))
    : payload;

  return (
    <div className="shell">
      <aside className="side">
        <div className="brand"><span style={{ color: "var(--accent-primary)" }}>MLPS</span> 等保三级扫描与报告</div>
        <input className="search" placeholder="搜索条款 / 资产 / CVE" value={query} onChange={(event) => setQuery(event.target.value)} />
        <div className="eyebrow" style={{ marginTop: 16 }}>FACTORY MODULES</div>
        <nav>
          {NAV.map(([id, label]) => (
            <button key={id} className={page === id ? "active" : ""} onClick={() => setPage(id)}>{label}</button>
          ))}
        </nav>
        <div className="side-foot">
          <div className="stripe" />
          <div className="themes">
            {THEMES.map(([id, label]) => (
              <button key={id} className={theme === id ? "on" : ""} onClick={() => applyTheme(id)}>● {label}</button>
            ))}
          </div>
          <div><strong>{user?.display_name}</strong><div className="sub">{user?.role}</div></div>
          <button className="btn ghost" onClick={() => { clearSession(); navigate("/login"); }}>退出登录</button>
        </div>
      </aside>
      <main className="main"><div className="wrap">
        {page === "workspace" ? <Workspace /> : <ModulePage name={page} payload={filtered} error={error} query={query} />}
      </div></main>
    </div>
  );
}
