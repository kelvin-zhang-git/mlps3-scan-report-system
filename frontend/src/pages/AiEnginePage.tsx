import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, savedUser } from "../api";
import { rememberedProject, rememberProject } from "../project";
import DataTable from "../components/DataTable";
import StatusBadge from "../components/StatusBadge";

type Log = { log_id?: string; stage: string; model_id: string; status: string; latency_ms: number; prompt_tokens: number; completion_tokens: number; error_detail?: string };
type Project = { project_id?: string; name?: string; llm_profile: string; env_tier: string };

export default function AiEnginePage() {
  const [logs, setLogs] = useState<Log[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [project, setProject] = useState<Project | null>(null);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const admin = savedUser()?.role === "admin";

  useEffect(() => {
    Promise.all([
      api<Log[]>("/api/llm/audit"),
      api<Project[]>("/api/projects"),
    ]).then(([audit, rows]) => {
      setLogs(audit);
      setProjects(rows);
      const remembered = rememberedProject();
      const picked = rows.find((item) => item.project_id === remembered) || rows[0];
      if (picked?.project_id) setProjectId(picked.project_id);
    }).catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!projectId) return;
    rememberProject(projectId);
    api<{ project: Project }>(`/api/projects/${projectId}/overview`).then((overview) => setProject(overview.project)).catch((err: Error) => setError(err.message));
  }, [projectId]);

  const rows = logs.filter((row) => !status || row.status === status);
  return (
    <>
      <div className="page-head">
        <div>
          <h1>AI 评审引擎</h1>
          <p>外部模型需在脱敏结果经人工确认之后才会调用；调用 Gemini 系列模型时会自动附加 BLOCK_NONE 安全设置，避免因安全漏洞文本敏感而中断评审。</p>
        </div>
        <div className="filters">
          <select value={projectId} onChange={(event) => setProjectId(event.target.value)}>
            {projects.map((item) => <option key={item.project_id} value={item.project_id}>{item.name}</option>)}
          </select>
          {admin && <Link className="btn" to="/admin?tab=llm">管理模型通道</Link>}
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      <section className="kpi-grid">
        <article className="kpi"><div className="label">项目通道</div><div className="value" style={{ fontSize: 18 }}>{project?.llm_profile || "—"}</div></article>
        <article className="kpi blue"><div className="label">资产密级</div><div className="value" style={{ fontSize: 18 }}>{project?.env_tier || "—"}</div></article>
        <article className="kpi orange"><div className="label">调用次数</div><div className="value">{logs.length}</div></article>
        <article className="kpi green"><div className="label">最近耗时</div><div className="value" style={{ fontSize: 18 }}>{logs[0] ? `${logs[0].latency_ms} ms` : "—"}</div></article>
      </section>
      <article className="card">
        <div className="card-pad filters">
          <select value={status} onChange={(event) => setStatus(event.target.value)}>
            <option value="">全部状态</option>
            <option value="ok">成功</option>
            <option value="local_rules">本地规则</option>
            <option value="skipped">跳过</option>
            <option value="error">失败</option>
            <option value="blocked">已中止</option>
          </select>
        </div>
        <DataTable
          rows={rows}
          empty="脱敏结果确认之后，调用记录会出现在这里。"
          columns={[
            { key: "stage", title: "阶段", render: (row) => row.stage },
            { key: "model", title: "模型", render: (row) => <span className="mono">{row.model_id}</span> },
            { key: "status", title: "状态", render: (row) => <StatusBadge value={row.status} /> },
            { key: "latency", title: "耗时", render: (row) => `${row.latency_ms || 0} ms` },
            { key: "tokens", title: "Token", render: (row) => `${row.prompt_tokens || 0} / ${row.completion_tokens || 0}` },
            { key: "detail", title: "说明", render: (row) => row.error_detail || "" },
          ]}
        />
      </article>
    </>
  );
}
