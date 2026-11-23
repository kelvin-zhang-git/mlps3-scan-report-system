import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../api";
import { DomainBars, DonutChart, TrendChart } from "../components/Charts";
import { statusText } from "../labels";
import { rememberedProject, rememberProject } from "../project";

type Analytics = {
  project?: { name: string; summary: string; llm_profile: string };
  job?: { job_id: string; status: string } | null;
  effective_job?: { job_id: string; status: string } | null;
  awaiting_approval?: { job_id: string } | null;
  coverage: number;
  high_open: number;
  pending_manual: number;
  finding_total: number;
  severity: Record<string, number>;
  domains: Array<{ domain: string; completeness?: number; compliant_rate?: number; checked_score?: number; high_open: number; pending?: number; total?: number }>;
  trend: Array<{ job_id: string; started_at?: string; high: number; other: number; total?: number; status: string }>;
};

type ProjectOption = { project_id: string; name: string; status: string };

export default function DashboardPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<ProjectOption[]>([]);
  const [projectId, setProjectId] = useState("");
  const [ready, setReady] = useState(false);
  const [data, setData] = useState<Analytics | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api<ProjectOption[]>("/api/projects").then((rows) => {
      setProjects(rows);
      const remembered = rememberedProject();
      const picked = rows.find((item) => item.project_id === remembered) || rows.find((item) => item.status === "active") || rows[0];
      if (picked) setProjectId(picked.project_id);
      setReady(true);
    }).catch((err: Error) => setError(err.message));
  }, []);

  useEffect(() => {
    if (!projectId) return;
    rememberProject(projectId);
    api<Analytics>(`/api/projects/${projectId}/analytics`).then(setData).catch((err: Error) => setError(err.message));
  }, [projectId]);

  if (error) return <div className="error">{error}</div>;
  if (!ready || (projectId && !data)) return <div className="card card-pad">正在汇总安全态势...</div>;
  if (!projectId || !data) return <div className="card card-pad">还没有评估项目。<Link to="/projects">去创建</Link></div>;
  const latest = data.job;
  return (
    <>
      <div className="page-head">
        <div>
          <h1>全局安全态势</h1>
          <p>{data.project?.summary}</p>
        </div>
        <select value={projectId} onChange={(event) => setProjectId(event.target.value)}>
          {projects.map((item) => <option key={item.project_id} value={item.project_id}>{item.name}</option>)}
        </select>
      </div>
      {data.awaiting_approval && (
        <div className="banner">
          <span>任务 {data.awaiting_approval.job_id} 已完成技术采集，脱敏结果尚待人工确认；下方展示的覆盖率与统计来自最近一次已完成的评估。</span>
          <Link to={`/projects/${projectId}?tab=collect`}>前往确认</Link>
        </div>
      )}
      <section className="kpi-grid">
        <article className="kpi">
          <div className="label">最新任务</div>
          <div className="value" style={{ fontSize: 18 }}>{latest ? statusText(latest.status) : "未开始"}</div>
          <Link to={`/projects/${projectId}`}>查看详情 →</Link>
        </article>
        <article className="kpi orange">
          <div className="label">条款覆盖率</div>
          <div className="value">{data.coverage}%</div>
          <Link to={`/projects/${projectId}?tab=review`}>待人工 {data.pending_manual} →</Link>
        </article>
        <article className="kpi">
          <div className="label">高风险未关闭</div>
          <div className="value">{data.high_open}</div>
          <Link to="/todos">进入待办 →</Link>
        </article>
        <article className="kpi blue">
          <div className="label">已归集发现</div>
          <div className="value">{data.finding_total}</div>
          <Link to={`/projects/${projectId}?tab=delivery`}>前往协同交付 →</Link>
        </article>
      </section>
      <section className="split">
        <article className="card">
          <div className="section-title"><h2>发现严重度</h2><span className="muted">最近一次已完成评估</span></div>
          <DonutChart counts={data.severity || {}} />
        </article>
        <article className="card">
          <div className="section-title"><h2>最近扫描</h2><span className="muted">较新的任务排在上面</span></div>
          <TrendChart points={data.trend || []} />
        </article>
      </section>
      <article className="card">
        <div className="section-title">
          <div className="title-inline">
            <h2>安全域核查进度</h2>
            {(data.domains || []).length > 0 && (data.domains || []).every((item) => (item.completeness ?? 0) === 0) && (
              <span className="badge warn">待人工复核</span>
            )}
          </div>
          <span className="muted">共 {(data.domains || []).length} 个安全域 · 最近一次已完成评估</span>
        </div>
        <DomainBars
          rows={data.domains || []}
          onSelect={() => navigate(`/projects/${projectId}?tab=review`)}
        />
      </article>
      <article className="card channel-bar">
        <div className="channel-info">
          <div className="title-inline">
            <h2>当前模型通道</h2>
            <span className="badge info">{data.project?.llm_profile || "尚未指定"}</span>
          </div>
          <p className="muted">测试环境跨境调用经指定代理执行；管理制度类条款保留人工复核，模型仅基于已确认脱敏的技术证据提出映射意见。</p>
        </div>
        <Link className="btn-ghost" to="/ai-engine">查看评审审计 →</Link>
      </article>
    </>
  );
}
