import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, savedUser } from "../api";
import Modal from "../components/Modal";
import StatusBadge from "../components/StatusBadge";
import { canOperate } from "../labels";
import { rememberProject } from "../project";

type JobBrief = { job_id: string; status: string; started_at: string };
type ProjectCard = {
  project_id: string;
  name: string;
  summary: string;
  status: string;
  env_tier: string;
  llm_profile: string;
  stage_label?: string;
  classification?: string;
  whitelist_cidrs?: string[];
  enabled_extensions?: string[];
  clause_count?: number;
  enabled_asset_count: number;
  asset_count: number;
  job_count: number;
  coverage: number;
  latest_job?: JobBrief | null;
};

type Profile = { profile_key: string; display_name: string; is_enabled: boolean };

const EMPTY = {
  name: "",
  summary: "",
  env_tier: "L1_TEST",
  llm_profile: "local_rules",
  whitelist: "",
  include_cloud: false,
};

export default function ProjectsPage() {
  const navigate = useNavigate();
  const allowed = canOperate(savedUser()?.role);
  const [rows, setRows] = useState<ProjectCard[]>([]);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [draft, setDraft] = useState<typeof EMPTY | null>(null);
  const [editing, setEditing] = useState("");

  async function load() {
    const [projects, profileRows] = await Promise.all([
      api<ProjectCard[]>("/api/projects"),
      api<Profile[]>("/api/admin/llm-profiles").catch(() => [] as Profile[]),
    ]);
    setRows(projects);
    setProfiles(profileRows.filter((item) => item.is_enabled));
  }

  useEffect(() => { load().catch((err: Error) => setError(err.message)); }, []);

  function openCreate() {
    setEditing("");
    setDraft({ ...EMPTY, llm_profile: profiles[0]?.profile_key || "local_rules" });
  }

  function openEdit(project: ProjectCard) {
    setEditing(project.project_id);
    setDraft({
      name: project.name,
      summary: project.summary,
      env_tier: project.env_tier,
      llm_profile: project.llm_profile,
      whitelist: (project.whitelist_cidrs || []).join("\n"),
      include_cloud: (project.enabled_extensions || []).includes("CLOUD"),
    });
  }

  async function save() {
    if (!draft) return;
    const body = {
      name: draft.name,
      summary: draft.summary,
      env_tier: draft.env_tier,
      llm_profile: draft.llm_profile,
      whitelist_cidrs: draft.whitelist.split(/[\s,，]+/).map((item) => item.trim()).filter(Boolean),
      enabled_extensions: draft.include_cloud ? ["GENERAL", "CLOUD"] : ["GENERAL"],
    };
    if (editing) {
      await api(`/api/projects/${editing}`, { method: "PUT", body: JSON.stringify(body) });
      setNotice("项目资料已更新");
    } else {
      const created = await api<ProjectCard>("/api/projects", { method: "POST", body: JSON.stringify(body) });
      rememberProject(created.project_id);
      setNotice("草稿已创建。启动之后才能配置主机并发起核查。");
    }
    setDraft(null);
    await load();
  }

  async function act(projectId: string, action: "start" | "archive" | "delete") {
    setError("");
    if (action === "delete") {
      await api(`/api/projects/${projectId}`, { method: "DELETE" });
      setNotice("草稿已删除");
    } else {
      await api(`/api/projects/${projectId}/${action}`, { method: "POST" });
      setNotice(action === "start" ? "项目已启动，可以配置远程主机" : "项目已归档，历史结果仍可查看");
      if (action === "start") {
        rememberProject(projectId);
        navigate(`/projects/${projectId}?tab=assets`);
        return;
      }
    }
    await load();
  }

  function enter(projectId: string) {
    rememberProject(projectId);
    navigate(`/projects/${projectId}`);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>评估项目</h1>
          <p>每个项目对应一次正式测评前的差距自查周期；新建草稿后填写名称与白名单范围，启动项目即可配置受测主机并按阶段推进核查与交付。</p>
        </div>
        <button className="btn" disabled={!allowed} onClick={openCreate}>新建项目</button>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}
      <section className="project-grid">
        {rows.map((project) => (
          <article className="card card-pad project-card" key={project.project_id}>
            <div className="filters">
              <h2>{project.name}</h2>
              <StatusBadge value={project.status} />
            </div>
            <p className="muted">{project.summary || "还没有项目说明"}</p>
            <p className="muted">
              密级 {project.env_tier} · 条款 {project.clause_count || 211} 项{(project.enabled_extensions || []).includes("CLOUD") ? "（含云扩展）" : "（通用要求）"} · 启用主机 {project.enabled_asset_count} 台 · 作业 {project.job_count} 轮 · 覆盖率 {project.coverage}%
            </p>
            <div className="filters">
              <button className="btn" onClick={() => enter(project.project_id)}>进入工作台</button>
              {allowed && project.status !== "archived" && <button className="btn-ghost" onClick={() => openEdit(project)}>编辑</button>}
              {allowed && project.status !== "active" && <button className="btn-ghost" onClick={() => act(project.project_id, "start").catch((err: Error) => setError(err.message))}>{project.status === "archived" ? "重新启用" : "启动项目"}</button>}
              {allowed && project.status === "active" && <button className="btn-ghost" onClick={() => act(project.project_id, "archive").catch((err: Error) => setError(err.message))}>归档</button>}
              {allowed && project.status === "draft" && <button className="btn-danger" onClick={() => act(project.project_id, "delete").catch((err: Error) => setError(err.message))}>删除</button>}
            </div>
          </article>
        ))}
      </section>
      {rows.length === 0 && <div className="card card-pad">还没有项目。新建一个草稿，启动后再配置要核查的虚拟机。</div>}
      <Modal open={!!draft} title={editing ? "编辑项目" : "新建项目"} onClose={() => setDraft(null)}>
        {draft && (
          <>
            <label className="field">名称<input value={draft.name} onChange={(event) => setDraft({ ...draft, name: event.target.value })} /></label>
            <label className="field">说明<textarea value={draft.summary} onChange={(event) => setDraft({ ...draft, summary: event.target.value })} /></label>
            <label className="field">密级
              <select value={draft.env_tier} onChange={(event) => setDraft({ ...draft, env_tier: event.target.value })}>
                <option value="L1_TEST">L1_TEST</option>
                <option value="L2_INTERNAL">L2_INTERNAL</option>
                <option value="L3_CROSSBORDER_APPROVED">L3_CROSSBORDER_APPROVED</option>
              </select>
            </label>
            <label className="field">默认模型通道
              <select value={draft.llm_profile} onChange={(event) => setDraft({ ...draft, llm_profile: event.target.value })}>
                {(profiles.length ? profiles : [{ profile_key: draft.llm_profile, display_name: draft.llm_profile, is_enabled: true }]).map((item) => (
                  <option key={item.profile_key} value={item.profile_key}>{item.display_name}</option>
                ))}
              </select>
            </label>
            <label className="field">白名单网段，一行一个<input value={draft.whitelist} onChange={(event) => setDraft({ ...draft, whitelist: event.target.value })} placeholder="192.168.1.220/32" /></label>
            <div className="field">
              <span>适用标准条款</span>
              <label className="check" style={{ marginTop: 6 }}>
                <input type="checkbox" checked disabled />
                安全通用要求（GB/T 22239-2019 第三级必选，211 项）
              </label>
              <label className="check" style={{ marginTop: 6 }}>
                <input
                  type="checkbox"
                  checked={draft.include_cloud}
                  onChange={(event) => setDraft({ ...draft, include_cloud: event.target.checked })}
                />
                云计算安全扩展要求（上云或虚拟化平台适用，叠加 46 项，合计 257 项）
              </label>
            </div>
            <button className="btn" onClick={() => save().catch((err: Error) => setError(err.message))}>保存</button>
          </>
        )}
      </Modal>
    </>
  );
}
