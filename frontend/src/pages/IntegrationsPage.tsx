import { useEffect, useState } from "react";
import { api, savedUser } from "../api";
import Modal from "../components/Modal";
import { canOperate } from "../labels";
import { rememberedProject, rememberProject } from "../project";

type Connector = {
  key: string;
  name: string;
  category: string;
  role: string;
  flow: string;
  configured: boolean;
  reachable: boolean;
  external_url?: string;
  actions: string[];
  detail: string;
};

const GROUPS = [
  ["upstream_scanner", "上游采集引擎", "以下采集引擎均在扫描机上以只读方式执行，采集结果首先写入本系统，是否同步到外部平台由用户在项目工作台确认。"],
  ["downstream_platform", "下游协同平台", "可在此验证外部协同平台的连通状态；面向具体项目的漏洞派发、整改状态同步与合规台账归档，均在对应项目工作台的「5 协同交付」中完成。"],
  ["cloud_and_import", "扩展采集与导入", "尚未接入在线采集的云平台、数据库或代码扫描结果，可将对应工具导出的 JSON 报告导入当前评估任务。"],
];

export default function IntegrationsPage() {
  const [rows, setRows] = useState<Connector[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [projects, setProjects] = useState<Array<{ project_id: string; name: string }>>([]);
  const [projectId, setProjectId] = useState("");
  const [source, setSource] = useState("");
  const [payload, setPayload] = useState("{\n  \n}");
  const allowed = canOperate(savedUser()?.role);

  async function load() {
    const [connectors, projectRows] = await Promise.all([
      api<Connector[]>("/api/connectors"),
      api<Array<{ project_id: string; name: string }>>("/api/projects"),
    ]);
    setRows(connectors);
    setProjects(projectRows);
    setProjectId((current) => current || projectRows.find((item) => item.project_id === rememberedProject())?.project_id || projectRows[0]?.project_id || "");
  }
  useEffect(() => { load().catch((err: Error) => setError(err.message)); }, []);

  async function act(key: string, action: "test" | "sync") {
    setError("");
    if (projectId) rememberProject(projectId);
    const result = await api<Record<string, unknown>>(`/api/connectors/${key}/${action}`, { method: "POST", body: JSON.stringify({ project_id: projectId }) });
    setNotice(`${key} ${action === "test" ? "探测" : "同步"}：${JSON.stringify(result.detail || result)}`);
    if (action === "test") await load();
  }

  async function importJson() {
    const parsed = JSON.parse(payload);
    if (!projectId) throw new Error("先选择要写入的项目");
    rememberProject(projectId);
    const result = await api<{ imported: number }>(`/api/imports/${projectId}`, { method: "POST", body: JSON.stringify({ source, payload: parsed }) });
    setNotice(`已导入 ${result.imported} 条`);
    setSource("");
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>集成与引擎</h1>
          <p>本页用于核验采集引擎与外部协同平台的连通状态，并支持导入扩展 JSON 报告；面向单个项目的漏洞推送、状态同步与合规台账归档，可在对应项目工作台的「5 协同交付」中执行。</p>
        </div>
        <select value={projectId} onChange={(event) => { setProjectId(event.target.value); rememberProject(event.target.value); }}>
          {projects.map((item) => <option key={item.project_id} value={item.project_id}>{item.name}</option>)}
        </select>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}
      {GROUPS.map(([id, title, intro]) => (
        <section key={id}>
          <div className="page-head"><div><h2>{title}</h2><p>{intro}</p></div></div>
          <div className="integration-grid">
            {rows.filter((row) => row.category === id).map((row) => (
              <article className="card integration" key={row.key}>
                <div className="filters">
                  <h3>{row.name}</h3>
                  <span className={`badge ${row.reachable ? "ok" : "danger"}`}>{row.reachable ? "可达" : "未连通"}</span>
                  <span className="badge">{row.configured ? "已配置" : "未配置"}</span>
                </div>
                <p>{row.role}</p>
                <p className="muted">{row.flow}</p>
                <p className="muted">{row.detail}</p>
                <div className="actions">
                  {row.actions.includes("test") && <button className="btn-ghost" disabled={!allowed} onClick={() => act(row.key, "test").catch((err: Error) => setError(err.message))}>测试连通</button>}
                  {row.actions.includes("sync") && <button className="btn" disabled={!allowed} onClick={() => act(row.key, "sync").catch((err: Error) => setError(err.message))}>同步最新任务</button>}
                  {row.external_url && <a className="btn-ghost" href={row.external_url} target="_blank" rel="noreferrer">打开控制台</a>}
                  {row.actions.includes("import") && <button className="btn-ghost" disabled={!allowed} onClick={() => setSource(row.key)}>导入 JSON</button>}
                </div>
              </article>
            ))}
          </div>
        </section>
      ))}
      <Modal open={!!source} title={`导入 ${source}`} onClose={() => setSource("")}>
        <label className="field">JSON 报告<textarea value={payload} onChange={(event) => setPayload(event.target.value)} /></label>
        <button className="btn" onClick={() => importJson().catch((err: Error) => setError(err.message))}>写入当前任务</button>
      </Modal>
    </>
  );
}
