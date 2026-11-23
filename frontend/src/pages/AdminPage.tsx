import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, savedUser } from "../api";
import DataTable from "../components/DataTable";
import Drawer from "../components/Drawer";
import Modal from "../components/Modal";
import { ROLE_LABEL } from "../labels";
import { rememberedProject, rememberProject } from "../project";
import { formatBeijing } from "../time";

type Profile = {
  profile_key: string;
  display_name: string;
  provider: string;
  is_cross_border: boolean;
  allowed_env_tiers: string[];
  fast_mapper_model: string;
  deep_reasoner_model: string;
  api_base: string;
  proxy_env: string;
  auth_mode: "env_ref" | "encrypted_key";
  api_key_env: string;
  api_key_masked: string;
  has_api_key: boolean;
  enable_context_caching: boolean;
  inject_block_none_safety: boolean;
  is_enabled: boolean;
};
type Account = { user_id: string; email: string; display_name: string; role: string; is_active: boolean };
type RoleInfo = { role: string; label: string; summary: string; permissions: string[] };
type PromptConfig = {
  prompt_key: string;
  title: string;
  content: string;
  version: number;
  updated_by: string;
  updated_at: string;
  is_default: boolean;
  section_hints: Array<{ key: string; label: string }>;
};

const EMPTY: Profile = {
  profile_key: "",
  display_name: "",
  provider: "openai_compatible",
  is_cross_border: false,
  allowed_env_tiers: ["L1_TEST"],
  fast_mapper_model: "",
  deep_reasoner_model: "",
  api_base: "",
  proxy_env: "",
  auth_mode: "env_ref",
  api_key_env: "",
  api_key_masked: "",
  has_api_key: false,
  enable_context_caching: false,
  inject_block_none_safety: false,
  is_enabled: true,
};
const TIERS = ["L1_TEST", "L2_INTERNAL", "L3_CROSSBORDER", "L3_CROSSBORDER_APPROVED"];

export default function AdminPage() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") || "llm";
  const me = savedUser();
  const admin = me?.role === "admin";
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [users, setUsers] = useState<Account[]>([]);
  const [roles, setRoles] = useState<RoleInfo[]>([]);
  const [projectProfile, setProjectProfile] = useState("");
  const [draft, setDraft] = useState<Profile | null>(null);
  const [apiKey, setApiKey] = useState("");
  const [creating, setCreating] = useState(false);
  const [userDraft, setUserDraft] = useState<Account | null>(null);
  const [userForm, setUserForm] = useState({ email: "", display_name: "", role: "auditor", password: "", is_active: true });
  const [passwordFor, setPasswordFor] = useState<Account | null>(null);
  const [password, setPassword] = useState("");
  const [projects, setProjects] = useState<Array<{ project_id: string; name: string; status: string }>>([]);
  const [projectId, setProjectId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [roleFilter, setRoleFilter] = useState("");
  const [promptConfig, setPromptConfig] = useState<PromptConfig | null>(null);
  const [promptTitle, setPromptTitle] = useState("");
  const [promptText, setPromptText] = useState("");
  const [savingPrompt, setSavingPrompt] = useState(false);

  async function load() {
    const [roleRows, promptRow] = await Promise.all([
      api<RoleInfo[]>("/api/admin/roles"),
      api<PromptConfig>("/api/admin/prompts/mlps3_final_report"),
    ]);
    setRoles(roleRows);
    setPromptConfig(promptRow);
    setPromptTitle(promptRow.title);
    setPromptText(promptRow.content);
    if (!admin) return;
    const [profileRows, userRows, projectRows] = await Promise.all([
      api<Profile[]>("/api/admin/llm-profiles"),
      api<Account[]>("/api/admin/users"),
      api<Array<{ project_id: string; name: string; status: string; llm_profile: string }>>("/api/projects"),
    ]);
    setProfiles(profileRows);
    setUsers(userRows);
    setProjects(projectRows);
    const remembered = rememberedProject();
    const picked = projectRows.find((item) => item.project_id === remembered) || projectRows.find((item) => item.status === "active") || projectRows[0];
    if (picked) {
      setProjectId(picked.project_id);
      setProjectProfile(picked.llm_profile);
    }
  }

  useEffect(() => { load().catch((err: Error) => setError(err.message)); }, []);

  function openProfile(profile?: Profile) {
    setCreating(!profile);
    setDraft(profile ? { ...profile } : { ...EMPTY });
    setApiKey("");
  }

  async function saveProfile() {
    if (!draft) return;
    const body = { ...draft, api_key: apiKey };
    const path = creating ? "/api/admin/llm-profiles" : `/api/admin/llm-profiles/${draft.profile_key}`;
    await api(path, { method: creating ? "POST" : "PUT", body: JSON.stringify(body) });
    setDraft(null);
    setNotice("模型通道已保存");
    await load();
  }

  async function testProfile(key: string) {
    const result = await api<{ ok: boolean; latency_ms: number; detail: string }>(`/api/admin/llm-profiles/${key}/test`, { method: "POST" });
    setNotice(`${key}：${result.ok ? "连通" : "未连通"}，${result.latency_ms} ms，${result.detail}`);
  }

  const visibleUsers = users.filter((user) => {
    const blob = `${user.email} ${user.display_name}`.toLowerCase();
    if (query && !blob.includes(query.toLowerCase())) return false;
    if (roleFilter && user.role !== roleFilter) return false;
    return true;
  });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>系统管理</h1>
          <p>系统管理员可在此维护大模型通道、用户账户以及报告 AI 系统提示词；等保负责人和只读审计员可查阅下方的角色权限说明与当前生效提示词。</p>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {notice && <div className="banner">{notice}</div>}
      <div className="tabs">
        <button className={tab === "llm" ? "on" : ""} onClick={() => setParams({ tab: "llm" })}>模型通道</button>
        <button className={tab === "users" ? "on" : ""} onClick={() => setParams({ tab: "users" })}>账户与权限</button>
        <button className={tab === "prompt" ? "on" : ""} onClick={() => setParams({ tab: "prompt" })}>报告 AI 提示词</button>
      </div>
      {!admin && tab !== "prompt" && <div className="card card-pad">当前登录账号为{ROLE_LABEL[me?.role || ""] || "普通成员"}，模型通道与账户权限调整需由系统管理员完成。</div>}
      {tab === "llm" && admin && (
        <article className="card">
          <div className="section-title">
            <h2>项目默认通道：{projectProfile || "尚未指定"}</h2>
            <select value={projectId} onChange={(event) => {
              const next = event.target.value;
              setProjectId(next);
              rememberProject(next);
              const found = projects.find((item) => item.project_id === next) as { llm_profile?: string } | undefined;
              setProjectProfile(found?.llm_profile || "");
            }}>
              {projects.map((item) => <option key={item.project_id} value={item.project_id}>{item.name}</option>)}
            </select>
            <button className="btn" onClick={() => openProfile()}>新建通道</button>
          </div>
          <DataTable rows={profiles} columns={[
            { key: "name", title: "名称", render: (row) => row.display_name },
            { key: "key", title: "标识", render: (row) => <span className="mono">{row.profile_key}</span> },
            { key: "provider", title: "厂商", render: (row) => row.provider },
            { key: "model", title: "快模型", render: (row) => row.fast_mapper_model },
            { key: "keymask", title: "密钥", render: (row) => row.api_key_masked || row.api_key_env || "未配置" },
            { key: "state", title: "状态", render: (row) => <span className={`badge ${row.is_enabled ? "ok" : "danger"}`}>{row.is_enabled ? "启用" : "停用"}</span> },
            { key: "ops", title: "操作", render: (row) => (
              <div className="filters" onClick={(event) => event.stopPropagation()}>
                <button className="btn-ghost" onClick={() => openProfile(row)}>编辑</button>
                <button className="btn-ghost" onClick={() => testProfile(row.profile_key).catch((err: Error) => setError(err.message))}>测试</button>
                <button className="btn-ghost" onClick={async () => { if (!projectId) return; await api(`/api/projects/${projectId}/llm-profile`, { method: "PATCH", body: JSON.stringify({ profile_key: row.profile_key }) }); setNotice("已设为所选项目的默认通道"); await load(); }}>设为默认</button>
                <button className="btn-danger" onClick={async () => { if (!window.confirm(`删除通道 ${row.display_name}？`)) return; await api(`/api/admin/llm-profiles/${row.profile_key}`, { method: "DELETE" }); await load(); }}>删除</button>
              </div>
            ) },
          ]} />
        </article>
      )}
      {tab === "users" && admin && (
        <article className="card">
          <div className="card-pad filters">
            <input placeholder="搜索姓名或邮箱" value={query} onChange={(event) => setQuery(event.target.value)} />
            <select value={roleFilter} onChange={(event) => setRoleFilter(event.target.value)}>
              <option value="">全部角色</option>
              <option value="admin">系统管理员</option>
              <option value="security_lead">等保负责人</option>
              <option value="auditor">只读审计员</option>
            </select>
            <button className="btn" onClick={() => { setUserForm({ email: "", display_name: "", role: "auditor", password: "", is_active: true }); setUserDraft({ user_id: "", email: "", display_name: "", role: "auditor", is_active: true }); }}>新建账户</button>
          </div>
          <DataTable rows={visibleUsers} columns={[
            { key: "name", title: "姓名", render: (row) => row.display_name },
            { key: "email", title: "邮箱", render: (row) => row.email },
            { key: "role", title: "角色", render: (row) => ROLE_LABEL[row.role] || row.role },
            { key: "active", title: "状态", render: (row) => <span className={`badge ${row.is_active ? "ok" : "danger"}`}>{row.is_active ? "启用" : "停用"}</span> },
            { key: "ops", title: "操作", render: (row) => (
              <div className="filters" onClick={(event) => event.stopPropagation()}>
                <button className="btn-ghost" onClick={() => setUserDraft(row)}>编辑</button>
                <button className="btn-ghost" onClick={() => { setPasswordFor(row); setPassword(""); }}>重置口令</button>
                <button className="btn-danger" onClick={async () => { if (!window.confirm(`删除 ${row.email}？`)) return; await api(`/api/admin/users/${row.user_id}`, { method: "DELETE" }); await load(); }}>删除</button>
              </div>
            ) },
          ]} />
        </article>
      )}
      {tab === "prompt" && (
        <article className="card card-pad prompt-editor-card">
          <div className="prompt-head">
            <div>
              <h2>等保三级最终报告 AI 系统提示词</h2>
              <p className="muted" style={{ marginTop: 4 }}>
                生成「中文等保三级预评估终版报告（Word 与网页版）」以及同步写入「CISO Assistant 评估总述」时，系统会统一依据这份提示词指导大模型撰写研判正文与分阶段整改建议。
              </p>
            </div>
            {promptConfig && (
              <div className="filters">
                <span className="badge ok">当前版本 v{promptConfig.version}</span>
                <span className="badge">{promptConfig.is_default ? "系统内置默认" : "管理员已定制"}</span>
              </div>
            )}
          </div>

          {!admin && (
            <div className="banner" style={{ marginTop: 12 }}>
              当前登录账号为{ROLE_LABEL[me?.role || ""] || "普通成员"}，可浏览当前生效的报告系统提示词；如需修改或恢复默认模板，请联系系统管理员处理。
            </div>
          )}

          <div className="prompt-layout">
            <div className="prompt-main">
              <label className="field">
                提示词名称
                <input
                  disabled={!admin}
                  value={promptTitle}
                  onChange={(event) => setPromptTitle(event.target.value)}
                />
              </label>
              <label className="field">
                System Prompt 正文（共 {promptText.length} 字）
                <textarea
                  className="prompt-textarea"
                  disabled={!admin}
                  rows={18}
                  value={promptText}
                  onChange={(event) => setPromptText(event.target.value)}
                />
              </label>
              {promptConfig && (
                <p className="muted">
                  最近保存：{promptConfig.updated_by || "系统内置"} · {formatBeijing(promptConfig.updated_at)}
                </p>
              )}
              {admin && (
                <div className="filters" style={{ marginTop: 12 }}>
                  <button
                    className="btn"
                    disabled={savingPrompt || promptText.trim().length < 20}
                    onClick={async () => {
                      setSavingPrompt(true);
                      setError("");
                      try {
                        const saved = await api<PromptConfig>("/api/admin/prompts/mlps3_final_report", {
                          method: "PUT",
                          body: JSON.stringify({ title: promptTitle, content: promptText }),
                        });
                        setPromptConfig(saved);
                        setPromptTitle(saved.title);
                        setPromptText(saved.content);
                        setNotice(`报告 AI 提示词已保存生效（当前版本 v${saved.version}）。在项目「5 协同交付」可一键按新版提示词重新生成终版报告。`);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "保存提示词失败");
                      } finally {
                        setSavingPrompt(false);
                      }
                    }}
                  >
                    {savingPrompt ? "正在保存…" : "保存并生效"}
                  </button>
                  <button
                    className="btn-ghost"
                    disabled={savingPrompt}
                    onClick={async () => {
                      if (!window.confirm("恢复为系统内置的等保三级专业报告 System Prompt？")) return;
                      setSavingPrompt(true);
                      setError("");
                      try {
                        const reset = await api<PromptConfig>("/api/admin/prompts/mlps3_final_report/reset", { method: "POST" });
                        setPromptConfig(reset);
                        setPromptTitle(reset.title);
                        setPromptText(reset.content);
                        setNotice(`已恢复系统内置默认提示词（当前版本 v${reset.version}）。`);
                      } catch (err) {
                        setError(err instanceof Error ? err.message : "恢复默认失败");
                      } finally {
                        setSavingPrompt(false);
                      }
                    }}
                  >
                    恢复系统内置默认
                  </button>
                </div>
              )}
            </div>

            <aside className="prompt-aside">
              <h3>输出章节结构说明</h3>
              <p className="muted">编辑提示词时，可根据行业特点调整表述口吻与分析深度；建议保留以下 JSON 字段名称，以便系统将研判内容自动排入 Word、网页报告及合规台账：</p>
              <ul className="prompt-hints">
                {(promptConfig?.section_hints || []).map((item) => (
                  <li key={item.key}>
                    <span className="mono">{item.key}</span>
                    <span className="muted">{item.label}</span>
                  </li>
                ))}
              </ul>
            </aside>
          </div>
        </article>
      )}
      <section className="integration-grid">
        {roles.map((role) => (
          <article className="card card-pad" key={role.role}>
            <h3>{role.label}</h3>
            <p className="muted">{role.summary}</p>
            <ul>{role.permissions.map((item) => <li key={item}>{item}</li>)}</ul>
          </article>
        ))}
      </section>
      <Drawer open={!!draft} title={creating ? "新建模型通道" : "编辑模型通道"} onClose={() => setDraft(null)}>
        {draft && (
          <>
            <label className="field">标识<input disabled={!creating} value={draft.profile_key} onChange={(event) => setDraft({ ...draft, profile_key: event.target.value })} /></label>
            <label className="field">名称<input value={draft.display_name} onChange={(event) => setDraft({ ...draft, display_name: event.target.value })} /></label>
            <label className="field">厂商
              <select value={draft.provider} onChange={(event) => setDraft({ ...draft, provider: event.target.value, inject_block_none_safety: event.target.value === "gemini" })}>
                <option value="gemini">Gemini</option>
                <option value="openai_compatible">OpenAI 兼容</option>
                <option value="local_rules">本地规则</option>
              </select>
            </label>
            <label className="field">快模型 ID<input value={draft.fast_mapper_model} onChange={(event) => setDraft({ ...draft, fast_mapper_model: event.target.value })} /></label>
            <label className="field">深模型 ID<input value={draft.deep_reasoner_model} onChange={(event) => setDraft({ ...draft, deep_reasoner_model: event.target.value })} /></label>
            <label className="field">API Base<input value={draft.api_base} onChange={(event) => setDraft({ ...draft, api_base: event.target.value })} /></label>
            <label className="field">密钥模式
              <select value={draft.auth_mode} onChange={(event) => setDraft({ ...draft, auth_mode: event.target.value as Profile["auth_mode"] })}>
                <option value="env_ref">环境变量名</option>
                <option value="encrypted_key">页面输入并加密保存</option>
              </select>
            </label>
            {draft.auth_mode === "env_ref" ? (
              <label className="field">环境变量名<input value={draft.api_key_env} onChange={(event) => setDraft({ ...draft, api_key_env: event.target.value })} /></label>
            ) : (
              <label className="field">API Key（留空则保留 {draft.api_key_masked || "原密钥"}）<input type="password" value={apiKey} onChange={(event) => setApiKey(event.target.value)} /></label>
            )}
            <label className="check"><input type="checkbox" checked={draft.is_cross_border} onChange={(event) => setDraft({ ...draft, is_cross_border: event.target.checked })} />跨境通道</label>
            <label className="field">代理环境变量<input value={draft.proxy_env} onChange={(event) => setDraft({ ...draft, proxy_env: event.target.value })} /></label>
            <div className="field">允许密级{TIERS.map((tier) => (
              <label className="check" key={tier}><input type="checkbox" checked={draft.allowed_env_tiers.includes(tier)} onChange={(event) => {
                const next = event.target.checked ? [...draft.allowed_env_tiers, tier] : draft.allowed_env_tiers.filter((item) => item !== tier);
                setDraft({ ...draft, allowed_env_tiers: next });
              }} />{tier}</label>
            ))}</div>
            <label className="check"><input type="checkbox" checked={draft.inject_block_none_safety} onChange={(event) => setDraft({ ...draft, inject_block_none_safety: event.target.checked })} />Gemini BLOCK_NONE</label>
            <label className="check"><input type="checkbox" checked={draft.is_enabled} onChange={(event) => setDraft({ ...draft, is_enabled: event.target.checked })} />启用</label>
            <button className="btn" onClick={() => saveProfile().catch((err: Error) => setError(err.message))}>保存</button>
          </>
        )}
      </Drawer>
      <Modal open={!!userDraft && !userDraft.user_id} title="新建账户" onClose={() => setUserDraft(null)}>
        <label className="field">邮箱<input value={userForm.email} onChange={(event) => setUserForm({ ...userForm, email: event.target.value })} /></label>
        <label className="field">姓名<input value={userForm.display_name} onChange={(event) => setUserForm({ ...userForm, display_name: event.target.value })} /></label>
        <label className="field">角色
          <select value={userForm.role} onChange={(event) => setUserForm({ ...userForm, role: event.target.value })}>
            <option value="admin">系统管理员</option>
            <option value="security_lead">等保负责人</option>
            <option value="auditor">只读审计员</option>
          </select>
        </label>
        <label className="field">初始口令<input type="password" value={userForm.password} onChange={(event) => setUserForm({ ...userForm, password: event.target.value })} /></label>
        <button className="btn" onClick={async () => { await api("/api/admin/users", { method: "POST", body: JSON.stringify(userForm) }); setUserDraft(null); await load(); }}>创建</button>
      </Modal>
      <Modal open={!!userDraft?.user_id} title="编辑账户" onClose={() => setUserDraft(null)}>
        {userDraft?.user_id && (
          <>
            <p className="muted">{userDraft.email}</p>
            <label className="field">姓名<input value={userDraft.display_name} onChange={(event) => setUserDraft({ ...userDraft, display_name: event.target.value })} /></label>
            <label className="field">角色
              <select value={userDraft.role} onChange={(event) => setUserDraft({ ...userDraft, role: event.target.value })}>
                <option value="admin">系统管理员</option>
                <option value="security_lead">等保负责人</option>
                <option value="auditor">只读审计员</option>
              </select>
            </label>
            <label className="check"><input type="checkbox" checked={userDraft.is_active} onChange={(event) => setUserDraft({ ...userDraft, is_active: event.target.checked })} />启用</label>
            <button className="btn" onClick={async () => {
              await api(`/api/admin/users/${userDraft.user_id}`, { method: "PATCH", body: JSON.stringify({ display_name: userDraft.display_name, role: userDraft.role, is_active: userDraft.is_active }) });
              setUserDraft(null);
              await load();
            }}>保存</button>
          </>
        )}
      </Modal>
      <Modal open={!!passwordFor} title="重置口令" onClose={() => setPasswordFor(null)}>
        <label className="field">新口令<input type="password" value={password} onChange={(event) => setPassword(event.target.value)} /></label>
        <button className="btn" onClick={async () => {
          if (!passwordFor) return;
          await api(`/api/admin/users/${passwordFor.user_id}/reset-password`, { method: "POST", body: JSON.stringify({ password }) });
          setPasswordFor(null);
          setNotice("口令已重置");
        }}>确认</button>
      </Modal>
    </>
  );
}
