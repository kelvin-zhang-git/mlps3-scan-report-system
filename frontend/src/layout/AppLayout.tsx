import { FormEvent, useEffect, useState } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { Bot, Cable, FolderKanban, LayoutDashboard, Library, ListTodo, LogOut, Settings } from "lucide-react";
import { api, clearSession, savedUser } from "../api";
import KyndrylLogo from "../components/KyndrylLogo";
import { ROLE_LABEL } from "../labels";

const GROUPS = [
  {
    label: "安全态势",
    items: [{ to: "/dashboard", label: "全局大盘", icon: LayoutDashboard }],
  },
  {
    label: "合规作业",
    items: [
      { to: "/projects", label: "评估项目", icon: FolderKanban },
      { to: "/todos", label: "待办与审批", icon: ListTodo },
      { to: "/clauses", label: "等保条款库", icon: Library },
      { to: "/ai-engine", label: "AI 评审引擎", icon: Bot },
    ],
  },
  {
    label: "平台集成",
    items: [{ to: "/integrations", label: "集成与引擎", icon: Cable }],
  },
  {
    label: "系统管理",
    items: [{ to: "/admin", label: "系统管理", icon: Settings }],
  },
];

const CRUMB: Record<string, string> = {
  dashboard: "全局大盘",
  projects: "评估项目",
  todos: "待办与审批",
  clauses: "等保条款库",
  "ai-engine": "AI 评审引擎",
  integrations: "集成与引擎",
  admin: "系统管理",
};

const THEMES = [
  ["classic_red", "红白"],
  ["arctic_blue", "蓝白"],
  ["midnight_dark", "深色"],
];

export default function AppLayout() {
  const navigate = useNavigate();
  const location = useLocation();
  const user = savedUser();
  const [query, setQuery] = useState("");
  const [theme, setTheme] = useState(document.documentElement.dataset.theme || "classic_red");
  const section = location.pathname.split("/")[1] || "dashboard";

  useEffect(() => {
    if (!location.pathname.startsWith("/clauses")) return;
    setQuery(new URLSearchParams(location.search).get("q") || "");
  }, [location.pathname, location.search]);

  function applyTheme(next: string) {
    document.documentElement.dataset.theme = next;
    localStorage.setItem("mlps_theme", next);
    setTheme(next);
    api("/api/auth/theme", { method: "PATCH", body: JSON.stringify({ theme: next }) }).catch(() => undefined);
  }

  function onSearch(event: FormEvent) {
    event.preventDefault();
    navigate(`/clauses?q=${encodeURIComponent(query)}`);
  }

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-row">
            <KyndrylLogo className="brand-wordmark brand-wordmark-sm" />
            <span className="brand-rule" aria-hidden />
            <span className="stencil brand-tag">MLPS 3.0</span>
          </div>
          <div className="brand-name">等保三级 · 扫描与报告系统</div>
        </div>
        {GROUPS.map((group) => (
          <div className="nav-group" key={group.label}>
            <div className="nav-label">{group.label}</div>
            {group.items.map((item) => (
              <NavLink key={item.to} to={item.to} className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}>
                <item.icon size={16} />{item.label}
              </NavLink>
            ))}
          </div>
        ))}
        <div className="side-user">
          <div className="theme-row" style={{ marginBottom: 10 }}>
            {THEMES.map(([id, label]) => (
              <button key={id} className={`btn-ghost${theme === id ? " on" : ""}`} aria-pressed={theme === id} onClick={() => applyTheme(id)}>{label}</button>
            ))}
          </div>
          <button className="btn-ghost" style={{ width: "100%" }} onClick={() => { clearSession(); navigate("/login"); }}>
            <LogOut size={14} />退出
          </button>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="crumbs"><span>当前位置</span><b>{CRUMB[section] || "工作台"}</b></div>
          <form className="search-form" onSubmit={onSearch}>
            <span className="search-prefix">条款库</span>
            <input
              value={query}
              aria-label="在条款库中搜索条款编号或控制点"
              placeholder="输入条款编号或控制点，搜索后打开条款库"
              onChange={(event) => setQuery(event.target.value)}
            />
            <button className="btn" type="submit">搜索</button>
          </form>
          <div className="top-actions">
            <div className="user-chip">
              <b>{user?.display_name}</b>
              <span>{ROLE_LABEL[user?.role || ""] || user?.role}</span>
            </div>
          </div>
        </header>
        <main className="content">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
