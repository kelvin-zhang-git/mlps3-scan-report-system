import { FormEvent, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  ArrowRight,
  Bot,
  FileCheck2,
  GitCompareArrows,
  Library,
  Palette,
  Radar,
  ShieldCheck,
} from "lucide-react";
import { api, saveSession, type User } from "../api";
import KyndrylLogo from "../components/KyndrylLogo";

const CAPABILITIES = [
  {
    icon: Radar,
    title: "多源只读采集与去重",
    desc: "集成 Nmap、Nuclei、Trivy SBOM、TLS 与 OS/DB/MW 只读基线，经本地与 DefectDojo 去重归集。",
  },
  {
    icon: ShieldCheck,
    title: "保拓扑可逆脱敏",
    desc: "按安全域生成可读资产代号，映射关系加密留存本地保险箱，送审前强制零泄漏校验。",
  },
  {
    icon: Bot,
    title: "AI 研判与攻击路径",
    desc: "经 LiteLLM 统一网关按域映射技术条款、推演跨组件攻击链，输出管理层专业研判与整改路线。",
  },
  {
    icon: Library,
    title: "GB/T 22239 全量条款",
    desc: "覆盖通用 211 项与云扩展 46 项条款、7 类测评对象覆盖矩阵及 106 项高风险判例双口径计分。",
  },
  {
    icon: FileCheck2,
    title: "双版本报告与工单",
    desc: "一键生成脱敏对外版与受控还原版中文 HTML/Word 差距报告，并导出分部门整改工单。",
  },
  {
    icon: GitCompareArrows,
    title: "DefectDojo 与 CISO 协同",
    desc: "漏洞处置在 DefectDojo 闭环追踪，合规结论与整改控制项经终检后一键归档至 CISO Assistant。",
  },
] as const;

const LOGIN_THEMES = [
  { id: "classic_red", label: "经典红白" },
  { id: "arctic_blue", label: "极地蓝白" },
  { id: "midnight_dark", label: "暗夜深空" },
] as const;

export default function LoginPage() {
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [theme, setTheme] = useState<string>(
    () => document.documentElement.dataset.theme || localStorage.getItem("mlps_theme") || "classic_red",
  );

  function cycleTheme() {
    const idx = LOGIN_THEMES.findIndex((item) => item.id === theme);
    const next = LOGIN_THEMES[(idx + 1) % LOGIN_THEMES.length];
    document.documentElement.dataset.theme = next.id;
    localStorage.setItem("mlps_theme", next.id);
    setTheme(next.id);
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = new FormData(event.currentTarget);
    setError("");
    setBusy(true);
    try {
      const result = await api<{ access_token: string; user: User }>("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: String(form.get("email") || ""),
          password: String(form.get("password") || ""),
        }),
      });
      saveSession(result.access_token, result.user);
      const preferred = result.user.theme_preference || theme || "classic_red";
      document.documentElement.dataset.theme = preferred;
      localStorage.setItem("mlps_theme", preferred);
      navigate("/dashboard");
    } catch (err) {
      setError(err instanceof Error ? err.message : "登录失败");
    } finally {
      setBusy(false);
    }
  }

  const currentTheme = LOGIN_THEMES.find((item) => item.id === theme) || LOGIN_THEMES[0];

  return (
    <div className="sdf-login">
      <header className="sdf-login-header">
        <div className="sdf-login-header-inner">
          <div className="sdf-brand-inline">
            <KyndrylLogo className="brand-wordmark" />
            <span className="brand-rule" aria-hidden />
            <div className="sdf-brand-titles">
              <strong>MLPS 3.0 Compliance Platform</strong>
              <span>等保三级扫描与报告系统</span>
            </div>
          </div>
          <button
            type="button"
            className="sdf-theme-btn"
            onClick={cycleTheme}
            title={`切换界面主题（当前：${currentTheme.label}）`}
          >
            <Palette size={14} />
            <span>{currentTheme.label}</span>
          </button>
        </div>
      </header>

      <main className="sdf-login-main">
        <section className="sdf-hero blueprint-grid">
          <p className="stencil sdf-eyebrow">MLPS 3.0 COMPLIANCE FACTORY</p>
          <h1 className="sdf-hero-title">
            把等保三级合规评估纳入统一治理，从只读采集直达整改闭环。
          </h1>
          <p className="sdf-hero-desc">
            多源只读探针、保拓扑脱敏与 AI 大模型协同研判，自动化完成 GB/T 22239-2019 条款映射与跨组件攻击路径分析；安全负责人在关键确认点复核拍板，漏洞处置与合规台账全链路留痕可追溯。
          </p>
          <div className="hazard-stripe sdf-hero-stripe" aria-hidden />

          <div className="sdf-cap-wrap">
            <h2 className="stencil sdf-cap-heading">PLATFORM CAPABILITIES</h2>
            <div className="sdf-cap-grid">
              {CAPABILITIES.map((item) => (
                <div key={item.title} className="sdf-cap-cell">
                  <item.icon size={16} className="sdf-cap-icon" aria-hidden />
                  <h3>{item.title}</h3>
                  <p>{item.desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="sdf-auth-wrap">
          <form className="sdf-auth-card" onSubmit={onSubmit}>
            <div className="sdf-auth-head">
              <p className="stencil sdf-eyebrow">WORKBENCH ACCESS</p>
              <h2>登录工作台</h2>
              <p>使用工作台账号与口令进入受治理的等保合规评估空间</p>
            </div>

            <div className="sdf-auth-fields">
              <label className="field">
                <span>邮箱</span>
                <input
                  name="email"
                  type="email"
                  required
                  defaultValue="security@company.com"
                  placeholder="name@company.com"
                  autoComplete="username"
                />
              </label>
              <label className="field">
                <span>密码</span>
                <input
                  name="password"
                  type="password"
                  required
                  placeholder="请输入登录口令"
                  autoComplete="current-password"
                />
              </label>
              {error && <div className="error">{error}</div>}
              <button className="btn sdf-login-submit" type="submit" disabled={busy}>
                <span>{busy ? "正在登录…" : "登录"}</span>
                {!busy && <ArrowRight size={15} />}
              </button>
            </div>

            <p className="sdf-auth-footnote">
              系统管理员、等保负责人与只读审计员按最小权限隔离操作范围；正式测评报告仍由具备资质的测评机构出具。
            </p>
          </form>
        </section>
      </main>

      <footer className="sdf-login-footer">
        <div className="sdf-login-footer-inner">
          <span>Kyndryl MLPS 3.0 Compliance Platform · 等保三级扫描与报告系统</span>
          <span className="stencil">GOVERNED COMPLIANCE WORKBENCH</span>
        </div>
      </footer>
    </div>
  );
}
