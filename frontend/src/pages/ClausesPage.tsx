import { useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import DataTable from "../components/DataTable";
import Drawer from "../components/Drawer";
import StatusBadge from "../components/StatusBadge";
import { AUTO_LABEL, OBJECT_TYPE_LABEL, RISK_WEIGHT_LABEL } from "../labels";

type HighRiskPrecedent = {
  standard_ref: string;
  precedent_code: string;
  category: string;
  direct_high_risk: boolean;
  can_downgrade_with_compensation: boolean;
  trigger_condition: string;
  compensating_controls: string[];
};

type Clause = {
  clause_id: string;
  domain: string;
  control_point: string;
  extension_type?: string;
  auto_level: string;
  high_risk: boolean;
  requirement_text: string;
  manual_check_guide: string;
  applicable_objects?: string[];
  applicable_object_labels?: string[];
  risk_weight_level?: string;
  risk_weight?: number;
  high_risk_precedent?: HighRiskPrecedent | null;
};

const EXT_LABEL: Record<string, string> = {
  GENERAL: "安全通用要求",
  CLOUD: "云计算安全扩展",
};

export default function ClausesPage() {
  const [params, setParams] = useSearchParams();
  const [rows, setRows] = useState<Clause[]>([]);
  const [error, setError] = useState("");
  const [extension, setExtension] = useState("");
  const [domain, setDomain] = useState("");
  const [objectFilter, setObjectFilter] = useState("");
  const [level, setLevel] = useState("");
  const [highOnly, setHighOnly] = useState(false);
  const [current, setCurrent] = useState<Clause | null>(null);
  const query = params.get("q") || "";

  useEffect(() => {
    api<Clause[]>("/api/clauses").then(setRows).catch((err: Error) => setError(err.message));
  }, []);

  const generalCount = useMemo(() => rows.filter((row) => (row.extension_type || "GENERAL") === "GENERAL").length, [rows]);
  const cloudCount = useMemo(() => rows.filter((row) => row.extension_type === "CLOUD").length, [rows]);
  const domains = useMemo(() => Array.from(new Set(rows.map((row) => row.domain))), [rows]);
  const filtered = rows.filter((row) => {
    const text = `${row.clause_id} ${row.control_point} ${row.requirement_text} ${(row.applicable_object_labels || []).join(" ")} ${row.high_risk_precedent?.category || ""}`;
    if (query && !text.toLowerCase().includes(query.toLowerCase())) return false;
    if (extension && (row.extension_type || "GENERAL") !== extension) return false;
    if (domain && row.domain !== domain) return false;
    if (objectFilter && !(row.applicable_objects || []).includes(objectFilter)) return false;
    if (level && row.auto_level !== level) return false;
    if (highOnly && !row.high_risk) return false;
    return true;
  });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>等保三级条款库</h1>
          <p>
            本库严格对齐国家标准 GB/T 22239-2019 第三级，共收录 {rows.length} 项要求（安全通用要求 {generalCount} 项 + 云计算安全扩展 {cloudCount} 项），逐条标注适用测评对象与 T/ISEAA 001-2020 高风险判例参考。
          </p>
        </div>
      </div>
      {error && <div className="error">{error}</div>}
      {query && (
        <div className="banner">
          <span>条款库正在按「{query}」筛选条款编号、控制点、测评对象和要求原文。</span>
          <button className="btn-ghost" onClick={() => setParams({})}>清除筛选</button>
        </div>
      )}
      <section className="kpi-grid">
        <article className="kpi"><div className="label">条款总数</div><div className="value">{rows.length}</div><div className="muted">通用 {generalCount} · 云扩展 {cloudCount}</div></article>
        <article className="kpi orange"><div className="label">高风险判例项</div><div className="value">{rows.filter((row) => row.high_risk).length}</div><div className="muted">对照 T/ISEAA 001-2020 · 权重 3</div></article>
        <article className="kpi blue"><div className="label">可自动 / 部分证据</div><div className="value">{rows.filter((row) => row.auto_level !== "MANUAL_ONLY").length}</div><div className="muted">结合 7 类技术测评对象覆盖度核验</div></article>
        <article className="kpi green"><div className="label">仅人工核查</div><div className="value">{rows.filter((row) => row.auto_level === "MANUAL_ONLY").length}</div><div className="muted">物理机房与安全管理体系为主</div></article>
      </section>
      <article className="card">
        <div className="card-pad filters">
          <input
            aria-label="在当前条款库中筛选"
            placeholder="条款编号、控制点、判例或关键词"
            value={query}
            onChange={(event) => {
              const next = event.target.value;
              if (next) setParams({ q: next });
              else setParams({});
            }}
          />
          <select value={extension} onChange={(event) => setExtension(event.target.value)}>
            <option value="">全部标准类别（{rows.length} 项）</option>
            <option value="GENERAL">安全通用要求（{generalCount} 项）</option>
            <option value="CLOUD">云计算安全扩展（{cloudCount} 项）</option>
          </select>
          <select value={domain} onChange={(event) => setDomain(event.target.value)}>
            <option value="">全部安全域</option>
            {domains.map((item) => <option key={item}>{item}</option>)}
          </select>
          <select value={objectFilter} onChange={(event) => setObjectFilter(event.target.value)}>
            <option value="">全部测评对象</option>
            {Object.entries(OBJECT_TYPE_LABEL).map(([key, label]) => (
              <option key={key} value={key}>{label}</option>
            ))}
          </select>
          <select value={level} onChange={(event) => setLevel(event.target.value)}>
            <option value="">全部自动化级别</option>
            <option value="FULL_AUTO">可由系统给出结论</option>
            <option value="PARTIAL_EVIDENCE">部分证据</option>
            <option value="MANUAL_ONLY">仅人工</option>
          </select>
          <label className="check"><input type="checkbox" checked={highOnly} onChange={(event) => setHighOnly(event.target.checked)} />只看高风险</label>
        </div>
        <DataTable
          rows={filtered}
          onRow={setCurrent}
          columns={[
            { key: "id", title: "条款编号", render: (row) => <span className="mono">{row.clause_id}</span> },
            { key: "ext", title: "类别", render: (row) => <span className={`badge ${row.extension_type === "CLOUD" ? "info" : ""}`}>{EXT_LABEL[row.extension_type || "GENERAL"] || "安全通用要求"}</span> },
            { key: "domain", title: "安全域", render: (row) => row.domain },
            { key: "point", title: "控制点", render: (row) => row.control_point },
            {
              key: "objects",
              title: "适用测评对象",
              render: (row) => (
                <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                  {(row.applicable_object_labels || []).map((label) => (
                    <span key={label} className="badge">{label}</span>
                  ))}
                </div>
              ),
            },
            { key: "auto", title: "自动化", render: (row) => AUTO_LABEL[row.auto_level] || row.auto_level },
            {
              key: "risk",
              title: "高风险判例",
              render: (row) => row.high_risk
                ? <span title={row.high_risk_precedent?.category || ""}><StatusBadge value="high" /></span>
                : <span className="muted">{RISK_WEIGHT_LABEL[row.risk_weight_level || "medium"]?.split("（")[0] || "中风险"}</span>,
            },
            { key: "text", title: "标准要求", render: (row) => row.requirement_text },
          ]}
        />
      </article>
      <Drawer open={!!current} title={current?.clause_id || ""} onClose={() => setCurrent(null)}>
        {current && (
          <>
            <p>
              <b>{current.domain}</b> · {current.control_point} ·{" "}
              <span className="badge">{EXT_LABEL[current.extension_type || "GENERAL"] || "安全通用要求"}</span>{" "}
              <span className="badge">{RISK_WEIGHT_LABEL[current.risk_weight_level || "medium"] || "中风险（权重 2）"}</span>
            </p>
            <p style={{ margin: "12px 0" }}>{current.requirement_text}</p>
            <div className="muted" style={{ marginTop: 10 }}>适用测评对象</div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6, margin: "6px 0 12px" }}>
              {(current.applicable_object_labels || []).map((label) => (
                <span key={label} className="badge info">{label}</span>
              ))}
            </div>
            <div className="muted">核查指引</div>
            <p style={{ margin: "4px 0 12px" }}>{current.manual_check_guide}</p>
            {current.high_risk_precedent && (
              <div style={{ border: "1px solid var(--border)", borderLeft: "3px solid var(--accent)", borderRadius: 6, padding: "10px 12px", marginTop: 12 }}>
                <div style={{ fontWeight: 700, marginBottom: 4 }}>
                  高风险判例参考（{current.high_risk_precedent.standard_ref} · {current.high_risk_precedent.precedent_code}）
                </div>
                <p style={{ margin: "4px 0" }}>
                  <b>判例类别：</b>{current.high_risk_precedent.category}
                  {" "}
                  <span className={`badge ${current.high_risk_precedent.can_downgrade_with_compensation ? "info" : "danger"}`}>
                    {current.high_risk_precedent.can_downgrade_with_compensation ? "存在有效补偿措施可评估降级" : "核心底线 · 建议优先直接整改"}
                  </span>
                </p>
                <p style={{ margin: "4px 0" }}><b>典型触发情形：</b>{current.high_risk_precedent.trigger_condition}</p>
                {current.high_risk_precedent.compensating_controls.length > 0 && (
                  <>
                    <div className="muted" style={{ marginTop: 6 }}>常见弥补 / 补偿控制参考：</div>
                    <ul style={{ margin: "4px 0 0 18px", padding: 0 }}>
                      {current.high_risk_precedent.compensating_controls.map((item) => (
                        <li key={item} style={{ marginBottom: 4 }}>{item}</li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
            )}
          </>
        )}
      </Drawer>
    </>
  );
}
