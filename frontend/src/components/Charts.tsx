import { statusText } from "../labels";
import { formatBeijing } from "../time";

const SEVERITY = [
  { key: "critical", label: "严重", hint: "需立即处理", color: "#b42318" },
  { key: "high", label: "高危", hint: "优先整改", color: "#ea580c" },
  { key: "medium", label: "中危", hint: "纳入整改计划", color: "#d97706" },
  { key: "low", label: "低危", hint: "可排期处理", color: "#2563eb" },
  { key: "info", label: "信息", hint: "基线通过或提示", color: "#98a2b3" },
];

function when(value?: string) {
  if (!value) return "时间未知";
  const text = formatBeijing(value);
  return text ? text.slice(5) : "时间未知";
}

export function DonutChart({ counts }: { counts: Record<string, number> }) {
  const total = SEVERITY.reduce((sum, item) => sum + (counts[item.key] || 0), 0);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  return (
    <div className="severity-layout">
      <svg viewBox="0 0 140 140" role="img" aria-label="发现严重度分布">
        <circle cx="70" cy="70" r={radius} fill="none" stroke="var(--border-hairline)" strokeWidth="18" />
        {SEVERITY.map((item) => {
          const value = counts[item.key] || 0;
          const length = total ? (value / total) * circumference : 0;
          const node = (
            <circle key={item.key} cx="70" cy="70" r={radius} fill="none" stroke={item.color} strokeWidth="18"
              strokeDasharray={`${length} ${circumference - length}`} strokeDashoffset={-offset} transform="rotate(-90 70 70)" />
          );
          offset += length;
          return value ? node : null;
        })}
        <text x="70" y="66" textAnchor="middle" fontSize="22" fontWeight="700" fill="currentColor">{total}</text>
        <text x="70" y="86" textAnchor="middle" fontSize="11" fill="var(--text-muted)">条发现</text>
      </svg>
      <table className="severity-table">
        <thead>
          <tr><th>严重度</th><th>含义</th><th>数量</th><th>占比</th></tr>
        </thead>
        <tbody>
          {SEVERITY.map((item) => {
            const value = counts[item.key] || 0;
            const pct = total ? Math.round(value / total * 1000) / 10 : 0;
            return (
              <tr key={item.key}>
                <td><span className="swatch" style={{ background: item.color }} />{item.label}</td>
                <td className="muted">{item.hint}</td>
                <td>{value}</td>
                <td>
                  <div className="mini-track"><div style={{ width: `${pct}%`, background: item.color }} /></div>
                  <span>{pct}%</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function TrendChart({ points }: { points: Array<{ job_id: string; started_at?: string; status?: string; high: number; other: number; total?: number }> }) {
  const rows = [...points].reverse();
  const max = Math.max(1, ...rows.map((item) => item.high + item.other));
  if (!rows.length) return <div className="empty">发起核查之后，这里会按时间列出每次扫描归集到的发现。</div>;
  return (
    <div className="scan-list">
      <p className="muted">每一行对应一次扫描。橙色表示严重和高危，灰色表示中危、低危和信息，后面的数字是这一次归集到的条数。</p>
      {rows.map((point) => {
        const total = point.total ?? point.high + point.other;
        const highPct = (point.high / max) * 100;
        const otherPct = (point.other / max) * 100;
        return (
          <div className="scan-row" key={point.job_id}>
            <div className="scan-meta">
              <strong>{when(point.started_at)}</strong>
              <span className="mono" title={point.job_id}>{point.job_id}</span>
              <span className="muted">{statusText(point.status || "")}</span>
            </div>
            <div>
              <div className="scan-track" aria-label={`${point.job_id} 高危 ${point.high}，其余 ${point.other}`}>
                <div style={{ width: `${highPct}%`, background: "#ea580c" }} />
                <div style={{ width: `${otherPct}%`, background: "#98a2b3" }} />
              </div>
              <div className="scan-note">高危及以上 {point.high} 条 · 其余 {point.other} 条 · 合计 {total} 条</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

export function DomainBars({
  rows,
  onSelect,
}: {
  rows: Array<{ domain: string; completeness?: number; compliant_rate?: number; checked_score?: number; high_open: number; pending?: number; total?: number }>;
  onSelect?: (domain: string) => void;
}) {
  if (!rows.length) return <div className="empty">完成一次条款评估后，这里按安全域显示核查进度。</div>;
  return (
    <div className="table-wrap domain-table-wrap">
      <table className="domain-table">
        <thead>
          <tr>
            <th>安全域</th>
            <th className="num">条款数</th>
            <th>核查完备度</th>
            <th className="num">已核查得分</th>
            <th className="num">待人工</th>
            <th className="num">高风险未关闭</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const completeness = row.completeness ?? row.compliant_rate ?? 0;
            const pending = row.pending ?? 0;
            const total = row.total ?? pending;
            const scored = completeness > 0 && row.checked_score != null;
            return (
              <tr
                key={row.domain}
                className={onSelect ? "clickable" : undefined}
                onClick={() => onSelect?.(row.domain)}
              >
                <td className="domain-name">{row.domain}</td>
                <td className="num muted">{total}</td>
                <td>
                  <div className="domain-prog">
                    <div className="bar-track" aria-label={`${row.domain} 完备度 ${completeness}%`}>
                      <div className="bar-fill" style={{ width: `${completeness}%` }} />
                    </div>
                    <span className="num pct">{completeness}%</span>
                  </div>
                </td>
                <td className="num">
                  {scored ? <b>{row.checked_score} 分</b> : <span className="muted">—</span>}
                </td>
                <td className="num">
                  {pending > 0 ? <span className="badge warn">{pending} 条</span> : <span className="muted">0</span>}
                </td>
                <td className="num">
                  {row.high_open > 0
                    ? <span className={`badge ${row.high_open >= 5 ? "danger" : "high"}`}>{row.high_open} 项</span>
                    : <span className="badge ok">0 项</span>}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
