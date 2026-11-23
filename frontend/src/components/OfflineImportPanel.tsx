import { useState } from "react";
import { api } from "../api";

type Props = {
  projectId: string;
  jobId: string;
  writable: boolean;
  onImported: (result: { imported: number; passed: number; failed: number; job_id: string; source: string }) => Promise<void> | void;
};

type TemplateResp = {
  netdev_config: { device_name: string; device_role: string; config_text: string };
  cloud_audit: Record<string, unknown>;
};

export default function OfflineImportPanel({ projectId, jobId, writable, onImported }: Props) {
  const [mode, setMode] = useState<"netdev_config" | "cloud_audit">("netdev_config");
  const [deviceName, setDeviceName] = useState("FW-BORDER-01");
  const [deviceRole, setDeviceRole] = useState("security_device");
  const [configText, setConfigText] = useState("");
  const [cloudJson, setCloudJson] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  async function loadSample() {
    setError("");
    setSuccess("");
    try {
      const tpl = await api<TemplateResp>("/api/imports/templates");
      if (mode === "netdev_config") {
        setDeviceName(tpl.netdev_config.device_name || "FW-BORDER-01");
        setDeviceRole(tpl.netdev_config.device_role || "security_device");
        setConfigText(tpl.netdev_config.config_text || "");
      } else {
        setCloudJson(JSON.stringify(tpl.cloud_audit, null, 2));
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "载入示例模板失败");
    }
  }

  async function submit() {
    setError("");
    setSuccess("");
    setBusy(true);
    try {
      let payload: Record<string, unknown>;
      if (mode === "netdev_config") {
        if (!configText.trim()) throw new Error("请先粘贴或选择网络/安全设备脱敏配置文本");
        payload = { device_name: deviceName.trim() || "边界设备", device_role: deviceRole, config_text: configText };
      } else {
        if (!cloudJson.trim()) throw new Error("请先粘贴或选择云平台只读核查 JSON");
        try {
          payload = JSON.parse(cloudJson) as Record<string, unknown>;
        } catch {
          throw new Error("云平台核查内容不是合法的 JSON 格式，请检查后重试");
        }
      }
      const res = await api<{ imported: number; passed: number; failed: number; job_id: string; source: string }>(
        `/api/imports/${projectId}`,
        {
          method: "POST",
          body: JSON.stringify({ source: mode, payload, job_id: jobId || null }),
        },
      );
      setSuccess(`已解析并导入 ${res.imported} 条核查证据（通过 ${res.passed} 条 · 不符合 ${res.failed} 条），测评对象覆盖矩阵已自动更新。`);
      await onImported(res);
    } catch (err) {
      setError(err instanceof Error ? err.message : "离线导入失败");
    } finally {
      setBusy(false);
    }
  }

  function onFile(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      const content = String(reader.result || "");
      if (mode === "netdev_config") setConfigText(content);
      else setCloudJson(content);
    };
    reader.readAsText(file, "utf-8");
    event.target.value = "";
  }

  return (
    <article className="card card-pad" style={{ marginTop: 14 }}>
      <div className="section-title" style={{ padding: 0, borderBottom: "none", marginBottom: 10 }}>
        <h2 style={{ margin: 0 }}>离线配置与云平台只读核查导入（补齐网络、安全设备与云端实测）</h2>
      </div>
      <p className="muted" style={{ marginTop: 0, marginBottom: 10 }}>
        对于不便直接 SSH 接入的防火墙、交换机与云平台控制面，可在此导入脱敏配置文本或只读核查 JSON；系统将自动完成规则解析、零泄漏检查并关联至等保三级条款与测评对象覆盖矩阵。
      </p>
      <div className="filters" style={{ marginBottom: 12 }}>
        <button className={mode === "netdev_config" ? "btn" : "btn-ghost"} onClick={() => { setMode("netdev_config"); setError(""); setSuccess(""); }}>
          网络 / 安全设备配置解析
        </button>
        <button className={mode === "cloud_audit" ? "btn" : "btn-ghost"} onClick={() => { setMode("cloud_audit"); setError(""); setSuccess(""); }}>
          云平台只读核查导入（安全组 / IAM / 审计）
        </button>
        <button className="btn-ghost" disabled={!writable} onClick={() => { void loadSample(); }}>载入脱敏示例</button>
        <label className="btn-ghost" style={{ cursor: writable ? "pointer" : "not-allowed", display: "inline-flex", alignItems: "center" }}>
          从本地文件读取
          <input type="file" accept=".txt,.cfg,.conf,.json" disabled={!writable} style={{ display: "none" }} onChange={onFile} />
        </label>
      </div>
      {error && <div className="error" style={{ marginBottom: 10 }}>{error}</div>}
      {success && <div className="banner" style={{ marginBottom: 10 }}>{success}</div>}
      {mode === "netdev_config" ? (
        <>
          <div className="filters" style={{ marginBottom: 10 }}>
            <input
              className="inline-input"
              placeholder="设备标识（如 FW-BORDER-01）"
              value={deviceName}
              onChange={(event) => setDeviceName(event.target.value)}
            />
            <select value={deviceRole} onChange={(event) => setDeviceRole(event.target.value)}>
              <option value="security_device">安全设备（防火墙 / NGFW / IPS）</option>
              <option value="network_device">网络设备（核心交换机 / 路由器）</option>
            </select>
          </div>
          <label className="field">
            设备脱敏配置文本（支持华为 VRP/USG、H3C、Cisco IOS/ASA、FortiGate、iptables）
            <textarea
              rows={8}
              placeholder="粘贴已去除口令/密钥的设备配置文件（display current-configuration / show running-config）..."
              value={configText}
              onChange={(event) => setConfigText(event.target.value)}
              style={{ fontFamily: "Consolas, monospace", fontSize: 12 }}
            />
          </label>
        </>
      ) : (
        <label className="field">
          云平台只读核查 JSON（包含 region、security_groups、iam、audit_trail、encryption、backup 等字段）
          <textarea
            rows={9}
            placeholder='{"provider":"Aliyun","region":"cn-hangzhou","security_groups":[...],"iam":{...},"audit_trail":{...}}'
            value={cloudJson}
            onChange={(event) => setCloudJson(event.target.value)}
            style={{ fontFamily: "Consolas, monospace", fontSize: 12 }}
          />
        </label>
      )}
      <div className="filters" style={{ marginTop: 10 }}>
        <button className="btn" disabled={!writable || busy} onClick={() => { void submit(); }}>
          {busy ? "正在解析并导入…" : "解析并导入至当前任务"}
        </button>
        <span className="muted">导入后建议在下方确认脱敏状态，或重新触发「确认脱敏结果并开始评审」以刷新全量条款结论。</span>
      </div>
    </article>
  );
}
