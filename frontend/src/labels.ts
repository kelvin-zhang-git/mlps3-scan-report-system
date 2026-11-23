export const STATUS_LABEL: Record<string, string> = {
  awaiting_approval: "待确认脱敏",
  completed: "已完成",
  running: "扫描中",
  failed: "失败",
  queued: "排队",
  compliant: "符合",
  partially_compliant: "部分符合",
  non_compliant: "不符合",
  pending_manual: "待人工",
  not_applicable: "不适用",
  not_assessed: "未评估",
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
  BASELINE_PASS: "通过",
  BASELINE_FAIL: "未通过",
  READONLY_AUDIT: "只读核查",
  ACTIVE_SCAN: "主动扫描",
  draft: "草稿",
  active: "已启动",
  archived: "已归档",
};

export const ROLE_LABEL: Record<string, string> = {
  admin: "系统管理员",
  security_lead: "等保负责人",
  auditor: "只读审计员",
};

export const AUTO_LABEL: Record<string, string> = {
  FULL_AUTO: "可由系统给出结论",
  PARTIAL_EVIDENCE: "部分证据",
  MANUAL_ONLY: "仅人工",
};

export const OBJECT_TYPE_LABEL: Record<string, string> = {
  host_os: "主机操作系统",
  network_device: "网络设备",
  security_device: "安全设备",
  database: "数据库",
  middleware: "中间件",
  application: "业务应用",
  cloud_platform: "云平台",
  physical_room: "物理机房",
  org_management: "安全管理体系",
};

export const TECH_OBJECT_OPTIONS: Array<[string, string]> = [
  ["host_os", "主机操作系统"],
  ["network_device", "网络设备"],
  ["security_device", "安全设备"],
  ["database", "数据库"],
  ["middleware", "中间件"],
  ["application", "业务应用"],
  ["cloud_platform", "云平台"],
];

export const RISK_WEIGHT_LABEL: Record<string, string> = {
  high: "高风险（权重 3）",
  medium: "中风险（权重 2）",
  low: "低风险（权重 1）",
};

export function statusText(value: string) {
  return STATUS_LABEL[value] || value || "—";
}

export function canOperate(role?: string) {
  return role === "admin" || role === "security_lead";
}
