import { statusText } from "../labels";

const TONE: Record<string, string> = {
  completed: "ok",
  compliant: "ok",
  reachable: "ok",
  running: "info",
  queued: "info",
  awaiting_approval: "warn",
  partially_compliant: "warn",
  pending_manual: "warn",
  medium: "warn",
  failed: "danger",
  non_compliant: "danger",
  critical: "critical",
  high: "high",
};

export default function StatusBadge({ value }: { value: string }) {
  return <span className={`badge ${TONE[value] || ""}`}>{statusText(value)}</span>;
}
