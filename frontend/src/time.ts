/** 界面时间统一按北京时间（UTC+8）展示，库内仍保存 UTC。 */

function asDate(value: string): Date | null {
  const raw = value.trim();
  if (!raw) return null;
  const hasZone = /(?:[zZ]|[+-]\d{2}:?\d{2})$/.test(raw);
  const normalized = hasZone ? raw : `${raw.replace(" ", "T")}Z`;
  const date = new Date(normalized);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatBeijing(value?: string | null): string {
  if (!value) return "";
  const date = asDate(value);
  if (!date) return value.replace("T", " ").slice(0, 16);
  const parts = new Intl.DateTimeFormat("zh-CN", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  const pick = (type: string) => parts.find((item) => item.type === type)?.value || "";
  return `${pick("year")}-${pick("month")}-${pick("day")} ${pick("hour")}:${pick("minute")}`;
}
