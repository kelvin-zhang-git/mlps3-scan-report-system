import { MouseEvent, ReactNode } from "react";

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

export function cveIds(text?: string | null): string[] {
  if (!text) return [];
  const found = text.match(new RegExp(CVE_RE.source, "gi")) || [];
  return Array.from(new Set(found.map((item) => item.toUpperCase())));
}

export function cveRecordUrl(id: string): string {
  return `https://www.cve.org/CVERecord?id=${id.toUpperCase()}`;
}

export function nvdUrl(id: string): string {
  return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`;
}

function keepRow(event: MouseEvent) {
  event.stopPropagation();
}

/** 正文里的 CVE 编号链到 CVE Program 官方记录。 */
export function CveText({ text }: { text?: string | null }) {
  const value = text || "";
  const nodes: ReactNode[] = [];
  const re = new RegExp(CVE_RE.source, "gi");
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = re.exec(value))) {
    if (match.index > last) nodes.push(value.slice(last, match.index));
    const id = match[0].toUpperCase();
    nodes.push(
      <a
        key={`${id}-${match.index}`}
        className="cve-link"
        href={cveRecordUrl(id)}
        target="_blank"
        rel="noreferrer"
        title="打开 CVE 官方记录"
        onClick={keepRow}
      >
        {id}
      </a>,
    );
    last = match.index + match[0].length;
  }
  if (!nodes.length) return <>{value}</>;
  if (last < value.length) nodes.push(value.slice(last));
  return <>{nodes}</>;
}

/** CVE 字段：编号打开官方记录，旁边的 NVD 打开评分和受影响范围。 */
export function CveField({ value }: { value?: string | null }) {
  const ids = cveIds(value);
  if (!value) return <>—</>;
  return (
    <span className="cve-field">
      <CveText text={value} />
      {ids.map((id) => (
        <a
          key={id}
          className="cve-nvd"
          href={nvdUrl(id)}
          target="_blank"
          rel="noreferrer"
          title="在 NVD 查看评分和受影响范围"
          onClick={keepRow}
        >
          NVD
        </a>
      ))}
    </span>
  );
}
