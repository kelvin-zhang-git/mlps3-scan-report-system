"""把正文里的 CVE 编号换成可点击的官方记录地址。"""
from __future__ import annotations

import re

from markupsafe import Markup, escape

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def cve_record_url(cve_id: str) -> str:
    return f"https://www.cve.org/CVERecord?id={cve_id.upper()}"


def linkify_cves_html(value: object) -> Markup:
    raw = "" if value is None else str(value)
    chunks: list[str] = []
    last = 0
    for match in CVE_RE.finditer(raw):
        chunks.append(str(escape(raw[last:match.start()])))
        cve_id = match.group(0).upper()
        href = escape(cve_record_url(cve_id))
        chunks.append(f'<a href="{href}">{escape(cve_id)}</a>')
        last = match.end()
    chunks.append(str(escape(raw[last:])))
    return Markup("".join(chunks))


def linkify_cves_md(value: object) -> str:
    def repl(match: re.Match[str]) -> str:
        cve_id = match.group(0).upper()
        return f"[{cve_id}]({cve_record_url(cve_id)})"

    return CVE_RE.sub(repl, "" if value is None else str(value))
