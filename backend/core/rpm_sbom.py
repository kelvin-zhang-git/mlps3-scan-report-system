"""把目标机的 RPM 清单转成 CycloneDX，供 Trivy 做离线漏洞比对。"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote


def _normalize_family(os_name: str) -> str:
    low = (os_name or "").strip().lower()
    if "centos" in low:
        return "centos"
    if "alma" in low:
        return "almalinux"
    if "rhel" in low or "redhat" in low:
        return "redhat"
    if "fedora" in low:
        return "fedora"
    if "oracle" in low or low == "ol":
        return "oracle"
    if "sles" in low or "suse" in low:
        return "suse"
    if "rocky" in low:
        return "rocky"
    return low or "rocky"


def _clean_epoch(raw_epoch: str) -> str:
    ep = (raw_epoch or "").strip()
    if not ep or ep.lower() == "(none)" or ep == "0":
        return ""
    return ep if ep.isdigit() else ""


def rpm_to_cyclonedx(lines: list[str], os_name: str, os_version: str) -> dict[str, Any]:
    family = _normalize_family(os_name)
    distro = f"{family}-{os_version}" if os_version else family
    components = []
    seen: set[tuple[str, str, str, str]] = set()
    for line in lines:
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        name, raw_epoch, version, release, arch = [p.strip() for p in parts[:5]]
        if not name or not version:
            continue
        epoch = _clean_epoch(raw_epoch)
        ver_rel = f"{version}-{release}" if release else version
        key = (name, epoch, ver_rel, arch)
        if key in seen:
            continue
        seen.add(key)
        # RPM Epoch 必须完整写入 CycloneDX version 与 PURL qualifier，否则 Trivy 会将带 Epoch 的包误判为极旧版本导致大量历史 CVE 误报
        full_version = f"{epoch}:{ver_rel}" if epoch else ver_rel
        qualifiers = [f"arch={quote(arch)}", f"distro={quote(distro)}"]
        if epoch:
            qualifiers.append(f"epoch={epoch}")
        purl = f"pkg:rpm/{family}/{quote(name)}@{quote(ver_rel)}?{'&'.join(qualifiers)}"
        components.append({
            "type": "library",
            "name": name,
            "version": full_version,
            "purl": purl,
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "operating-system",
                "name": family,
                "version": os_version or "unknown",
            }
        },
        "components": components,
    }
