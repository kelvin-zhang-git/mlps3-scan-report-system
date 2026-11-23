"""在扫描机上按白名单调用一次性扫描容器。超时时强制清理容器，不留僵尸进程。"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import subprocess

from core.policy import PolicyError, host_decision

NMAP_IMAGE = os.environ.get("NMAP_IMAGE", "instrumentisto/nmap:latest")
NUCLEI_IMAGE = os.environ.get("NUCLEI_IMAGE", "projectdiscovery/nuclei:latest")
TRIVY_IMAGE = os.environ.get("TRIVY_IMAGE", "aquasec/trivy:latest")
TRIVY_TARGET = os.environ.get("TRIVY_IMAGE_REF", "bkimminich/juice-shop:latest")


def _assert_host(host: str, policy: dict) -> None:
    ok, reason = host_decision(host, policy["whitelist_cidrs"], policy["forbidden_cidrs"])
    if not ok:
        raise PolicyError(f"{host}：{reason}")


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    if not shutil.which("docker"):
        raise RuntimeError("扫描机没有 docker 命令")
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def _run_container(prefix: str, docker_args: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
    """带命名容器与超时强杀机制的容器调度，避免超时熔断后留下僵尸容器。"""
    if not shutil.which("docker"):
        raise RuntimeError("扫描机没有 docker 命令")
    name = f"mlps-scan-{prefix}-{secrets.token_hex(4)}"
    cmd = ["docker", "run", "--rm", "--name", name, *docker_args]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        subprocess.run(["docker", "rm", "-f", name], capture_output=True, text=True, timeout=15, check=False)
        raise


def _proxy_env() -> list[str]:
    proxy = os.environ.get("OUTBOUND_PROXY", "").strip()
    if not proxy:
        return []
    return [
        "-e", f"http_proxy={proxy}",
        "-e", f"https_proxy={proxy}",
        "-e", f"HTTP_PROXY={proxy}",
        "-e", f"HTTPS_PROXY={proxy}",
        "-e", "no_proxy=localhost,127.0.0.1,192.168.1.0/24",
        "-e", "NO_PROXY=localhost,127.0.0.1,192.168.1.0/24",
    ]


def scan_nmap(host: str, policy: dict) -> tuple[str, list[dict]]:
    _assert_host(host, policy)
    timeout = int(os.environ.get("NMAP_TIMEOUT_SEC", "240"))
    arguments = ["-Pn", "-sT", "-sV", "--version-intensity", "2", "--top-ports", "1000", "-oX", "-", host]
    if shutil.which("nmap"):
        completed = _run(["nmap", *arguments], timeout)
        source = "本机 nmap"
    else:
        completed = _run_container(
            "nmap",
            ["--network", "host", NMAP_IMAGE, *arguments],
            timeout,
        )
        source = NMAP_IMAGE
    if completed.returncode not in (0, 1) or "<nmaprun" not in completed.stdout:
        detail = (completed.stderr or completed.stdout or "无输出").strip()[:400]
        return f"{source} 未返回结果：{detail}", []
    from core.runner import parse_nmap_xml

    rows = parse_nmap_xml(completed.stdout, "")
    return f"{source} 发现开放端口 {len(rows)} 个", rows


def scan_nuclei(host: str, policy: dict) -> tuple[str, list[dict]]:
    _assert_host(host, policy)
    excluded = policy.get("global_limits", {}).get("nuclei_exclude_tags") or ["dos", "fuzz", "intrusive", "bruteforce"]
    rate = str(policy.get("global_limits", {}).get("nuclei_rate_limit") or 50)
    timeout = int(os.environ.get("NUCLEI_TIMEOUT_SEC", "240"))
    # 让 Nuclei 在容器被杀掉之前自己结束，把已经命中的结果写出来。
    budget = max(60, timeout - 30)
    max_time = f"{max(1, budget // 60)}m"
    targets = list(policy.get("web_targets") or [f"http://{host}"])
    target_args: list[str] = []
    for url in targets[:8]:
        target_args.extend(["-u", url])
    docker_args = [
        "--network", "host",
        *_proxy_env(),
        "-v", "mlps-nuclei-templates:/root/nuclei-templates",
        "-v", "mlps-nuclei-config:/root/.config/nuclei",
        NUCLEI_IMAGE,
        *target_args,
        "-rate-limit", rate,
        "-etags", ",".join(excluded),
        "-severity", "low,medium,high,critical",
        "-t", "http/misconfiguration/",
        "-t", "http/exposures/",
        "-t", "ssl/",
        "-duc",
        "-no-interactsh",
        "-omit-raw",
        "-jsonl",
        "-silent",
        "-timeout", "5",
        "-retries", "0",
        "-mhe", "10",
        "-max-time", max_time,
    ]
    timed_out = False
    try:
        completed = _run_container("nuclei", docker_args, timeout)
        output = completed.stdout or ""
        returncode = completed.returncode
        error_text = completed.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        raw_out = exc.stdout or ""
        output = raw_out.decode("utf-8", "replace") if isinstance(raw_out, bytes) else raw_out
        returncode = 124
        raw_err = exc.stderr or ""
        error_text = raw_err.decode("utf-8", "replace") if isinstance(raw_err, bytes) else raw_err
    rows = []
    seen_keys: set[tuple[str, str]] = set()
    for line in output.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        classification = info.get("classification") or {}
        cves = classification.get("cve-id") or []
        cwes = classification.get("cwe-id") or []
        raw_sev = str(info.get("severity") or "info").lower()
        template_id = str(item.get("template-id") or "nuclei")
        port = str(item.get("port") or "")
        if raw_sev == "info" and template_id == "http-missing-security-headers":
            severity = "low"
        elif raw_sev in {"low", "medium", "high", "critical"}:
            severity = raw_sev
        else:
            continue
        dedup_key = (template_id, port)
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        rows.append({
            "source_tool": "nuclei",
            "evidence_type": "VULNERABILITY",
            "severity": severity,
            "cve_or_cwe": cves[0] if cves else (cwes[0] if cwes else None),
            "title": str(info.get("name") or template_id),
            "port": port,
            "detail": {"text": str(item.get("matched-at") or ""), "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"]},
            "origin": "live",
            "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"],
        })
    if returncode not in (0, 1, 124) and not rows:
        detail = (error_text or "Nuclei 执行失败").strip()[:400]
        return detail, []
    kept = f"Nuclei 命中 {len(rows)} 条，已排除 {', '.join(excluded)}，未启用 interactsh"
    if timed_out or returncode == 124:
        kept = f"Nuclei 在 {max_time} 时限内命中 {len(rows)} 条，未完成的模板已停止。已排除 {', '.join(excluded)}"
    return kept, rows


def scan_trivy(host: str, policy: dict) -> tuple[str, list[dict]]:
    _assert_host(host, policy)
    inspect = _run(["docker", "image", "inspect", TRIVY_TARGET], 30)
    if inspect.returncode != 0:
        return f"本地没有镜像 {TRIVY_TARGET}，跳过 Trivy", []
    timeout = int(os.environ.get("TRIVY_TIMEOUT_SEC", "300"))
    try:
        completed = _run_container(
            "trivy",
            [
                *_proxy_env(),
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", "mlps-trivy-cache:/root/.cache/",
                TRIVY_IMAGE, "image", "--quiet", "--format", "json",
                "--severity", "HIGH,CRITICAL", "--no-progress", TRIVY_TARGET,
            ],
            timeout,
        )
    except subprocess.TimeoutExpired:
        return "Trivy 达到超时上限，已熔断并销毁容器", []
    if not completed.stdout.strip():
        detail = (completed.stderr or "Trivy 无输出").strip()[:400]
        return detail, []
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return "Trivy 输出不是 JSON", []
    rows = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            severity = str(vuln.get("Severity") or "HIGH").lower()
            rows.append({
                "source_tool": "trivy",
                "evidence_type": "VULNERABILITY",
                "severity": severity,
                "cve_or_cwe": vuln.get("VulnerabilityID"),
                "title": f"{vuln.get('PkgName')} {vuln.get('VulnerabilityID')}",
                "port": "",
                "detail": {
                    "text": f"镜像 {TRIVY_TARGET}：{vuln.get('Title') or vuln.get('Description') or ''}"[:500],
                    "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"],
                },
                "origin": "live",
                "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"],
            })
    return f"Trivy 在镜像 {TRIVY_TARGET} 中发现 {len(rows)} 条高危或严重漏洞", rows


def _extract_cvss(vuln: dict) -> tuple[float | None, str]:
    """从 Trivy CVSS 字段提取最具代表性的 V3 分数与向量（优先发行版厂商，其次 NVD）。"""
    cvss = vuln.get("CVSS")
    if not isinstance(cvss, dict):
        return None, ""
    preferred = ("redhat", "nvd", "ghsa", "rocky", "ubuntu")
    ordered_keys = [k for k in preferred if k in cvss] + [k for k in cvss if k not in preferred]
    best_score: float | None = None
    best_vec = ""
    for key in ordered_keys:
        entry = cvss.get(key)
        if not isinstance(entry, dict):
            continue
        score = entry.get("V3Score")
        if score is None:
            score = entry.get("V2Score")
        if score is not None:
            try:
                num = float(score)
            except (TypeError, ValueError):
                continue
            return round(num, 1), str(entry.get("V3Vector") or entry.get("V2Vector") or "")
    return best_score, best_vec


def scan_trivy_sbom(sbom: dict) -> tuple[str, list[dict]]:
    """用目标机自己的软件包清单做漏洞比对，保留全部高危与严重漏洞，补齐版本与 CVSS 元数据。"""
    import json
    import tempfile
    from pathlib import Path

    if not sbom.get("components"):
        return "没有读到软件包清单，跳过操作系统漏洞扫描", []
    timeout = int(os.environ.get("TRIVY_TIMEOUT_SEC", "300"))
    with tempfile.TemporaryDirectory(prefix="mlps-sbom-") as folder:
        path = Path(folder) / "sbom.json"
        path.write_text(json.dumps(sbom, ensure_ascii=False), encoding="utf-8")
        try:
            completed = _run_container(
                "trivy",
                [
                    *_proxy_env(),
                    "-v", f"{folder}:/work",
                    "-v", "mlps-trivy-cache:/root/.cache/",
                    TRIVY_IMAGE, "sbom", "--quiet", "--format", "json",
                    "--severity", "MEDIUM,HIGH,CRITICAL", "--no-progress", "/work/sbom.json",
                ],
                timeout,
            )
        except subprocess.TimeoutExpired:
            return "Trivy 达到超时上限，已熔断并销毁容器", []
    if not completed.stdout.strip():
        detail = (completed.stderr or "Trivy 无输出").strip()[:400]
        return detail, []
    try:
        report = json.loads(completed.stdout)
    except json.JSONDecodeError:
        return "Trivy 输出不是 JSON", []

    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    raw_vulns: list[tuple[int, float, dict]] = []
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            sev = str(vuln.get("Severity") or "MEDIUM").lower()
            cvss_score, cvss_vec = _extract_cvss(vuln)
            raw_vulns.append((
                sev_rank.get(sev, 1),
                cvss_score or 0.0,
                {
                    "vuln": vuln,
                    "severity": sev,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vec,
                },
            ))

    # 按严重度与 CVSS 降序排序：保留全部 CRITICAL/HIGH，仅对中危做上限控制，防止字母序截断核心包
    raw_vulns.sort(key=lambda item: (-item[0], -item[1], str(item[2]["vuln"].get("PkgName") or ""), str(item[2]["vuln"].get("VulnerabilityID") or "")))

    rows: list[dict] = []
    medium_kept = 0
    medium_limit = 200
    medium_dropped = 0
    for _, _, entry in raw_vulns:
        vuln = entry["vuln"]
        severity = entry["severity"]
        if severity == "medium":
            if medium_kept >= medium_limit:
                medium_dropped += 1
                continue
            medium_kept += 1
        pkg_name = str(vuln.get("PkgName") or "")
        vuln_id = str(vuln.get("VulnerabilityID") or "")
        installed_ver = str(vuln.get("InstalledVersion") or "")
        fixed_ver = str(vuln.get("FixedVersion") or "")
        cvss_score = entry["cvss_score"]
        cvss_vec = entry["cvss_vector"]
        sev_source = str(vuln.get("SeveritySource") or "")
        summary = str(vuln.get("Title") or vuln.get("Description") or "")[:400]
        rows.append({
            "source_tool": "trivy_os",
            "evidence_type": "VULNERABILITY",
            "severity": severity,
            "cve_or_cwe": vuln_id or None,
            "title": f"{pkg_name} {vuln_id}".strip(),
            "port": "",
            "detail": {
                "text": summary,
                "pkg_name": pkg_name,
                "installed_version": installed_ver,
                "fixed_version": fixed_ver,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vec,
                "severity_source": sev_source,
                "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"],
            },
            "origin": "live",
            "clause_hints": ["8.1.4.4-e", "8.1.10.5-a"],
        })
    crit_cnt = sum(1 for r in rows if r["severity"] == "critical")
    high_cnt = sum(1 for r in rows if r["severity"] == "high")
    message = f"操作系统软件包检出严重 {crit_cnt} 条、高危 {high_cnt} 条、中危 {medium_kept} 条（共保留 {len(rows)} 条）"
    if medium_dropped:
        message += f"；其余 {medium_dropped} 条中危漏洞已省略，高危与严重漏洞已完整保留"
    return message, rows
