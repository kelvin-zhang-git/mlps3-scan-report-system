import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.cve_links import linkify_cves_html, linkify_cves_md
from core.dedup import aggregate_findings
from core.policy import CompliancePolicyError, assert_llm_route, filter_nuclei_tags, gemini_safety_settings, host_decision
from core.sanitizer import build_zone_map, leak_findings, redact_text, sanitize_records
from cryptography.fernet import Fernet


def test_whitelist_blocks_scanner_and_lan() -> None:
    ok, _ = host_decision("192.168.1.220", ["192.168.1.220/32"], ["192.168.1.250/32"])
    assert ok
    blocked, reason = host_decision("192.168.1.250", ["192.168.1.220/32"], ["192.168.1.250/32"])
    assert not blocked and "排除网段" in reason
    outside, _ = host_decision("192.168.1.1", ["192.168.1.220/32"], ["192.168.1.250/32"])
    assert not outside


def test_nuclei_dangerous_tags_removed() -> None:
    kept = filter_nuclei_tags(["cve", "dos", "fuzz", "tech"], ["dos", "fuzz", "intrusive"])
    assert kept == ["cve", "tech"]


def test_cross_border_route_blocked() -> None:
    profiles = {
        "gemini_paid": {"allowed_env_tiers": ["L1_TEST", "L3_CROSSBORDER_APPROVED"], "fast_mapper_model": "gemini/gemini-2.0-flash", "inject_block_none_safety": True}
    }
    with pytest.raises(CompliancePolicyError):
        assert_llm_route("L2_INTERNAL", "gemini_paid", profiles)
    profile = assert_llm_route("L1_TEST", "gemini_paid", profiles)
    settings = gemini_safety_settings(profile)
    assert settings and all(item["threshold"] == "BLOCK_NONE" for item in settings)


def test_cve_official_link() -> None:
    html = str(linkify_cves_html("ca-certificates CVE-2026-114406 与条款 8.1.4.4-a"))
    assert 'href="https://www.cve.org/CVERecord?id=CVE-2026-114406"' in html
    assert "8.1.4.4-a" in html
    assert "<script" not in str(linkify_cves_html("<script>CVE-2024-0001</script>"))
    assert linkify_cves_md("见 CVE-2024-0001。") == "见 [CVE-2024-0001](https://www.cve.org/CVERecord?id=CVE-2024-0001)。"


def test_dedup_same_cve() -> None:
    rows = aggregate_findings([
        {"asset_id": "a", "source_tool": "trivy", "cve_or_cwe": "CVE-2024-0001", "port": "22", "title": "openssl", "severity": "high"},
        {"asset_id": "a", "source_tool": "nuclei", "cve_or_cwe": "CVE-2024-0001", "port": "22", "title": "openssl", "severity": "medium"},
    ])
    assert len(rows) == 1
    assert set(rows[0]["detected_by"]) == {"trivy", "nuclei"}


def test_sanitizer_zero_leak() -> None:
    assets = [{"host": "192.168.1.220", "security_zone": "DMZ"}]
    zone = build_zone_map(assets)
    assert zone["192.168.1.220"] == "ZONE_DMZ_HOST_01"
    raw = "root@192.168.1.220 password mail admin@corp.internal AKIAIOSFODNN7EXAMPLE eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U 13812345678"
    clean = redact_text(raw, zone)
    assert leak_findings(clean, ["192.168.1.220"]) == []
    key = Fernet.generate_key().decode()
    records = [{"asset_id": "a", "title": "ssh", "detail": {"text": raw, "clause_hints": ["8.1.4.4-a"]}}]
    sanitized, preview, _blob, passed = sanitize_records(records, assets, key)
    assert passed
    assert "192.168.1.220" not in json.dumps(sanitized)
    assert sanitized[0]["detail"]["text"].startswith("root@ZONE_DMZ_HOST_01")
    assert sanitized[0]["detail"]["clause_hints"] == ["8.1.4.4-a"]


def test_manual_clause_cannot_pass() -> None:
    from core.llm_assessor import assess_clauses

    clauses = [
        {"clause_id": "8.1.6.1-a", "auto_level": "MANUAL_ONLY", "high_risk": False, "manual_check_guide": "上传制度"},
        {"clause_id": "8.1.4.1-a", "auto_level": "FULL_AUTO", "high_risk": True, "manual_check_guide": ""},
    ]
    evidences = [{
        "evidence_id": "ev1",
        "evidence_type": "BASELINE_FAIL",
        "severity": "high",
        "title": "SSH 允许 root 远程登录",
        "clause_hints": ["8.1.4.1-a"],
    }]
    profiles = {"local_rules": {"allowed_env_tiers": ["L1_TEST"], "fast_mapper_model": "local/rules-mapper", "inject_block_none_safety": False, "enable_context_caching": False}}
    assessments, _paths, _audit = assess_clauses(clauses, evidences, "L1_TEST", "local_rules", profiles)
    manual = next(item for item in assessments if item["clause_id"] == "8.1.6.1-a")
    identity = next(item for item in assessments if item["clause_id"] == "8.1.4.1-a")
    assert manual["final_status"] == "pending_manual"
    assert identity["final_status"] == "non_compliant"


def test_rocky_baseline_parser() -> None:
    from core.collectors.ssh_baseline import parse_baseline

    rows = parse_baseline({
        "sshd": "PermitRootLogin yes\n",
        "selinux": "Enforcing\n",
        "auditd": "inactive\n",
        "firewalld": "running\n",
        "chronyd": "active\n",
        "uid0": "root\n",
    }, "stage1-rocky-target-01")
    titles = {row["title"]: row["evidence_type"] for row in rows}
    assert titles["SSH 允许 root 远程登录"] == "BASELINE_FAIL"
    assert titles["安全审计服务未运行"] == "BASELINE_FAIL"


def test_proxy_is_only_used_for_cross_border(monkeypatch: pytest.MonkeyPatch) -> None:
    from core.llm_gateway import proxy_for_profile

    monkeypatch.setenv("OUTBOUND_PROXY", "http://192.168.1.14:10808")
    assert proxy_for_profile({"is_cross_border": False}) is None
    assert proxy_for_profile({"is_cross_border": True, "proxy_env": "OUTBOUND_PROXY"}) == "http://192.168.1.14:10808"
    monkeypatch.delenv("OUTBOUND_PROXY")
    with pytest.raises(CompliancePolicyError):
        proxy_for_profile({"is_cross_border": True})


def _project(db, project_id: str = "p") -> None:
    db.upsert_project({
        "project_id": project_id,
        "name": "测试项目",
        "summary": "摘要",
        "env_tier": "L1_TEST",
        "llm_profile": "local_rules",
        "stage_label": "扫描实施",
        "classification": "测试",
        "assets": [{
            "asset_id": "a1",
            "host": "192.168.1.220",
            "security_zone": "DMZ",
            "os_type": "rocky",
            "scan_mode": "READONLY_AUDIT",
            "scanners": ["nmap"],
        }],
    })


def test_dashboard_keeps_completed_coverage(tmp_path: Path) -> None:
    from database.db_manager import Database

    db = Database(tmp_path / "mlps.db")
    _project(db)
    db.update_asset_mode("a1", "ACTIVE_SCAN")
    _project(db)
    assert db.list_assets("p")[0]["scan_mode"] == "ACTIVE_SCAN"
    done = db.create_job(db.get_project("p"))
    db.update_job(done["job_id"], status="completed")
    db.replace_assessments(done["job_id"], [{
        "assessment_id": "asm1",
        "clause_id": "8.1.4.1-a",
        "auto_status": "non_compliant",
        "manual_status": None,
        "final_status": "non_compliant",
        "risk_level": "high",
        "is_high_risk": True,
        "evidence_ids": [],
        "ai_rationale": "证据不足以外的不符合",
        "remediation_script": "",
    }])
    waiting = db.create_job(db.get_project("p"))
    db.update_job(waiting["job_id"], status="awaiting_approval")
    stats = db.dashboard("p")
    assert stats["job"]["job_id"] == waiting["job_id"]
    assert stats["effective_job"]["job_id"] == done["job_id"]
    assert stats["coverage"] == 100.0
    analytics = db.dashboard_analytics("p")
    assert analytics["awaiting_approval"]["job_id"] == waiting["job_id"]
    assert any(item["domain"] == "安全计算环境" and item["high_open"] == 1 for item in analytics["domains"])


def test_llm_secret_is_masked_and_bound_profile_cannot_delete(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from api.llm_admin import ProfileBody, create_profile, delete_profile, list_profiles
    from database.db_manager import Database

    monkeypatch.setenv("VAULT_FERNET_KEY", Fernet.generate_key().decode())
    db = Database(tmp_path / "mlps.db")
    _project(db)
    secret = "AIzaSecretValue1234"
    create_profile(ProfileBody(
        profile_key="unit_gemini",
        display_name="测试通道",
        provider="gemini",
        is_cross_border=True,
        allowed_env_tiers=["L1_TEST"],
        fast_mapper_model="gemini/gemini-4-hydrogen",
        proxy_env="OUTBOUND_PROXY",
        auth_mode="encrypted_key",
        api_key=secret,
        inject_block_none_safety=True,
    ), db, {"role": "admin"})
    listed = list_profiles(db, {"role": "admin"})
    assert listed[0]["api_key_masked"].startswith("AIza")
    assert secret not in json.dumps(listed)
    assert db.get_llm_profile("unit_gemini")["api_key_encrypted"] != secret
    db.set_project_llm_profile("p", "unit_gemini")
    with pytest.raises(Exception) as exc:
        delete_profile("unit_gemini", db, {"role": "admin"})
    assert getattr(exc.value, "status_code", None) == 409


def test_rbac_blocks_auditor_and_last_admin(tmp_path: Path) -> None:
    from fastapi import HTTPException
    from api.deps import require_roles
    from api.scans import run_scan
    from api.users_admin import UserPatch, delete_user, update_user
    from core.security import hash_password
    from database.db_manager import Database

    db = Database(tmp_path / "mlps.db")
    _project(db, "prj_stage1")
    admin = db.create_user("admin@company.com", hash_password("password1"), "管理员", "admin")
    with pytest.raises(HTTPException) as blocked:
        run_scan(None, db, {"role": "auditor", "email": "audit@company.com"})
    assert blocked.value.status_code == 403
    with pytest.raises(HTTPException):
        require_roles("admin")({"role": "auditor", "is_active": True})
    with pytest.raises(HTTPException) as denied:
        delete_user(admin["user_id"], db, {"user_id": "other", "role": "admin"})
    assert denied.value.status_code == 400
    with pytest.raises(HTTPException):
        update_user(admin["user_id"], UserPatch(display_name="管理员", role="auditor", is_active=True), db, {"user_id": "other", "role": "admin"})


def test_rocky_baseline_covers_core_controls() -> None:
    from core.collectors.ssh_baseline import parse_baseline

    outputs = {
        "sshd": "\n".join([
            "permitrootlogin no", "maxauthtries 4", "permitemptypasswords no", "x11forwarding no",
            "clientaliveinterval 300", "clientalivecountmax 2", "ciphers aes128-ctr", "macs hmac-sha2-256",
        ]),
        "pwquality": "minlen = 10\nminclass = 3",
        "login_defs": "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7",
        "pam": "auth required pam_faillock.so deny=5 unlock_time=600",
        "shadow": "",
        "tmout": "TMOUT=600",
        "selinux": "Enforcing",
        "uid0": "root",
        "shells": "",
        "sudoers": "",
        "perms": "644 /etc/passwd\n400 /etc/shadow\n644 /etc/group\n400 /etc/gshadow\n600 /etc/ssh/sshd_config\n600 /etc/crontab",
        "umask": "umask 027",
        "sticky": "1777 /tmp\n1777 /var/tmp",
        "auditd": "active",
        "auditctl": "-w /etc/passwd -w /etc/shadow -w /etc/sudoers",
        "auditconf": "max_log_file_action = rotate\nnum_logs = 6",
        "logrotate": "rotate 12",
        "rsyslog": "active",
        "rsyslog_remote": "*.* @@10.0.0.8:514",
        "chronyd": "active",
        "firewalld": "running",
        "firewall_rules": "public (active)",
        "services": "telnet.socket inactive",
        "sysctl": "kernel.randomize_va_space = 2\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.accept_redirects = 0\nfs.suid_dumpable = 0",
        "core": "* hard core 0",
        "malware": "clamd active",
        "updates": "unavailable",
    }
    rows = parse_baseline(outputs, "vm-1")
    assert len(rows) >= 35
    assert any(row["title"] == "SSH 已关闭 root 远程登录" for row in rows)


def test_rpm_sbom_uses_target_packages() -> None:
    from core.rpm_sbom import rpm_to_cyclonedx

    bom = rpm_to_cyclonedx(["openssl\t0\t1.1.1k\t9.el9\tx86_64"], "rocky", "9.4")
    assert bom["components"][0]["purl"].startswith("pkg:rpm/rocky/openssl@")
    assert "distro=rocky-9.4" in bom["components"][0]["purl"]


def test_tls_flags_expired_and_weak_protocol(monkeypatch: pytest.MonkeyPatch) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from datetime import datetime, timedelta, timezone
    import core.collectors.tls_scanner as tls

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "vm")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now - timedelta(days=10)).not_valid_after(now - timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    monkeypatch.setattr(tls, "_accepts", lambda host, port, version: True)
    monkeypatch.setattr(tls, "_handshake", lambda host, port: (cert.public_bytes(serialization.Encoding.DER), ("AES128-SHA", "TLSv1.2", 128), False))
    rows = tls.inspect_endpoints("192.0.2.10", [443])
    titles = " ".join(row["title"] for row in rows)
    assert "过时的 TLS" in titles
    assert "已经过期" in titles


def test_asset_scope_keeps_scanner_out(tmp_path: Path) -> None:
    from database.db_manager import Database

    db = Database(tmp_path / "scope.db")
    _project(db)
    db.update_project_scope("p", "L2_INTERNAL", ["192.168.1.220/32"], 2, 40)
    project = db.get_project("p")
    assert project["env_tier"] == "L2_INTERNAL"
    assert "192.168.1.250/32" in project["forbidden_cidrs"]
    db.save_asset("p", {
        "asset_id": "a2", "host": "192.168.1.221", "security_zone": "APP", "os_type": "centos",
        "scan_mode": "READONLY_AUDIT", "scanners": ["ssh_baseline"], "ssh_port": 22, "ssh_user": "audit",
        "ssh_auth_mode": "env_ref", "ssh_secret_env": "STAGE1_TARGET_SSH_PASSWORD", "is_enabled": True, "notes": "",
    }, creating=True)
    _project(db)
    assert {item["asset_id"] for item in db.list_assets("p")} == {"a1", "a2"}


def test_external_adapters() -> None:
    from core.collectors import normalize_ecloud, parse_akto, parse_godlp, parse_kubescape, parse_zap

    cloud = normalize_ecloud({"mfa_enabled": False, "security_groups": [{"cidr": "0.0.0.0/0", "port": "22"}], "audit_enabled": False, "bucket_public": True}, "asset")
    assert any("MFA" in row["title"] for row in cloud)
    assert parse_godlp({"unmasked_count": 2}, "asset")[0]["severity"] == "high"
    assert parse_akto({"findings": [{"title": "未授权接口", "severity": "high", "cwe": "CWE-285", "endpoint": "/api/orders/1"}]}, "asset")
    assert parse_kubescape({"controls": [{"status": "failed", "name": "privileged", "severity": "high", "id": "C-001"}]}, "asset")
    assert parse_zap({"site": [{"alerts": [{"name": "XSS", "riskcode": "3", "cweid": "79", "desc": "reflected"}]}]}, "asset")


def test_project_lifecycle_and_workflow_gates(tmp_path: Path) -> None:
    from fastapi import HTTPException
    from api.projects import ProjectBody, archive_project, create_project, delete_project, start_project
    from api.reports import ReportBody, generate
    from api.scans import run_scan, ScanBody
    from core.workflow import build_workflow
    from database.db_manager import Database

    db = Database(tmp_path / "life.db")
    created = create_project(ProjectBody(name="新项目", whitelist_cidrs=["192.168.1.220/32"]), db, {"role": "admin"})
    assert created["status"] == "draft"
    draft_flow = build_workflow(created, [], None, None, 0)
    assert draft_flow["tabs"]["assets"]["enabled"] is False
    assert draft_flow["tabs"]["collect"]["enabled"] is False
    with pytest.raises(HTTPException) as blocked:
        run_scan(ScanBody(project_id=created["project_id"]), db, {"role": "security_lead", "email": "lead@company.com"})
    assert blocked.value.status_code == 400
    started = start_project(created["project_id"], db, {"role": "admin"})
    assert started["status"] == "active"
    with pytest.raises(HTTPException) as no_asset:
        run_scan(ScanBody(project_id=created["project_id"]), db, {"role": "admin", "email": "admin@company.com"})
    assert no_asset.value.status_code == 400
    job = db.create_job(started)
    db.update_job(job["job_id"], status="awaiting_approval")
    waiting = build_workflow(started, [{"is_enabled": True}], db.get_job(job["job_id"]), {"leak_check_passed": True}, 0)
    assert waiting["tabs"]["collect"]["enabled"] is True
    assert waiting["tabs"]["review"]["enabled"] is False
    assert waiting["tabs"]["reports"]["enabled"] is False
    running = build_workflow(started, [{"is_enabled": True}], {"status": "running"}, None, 0)
    assert running["tabs"]["collect"]["enabled"] is True
    assert running["tabs"]["review"]["enabled"] is False
    assert running["tabs"]["delivery"]["enabled"] is False
    assert "还在进行" in running["next_step"]["reason"]
    assert [running["tabs"][key]["step"] for key in ("assets", "collect", "review", "reports", "delivery")] == [1, 2, 3, 4, 5]
    with pytest.raises(HTTPException) as early_report:
        generate(job["job_id"], ReportBody(variant="masked"), db, {"role": "admin", "email": "admin@company.com"})
    assert early_report.value.status_code == 400
    archived = archive_project(created["project_id"], db, {"role": "security_lead"})
    assert archived["status"] == "archived"
    with pytest.raises(HTTPException):
        delete_project(created["project_id"], db, {"role": "admin"})
    restarted = start_project(created["project_id"], db, {"role": "admin"})
    assert restarted["status"] == "active"


def test_delivery_gate_dojo_scope_pull_and_ciso_receipt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from core.ciso_framework import build_library_yaml, load_clauses
    from core.defectdojo_client import import_findings
    from core.delivery import apply_dojo_pull, deliver_ciso
    from core.sanitizer import delivery_leak_findings
    from core.workflow import build_workflow
    from database.db_manager import Database

    clauses = load_clauses()
    library = build_library_yaml(clauses)
    assert library.count("assessable: true") == len(clauses)
    assert "8.1.1.1-a" in library

    project = {"status": "active", "name": "验收项目"}
    locked = build_workflow(project, [{"is_enabled": True}], {"status": "completed"}, {"leak_check_passed": True}, 3, False)
    assert locked["tabs"]["delivery"]["enabled"] is False
    assert "脱敏版报告" in locked["tabs"]["delivery"]["reason"]
    opened = build_workflow(project, [{"is_enabled": True}], {"status": "completed"}, {"leak_check_passed": True}, 3, True)
    assert opened["tabs"]["delivery"]["enabled"] is True

    captured: dict = {}

    class _Response:
        status_code = 200
        content = b"{}"
        text = ""

        def json(self) -> dict:
            return {"product": 9, "engagement": {"id": 3}, "test": 4}

    monkeypatch.setattr("core.defectdojo_client.connector_status", lambda: {"reachable": True, "detail": "ok"})
    monkeypatch.setattr("core.defectdojo_client._token", lambda: "token")

    def _post(url: str, headers: dict | None = None, data: dict | None = None, files: dict | None = None, timeout: float = 0) -> _Response:
        captured["data"] = data or {}
        captured["file"] = files["file"][1] if files else ""
        return _Response()

    monkeypatch.setattr("core.defectdojo_client.httpx.post", _post)
    pushed = import_findings(
        [{"evidence_id": "ev1", "evidence_type": "VULNERABILITY", "title": "OpenSSH", "severity": "high", "detail": {"text": "masked"}}],
        {"name": "验收项目"},
        {"job_id": "job_abcdef123456", "started_at": "2026-11-20T01:00:00"},
    )
    assert captured["data"]["product_name"] == "验收项目"
    assert captured["data"]["engagement_name"].startswith("job_abcdef12")
    assert "ev1" in captured["file"]
    assert pushed["engagement_id"] == "3"

    db = Database(tmp_path / "delivery.db")
    stored = db.create_project({"name": "验收项目", "project_id": "p-delivery"})
    job = db.create_job(stored)
    db.replace_evidences(job["job_id"], [{
        "evidence_id": "ev1", "asset_id": "asset", "source_tool": "nuclei", "evidence_type": "VULNERABILITY",
        "severity": "high", "cve_or_cwe": "CVE-2026-0001", "title": "OpenSSH", "detail": {}, "origin": "live",
    }])
    stats = apply_dojo_pull(db, job["job_id"], [{
        "id": 41, "title": "OpenSSH", "cve": "CVE-2026-0001", "unique_id_from_tool": "ev1",
        "false_p": True, "is_mitigated": False, "status": "false_positive",
    }])
    assert stats["false_positive"] == 1
    assert db.list_evidences(job["job_id"])[0]["dojo_status"] == "false_positive"
    assert delivery_leak_findings(["请连接 10.1.2.3 复核"], []) == ["10.1.2.3"]

    db.add_manual_doc(stored["project_id"], "8.1.1.1-a", "机房记录.pdf", "请连接 10.1.2.3 复核", "admin@company.com")
    blocked = deliver_ciso(db, stored, job, None)
    assert blocked["passed"] is False
    assert any(row["status"] == "blocked" for row in db.list_sync_records(stored["project_id"], job["job_id"]))

    db._write("DELETE FROM manual_evidence WHERE project_id=?", (stored["project_id"],))
    report = tmp_path / "ciso.docx"
    report.write_bytes(b"ciso")

    def _fake_deliver(*_args, **_kwargs) -> dict:
        return {
            "synced": True, "framework_id": "fw", "folder_id": "folder", "perimeter_id": "perimeter",
            "assessment_id": "assessment", "written": 1, "url": "https://ciso.example/assessment",
            "report_path": str(report), "filename": "ciso.docx", "detail": "已写入 1 条",
        }

    monkeypatch.setattr("core.delivery.deliver_assessment", _fake_deliver)
    saved = deliver_ciso(db, stored, job, None)
    assert saved["synced"] is True
    history = db.list_sync_records(stored["project_id"], job["job_id"])
    assert any(row["target"] == "ciso_push" and row["status"] == "ok" for row in history)
    assert db.get_integration(stored["project_id"])["ciso_assessment_id"] == "assessment"


def test_prompt_admin_and_ai_docx_report(tmp_path: Path, monkeypatch) -> None:
    import docx
    from fastapi.testclient import TestClient

    import api.deps as deps
    import main as app_main
    from core.delivery import deliver_ciso, final_leak_check
    from core.report_prompts import DEFAULT_MLPS3_REPORT_PROMPT
    from core.security import hash_password
    from database.db_manager import Database

    monkeypatch.setenv("JWT_SECRET", "test-secret-for-prompt-and-docx-reports-2026")
    db = Database(tmp_path / "prompt_report.db")
    deps.db = db
    admin = db.create_user("admin@example.com", hash_password("Admin#2026"), "系统管理员", "admin")
    auditor = db.create_user("auditor@example.com", hash_password("Auditor#2026"), "审计员", "auditor")
    db.save_llm_profile({
        "profile_key": "gemini_paid",
        "display_name": "Gemini",
        "provider": "gemini",
        "is_cross_border": False,
        "allowed_env_tiers": ["L1_TEST"],
        "fast_mapper_model": "gemini/gemini-2.0-flash",
        "deep_reasoner_model": "gemini/gemini-2.5-pro",
        "auth_mode": "env_ref",
        "api_key_env": "GEMINI_API_KEY",
        "inject_block_none_safety": True,
        "is_enabled": True,
    })

    client = TestClient(app_main.app)
    admin_token = client.post("/api/auth/login", json={"email": admin["email"], "password": "Admin#2026"}).json()["access_token"]
    auditor_token = client.post("/api/auth/login", json={"email": auditor["email"], "password": "Auditor#2026"}).json()["access_token"]
    admin_hdr = {"Authorization": f"Bearer {admin_token}"}
    auditor_hdr = {"Authorization": f"Bearer {auditor_token}"}

    # 默认 Prompt 可读；非管理员禁止修改；管理员保存递增版本并支持恢复默认。
    got = client.get("/api/admin/prompts/mlps3_final_report", headers=auditor_hdr)
    assert got.status_code == 200
    assert got.json()["version"] == 1
    assert got.json()["is_default"] is True

    denied = client.put(
        "/api/admin/prompts/mlps3_final_report",
        headers=auditor_hdr,
        json={"title": "越权修改", "content": "这是一段试图越权保存的等保三级系统提示词正文，用于测试权限拦截。"},
    )
    assert denied.status_code == 403

    custom_prompt = DEFAULT_MLPS3_REPORT_PROMPT + "\n额外要求：突出金融业务连续性与高危基线项。"
    updated = client.put(
        "/api/admin/prompts/mlps3_final_report",
        headers=admin_hdr,
        json={"title": "定制等保三级报告提示词", "content": custom_prompt},
    )
    assert updated.status_code == 200
    assert updated.json()["version"] == 2
    assert updated.json()["is_default"] is False

    # 创建已完成评估任务，验证生成报告时调用 AI 并传入自定义 system_prompt 与深模型槽位。
    project = db.create_project({
        "project_id": "p-ai-report",
        "name": "AI报告验收项目",
        "summary": "验证中文 Word 终版与 CISO 评估摘要",
        "env_tier": "L1_TEST",
        "llm_profile": "gemini_paid",
    })
    job = db.create_job(project)
    db.update_job(job["job_id"], status="completed", progress_pct=100, current_stage="completed")
    db.replace_evidences(job["job_id"], [{
        "evidence_id": "ev-cve",
        "asset_id": "ast_01",
        "source_tool": "trivy_os",
        "evidence_type": "VULNERABILITY",
        "severity": "critical",
        "cve_or_cwe": "CVE-2026-114406",
        "title": "ca-certificates CVE-2026-114406",
        "detail": {"text": "Distrust CA", "clause_hints": ["8.1.4.4-a"]},
        "origin": "live",
    }])
    db.replace_assessments(job["job_id"], [{
        "assessment_id": "asm_01",
        "clause_id": "8.1.4.4-a",
        "auto_status": "non_compliant",
        "manual_status": None,
        "final_status": "non_compliant",
        "risk_level": "high",
        "is_high_risk": True,
        "evidence_ids": ["ev-cve"],
        "ai_rationale": "存在严重级软件包漏洞 CVE-2026-114406。",
        "remediation_script": "dnf upgrade -y ca-certificates",
    }])

    captured_call: dict = {}

    def _fake_review(profile, prompt, *, system_prompt="", model_slot="fast", **_kwargs):
        captured_call["system_prompt"] = system_prompt
        captured_call["model_slot"] = model_slot
        return {
            "status": "ok",
            "model_id": "gemini-2.5-pro",
            "parsed": {
                "executive_summary": "本次针对 AI报告验收项目 完成等保三级预评估，发现高危软件包漏洞需要优先处置。",
                "scope_and_methodology": "本报告为预评估差距自查材料，不替代持证测评机构正式报告。",
                "domain_insights": [{
                    "domain": "安全计算环境",
                    "status_summary": "存在高风险不符合项",
                    "key_gaps": "ca-certificates 存在 CVE-2026-114406",
                    "priority_action": "立即升级软件包并复测",
                }],
                "critical_risk_analysis": [{
                    "risk_title": "根证书包严重级漏洞",
                    "severity": "高风险",
                    "affected_scope": "ast_01 / 8.1.4.4-a / CVE-2026-114406",
                    "business_impact": "影响信任链安全并触发等保高风险扣分",
                    "remediation_advice": "执行 dnf upgrade 升级 ca-certificates 并重启依赖服务",
                }],
                "remediation_roadmap": [{
                    "phase": "P0 立即阻断（1~3 天）",
                    "owner_department": "系统与主机运维",
                    "actions": ["升级 ca-certificates 至最新安全版本"],
                    "acceptance_criteria": "Trivy 复扫无 CVE-2026-114406",
                }],
                "manual_readiness_checklist": ["准备等保定级备案证明与安全管理制度汇编"],
                "ciso_summary": "AI报告验收项目当前存在 1 项高风险不符合条款，建议优先完成 P0 补丁升级后复测。",
            },
        }

    monkeypatch.setattr("core.report_narrative.review_with_profile", _fake_review)
    gen = client.post(f"/api/reports/{job['job_id']}/generate", headers=admin_hdr, json={"variant": "masked", "refresh_ai": True})
    assert gen.status_code == 200
    payload = gen.json()
    assert "金融业务连续性" in captured_call["system_prompt"]
    assert captured_call["model_slot"] == "deep"
    assert payload["narrative"]["status"] == "ai"
    assert payload["narrative"]["prompt_version"] == 2
    assert payload["docx_report"]["filename"].endswith(".docx")

    doc = docx.Document(payload["docx_report"]["content_path"])
    full_text = "\n".join(p.text for p in doc.paragraphs)
    assert "本次针对 AI报告验收项目 完成等保三级预评估" in full_text
    assert "根证书包严重级漏洞" in full_text
    assert "<Comments>" not in full_text

    # 验证零泄漏终检拦截 AI 正文里的真实主机地址。
    leaks = final_leak_check([], [], [{"host": "192.168.1.220"}], None, extra_texts=["请登录 192.168.1.220 执行补丁"])
    assert "192.168.1.220" in leaks

    # 验证 CISO 同步写入顶层 description、observation 和高危控制项。
    ciso_captured: dict = {}
    fake_ciso_doc = tmp_path / "ciso_snap.docx"
    fake_ciso_doc.write_bytes(b"ciso")

    def _fake_ciso(*_args, **kwargs) -> dict:
        ciso_captured.update(kwargs)
        return {
            "synced": True, "framework_id": "fw", "folder_id": "fd", "perimeter_id": "pm",
            "assessment_id": "asmt", "written": 1, "controls_written": len(kwargs.get("control_items") or []),
            "url": "https://ciso.example/asmt", "report_path": str(fake_ciso_doc), "filename": "ciso_snap.docx",
            "detail": "ok",
        }

    monkeypatch.setattr("core.delivery.deliver_assessment", _fake_ciso)
    delivered = deliver_ciso(db, project, job, None)
    assert delivered["synced"] is True
    assert "GB/T 22239-2019" in ciso_captured["assessment_description"]
    assert "AI报告验收项目当前存在" in ciso_captured["assessment_observation"]
    assert len(ciso_captured["control_items"]) >= 1

    reset = client.post("/api/admin/prompts/mlps3_final_report/reset", headers=admin_hdr)
    assert reset.status_code == 200
    assert reset.json()["is_default"] is True
    assert reset.json()["version"] == 3


def test_full_gbt22239_catalog_and_extension_selection(tmp_path: Path) -> None:
    from core.ciso_framework import build_library_yaml, framework_spec
    from core.clause_catalog import load_clauses
    from database.db_manager import Database

    all_rows = load_clauses(None)
    general_rows = load_clauses(["GENERAL"])
    cloud_all_rows = load_clauses(["GENERAL", "CLOUD"])
    assert len(general_rows) == 211
    assert len(all_rows) == 257
    assert len(cloud_all_rows) == 257
    assert len({row["clause_id"] for row in all_rows}) == 257
    assert any(row["clause_id"] == "8.1.10.6-j" for row in general_rows)
    assert any(row["clause_id"] == "8.2.7.1-a" for row in cloud_all_rows)
    assert not any(row["clause_id"].startswith("8.2.") for row in general_rows)

    gen_yaml = build_library_yaml(general_rows, extensions=["GENERAL"])
    cloud_yaml = build_library_yaml(cloud_all_rows, extensions=["GENERAL", "CLOUD"])
    assert gen_yaml.count("assessable: true") == 211
    assert cloud_yaml.count("assessable: true") == 257
    assert framework_spec(["GENERAL"])["framework_ref"] == "GB-T-22239-2019-L3-V2"
    assert framework_spec(["GENERAL", "CLOUD"])["framework_ref"] == "GB-T-22239-2019-L3-CLOUD-V2"

    db = Database(tmp_path / "ext.db")
    p_gen = db.create_project({"name": "本地机房项目", "project_id": "p-gen"})
    assert p_gen["enabled_extensions"] == ["GENERAL"]
    assert p_gen["clause_count"] == 211

    p_cloud = db.create_project({"name": "云上三级项目", "project_id": "p-cloud", "enabled_extensions": ["GENERAL", "CLOUD"]})
    assert p_cloud["enabled_extensions"] == ["GENERAL", "CLOUD"]
    assert p_cloud["clause_count"] == 257

    db.update_project_scope("p-gen", "L1_TEST", ["192.168.1.220/32"], 2, 50, enabled_extensions=["GENERAL", "CLOUD"])
    updated = db.get_project("p-gen")
    assert updated is not None and updated["clause_count"] == 257


def test_phase2_object_coverage_precedents_and_weighted_scoring(tmp_path: Path) -> None:
    import docx
    from core.clause_catalog import load_clauses
    from core.report_generator import render_docx_report, render_report
    from core.scoring import score_assessments
    from database.db_manager import Database

    clauses = load_clauses(None)
    assert len(clauses) == 257
    high_clauses = [c for c in clauses if c["high_risk"]]
    assert len(high_clauses) == 110
    high_ids = {c["clause_id"] for c in high_clauses}
    # 对照现行 T/ISEAA 001-2020 核定的新增 4 条通用高风险条款
    for required_hr in ("8.1.4.7-b", "8.1.6.2-a", "8.1.7.1-a", "8.1.7.3-b"):
        assert required_hr in high_ids
    for c in clauses:
        assert c.get("applicable_objects") and len(c["applicable_objects"]) >= 1
        assert c.get("risk_weight_level") in {"high", "medium", "low"}
        assert c.get("risk_weight") in {1.0, 2.0, 3.0}
    for c in high_clauses:
        prec = c.get("high_risk_precedent")
        assert prec and prec["standard_ref"] == "T/ISEAA 001-2020"
        assert prec["category"] and prec["trigger_condition"]
        assert isinstance(prec["compensating_controls"], list) and len(prec["compensating_controls"]) >= 1

    # 构造加权计分与高风险补偿控制降级测试
    sample_catalog = [
        next(c for c in clauses if c["clause_id"] == "8.1.4.1-a"),  # high, weight 3, host_os/database/middleware/application
        next(c for c in clauses if c["clause_id"] == "8.1.4.2-a"),  # medium, weight 2
        next(c for c in clauses if c["clause_id"] == "8.1.1.1-a"),  # low, weight 1
    ]
    rows_direct = [
        {"clause_id": "8.1.4.1-a", "final_status": "non_compliant", "is_high_risk": True, "compensation_status": "none"},
        {"clause_id": "8.1.4.2-a", "final_status": "compliant", "is_high_risk": False, "compensation_status": "none"},
        {"clause_id": "8.1.1.1-a", "final_status": "compliant", "is_high_risk": False, "compensation_status": "none"},
    ]
    assets = [{"asset_id": "ast-1", "host": "192.168.1.220", "object_type": "host_os", "security_zone": "APP", "os_type": "rocky_linux", "scan_mode": "READONLY_AUDIT", "is_enabled": True}]
    evidences = [{"asset_id": "ast-1", "source_tool": "ssh_baseline", "evidence_type": "BASELINE_FAIL", "severity": "high", "title": "口令策略未达标"}]

    score_direct = score_assessments(rows_direct, sample_catalog, assets=assets, evidences=evidences)
    # 加权：earned = 2 + 1 = 3, total = 3 + 2 + 1 = 6 => 50.0 分；等权：2/3 => 66.7 分
    assert score_direct["checked_score"] == 66.7
    assert score_direct["weighted_checked_score"] == 50.0
    assert score_direct["direct_high_fail"] == 1
    assert score_direct["mitigated_high_count"] == 0
    assert score_direct["verdict"] == "not_ready"

    obj_items = {item["object_key"]: item for item in score_direct["object_coverage"]["items"]}
    assert obj_items["host_os"]["status"] == "covered"
    assert obj_items["database"]["status"] == "unmanaged"

    # 采纳补偿控制降级后，直接高风险清零，且该项扣分权重由 3 降为 2：earned = 3, total = 2 + 2 + 1 = 5 => 60.0 分
    rows_mitigated = [dict(r) for r in rows_direct]
    rows_mitigated[0]["compensation_status"] = "mitigated"
    rows_mitigated[0]["compensation_note"] = "全部运维经堡垒机 MFA 登录并限制源 IP"
    score_mitigated = score_assessments(rows_mitigated, sample_catalog, assets=assets, evidences=evidences)
    assert score_mitigated["direct_high_fail"] == 0
    assert score_mitigated["mitigated_high_count"] == 1
    assert score_mitigated["weighted_checked_score"] == 60.0

    # 验证数据库持久化补偿状态、对象类别与 Word/HTML 报告渲染
    db = Database(tmp_path / "phase2.db")
    prj = db.create_project({"project_id": "p-p2", "name": "二阶段测试项目"})
    db.save_asset(prj["project_id"], {
        "asset_id": "ast-db", "host": "192.168.1.221", "security_zone": "DB",
        "os_type": "rocky_linux", "object_type": "database", "scan_mode": "READONLY_AUDIT",
        "scanners": ["ssh_baseline"], "ssh_port": 22, "ssh_user": "root", "ssh_auth_mode": "env_ref",
    }, creating=True)
    saved_asset = db.get_asset("ast-db")
    assert saved_asset and saved_asset["object_type"] == "database"

    job = db.create_job(prj)
    db.replace_assessments(job["job_id"], [{
        "assessment_id": "asmt-p2-1", "clause_id": "8.1.4.1-a",
        "auto_status": "non_compliant", "final_status": "non_compliant",
        "risk_level": "high", "is_high_risk": True, "evidence_ids": [], "ai_rationale": "基线未达标",
    }])
    updated = db.update_assessment(
        "asmt-p2-1", "lead@example.com", "non_compliant", "已核对堡垒机配置",
        compensation_status="mitigated", compensation_note="堡垒机双因子+白名单补偿",
    )
    assert updated and updated["compensation_status"] == "mitigated"
    assert "堡垒机双因子" in updated["compensation_note"]

    # 复核为符合时自动清除降级标记
    cleared = db.update_assessment("asmt-p2-1", "lead@example.com", "compliant", "已完成整改", compensation_status="mitigated")
    assert cleared and cleared["compensation_status"] == "none"

    ctx = {
        "project": prj,
        "job_id": job["job_id"],
        "score": score_mitigated,
        "assets": assets,
        "host_summary": [],
        "cves": [],
        "tls_rows": [],
        "departments": [],
        "assessments": rows_mitigated,
        "paths": [],
        "direct_high_risk_rows": [],
        "mitigated_high_risk_rows": [{
            **rows_mitigated[0],
            "control_point": "身份鉴别",
            "status_zh": "不符合",
            "applicable_object_labels": ["主机操作系统", "数据库"],
            "high_risk_precedent": sample_catalog[0]["high_risk_precedent"],
        }],
        "narrative": {"status": "fallback", "prompt_version": 1, "sections": {}},
    }
    _html_name, html_path = render_report(ctx, "masked")
    assert "测评对象覆盖矩阵" in html_path.read_text(encoding="utf-8")
    _docx_name, docx_path = render_docx_report(ctx, "masked")
    doc = docx.Document(str(docx_path))
    all_doc_text = "\n".join(p.text for p in doc.paragraphs)
    assert "测评对象覆盖矩阵" in all_doc_text
    assert "高风险判例分类与补偿控制评估" in all_doc_text


def test_phase3_db_mw_netdev_and_cloud_collectors(tmp_path: Path, monkeypatch) -> None:
    from fastapi.testclient import TestClient

    import api.deps as deps
    import main as app_main
    from core.clause_catalog import load_clauses
    from core.collectors import (
        SAMPLE_CLOUD_AUDIT,
        SAMPLE_NETDEV_CONFIG,
        parse_cloud_audit,
        parse_db_mw_baseline,
        parse_netdev_config,
    )
    from core.scoring import score_assessments
    from core.security import hash_password
    from database.db_manager import Database

    # 1. 数据库与中间件只读基线解析测试（MySQL + PostgreSQL + Redis + Nginx + Tomcat）
    fake_outputs = {
        "ports": "tcp LISTEN 0 128 0.0.0.0:3306 0.0.0.0:*\ntcp LISTEN 0 128 0.0.0.0:6379 0.0.0.0:*\n",
        "docker_ps": "",
        "mysql_detect": "/usr/sbin/mysqld\nactive\n",
        "mysql_conf": "bind-address = 0.0.0.0\nlocal-infile = 1\n",
        "mysql_vars": "bind_address\t0.0.0.0\nrequire_secure_transport\tOFF\nhave_ssl\tYES\ngeneral_log\tOFF\nlocal_infile\tON\n",
        "mysql_users": "root\t%\tSET\tcaching_sha2_password\n\tlocalhost\tEMPTY\tmysql_native_password\n",
        "mysql_plugins": "",
        "pg_detect": "/usr/bin/postgres\n",
        "pg_conf": "FILE=/var/lib/pgsql/data/postgresql.conf\nlisten_addresses = '*'\nssl = off\nlogging_collector = off\n",
        "pg_hba": "FILE=/var/lib/pgsql/data/pg_hba.conf\nhost all all 0.0.0.0/0 trust\n",
        "redis_detect": "/usr/bin/redis-server\nactive\n",
        "redis_conf": "bind 0.0.0.0\nprotected-mode no\n",
        "nginx_detect": "nginx version: nginx/1.24.0\nactive\n",
        "nginx_conf": "server_tokens on;\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\naccess_log /var/log/nginx/access.log;\nautoindex on;\n",
        "tomcat_detect": "org.apache.catalina.startup.Bootstrap\n",
        "tomcat_conf": 'FILE=/opt/tomcat/conf/server.xml\n<Server port="8005" shutdown="SHUTDOWN">\n<Connector protocol="AJP/1.3" port="8009"/>\n',
        "httpd_conf": "",
    }
    db_mw_rows = parse_db_mw_baseline(fake_outputs, "ast_db_230")
    db_rows = [r for r in db_mw_rows if r["source_tool"] == "db_baseline"]
    mw_rows = [r for r in db_mw_rows if r["source_tool"] == "mw_baseline"]
    assert len(db_rows) >= 10
    assert len(mw_rows) >= 5
    assert any("空口令或匿名账户" in r["title"] for r in db_rows)
    assert any("trust 免密" in r["title"] for r in db_rows)
    assert any("Redis 未配置访问口令" in r["title"] for r in db_rows)
    assert any("TLS" in r["title"] for r in mw_rows)
    assert any("SHUTDOWN" in r["title"] for r in mw_rows)

    # 2. 网络与安全设备脱敏配置解析测试
    net_rows = parse_netdev_config(SAMPLE_NETDEV_CONFIG, "netdev_fw01", device_name="FW-BORDER-01")
    assert len(net_rows) >= 5
    assert any("默认拒绝" in r["title"] and r["evidence_type"] == "BASELINE_PASS" for r in net_rows)
    assert any("Any-to-Any" in r["title"] and r["evidence_type"] == "BASELINE_FAIL" for r in net_rows)
    assert any("Syslog" in r["title"] and r["evidence_type"] == "BASELINE_PASS" for r in net_rows)

    # 3. 云平台只读核查导入测试
    cloud_rows = parse_cloud_audit(SAMPLE_CLOUD_AUDIT, "cloud_aliyun")
    assert len(cloud_rows) >= 7
    assert any("中国境内" in r["title"] and r["evidence_type"] == "BASELINE_PASS" for r in cloud_rows)
    assert any("高危端口全网放行" in r["title"] and r["evidence_type"] == "BASELINE_FAIL" for r in cloud_rows)
    assert any("本地备份副本" in r["title"] and r["evidence_type"] == "BASELINE_FAIL" for r in cloud_rows)

    # 4. 对象覆盖矩阵被三类新证据同步点亮
    catalog = load_clauses(["GENERAL", "CLOUD"])
    scored = score_assessments([], catalog, assets=[], evidences=db_mw_rows + net_rows + cloud_rows)
    cov = {item["object_key"]: item for item in scored["object_coverage"]["items"]}
    assert cov["database"]["status"] == "covered"
    assert cov["middleware"]["status"] == "covered"
    assert cov["network_device"]["status"] == "covered"
    assert cov["security_device"]["status"] == "covered"
    assert cov["cloud_platform"]["status"] == "covered"

    # 5. API 端到端测试（模板接口 + 离线配置导入 + 云核查导入）
    monkeypatch.setenv("JWT_SECRET", "test-secret-for-phase3-imports-2026")
    db = Database(tmp_path / "phase3.db")
    deps.db = db
    admin = db.create_user("admin@example.com", hash_password("Admin#2026"), "系统管理员", "admin")
    client = TestClient(app_main.app)
    token = client.post("/api/auth/login", json={"email": admin["email"], "password": "Admin#2026"}).json()["access_token"]
    hdr = {"Authorization": f"Bearer {token}"}

    prj = db.create_project({"project_id": "p-p3", "name": "三阶段导入测试", "enabled_extensions": ["GENERAL", "CLOUD"]})
    tpl = client.get("/api/imports/templates", headers=hdr)
    assert tpl.status_code == 200
    assert "netdev_config" in tpl.json() and "cloud_audit" in tpl.json()

    imp_net = client.post(
        f"/api/imports/{prj['project_id']}",
        headers=hdr,
        json={"source": "netdev_config", "payload": tpl.json()["netdev_config"]},
    )
    assert imp_net.status_code == 200
    assert imp_net.json()["imported"] >= 5

    imp_cloud = client.post(
        f"/api/imports/{prj['project_id']}",
        headers=hdr,
        json={"source": "cloud_audit", "payload": tpl.json()["cloud_audit"], "job_id": imp_net.json()["job_id"]},
    )
    assert imp_cloud.status_code == 200
    assert imp_cloud.json()["imported"] >= 7


def test_report_human_readable_asset_aliases(tmp_path: Path):
    """验证报告资产可读代号：脱敏版隐藏真实 IP 且无裸 ast_xxx，受控还原版精准附带真实 IP 且不重复嵌套。"""
    from core.report_narrative import build_asset_directory, format_beijing, replace_asset_refs_in_text, rewrite_narrative_assets
    from core.report_generator import render_docx_report, render_report

    assets = [
        {
            "asset_id": "ast_51e2caf4fc58",
            "host": "192.168.1.220",
            "security_zone": "APP",
            "object_type": "host_os",
            "os_type": "rocky_linux",
            "scan_mode": "READONLY_AUDIT",
            "notes": "应用靶机 192.168.1.220",
        },
        {
            "asset_id": "ast_310b59fa82f3",
            "host": "192.168.1.230",
            "security_zone": "DB",
            "object_type": "database",
            "os_type": "rocky_linux",
            "scan_mode": "READONLY_AUDIT",
            "notes": "数据库靶机（MySQL/PostgreSQL/Redis）",
        },
    ]
    enriched, lookup = build_asset_directory(assets)
    assert format_beijing("2026-11-22T15:14:30+00:00") == "2026-11-22 23:14"
    assert enriched[0]["masked_label"] == "应用域-主机01"
    assert enriched[0]["restored_label"] == "应用域-主机01（192.168.1.220）"
    assert "192.168.1.220" not in enriched[0]["role_note_masked"]
    assert enriched[1]["masked_label"] == "数据库域-数据库主机01"
    assert enriched[1]["restored_label"] == "数据库域-数据库主机01（192.168.1.230）"

    raw_text = "本轮核查覆盖应用安全域的 ast_51e2caf4fc58 与数据库安全域的 ast_310b59fa82f3，边界占位 ZONE_APP_HOST_01。"
    masked_out = replace_asset_refs_in_text(raw_text, lookup, variant="masked")
    assert "ast_51e2caf4fc58" not in masked_out
    assert "ast_310b59fa82f3" not in masked_out
    assert "应用域-主机01" in masked_out and "数据库域-数据库主机01" in masked_out
    assert "192.168.1.220" not in masked_out and "192.168.1.230" not in masked_out

    restored_out = replace_asset_refs_in_text(
        masked_out,
        lookup,
        variant="restored",
        vault_mapping={"ZONE_APP_HOST_01": "192.168.1.220"},
    )
    assert "应用域-主机01（192.168.1.220）" in restored_out
    assert "数据库域-数据库主机01（192.168.1.230）" in restored_out
    assert "（192.168.1.220）（192.168.1.220）" not in restored_out

    sections = rewrite_narrative_assets(
        {"executive_summary": raw_text, "critical_risk_analysis": [{"risk_title": "DB 风险", "affected_scope": "ast_310b59fa82f3"}]},
        lookup,
        variant="masked",
    )
    assert sections["critical_risk_analysis"][0]["affected_scope"] == "数据库域-数据库主机01"

    ctx = {
        "project": {"name": "可读代号测试", "summary": "验证报告输出", "classification": "等保三级", "env_tier": "L1_TEST", "stage_label": "已启动", "llm_profile": "gemini_paid"},
        "job_id": "job_alias_test",
        "assessments": [],
        "paths": [],
        "stats": {},
        "assets": enriched,
        "host_summary": [{"asset_id": "ast_310b59fa82f3", "asset_display": "数据库域-数据库主机01", "passed": 0, "failed": 0, "db_mw_passed": 2, "db_mw_failed": 11}],
        "db_mw_rows": [{"asset_id": "ast_310b59fa82f3", "asset_display": "数据库域-数据库主机01", "source_tool": "db_baseline", "severity": "critical", "severity_zh": "严重", "evidence_type": "BASELINE_FAIL", "title": "PostgreSQL 存在 trust 免密认证规则"}],
        "cves": [],
        "tls_rows": [],
        "score": {"verdict_label": "核查未完成", "verdict_advice": "补齐核查", "completeness": 0, "checked_score": 0, "conservative_score": 0, "weighted_checked_score": 0, "weighted_conservative_score": 0, "high_fail": 0, "direct_high_fail": 0, "mitigated_high_count": 0, "high_open": 0, "clause_total": 211, "counts": {}, "domains": [], "object_coverage": {"summary": "", "items": []}},
        "direct_high_risk_rows": [],
        "mitigated_high_risk_rows": [],
        "departments": [],
        "narrative": {"status": "fallback", "model_id": "rule_synthesizer", "prompt_version": 1, "sections": sections},
    }
    html_name, html_path = render_report(ctx, "masked")
    html_text = html_path.read_text(encoding="utf-8")
    assert "应用域-主机01" in html_text
    assert "数据库域-数据库主机01" in html_text
    assert "PostgreSQL 存在 trust 免密认证规则" in html_text
    assert "192.168.1.220" not in html_text and "192.168.1.230" not in html_text

    docx_name, docx_path = render_docx_report(ctx, "masked")
    assert docx_path.exists() and docx_name.endswith("-masked.docx")
    # 清理临时生成报告
    html_path.unlink(missing_ok=True)
    docx_path.unlink(missing_ok=True)


def test_p0_p3_precision_and_guardrails(tmp_path: Path) -> None:
    """回归验证 P0~P3 全部核心改进：clause_hints 透出、护栏、Epoch SBOM、DB/MW 精细化、覆盖矩阵与攻击路径。"""
    from core.collectors.db_mw_baseline import parse_db_mw_baseline
    from core.dedup import aggregate_findings
    from core.llm_assessor import _attack_paths, _merge_remote, assess_clauses
    from core.rpm_sbom import rpm_to_cyclonedx
    from core.scoring import compute_object_coverage
    from database.db_manager import Database

    # 1) P0-1: db.list_evidences 回填 clause_hints 且 _merge_remote 阻止大模型覆写规则结论回 not_assessed
    db = Database(tmp_path / "p0.db")
    proj = db.create_project({"name": "P0项目", "env_tier": "L1_TEST", "llm_profile": "local_rules", "enabled_extensions": ["GENERAL"]})
    job = db.create_job(proj)
    db.replace_evidences(job["job_id"], [
        {
            "evidence_id": "ev_fail_1",
            "asset_id": "ast_1",
            "source_tool": "ssh_baseline",
            "evidence_type": "BASELINE_FAIL",
            "severity": "high",
            "title": "SSH 允许 root 登录",
            "detail": {"text": "PermitRootLogin yes", "clause_hints": ["8.1.4.1-a"], "port": 22},
        },
        {
            "evidence_id": "ev_err_1",
            "asset_id": "ast_2",
            "source_tool": "ssh_baseline",
            "evidence_type": "COLLECT_ERROR",
            "severity": "info",
            "title": "主机基线采集失败",
            "detail": {"text": "TimeoutError: 执行超时", "clause_hints": []},
        },
    ])
    listed = db.list_evidences(job["job_id"])
    fail_row = next(r for r in listed if r["evidence_id"] == "ev_fail_1")
    assert fail_row["clause_hints"] == ["8.1.4.1-a"]
    assert str(fail_row["port"]) == "22"

    sample_clauses = [
        {"clause_id": "8.1.4.1-a", "domain": "安全计算环境", "control_point": "身份鉴别", "requirement_text": "身份鉴别", "auto_level": "FULL_AUTO", "high_risk": True, "manual_check_guide": ""},
        {"clause_id": "8.1.6.1-a", "domain": "安全管理制度", "control_point": "安全策略", "requirement_text": "制度", "auto_level": "MANUAL_ONLY", "high_risk": False, "manual_check_guide": "人工核查制度"},
    ]
    assessments, _paths, _logs = assess_clauses(
        sample_clauses,
        listed,
        "L1_TEST",
        "local_rules",
        {"local_rules": {"profile_key": "local_rules", "provider": "local_rules", "fast_mapper_model": "local/rules", "is_cross_border": False, "is_enabled": True, "allowed_env_tiers": ["L1_TEST"]}},
    )
    row_auth = next(a for a in assessments if a["clause_id"] == "8.1.4.1-a")
    row_manual = next(a for a in assessments if a["clause_id"] == "8.1.6.1-a")
    assert row_auth["final_status"] == "non_compliant"
    # P2-3: 人工条款不再把核查指南混入 remediation_script；技术失败生成安全加固脚本不含占位行
    assert row_manual["remediation_script"] == ""
    assert "sshd -t" in row_auth["remediation_script"] and "# 处理：" not in row_auth["remediation_script"]

    # 护栏：远端模型企图把有实测证据的条款改回 not_assessed 或把高危失败项改回 compliant 时必须拦截
    by_clause = {"8.1.4.1-a": [fail_row]}
    _merge_remote(
        assessments,
        {"items": [{"clause_id": "8.1.4.1-a", "status": "not_assessed", "note": "误判"}]},
        sample_clauses,
        by_clause=by_clause,
    )
    assert row_auth["final_status"] == "non_compliant"
    _merge_remote(
        assessments,
        {"items": [{"clause_id": "8.1.4.1-a", "status": "compliant", "note": "误判通过"}]},
        sample_clauses,
        by_clause=by_clause,
    )
    assert row_auth["final_status"] == "non_compliant"

    # 2) P0-2: RPM SBOM 必须保留非零 Epoch；dedup 合并同 CVE 跨子包
    sbom = rpm_to_cyclonedx(
        ["bind-libs\t32\t9.16.23\t34.el9_7.1\tx86_64", "openssl-libs\t1\t3.5.1\t7.el9_7\tx86_64", "expat\t(none)\t2.5.0\t5.el9_7\tx86_64"],
        "rocky",
        "9.7",
    )
    comps = {c["name"]: c for c in sbom["components"]}
    assert comps["bind-libs"]["version"] == "32:9.16.23-34.el9_7.1"
    assert "epoch=32" in comps["bind-libs"]["purl"]
    assert comps["expat"]["version"] == "2.5.0-5.el9_7"
    assert "epoch=" not in comps["expat"]["purl"]

    deduped = aggregate_findings([
        {"asset_id": "ast_1", "source_tool": "trivy_os", "cve_or_cwe": "CVE-2026-41651", "severity": "high", "title": "PackageKit 漏洞", "detail": {"pkg_name": "PackageKit", "fixed_version": "1.2.6-2", "cvss_score": 8.8}},
        {"asset_id": "ast_1", "source_tool": "trivy_os", "cve_or_cwe": "CVE-2026-41651", "severity": "high", "title": "PackageKit-glib 漏洞", "detail": {"pkg_name": "PackageKit-glib", "fixed_version": "1.2.6-2", "cvss_score": 7.5}},
    ])
    assert len(deduped) == 1
    assert set(deduped[0]["detail"]["affected_pkgs"]) == {"PackageKit", "PackageKit-glib"}
    assert deduped[0]["detail"]["cvss_score"] == 8.8

    # 3) P1-1 & P1-2: Nginx command not found 零误报；PG local trust=medium vs remote trust=critical；Redis 拆分且不挂 8.1.3.2-a
    fake_outputs = {
        "nginx_detect": "nginx=inactive\nbash: line 58: nginx: command not found",
        "pg_detect": "postgres=active",
        "redis_detect": "redis=active",
        "ports": "0.0.0.0:5432\n0.0.0.0:6379",
        "docker_ps": "",
        "nginx_conf": "",
        "pg_hba": "local all all trust\nhost all all 127.0.0.1/32 trust\n",
        "pg_conf": "listen_addresses = '*'\nssl = off\n",
        "redis_conf": "bind 0.0.0.0\nrequirepass secret123\nprotected-mode no\n",
    }
    findings = parse_db_mw_baseline(fake_outputs, "ast_db")
    assert not any("Nginx" in f["title"] for f in findings)
    pg_trust = next(f for f in findings if "trust" in f["title"])
    assert pg_trust["severity"] == "medium" and "本机/回环" in pg_trust["title"]
    redis_bind = next(f for f in findings if "Redis 监听" in f["title"])
    redis_pm = next(f for f in findings if "protected-mode" in f["title"])
    assert "8.1.3.2-a" not in redis_bind["clause_hints"]
    assert "已启用访问认证" in redis_bind["detail"]["text"]
    assert redis_pm["severity"] == "high"

    # 4) P1-4: 对象覆盖矩阵排除 COLLECT_ERROR，且未纳管业务应用仅 1 条 nuclei 线索判 partial 而非 covered
    cov = compute_object_coverage(
        [
            {"clause_id": "c1", "applicable_objects": ["host_os"]},
            {"clause_id": "c2", "applicable_objects": ["application"]},
        ],
        [],
        assets=[{"asset_id": "ast_1", "object_type": "host_os", "is_enabled": True, "scanners": ["ssh_baseline"]}],
        evidences=[
            {"asset_id": "ast_1", "source_tool": "ssh_baseline", "evidence_type": "COLLECT_ERROR"},
            {"asset_id": "ast_1", "source_tool": "nuclei", "evidence_type": "VULNERABILITY"},
        ],
    )
    by_obj = {x["object_key"]: x for x in cov["items"]}
    assert by_obj["host_os"]["scanned_assets"] == 0
    assert by_obj["application"]["status"] == "partial"

    # 5) P2-2: 攻击路径基于真实跨资产证据动态串联
    paths = _attack_paths([
        {"evidence_id": "ev_w", "asset_id": "ast_app", "source_tool": "nuclei", "evidence_type": "VULNERABILITY", "severity": "high", "title": "iTop 安装向导暴露"},
        {"evidence_id": "ev_d", "asset_id": "ast_db", "source_tool": "db_baseline", "evidence_type": "BASELINE_FAIL", "severity": "high", "title": "PostgreSQL 全网监听"},
    ])
    assert any("ast_app" in " ".join(p["steps"]) and "ast_db" in " ".join(p["steps"]) for p in paths)
    assert paths[0].get("precondition") and "ev_w" in (paths[0].get("evidence_ids") or [])





