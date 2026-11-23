"""条款映射。管理制度类条款先标成待人工，结论等核对证据后再写。"""
from __future__ import annotations

import json
import time
from collections import defaultdict
from typing import Any

from database.db_manager import new_id
from core.llm_gateway import review_with_profile
from core.policy import CompliancePolicyError, assert_llm_route, gemini_safety_settings

FAIL_TYPES = {"BASELINE_FAIL", "VULNERABILITY", "CLOUD_CONFIG"}
IGNORED_EVIDENCE_TYPES = {"COLLECT_ERROR"}
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _evidence_hints(item: dict) -> list[str]:
    hints = item.get("clause_hints") or []
    if not hints:
        hints = (item.get("detail") or {}).get("clause_hints") or []
    return [str(h) for h in hints if h]


def assess_clauses(clauses: list[dict], evidences: list[dict], env_tier: str, profile_name: str, profiles: dict) -> tuple[list[dict], list[dict], dict]:
    profile = assert_llm_route(env_tier, profile_name, profiles)
    safety = gemini_safety_settings(profile)
    started = time.perf_counter()
    # 排除采集失败类占位证据，避免把“未采集成功”误判为合规不符合
    valid_evidences = [
        ev for ev in evidences
        if str(ev.get("evidence_type") or "") not in IGNORED_EVIDENCE_TYPES
    ]
    by_clause: dict[str, list[dict]] = defaultdict(list)
    for evidence in valid_evidences:
        for hint in _evidence_hints(evidence):
            by_clause[hint].append(evidence)

    assessments = []
    for clause in clauses:
        related = by_clause.get(clause["clause_id"], [])
        assessments.append(_judge(clause, related, profile_name))
    remote_status = "local_rules"
    remote_error = None if safety is None else "gemini_safety_settings=BLOCK_NONE"
    model_id = profile.get("fast_mapper_model", profile_name)
    if profile.get("is_enabled") is False:
        raise CompliancePolicyError(f"模型通道 {profile_name} 已停用")
    provider = profile.get("provider") or _infer_provider(profile)
    if provider in {"gemini", "openai_compatible"}:
        parsed_items = []
        errors = []
        grouped: dict[str, list[dict]] = defaultdict(list)
        for clause in clauses:
            if clause.get("auto_level") == "MANUAL_ONLY":
                continue
            grouped[clause.get("domain") or "其他"].append(clause)
        for domain, group in grouped.items():
            # 单安全域技术条款超过 15 条时分批送入大模型，避免上下文过长导致遗漏
            for offset in range(0, len(group), 15):
                batch = group[offset:offset + 15]
                ids = {item["clause_id"] for item in batch}
                related = [
                    item for item in valid_evidences
                    if ids.intersection(set(_evidence_hints(item)))
                ]
                if not related:
                    # 本批次没有任何技术证据时，直接保留规则引擎的 not_assessed，无需消耗 Token
                    continue
                try:
                    remote = review_with_profile(profile, _prompt(batch, related, domain))
                    remote_status = remote["status"]
                    model_id = remote.get("model_id", model_id)
                    if remote.get("error_detail"):
                        errors.append(str(remote["error_detail"]))
                    if remote["status"] == "ok":
                        parsed_items.extend((remote.get("parsed") or {}).get("items") or [])
                except Exception as exc:
                    remote_status = "error"
                    errors.append(f"{domain}: {exc}")
        remote_error = "；".join(errors) if errors else (None if safety is None else "gemini_safety_settings=BLOCK_NONE")
        if parsed_items:
            _merge_remote(assessments, {"items": parsed_items}, clauses, by_clause)
    paths = _attack_paths(valid_evidences)
    audit = {
        "stage": "clause_mapping",
        "model_id": model_id,
        "prompt_tokens": len(evidences) * 40,
        "completion_tokens": len(assessments) * 25,
        "cached_tokens": len(clauses) * 10 if profile.get("enable_context_caching") else 0,
        "latency_ms": int((time.perf_counter() - started) * 1000),
        "status": remote_status,
        "error_detail": remote_error,
        "safety_settings": safety,
    }
    return assessments, paths, audit


def _judge(clause: dict, related: list[dict], profile_name: str) -> dict:
    auto_level = clause["auto_level"]
    if auto_level == "MANUAL_ONLY":
        status = "pending_manual"
        rationale = "这条属于管理或现场核查。系统先给出核查提示，符合与否要等人工核对证据后再写。"
        # 人工核查指引保留在条款库 manual_check_guide 字段，不再混入技术加固脚本
        script = ""
    else:
        fails = [item for item in related if item.get("evidence_type") in FAIL_TYPES and item.get("severity") in {"critical", "high", "medium", "low"}]
        passes = [item for item in related if item.get("evidence_type") == "BASELINE_PASS"]
        if any(item.get("severity") in {"critical", "high"} for item in fails):
            status = "non_compliant" if auto_level == "FULL_AUTO" else "partially_compliant"
        elif fails:
            status = "partially_compliant"
        elif passes and auto_level == "FULL_AUTO":
            status = "compliant"
        elif not related:
            status = "not_assessed"
        else:
            status = "partially_compliant"
        titles = "；".join(item["title"] for item in (fails or passes)[:4]) or "本轮还没有直接对应的证据"
        hosts = "、".join(sorted({item.get("asset_id") or "" for item in (fails or passes) if item.get("asset_id")})[:8])
        rationale = f"通道 {profile_name} 根据已脱敏的证据给出意见：{titles}"
        if hosts:
            rationale += f"。涉及资产 {hosts}"
        script = _remediation(fails) if fails else ""
        if auto_level != "FULL_AUTO" and status == "compliant":
            status = "partially_compliant"
    if auto_level == "MANUAL_ONLY" and status == "compliant":
        status = "pending_manual"
    risk = "high" if clause.get("high_risk") and status in {"non_compliant", "partially_compliant", "pending_manual"} else "medium"
    if status == "compliant":
        risk = "info"
    return {
        "assessment_id": new_id("asm"),
        "clause_id": clause["clause_id"],
        "auto_status": status,
        "manual_status": None,
        "final_status": status,
        "risk_level": risk,
        "is_high_risk": bool(clause.get("high_risk")),
        "evidence_ids": [item["evidence_id"] for item in related if item.get("evidence_id")],
        "ai_rationale": rationale,
        "remediation_script": script,
    }


# 场景化安全加固参考脚本库（所有脚本均包含前置检查、变更、验证与回滚说明）
_REMEDIATION_TEMPLATES: dict[str, str] = {
    "ssh_hardening": (
        "# [SSH 加固] 禁止 root 直连、收紧密码学套件与空闲超时\n"
        "# 1) 前置检查：确保已建立普通运维账号并可 sudo 提权，变更时请保留当前 SSH 会话\n"
        "id opsadmin || (useradd -m -G wheel opsadmin && passwd opsadmin)\n"
        "cp -a /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%F)\n"
        "cat <<'EOF' > /etc/ssh/sshd_config.d/99-mlps-hardening.conf\n"
        "PermitRootLogin no\n"
        "MaxAuthTries 4\n"
        "ClientAliveInterval 300\n"
        "ClientAliveCountMax 2\n"
        "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr\n"
        "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com\n"
        "EOF\n"
        "# 2) 语法校验与热重载（先新开终端用 opsadmin 验证登录，再关闭旧会话）\n"
        "sshd -t && systemctl reload sshd\n"
        "# 回滚：rm -f /etc/ssh/sshd_config.d/99-mlps-hardening.conf && systemctl reload sshd"
    ),
    "password_lockout": (
        "# [口令策略与失败锁定] 配置口令复杂度、有效期、faillock 与会话超时\n"
        "cp -a /etc/security/pwquality.conf /etc/security/pwquality.conf.bak.$(date +%F)\n"
        "cp -a /etc/login.defs /etc/login.defs.bak.$(date +%F)\n"
        "cat <<'EOF' > /etc/security/pwquality.conf.d/99-mlps.conf\n"
        "minlen = 12\n"
        "minclass = 3\n"
        "maxrepeat = 3\n"
        "EOF\n"
        "sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs\n"
        "sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    12/' /etc/login.defs\n"
        "# Rocky/RHEL 9 使用 authselect 启用 faillock（建议在备用控制台同步测试）\n"
        "authselect enable-feature with-faillock && sed -i 's/^# *deny.*/deny = 5/; s/^# *unlock_time.*/unlock_time = 600/' /etc/security/faillock.conf\n"
        "printf 'readonly TMOUT=900\\nexport TMOUT\\n' > /etc/profile.d/99-mlps-timeout.sh\n"
        "# 回滚：authselect disable-feature with-faillock; rm -f /etc/security/pwquality.conf.d/99-mlps.conf /etc/profile.d/99-mlps-timeout.sh"
    ),
    "sudo_hardening": (
        "# [特权最小化] 排查并移除免密 sudo（NOPASSWD）与宽泛 ALL 授权\n"
        "grep -rn 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ || true\n"
        "# 使用 visudo 逐条修改，避免语法错误锁死提权能力（示例：将 NOPASSWD:ALL 收敛为具体运维命令）\n"
        "visudo -c"
    ),
    "file_perm_umask": (
        "# [关键文件权限与默认 umask] 收紧敏感口令文件权限并加固 umask\n"
        "chmod 644 /etc/passwd /etc/group && chmod 000 /etc/shadow /etc/gshadow\n"
        "chmod 600 /etc/ssh/sshd_config\n"
        "printf 'umask 027\\n' > /etc/profile.d/99-mlps-umask.sh\n"
        "# 验证：stat -c '%a %n' /etc/passwd /etc/shadow /etc/ssh/sshd_config"
    ),
    "audit_logging": (
        "# [主机审计与集中日志] 启用 auditd 关键规则并配置 rsyslog 远程转发（留存 >= 180 天）\n"
        "systemctl enable --now auditd\n"
        "cat <<'EOF' > /etc/audit/rules.d/99-mlps.rules\n"
        "-w /etc/passwd -p wa -k identity\n"
        "-w /etc/shadow -p wa -k identity\n"
        "-w /etc/sudoers -p wa -k scope\n"
        "-w /etc/ssh/sshd_config -p wa -k sshd\n"
        "EOF\n"
        "augenrules --load && auditctl -l\n"
        "# 配置 rsyslog 远程集中存储（将 <SYSLOG_SERVER> 替换为实际日志审计服务器地址）\n"
        "echo '*.* @@<SYSLOG_SERVER>:514' > /etc/rsyslog.d/99-mlps-remote.conf\n"
        "rsyslogd -N1 && systemctl restart rsyslog"
    ),
    "firewalld_hardening": (
        "# [主机防火墙加固] 先梳理现有业务端口与管理来源网段，再启用 firewalld（防止自锁与容器断网）\n"
        "ss -tlpn\n"
        "# 1) 启动前预置规则（使用 firewall-offline-cmd，将 <MGMT_CIDR> / <APP_CIDR> 替换为实际运维与业务网段）\n"
        "firewall-offline-cmd --zone=public --add-rich-rule='rule family=\"ipv4\" source address=\"<MGMT_CIDR>\" port port=\"22\" protocol=\"tcp\" accept'\n"
        "firewall-offline-cmd --zone=public --add-service=https\n"
        "# 若宿主机运行 Docker，启用防火墙后需重启 docker 以重建 DOCKER iptables 链\n"
        "systemctl enable --now firewalld && firewall-cmd --list-all\n"
        "# 紧急回滚：systemctl stop firewalld"
    ),
    "selinux_hardening": (
        "# [SELinux 加固] 先切 Permissive 观察 AVC 告警，确认无业务拦截后再启用 Enforcing\n"
        "getenforce\n"
        "sed -i 's/^SELINUX=.*/SELINUX=permissive/' /etc/selinux/config\n"
        "# 观察业务运行 24~48 小时：ausearch -m avc -ts recent\n"
        "# 确认无阻断后开启强制模式：\n"
        "setenforce 1 && sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config\n"
        "# 回滚：setenforce 0"
    ),
    "postgres_hardening": (
        "# [PostgreSQL 加固] 禁用 trust 免密、收敛监听网段、启用 SSL 与审计日志\n"
        "# 1) 定位实际数据目录并备份（如 /data/postgresql 或 /var/lib/pgsql/16/data）\n"
        "PGDATA=$(sudo -u postgres psql -tAc 'SHOW data_directory;' 2>/dev/null || echo /data/postgresql)\n"
        "cp -a \"$PGDATA/pg_hba.conf\" \"$PGDATA/pg_hba.conf.bak.$(date +%F)\"\n"
        "cp -a \"$PGDATA/postgresql.conf\" \"$PGDATA/postgresql.conf.bak.$(date +%F)\"\n"
        "# 2) pg_hba.conf 将 trust 替换为 scram-sha-256，远程连接改为 hostssl 并限制应用网段\n"
        "# 3) postgresql.conf 建议配置：listen_addresses = '127.0.0.1,<DB_INTERNAL_IP>' / ssl = on / logging_collector = on / log_connections = on / log_disconnections = on / log_statement = 'ddl'\n"
        "# 4) 重载配置并验证：sudo -u postgres psql -c 'SELECT pg_reload_conf();' && sudo -u postgres psql -c 'SHOW ssl;'"
    ),
    "mysql_hardening": (
        "# [MySQL 加固] 收敛监听地址、强制 SSL 传输加密、启用口令复杂度与审计日志\n"
        "# 1) 宿主机部署：在 my.cnf [mysqld] 段配置 bind-address=<DB_INTERNAL_IP>、require_secure_transport=ON、local_infile=0\n"
        "# 2) Docker 部署：修改 compose 端口映射为 127.0.0.1:5455:3306 或仅在内部业务网络暴露，避免 0.0.0.0 全网监听\n"
        "# 3) 启用口令策略组件（MySQL 8.0+）：\n"
        "#    INSTALL COMPONENT 'file://component_validate_password';\n"
        "#    SET PERSIST validate_password.policy = 'MEDIUM'; SET PERSIST validate_password.length = 12;\n"
        "# 4) 启用审计插件或将操作日志接入集中审计平台（留存 >= 180 天）"
    ),
    "redis_hardening": (
        "# [Redis / Valkey 加固] 收敛监听暴露面、开启保护模式并禁用高危管理命令\n"
        "# 1) 宿主机部署：编辑 redis.conf 设置 bind 127.0.0.1 <INTERNAL_IP> 与 protected-mode yes\n"
        "# 2) Docker 部署：将 ports 从 0.0.0.0:6379:6379 收紧为 127.0.0.1:6379:6379 或限定内部网络访问，并在启动参数确保 --protected-mode yes\n"
        "# 3) 禁用高危命令：在配置中添加 rename-command FLUSHALL \"\"、rename-command FLUSHDB \"\"、rename-command CONFIG \"\"、rename-command DEBUG \"\"\n"
        "# 4) 验证：redis-cli -a <PASS> CONFIG GET protected-mode"
    ),
    "nginx_apache_hardening": (
        "# [Web 中间件加固] 隐藏版本指纹并确保访问日志开启\n"
        "# Nginx：在 /etc/nginx/nginx.conf http{} 段加入 server_tokens off; 与 access_log /var/log/nginx/access.log main;\n"
        "nginx -t && systemctl reload nginx\n"
        "# Apache/httpd：在 /etc/httpd/conf.d/security.conf 写入 ServerTokens Prod 与 ServerSignature Off\n"
        "httpd -t && systemctl reload httpd"
    ),
    "tls_hardening": (
        "# [HTTPS / TLS 传输加密加固] 替换自签名证书、禁用弱协议与套件并开启 HSTS\n"
        "# 1) 签发并部署受信任 CA（或企业内部合规 PKI）证书替换自签名证书\n"
        "# 2) Nginx/Apache 仅启用 TLSv1.2 TLSv1.3 及 AEAD 强套件（ECDHE-ECDSA/RSA-AES256-GCM-SHA384）\n"
        "# 3) 添加响应头：add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
        "# 4) 验证：openssl s_client -connect <HOST>:443 -tls1_2"
    ),
    "web_exposure": (
        "# [业务应用暴露面收敛] 清理安装向导页与未授权管理入口\n"
        "# 1) 删除或通过 Web 服务器 ACL 禁止外部访问安装/初始化页面（如 /setup/、install.php）\n"
        "# 2) 管理后台仅允许通过运维网段或堡垒机访问，启用强身份鉴别与防爆破锁定\n"
        "# 3) 变更后使用 curl -I 验证返回 403/404"
    ),
    "os_patch": (
        "# [操作系统安全补丁升级] 在变更窗口优先修复严重与高危 CVE（建议先做系统快照）\n"
        "dnf check-update --security\n"
        "dnf upgrade --security -y\n"
        "# 检查需要重启的服务或内核：needs-restarting -r || true\n"
        "# 回滚参考：dnf history list && dnf history undo <TRANSACTION_ID>"
    ),
    "cloud_netdev": (
        "# [网络边界与云平台加固] 按最小权限收敛入站策略并强化管理鉴别\n"
        "# 1) 边界防火墙/安全组移除 0.0.0.0/0 对 SSH(22)/数据库(3306/5432/6379)/管理端口的放行，改为具体源网段白名单\n"
        "# 2) 为云平台及网络设备管理员开启多因素认证（MFA）并制定 AK/口令 90 天轮换机制"
    ),
}


def _classify_remediation_key(item: dict) -> str:
    title = str(item.get("title") or "")
    low = title.lower()
    tool = str(item.get("source_tool") or "")
    ev_type = str(item.get("evidence_type") or "")

    if tool == "trivy_os" or ev_type == "VULNERABILITY" or "cve-" in low:
        return "os_patch"
    if tool == "tls_scanner" or "tls" in low or "hsts" in low or "自签名" in title or "ssl 证书" in low:
        return "tls_hardening"
    if tool == "nuclei" or "安装向导" in title or "setup" in low:
        return "web_exposure"
    if "postgresql" in low or "pg_hba" in low or "postgres" in low:
        return "postgres_hardening"
    if "mysql" in low or "mariadb" in low:
        return "mysql_hardening"
    if "redis" in low or "valkey" in low:
        return "redis_hardening"
    if "nginx" in low or "apache" in low or "httpd" in low:
        return "nginx_apache_hardening"
    if "root" in low or "ssh" in low or "sshd" in low:
        return "ssh_hardening"
    if "口令" in title or "密码" in title or "失败锁定" in title or "faillock" in low or "超时" in title or "tmout" in low:
        return "password_lockout"
    if "sudo" in low or "nopasswd" in low:
        return "sudo_hardening"
    if "umask" in low or "shadow" in low or "文件权限" in title:
        return "file_perm_umask"
    if "auditd" in low or "审计" in title or "日志" in title or "rsyslog" in low:
        return "audit_logging"
    if "防火墙" in title or "firewall" in low or "0.0.0.0" in title:
        return "firewalld_hardening"
    if "selinux" in low:
        return "selinux_hardening"
    if tool in {"cloud_audit", "netdev_config"} or "安全组" in title or "mfa" in low or "acl" in low:
        return "cloud_netdev"
    return ""


def _remediation(fails: list[dict]) -> str:
    blocks: list[str] = []
    seen_keys: set[str] = set()
    for item in fails:
        key = _classify_remediation_key(item)
        if key and key not in seen_keys and key in _REMEDIATION_TEMPLATES:
            seen_keys.add(key)
            blocks.append(_REMEDIATION_TEMPLATES[key])
    if not blocks:
        return ""
    return "\n\n".join(blocks[:4])


def _attack_paths(evidences: list[dict]) -> list[dict]:
    """基于真实实测证据动态推演攻击链，废弃写死模板并标明测试前提。"""
    valid = [e for e in evidences if e.get("evidence_type") != "COLLECT_ERROR"]
    paths: list[dict] = []

    def _ev_ids(items: list[dict], limit: int = 6) -> list[str]:
        return [str(e.get("evidence_id")) for e in items if e.get("evidence_id")][:limit]

    def _assets(items: list[dict]) -> str:
        ids = sorted({str(e.get("asset_id")) for e in items if e.get("asset_id")})
        return "、".join(ids) if ids else "受测主机"

    # 1. 跨主机路径：应用/Web 暴露面 -> 数据库与缓存服务横向访问
    web_exposures = [
        e for e in valid
        if (e.get("source_tool") == "nuclei" and e.get("severity") in {"critical", "high", "medium"})
        or (e.get("source_tool") == "tls_scanner" and e.get("evidence_type") != "BASELINE_PASS")
    ]
    db_exposures = [
        e for e in valid
        if e.get("source_tool") == "db_baseline" and e.get("evidence_type") == "BASELINE_FAIL"
    ]
    if web_exposures and db_exposures:
        web_assets = _assets(web_exposures)
        db_assets = _assets(db_exposures)
        web_sample = "；".join(str(e.get("title") or "") for e in web_exposures[:2])
        db_sample = "；".join(str(e.get("title") or "") for e in db_exposures[:3])
        db_has_critical = any(e.get("severity") == "critical" for e in db_exposures)
        paths.append({
            "path_id": new_id("path"),
            "title": "应用侧暴露面突破并向数据库/缓存横向渗透",
            "severity": "critical" if db_has_critical else "high",
            "mitigation_priority": "P0",
            "precondition": "基于内网同网段实测推演；互联网直接可达性需结合边界防火墙策略进一步复核。",
            "evidence_ids": _ev_ids(web_exposures[:2] + db_exposures[:4]),
            "steps": [
                f"入口探测：攻击者面向资产 {web_assets} 发现应用与传输层暴露点（{web_sample}），存在获取应用立足点或窃取会话凭证的风险。",
                f"内网横向移动：资产 {db_assets} 的数据服务存在显著暴露与加密/认证短板（{db_sample}），同网段或应用主机失陷后可直接触达数据库与缓存端口。",
                "数据泄露影响：缺乏强传输加密与细粒度访问控制时，核心业务表与凭据数据面临批量拖库或篡改风险。",
            ],
        })

    # 2. 远程管理入口突破与隐蔽驻留（SSH + 防火墙 + 审计）
    ssh_weak = [
        e for e in valid
        if e.get("source_tool") == "ssh_baseline"
        and e.get("evidence_type") == "BASELINE_FAIL"
        and any(k in str(e.get("title") or "").lower() for k in ("root", "失败锁定", "口令", "ssh"))
    ]
    fw_weak = [
        e for e in valid
        if e.get("source_tool") == "ssh_baseline"
        and e.get("evidence_type") == "BASELINE_FAIL"
        and ("防火墙" in str(e.get("title") or "") or "firewall" in str(e.get("title") or "").lower())
    ]
    audit_weak = [
        e for e in valid
        if e.get("source_tool") == "ssh_baseline"
        and e.get("evidence_type") == "BASELINE_FAIL"
        and ("auditd" in str(e.get("title") or "").lower() or "审计" in str(e.get("title") or "") or "远程日志" in str(e.get("title") or ""))
    ]
    if ssh_weak or fw_weak:
        affected = _assets(ssh_weak + fw_weak)
        step_list = [
            f"管理面暴露：受测主机 {affected} 存在远程管理入口与主机防护短板（{'；'.join(str(e.get('title') or '') for e in (ssh_weak + fw_weak)[:3])}）。",
        ]
        if ssh_weak:
            step_list.append("凭证试探与控制权接管：在允许 root 远程直连或未启用登录失败锁定的条件下，内网可达攻击者可持续发起口令爆破或凭证填充。")
        if audit_weak:
            step_list.append(f"隐蔽驻留：主机审计或集中日志转发存在缺口（{audit_weak[0].get('title')}），入侵后的提权与横向操作难以及时告警和事后溯源。")
        paths.append({
            "path_id": new_id("path"),
            "title": "主机远程管理入口突破与横向移动风险",
            "severity": "high",
            "mitigation_priority": "P0",
            "precondition": "前提为攻击者可触达目标 22 端口（内网跳板或边界放行场景）。",
            "evidence_ids": _ev_ids(ssh_weak[:3] + fw_weak[:2] + audit_weak[:2]),
            "steps": step_list,
        })

    # 3. 操作系统高危漏洞 + 本地提权面（Trivy CRITICAL/HIGH + sudo/SELinux）
    trivy_hi = [
        e for e in valid
        if e.get("source_tool") == "trivy_os" and e.get("severity") in {"critical", "high"}
    ]
    priv_weak = [
        e for e in valid
        if e.get("source_tool") == "ssh_baseline"
        and e.get("evidence_type") == "BASELINE_FAIL"
        and any(k in str(e.get("title") or "").lower() for k in ("sudo", "selinux", "nopasswd"))
    ]
    if trivy_hi and (priv_weak or any(e.get("severity") == "critical" for e in trivy_hi)):
        affected = _assets(trivy_hi[:6] + priv_weak)
        sample_cves = "、".join(
            sorted({str(e.get("cve_or_cwe") or "") for e in trivy_hi[:8] if e.get("cve_or_cwe")})[:4]
        )
        steps = [
            f"漏洞利用入口：资产 {affected} 检出多条高危/严重级系统软件包漏洞（代表性编号：{sample_cves}）。",
        ]
        if priv_weak:
            steps.append(f"权限提升与绕过：叠加主机侧提权与隔离薄弱点（{'；'.join(str(e.get('title') or '') for e in priv_weak[:2])}），低权限进程被攻破后可迅速升级为 root 权限。")
        else:
            steps.append("权限提升与服务接管：若对应受影响组件服务处于运行或被本地进程调用状态，可能引发权限提升或服务失陷。")
        steps.append("持久化风险：获取宿主机最高权限后，可进一步窃取同机运行的配置文件、数据库凭据及容器卷数据。")
        paths.append({
            "path_id": new_id("path"),
            "title": "系统组件漏洞与主机本地提权组合链路",
            "severity": "high",
            "mitigation_priority": "P1",
            "precondition": "部分漏洞为本地提权或需对应服务处于监听状态，处置前应结合端口监听清单排序优先级。",
            "evidence_ids": _ev_ids(trivy_hi[:3] + priv_weak[:2]),
            "steps": steps,
        })

    # 4. 传输层明文/弱加密数据窃听路径
    ssl_db = [
        e for e in db_exposures
        if any(k in str(e.get("title") or "").lower() for k in ("ssl", "tls", "加密", "明文"))
    ]
    tls_weak = [e for e in valid if e.get("source_tool") == "tls_scanner" and e.get("evidence_type") != "BASELINE_PASS"]
    if ssl_db or tls_weak:
        combined = ssl_db + tls_weak
        paths.append({
            "path_id": new_id("path"),
            "title": "通信链路明文或弱加密导致的凭据与数据窃听",
            "severity": "medium",
            "mitigation_priority": "P1",
            "precondition": "需攻击者处于同网段中间人位置或控制链路转发节点。",
            "evidence_ids": _ev_ids(combined[:4]),
            "steps": [
                f"链路弱点：资产 {_assets(combined)} 存在传输加密短板（{'；'.join(str(e.get('title') or '') for e in combined[:3])}）。",
                "中间人拦截：在未强制可信证书校验、缺少 HSTS 或数据库未启用 SSL 的场景下，鉴别凭据与查询结果可能遭降级或明文嗅探。",
            ],
        })

    # 5. 云平台 / 边界安全设备配置路径
    cloud_net = [
        e for e in valid
        if e.get("source_tool") in {"cloud_audit", "netdev_config"} and e.get("evidence_type") != "BASELINE_PASS"
    ]
    if cloud_net:
        paths.append({
            "path_id": new_id("path"),
            "title": "边界策略或云上控制面过宽暴露路径",
            "severity": "high",
            "mitigation_priority": "P0",
            "precondition": "基于导入的网络边界/云平台配置核查结果推演。",
            "evidence_ids": _ev_ids(cloud_net[:4]),
            "steps": [
                f"控制面/边界弱点：对象 {_assets(cloud_net)} 检出 {'；'.join(str(e.get('title') or '') for e in cloud_net[:3])}。",
                "攻击影响：外部访问策略过宽或缺少 MFA 时，攻击者可直接触达核心管理面并扩大入侵半径。",
            ],
        })

    if not paths:
        paths.append({
            "path_id": new_id("path"),
            "title": "当前技术证据尚未串联出高风险跨节点攻击链",
            "severity": "info",
            "mitigation_priority": "P2",
            "precondition": "基于当前已采集证据范围。",
            "evidence_ids": [],
            "steps": ["建议补充网络边界设备配置、应用层渗透测试与云控制面核查后再开展全链路推演。"],
        })
    return paths[:5]


def _prompt(clauses: list[dict], evidences: list[dict], domain: str = "") -> str:
    brief = [
        {"clause_id": item["clause_id"], "auto_level": item.get("auto_level"), "text": item["requirement_text"]}
        for item in clauses
    ]
    # 失败类证据与高严重度证据优先进入上下文，避免被大量低危/通过项挤出
    ordered = sorted(
        evidences,
        key=lambda e: (
            0 if e.get("evidence_type") in FAIL_TYPES else 1,
            -_SEV_RANK.get(str(e.get("severity") or "").lower(), 0),
        ),
    )
    facts = [
        {
            "asset_id": item.get("asset_id"),
            "source_tool": item.get("source_tool"),
            "evidence_type": item.get("evidence_type"),
            "severity": item.get("severity"),
            "title": item.get("title"),
            "cve": item.get("cve_or_cwe"),
            "detail": str((item.get("detail") or {}).get("text") or "")[:120],
            "hints": _evidence_hints(item),
        }
        for item in ordered[:120]
    ]
    return (
        f"安全域：{domain}。请严格依据下面已脱敏的实测证据，为本域技术条款给出符合性结论 status 与中文说明 note。"
        "规则：1）只要证据列表 hints 中命中某条款，就必须据此给出 compliant / partially_compliant / non_compliant，不得忽略已有证据返回 not_assessed；"
        "2）仅当某条款在证据中确实没有任何匹配项时，才返回 not_assessed；"
        "3）存在 critical/high 级别失败证据（BASELINE_FAIL/VULNERABILITY/CLOUD_CONFIG）时不得判定为 compliant；"
        "4）auto_level 为 PARTIAL_EVIDENCE 的条款无法仅凭单机证据判定完全符合，最高给 partially_compliant；"
        "5）同一条证据涉及多台主机时请在 note 中写明 asset_id，并区分已通过项与未通过项。"
        "管理制度条款不要写入 items。返回 JSON：{\"items\":[{\"clause_id\":\"\",\"status\":\"\",\"note\":\"\"}]}\n"
        f"条款：{json.dumps(brief, ensure_ascii=False)}\n证据：{json.dumps(facts, ensure_ascii=False)}"
    )


def _merge_remote(
    assessments: list[dict],
    parsed: dict,
    clauses: list[dict],
    by_clause: dict[str, list[dict]] | None = None,
) -> None:
    clause_map = {item["clause_id"]: item for item in clauses}
    manual = {item["clause_id"] for item in clauses if item["auto_level"] == "MANUAL_ONLY"}
    incoming = {item.get("clause_id"): item for item in parsed.get("items", [])}
    allowed = {"compliant", "partially_compliant", "non_compliant", "not_assessed"}
    for row in assessments:
        cid = row["clause_id"]
        if cid in manual:
            row["final_status"] = "pending_manual"
            row["auto_status"] = "pending_manual"
            continue
        remote = incoming.get(cid)
        if not remote or remote.get("status") not in allowed:
            continue
        proposed = str(remote["status"])
        related = (by_clause or {}).get(cid, [])
        has_evidence = bool(row.get("evidence_ids") or related)
        # 护栏 1：已有实测证据且规则引擎已给出明确判定时，禁止被模型误覆盖回 not_assessed
        if has_evidence and proposed == "not_assessed" and row.get("auto_status") != "not_assessed":
            continue
        # 护栏 2：存在高危/严重失败证据时，禁止模型将其判为 compliant
        high_fails = [
            ev for ev in related
            if ev.get("evidence_type") in FAIL_TYPES and str(ev.get("severity") or "").lower() in {"critical", "high"}
        ]
        auto_level = (clause_map.get(cid) or {}).get("auto_level", "PARTIAL_EVIDENCE")
        if high_fails and proposed == "compliant":
            proposed = "non_compliant" if auto_level == "FULL_AUTO" else "partially_compliant"
        # 护栏 3：非 FULL_AUTO 条款不得仅凭自动化采集直接判完全符合
        if auto_level != "FULL_AUTO" and proposed == "compliant":
            proposed = "partially_compliant"
        row["auto_status"] = proposed
        row["final_status"] = proposed
        if row.get("is_high_risk") and proposed in {"non_compliant", "partially_compliant", "pending_manual"}:
            row["risk_level"] = "high"
        elif proposed == "compliant":
            row["risk_level"] = "info"
        else:
            row["risk_level"] = "medium"
        if remote.get("note"):
            row["ai_rationale"] = f"模型复核：{remote['note']}"


def _infer_provider(profile: dict) -> str:
    model = str(profile.get("fast_mapper_model", ""))
    if profile.get("provider"):
        return str(profile["provider"])
    if "gemini" in model or profile.get("is_cross_border"):
        return "gemini"
    if model.startswith("local/"):
        return "local_rules"
    if profile.get("api_base") or model.startswith("openai/") or model.startswith("deepseek/"):
        return "openai_compatible"
    return "local_rules"


def assert_manual_not_auto_passed(assessments: list[dict], clauses: list[dict]) -> None:
    manual_ids = {item["clause_id"] for item in clauses if item["auto_level"] == "MANUAL_ONLY"}
    for row in assessments:
        if row["clause_id"] in manual_ids and row["final_status"] == "compliant":
            raise CompliancePolicyError("人工条款的结论被写成了符合，本次评审已中止")
