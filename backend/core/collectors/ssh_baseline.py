"""Rocky Linux 与 CentOS 的只读基线。命令只读取配置，不修改目标。"""
from __future__ import annotations

import os
from typing import Any

READONLY_SCRIPT = r"""
echo @@os@@
cat /etc/os-release 2>/dev/null || true
echo @@sshd@@
sshd -T 2>/dev/null || grep -E '^(PermitRootLogin|Protocol|ClientAliveInterval|ClientAliveCountMax|MaxAuthTries|PermitEmptyPasswords|X11Forwarding|Ciphers|MACs|KexAlgorithms)' /etc/ssh/sshd_config || true
echo @@pwquality@@
grep -E '^(minlen|minclass|dcredit|ucredit|lcredit|ocredit)' /etc/security/pwquality.conf 2>/dev/null || true
echo @@login_defs@@
grep -E '^(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|PASS_MIN_LEN)' /etc/login.defs 2>/dev/null || true
echo @@pam@@
grep -R -E 'pam_faillock|pam_tally2|deny=|unlock_time=' /etc/pam.d/system-auth /etc/pam.d/password-auth 2>/dev/null || true
echo @@shadow@@
awk -F: '($2==""){print $1}' /etc/shadow 2>/dev/null || true
echo @@tmout@@
grep -R -h '^TMOUT=' /etc/profile /etc/profile.d /etc/bashrc 2>/dev/null || true
echo @@selinux@@
getenforce 2>/dev/null || true
echo @@uid0@@
awk -F: '($3==0){print $1}' /etc/passwd || true
echo @@shells@@
awk -F: '$3<1000 && $3!=0 && $7 !~ /(nologin|false)/ {print $1":"$7}' /etc/passwd || true
echo @@sudoers@@
grep -R -n 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
echo @@perms@@
stat -c '%a %n' /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/ssh/sshd_config /etc/crontab 2>/dev/null || true
echo @@umask@@
grep -R -h '^umask' /etc/profile /etc/bashrc /etc/login.defs 2>/dev/null | head -n 5 || true
echo @@sticky@@
stat -c '%a %n' /tmp /var/tmp 2>/dev/null || true
echo @@auditd@@
systemctl is-active auditd 2>/dev/null || service auditd status 2>/dev/null || true
echo @@auditctl@@
auditctl -l 2>/dev/null || true
echo @@auditconf@@
grep -E '^(max_log_file_action|num_logs|max_log_file)' /etc/audit/auditd.conf 2>/dev/null || true
echo @@logrotate@@
grep -E '^rotate' /etc/logrotate.conf 2>/dev/null || true
echo @@rsyslog@@
systemctl is-active rsyslog 2>/dev/null || true
echo @@rsyslog_remote@@
grep -R -E '^[^#].*@' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null || true
echo @@chrony@@
systemctl is-active chronyd 2>/dev/null || systemctl is-active ntpd 2>/dev/null || true
chronyc tracking 2>/dev/null | head -n 3 || ntpq -p 2>/dev/null | head -n 3 || true
echo @@firewalld@@
firewall-cmd --state 2>/dev/null || echo inactive
echo @@firewall_rules@@
firewall-cmd --list-all 2>/dev/null || iptables -S 2>/dev/null | head -n 80 || true
echo @@services@@
for s in telnet.socket rsh.socket rlogin.socket tftp.socket rpcbind avahi-daemon cups; do printf '%s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"; done
echo @@sysctl@@
sysctl kernel.randomize_va_space net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects fs.suid_dumpable 2>/dev/null || true
echo @@core@@
grep -R -h 'core' /etc/security/limits.conf /etc/security/limits.d 2>/dev/null | head -n 10 || true
echo @@malware@@
for s in clamd wazuh-agent ossec-hids; do printf '%s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo inactive)"; done
ps -eo comm 2>/dev/null | grep -E 'clam|wazuh|ossec|yunjing|hostguard' | head -n 10 || true
echo @@updates@@
(timeout 8 dnf -C updateinfo list security --available 2>/dev/null || echo unavailable) | head -n 30
"""


def parse_baseline(outputs: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    evidences: list[dict[str, Any]] = []
    for checker in _CHECKERS:
        evidences.extend(checker(outputs, asset_id))
    return evidences


def collect_over_ssh(host: str, port: int, username: str, password: str | None, key_path: str | None, key_text: str | None = None) -> dict[str, str]:
    client = _connect(host, port, username, password, key_path, key_text)
    try:
        _, stdout, stderr = client.exec_command(READONLY_SCRIPT, timeout=60)
        text = (stdout.read() + stderr.read()).decode("utf-8", errors="replace")
    finally:
        client.close()
    return split_sections(text)


def probe_os(host: str, resolved: dict) -> str:
    client = _connect(host, resolved["port"], resolved["username"], resolved.get("password"), resolved.get("key_path"), resolved.get("key_text"))
    try:
        _, stdout, _ = client.exec_command("grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release", timeout=12)
        text = stdout.read().decode("utf-8", errors="replace").strip()
    finally:
        client.close()
    return text or "已连通，未读到发行版信息"


def collect_rpm_lines(host: str, resolved: dict) -> tuple[str, str, list[str]]:
    script = "grep -E '^(ID|VERSION_ID)=' /etc/os-release; echo @@RPM@@; rpm -qa --qf '%{NAME}\\t%{EPOCH}\\t%{VERSION}\\t%{RELEASE}\\t%{ARCH}\\n'"
    client = _connect(host, resolved["port"], resolved["username"], resolved.get("password"), resolved.get("key_path"), resolved.get("key_text"))
    try:
        _, stdout, stderr = client.exec_command(script, timeout=60)
        text = (stdout.read() + stderr.read()).decode("utf-8", errors="replace")
    finally:
        client.close()
    os_name, version = "rocky", ""
    lines: list[str] = []
    in_rpm = False
    for line in text.splitlines():
        if line.strip() == "@@RPM@@":
            in_rpm = True
            continue
        if not in_rpm:
            if line.startswith("ID="):
                os_name = line.split("=", 1)[1].strip().strip('"')
            elif line.startswith("VERSION_ID="):
                version = line.split("=", 1)[1].strip().strip('"')
            continue
        if "\t" in line:
            lines.append(line)
    return os_name, version, lines


def split_sections(text: str) -> dict[str, str]:
    current = "raw"
    buckets: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.startswith("@@") and line.endswith("@@") and len(line) > 4:
            current = line.strip("@").lower()
            buckets.setdefault(current, [])
            continue
        buckets.setdefault(current, []).append(line)
    parsed = {key: "\n".join(rows).strip() for key, rows in buckets.items()}
    if "chrony" in parsed and "chronyd" not in parsed:
        parsed["chronyd"] = parsed["chrony"].splitlines()[0] if parsed["chrony"] else ""
    return parsed


def _load_private_key(paramiko: Any, key_text: str):
    import io

    loaders = [paramiko.Ed25519Key, paramiko.RSAKey, paramiko.ECDSAKey]
    for loader in loaders:
        try:
            return loader.from_private_key(io.StringIO(key_text))
        except Exception:
            continue
    raise RuntimeError("私钥无法解析")


def _connect(host: str, port: int, username: str, password: str | None, key_path: str | None, key_text: str | None):
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": 12,
        "allow_agent": False,
        "look_for_keys": False,
    }
    if key_text:
        kwargs["pkey"] = _load_private_key(paramiko, key_text)
    elif key_path and os.path.exists(key_path):
        kwargs["key_filename"] = key_path
    elif password:
        kwargs["password"] = password
    else:
        raise RuntimeError("未配置 SSH 密钥或口令")
    client.connect(**kwargs)
    return client


def _value(text: str, key: str) -> str:
    for line in text.splitlines():
        lowered = line.strip().lower()
        if lowered.startswith(key.lower()):
            parts = line.strip().split(None, 1)
            if len(parts) == 1 and "=" in line:
                return line.split("=", 1)[1].strip()
            value = parts[1].strip() if len(parts) > 1 else ""
            return value[1:].strip() if value.startswith("=") else value
        if "=" in line and line.split("=", 1)[0].strip().lower() == key.lower():
            return line.split("=", 1)[1].strip()
    return ""


def _has(outputs: dict[str, str], *keys: str) -> bool:
    return any(key in outputs for key in keys)


def _text(outputs: dict[str, str], *keys: str) -> str:
    return "\n".join(outputs.get(key, "") for key in keys if key in outputs)


def _identity(outputs: dict[str, str], asset_id: str) -> list[dict]:
    rows: list[dict] = []
    if "sshd" in outputs:
        sshd = outputs.get("sshd", "")
        permit = _value(sshd, "PermitRootLogin") or _value(sshd, "permitrootlogin")
        if permit.lower() == "yes":
            rows.append(_fail(asset_id, "SSH 允许 root 远程登录", "PermitRootLogin yes", "high", ["8.1.4.1-c", "8.1.4.2-d"]))
        elif permit.lower() in {"no", "forced-commands-only"}:
            rows.append(_pass(asset_id, "SSH 已关闭 root 远程登录", permit, ["8.1.4.1-c", "8.1.4.2-d"]))
        else:
            rows.append(_pass(asset_id, "SSH 未允许 root 密码登录", permit or "未显式开启", ["8.1.4.1-c"]))
        protocol = _value(sshd, "Protocol")
        if protocol:
            rows.append(_fail(asset_id, "SSH 协议版本过旧", protocol, "high", ["8.1.4.1-c"]) if protocol.strip() == "1" else _pass(asset_id, "SSH 协议版本可用", protocol, ["8.1.4.1-c"]))
        tries = _value(sshd, "MaxAuthTries") or _value(sshd, "maxauthtries")
        if tries.isdigit():
            rows.append(_fail(asset_id, "SSH 认证尝试次数偏高", tries, "medium", ["8.1.4.1-b"]) if int(tries) > 5 else _pass(asset_id, "SSH 认证尝试次数已限制", tries, ["8.1.4.1-b"]))
        empty = (_value(sshd, "PermitEmptyPasswords") or _value(sshd, "permitemptypasswords")).lower()
        if empty:
            rows.append(_fail(asset_id, "SSH 允许空口令", empty, "high", ["8.1.4.1-a"]) if empty == "yes" else _pass(asset_id, "SSH 已关闭空口令", empty, ["8.1.4.1-a"]))
        x11 = (_value(sshd, "X11Forwarding") or _value(sshd, "x11forwarding")).lower()
        if x11:
            rows.append(_fail(asset_id, "SSH 开启了 X11 转发", x11, "low", ["8.1.4.4-b"]) if x11 == "yes" else _pass(asset_id, "SSH 已关闭 X11 转发", x11, ["8.1.4.4-b"]))
        alive = _value(sshd, "ClientAliveInterval") or _value(sshd, "clientaliveinterval")
        count = _value(sshd, "ClientAliveCountMax") or _value(sshd, "clientalivecountmax")
        if alive.isdigit():
            window = int(alive) * (int(count) if count.isdigit() else 3)
            rows.append(_fail(asset_id, "SSH 空闲会话超时过长", f"{window} 秒", "medium", ["8.1.4.1-b"]) if window == 0 or window > 600 else _pass(asset_id, "SSH 空闲会话会断开", f"{window} 秒", ["8.1.4.1-b"]))
        crypto = "\n".join(_value(sshd, name) for name in ("Ciphers", "MACs", "KexAlgorithms", "ciphers", "macs", "kexalgorithms"))
        weak = [token for token in ("arcfour", "3des", "diffie-hellman-group1", "hmac-md5") if token in crypto.lower()]
        if crypto.strip():
            rows.append(_fail(asset_id, "SSH 仍包含弱算法", ",".join(weak), "high", ["8.1.2.2-a", "8.1.2.2-b", "8.1.4.1-c"]) if weak else _pass(asset_id, "SSH 算法列表未发现弱算法", "已检查", ["8.1.2.2-a", "8.1.2.2-b", "8.1.4.1-c"]))
    if "pwquality" in outputs:
        minlen = _value(outputs["pwquality"], "minlen")
        if minlen.isdigit():
            rows.append(_fail(asset_id, "口令最小长度不足 8 位", f"minlen {minlen}", "medium", ["8.1.4.1-a"]) if int(minlen) < 8 else _pass(asset_id, "口令最小长度已配置", f"minlen {minlen}", ["8.1.4.1-a"]))
        minclass = _value(outputs["pwquality"], "minclass")
        credits = [_value(outputs["pwquality"], name) for name in ("dcredit", "ucredit", "lcredit", "ocredit")]
        credit_ok = sum(1 for item in credits if item.lstrip("-").isdigit() and int(item) != 0) >= 3
        if minclass.isdigit() or any(credits):
            ok = (minclass.isdigit() and int(minclass) >= 3) or credit_ok
            rows.append(_pass(asset_id, "口令复杂度已配置", f"minclass {minclass or '-'}", ["8.1.4.1-a"]) if ok else _fail(asset_id, "口令复杂度不足", f"minclass {minclass or '-'}", "medium", ["8.1.4.1-a"]))
    if "login_defs" in outputs:
        text = outputs["login_defs"]
        max_days = _value(text, "PASS_MAX_DAYS")
        min_days = _value(text, "PASS_MIN_DAYS")
        warn = _value(text, "PASS_WARN_AGE")
        if max_days.isdigit():
            rows.append(_fail(asset_id, "口令最长使用天数过长", max_days, "medium", ["8.1.4.1-a"]) if int(max_days) > 90 else _pass(asset_id, "口令最长使用天数已限制", max_days, ["8.1.4.1-a"]))
        if min_days.isdigit():
            rows.append(_pass(asset_id, "口令最短使用天数已配置", min_days, ["8.1.4.1-a"]) if int(min_days) >= 1 else _fail(asset_id, "口令可以立刻再次修改", min_days, "low", ["8.1.4.1-a"]))
        if warn.isdigit():
            rows.append(_pass(asset_id, "口令到期前提醒已配置", warn, ["8.1.4.1-a"]) if int(warn) >= 7 else _fail(asset_id, "口令到期提醒天数偏短", warn, "low", ["8.1.4.1-a"]))
    if "pam" in outputs:
        pam = outputs["pam"].lower()
        deny = _pam_number(pam, "deny")
        unlock = _pam_number(pam, "unlock_time")
        if "pam_faillock" in pam or "pam_tally2" in pam or deny is not None:
            rows.append(_fail(asset_id, "登录失败锁定阈值偏高", str(deny), "medium", ["8.1.4.1-b"]) if deny is None or deny > 5 else _pass(asset_id, "登录失败锁定阈值已配置", str(deny), ["8.1.4.1-b"]))
            rows.append(_fail(asset_id, "登录失败锁定时间偏短", str(unlock), "medium", ["8.1.4.1-b"]) if unlock is None or unlock < 600 else _pass(asset_id, "登录失败锁定时间已配置", str(unlock), ["8.1.4.1-b"]))
        else:
            rows.append(_fail(asset_id, "未发现登录失败锁定策略", "pam_faillock/pam_tally2", "high", ["8.1.4.1-b"]))
    if "shadow" in outputs:
        names = [line.strip() for line in outputs["shadow"].splitlines() if line.strip() and "permission denied" not in line.lower()]
        if "permission denied" in outputs["shadow"].lower():
            rows.append(_fail(asset_id, "未能读取口令库", "权限不足", "medium", ["8.1.4.1-a"]))
        elif names:
            rows.append(_fail(asset_id, "存在空口令账户", ",".join(names[:8]), "high", ["8.1.4.1-a"]))
        else:
            rows.append(_pass(asset_id, "未发现空口令账户", "shadow", ["8.1.4.1-a"]))
    if "tmout" in outputs:
        values = [line.split("=", 1)[1].strip() for line in outputs["tmout"].splitlines() if "TMOUT=" in line]
        if not values:
            rows.append(_fail(asset_id, "未配置登录空闲超时", "TMOUT", "medium", ["8.1.4.1-b"]))
        else:
            number = values[-1]
            rows.append(_fail(asset_id, "登录空闲超时过长", number, "medium", ["8.1.4.1-b"]) if not number.isdigit() or int(number) > 600 or int(number) == 0 else _pass(asset_id, "登录空闲超时已配置", number, ["8.1.4.1-b"]))
    return rows


def _access(outputs: dict[str, str], asset_id: str) -> list[dict]:
    rows: list[dict] = []
    if "selinux" in outputs:
        selinux = (outputs.get("selinux") or "").strip().splitlines()[-1] if outputs.get("selinux") else ""
        if selinux.lower() == "enforcing":
            rows.append(_pass(asset_id, "SELinux 处于 Enforcing", selinux, ["8.1.4.2-g"]))
        else:
            rows.append(_fail(asset_id, "SELinux 未处于 Enforcing", selinux or "未知", "medium", ["8.1.4.2-g"]))
    if "uid0" in outputs:
        uid0 = [line.strip() for line in (outputs.get("uid0") or "").splitlines() if line.strip()]
        extra = [name for name in uid0 if name != "root"]
        rows.append(_fail(asset_id, "存在非 root 的 UID 0 账户", ",".join(extra), "high", ["8.1.4.2-c", "8.1.4.2-d"]) if extra else _pass(asset_id, "不存在额外 UID 0 账户", "仅 root", ["8.1.4.2-c"]))
    if "shells" in outputs:
        shells = [line.strip() for line in outputs["shells"].splitlines() if line.strip()]
        rows.append(_fail(asset_id, "系统账户仍可登录", ",".join(shells[:6]), "medium", ["8.1.4.2-b", "8.1.4.2-c"]) if shells else _pass(asset_id, "系统账户没有可登录 Shell", "已检查", ["8.1.4.2-b", "8.1.4.2-c"]))
    if "sudoers" in outputs:
        loose = [line.strip() for line in outputs["sudoers"].splitlines() if "NOPASSWD" in line.upper() and "ALL" in line.upper()]
        rows.append(_fail(asset_id, "sudo 存在免密全部权限", loose[0][:180], "high", ["8.1.4.2-d"]) if loose else _pass(asset_id, "未发现免密的全部 sudo 权限", "已检查", ["8.1.4.2-d"]))
    if "perms" in outputs:
        expected = {
            "/etc/passwd": {"644"},
            "/etc/shadow": {"000", "400", "600"},
            "/etc/group": {"644"},
            "/etc/gshadow": {"000", "400", "600"},
            "/etc/ssh/sshd_config": {"600", "640"},
            "/etc/crontab": {"600", "644"},
        }
        for line in outputs["perms"].splitlines():
            parts = line.split()
            if len(parts) != 2 or parts[1] not in expected:
                continue
            rows.append(_pass(asset_id, f"{parts[1]} 权限符合预期", parts[0], ["8.1.4.2-f"]) if parts[0] in expected[parts[1]] else _fail(asset_id, f"{parts[1]} 权限过宽", parts[0], "medium", ["8.1.4.2-f"]))
    if "umask" in outputs:
        text = outputs["umask"]
        rows.append(_pass(asset_id, "默认 umask 已收紧", text.splitlines()[0][:80], ["8.1.4.2-f"]) if any(token in text for token in ("027", "077", "022")) else _fail(asset_id, "未发现默认 umask", "profile", "low", ["8.1.4.2-f"]))
    if "sticky" in outputs:
        bad = [line for line in outputs["sticky"].splitlines() if line.endswith("/tmp") or line.endswith("/var/tmp")]
        loose = [line for line in bad if line.split()[0][-1:] != "1" and not line.split()[0].startswith("1")]
        rows.append(_fail(asset_id, "临时目录缺少粘滞位", "; ".join(loose), "medium", ["8.1.4.2-f"]) if loose else _pass(asset_id, "临时目录保留粘滞位", "已检查", ["8.1.4.2-f"]))
    return rows


def _audit(outputs: dict[str, str], asset_id: str) -> list[dict]:
    rows: list[dict] = []
    if "auditd" in outputs:
        auditd = (outputs.get("auditd") or "").strip().splitlines()[0] if outputs.get("auditd") else ""
        rows.append(_pass(asset_id, "auditd 正在运行", auditd, ["8.1.4.3-a"]) if auditd == "active" else _fail(asset_id, "安全审计服务未运行", auditd or "inactive", "high", ["8.1.4.3-a"]))
    if "auditctl" in outputs:
        rules = outputs["auditctl"]
        missing = [path for path in ("/etc/passwd", "/etc/shadow", "/etc/sudoers") if path not in rules]
        rows.append(_fail(asset_id, "审计规则未覆盖关键文件", ",".join(missing), "medium", ["8.1.4.3-a", "8.1.4.3-b"]) if missing else _pass(asset_id, "审计规则覆盖关键文件", "passwd/shadow/sudoers", ["8.1.4.3-a", "8.1.4.3-b"]))
    if "auditconf" in outputs:
        action = _value(outputs["auditconf"], "max_log_file_action")
        logs = _value(outputs["auditconf"], "num_logs")
        if action:
            rows.append(_pass(asset_id, "审计日志写满后有处理动作", action, ["8.1.4.3-c"]) if action.lower() in {"rotate", "keep_logs"} else _fail(asset_id, "审计日志写满后可能丢失", action, "medium", ["8.1.4.3-c"]))
        if logs.isdigit():
            rows.append(_pass(asset_id, "审计日志保留份数已配置", logs, ["8.1.4.3-c"]) if int(logs) >= 5 else _fail(asset_id, "审计日志保留份数偏少", logs, "low", ["8.1.4.3-c"]))
    if "logrotate" in outputs:
        rotate = _value(outputs["logrotate"], "rotate")
        if rotate.isdigit():
            rows.append(_pass(asset_id, "系统日志轮转份数已配置", rotate, ["8.1.4.3-c"]) if int(rotate) >= 6 else _fail(asset_id, "系统日志轮转份数不足以辅助核对留存", rotate, "low", ["8.1.4.3-c"]))
    if "rsyslog" in outputs:
        state = (outputs["rsyslog"].splitlines() or [""])[0].strip()
        rows.append(_pass(asset_id, "rsyslog 正在运行", state, ["8.1.4.3-a", "8.1.5.4-d"]) if state == "active" else _fail(asset_id, "系统日志服务未运行", state or "inactive", "medium", ["8.1.4.3-a", "8.1.5.4-d"]))
    if "rsyslog_remote" in outputs:
        remote = [line for line in outputs["rsyslog_remote"].splitlines() if "@" in line and not line.strip().startswith("#")]
        rows.append(_pass(asset_id, "日志已转发到集中服务器", remote[0][:120], ["8.1.5.4-d", "8.1.4.3-c"]) if remote else _fail(asset_id, "日志还没有转发到集中服务器", "rsyslog", "medium", ["8.1.5.4-d", "8.1.4.3-c"]))
    if _has(outputs, "chronyd", "chrony"):
        text = _text(outputs, "chronyd", "chrony")
        running = "active" in text.splitlines()[0] if text else False
        synced = "Leap status" in text or "synchronised" in text.lower() or text.strip() == "active"
        rows.append(_pass(asset_id, "时间同步服务正在运行", text.splitlines()[0][:80], ["8.1.4.3-b", "8.1.5.4-d"]) if running or synced else _fail(asset_id, "时间同步服务未运行", text[:80] or "inactive", "low", ["8.1.4.3-b", "8.1.5.4-d"]))
    return rows


def _boundary(outputs: dict[str, str], asset_id: str) -> list[dict]:
    rows: list[dict] = []
    if "firewalld" in outputs:
        firewall = (outputs.get("firewalld") or "").strip().lower()
        # 主机防火墙归属安全计算环境（8.1.4.4-b/c），不再跨对象层污染区域边界网络设备条款（8.1.3.*）
        rows.append(_pass(asset_id, "firewalld 正在运行", firewall, ["8.1.4.4-c"]) if "running" in firewall else _fail(asset_id, "主机防火墙未运行", firewall or "unknown", "high", ["8.1.4.4-c"]))
    if "firewall_rules" in outputs:
        text = outputs["firewall_rules"]
        exposed = []
        for port in ("22/tcp", "23/tcp", "3306/tcp", "3389/tcp", "5432/tcp", "6379/tcp", "9200/tcp"):
            if port in text and ("0.0.0.0/0" in text or "public" in text):
                exposed.append(port)
        if text.strip():
            rows.append(_fail(asset_id, "防火墙对来源不限的地址开放了管理或数据端口", ",".join(exposed), "high", ["8.1.4.4-b", "8.1.4.4-c"]) if exposed else _pass(asset_id, "防火墙规则中未发现对全网开放的高危端口", "已检查", ["8.1.4.4-b", "8.1.4.4-c"]))
    if "services" in outputs:
        active = [line.split()[0] for line in outputs["services"].splitlines() if line.strip().endswith("active") and "inactive" not in line]
        rows.append(_fail(asset_id, "仍启用了不必要的网络服务", ",".join(active), "medium", ["8.1.4.4-b"]) if active else _pass(asset_id, "未启用不必要的传统网络服务", "已检查", ["8.1.4.4-b"]))
    if "sysctl" in outputs:
        expected = {
            "kernel.randomize_va_space": "2",
            "net.ipv4.tcp_syncookies": "1",
            "net.ipv4.conf.all.accept_redirects": "0",
            "fs.suid_dumpable": "0",
        }
        for key, want in expected.items():
            got = _value(outputs["sysctl"], key)
            if not got:
                continue
            rows.append(_pass(asset_id, f"{key} 符合预期", got, ["8.1.4.4-a"]) if got == want else _fail(asset_id, f"{key} 与加固值不一致", got, "medium", ["8.1.4.4-a"]))
    if "core" in outputs:
        text = outputs["core"].lower()
        if text.strip():
            rows.append(_pass(asset_id, "核心转储已限制", text.splitlines()[0][:80], ["8.1.4.4-a"]) if "0" in text else _fail(asset_id, "未限制核心转储", text[:80], "low", ["8.1.4.4-a"]))
        else:
            rows.append(_fail(asset_id, "未发现核心转储限制", "limits.conf", "low", ["8.1.4.4-a"]))
    if "malware" in outputs:
        text = outputs["malware"].lower()
        found = any(name in text for name in ("active", "clam", "wazuh", "ossec", "yunjing", "hostguard")) and "inactive" not in text.replace("active", "", 1)
        running = [line for line in outputs["malware"].splitlines() if line.strip().endswith("active") and not line.strip().endswith("inactive")]
        process = [line for line in outputs["malware"].splitlines() if line.strip() and " " not in line.strip()]
        rows.append(_pass(asset_id, "发现主机恶意代码或防护进程", ",".join((running + process)[:3]), ["8.1.4.5-a"]) if running or process else _fail(asset_id, "未发现主机恶意代码防护进程", "clamav/wazuh/edr", "medium", ["8.1.4.5-a"]))
    if "updates" in outputs:
        text = outputs["updates"].strip()
        if not text or text == "unavailable" or "Error" in text or "No such command" in text:
            rows.append(_pass(asset_id, "在线补丁源不可用，改由软件包漏洞扫描核对", "offline", ["8.1.4.4-e"]))
        else:
            count = len([line for line in text.splitlines() if "/" in line or "ELSA" in line or "CESA" in line])
            rows.append(_fail(asset_id, "存在尚未安装的安全更新", f"{count} 条", "medium", ["8.1.4.4-e", "8.1.10.5-a"]) if count else _pass(asset_id, "未列出待安装的安全更新", "updateinfo", ["8.1.4.4-e", "8.1.10.5-a"]))
    return rows


def _pam_number(text: str, key: str) -> int | None:
    token = f"{key}="
    if token not in text:
        return None
    raw = text.split(token, 1)[1].split()[0].strip(",;")
    return int(raw) if raw.isdigit() else None


def _fail(asset_id: str, title: str, detail: str, severity: str, hints: list[str]) -> dict:
    return {
        "asset_id": asset_id,
        "source_tool": "ssh_baseline",
        "evidence_type": "BASELINE_FAIL",
        "severity": severity,
        "cve_or_cwe": None,
        "title": title,
        "port": "",
        "detail": {"text": detail, "clause_hints": hints},
        "origin": "live",
        "clause_hints": hints,
    }


def _pass(asset_id: str, title: str, detail: str, hints: list[str]) -> dict:
    return {
        "asset_id": asset_id,
        "source_tool": "ssh_baseline",
        "evidence_type": "BASELINE_PASS",
        "severity": "info",
        "cve_or_cwe": None,
        "title": title,
        "port": "",
        "detail": {"text": detail, "clause_hints": hints},
        "origin": "live",
        "clause_hints": hints,
    }


_CHECKERS = (_identity, _access, _audit, _boundary)
