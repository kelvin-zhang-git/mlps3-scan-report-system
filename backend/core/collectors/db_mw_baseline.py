"""数据库与中间件只读安全基线采集器（MySQL/MariaDB、PostgreSQL、Redis、Nginx、Tomcat/HTTPD）。

设计约束：
- 全程只读采集，不修改目标主机、数据库或中间件的任何配置与数据；
- 同时支持宿主机原生服务与 Docker/Podman 容器内运行的常见数据库及中间件；
- 按对象类型拆分 source_tool 为 `db_baseline`（数据库）与 `mw_baseline`（中间件），
  精准映射 GB/T 22239-2019 第三级条款并驱动测评对象覆盖矩阵。
"""
from __future__ import annotations

import re
from typing import Any

from core.collectors.ssh_baseline import _connect, split_sections

DB_MW_READONLY_SCRIPT = r"""
echo @@ports@@
ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true
echo @@docker_ps@@
docker ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null || podman ps --format '{{.Names}}|{{.Image}}|{{.Ports}}' 2>/dev/null || true
echo @@mysql_detect@@
(which mysqld mariadb mysql 2>/dev/null || true)
systemctl is-active mysqld mariadb mysql 2>/dev/null || true
ps -eo args 2>/dev/null | grep -vE '@@ports@@|bash -c' | grep -E '[m]ysqld|[m]ariadbd' | head -n 5 || true
echo @@mysql_conf@@
cat /etc/my.cnf /etc/my.cnf.d/*.cnf /etc/mysql/my.cnf /etc/mysql/mysql.conf.d/*.cnf /etc/mysql/mariadb.conf.d/*.cnf 2>/dev/null | grep -vE '^[[:space:]]*(#|;|$)' | head -n 200 || true
echo @@mysql_vars@@
(mysql --batch --skip-column-names -e "SELECT 'bind_address',@@bind_address UNION ALL SELECT 'require_secure_transport',@@require_secure_transport UNION ALL SELECT 'have_ssl',@@have_ssl UNION ALL SELECT 'general_log',@@general_log UNION ALL SELECT 'local_infile',@@local_infile;" 2>/dev/null || true)
echo @@mysql_users@@
(mysql --batch --skip-column-names -e "SELECT user,host,IF(authentication_string='' OR authentication_string IS NULL,'EMPTY','SET'),plugin FROM mysql.user;" 2>/dev/null || true)
echo @@mysql_plugins@@
(mysql --batch --skip-column-names -e "SELECT PLUGIN_NAME,PLUGIN_STATUS FROM information_schema.PLUGINS WHERE PLUGIN_NAME LIKE '%audit%' OR PLUGIN_NAME LIKE '%validate_password%' OR PLUGIN_NAME LIKE '%connection_control%';" 2>/dev/null || true)
echo @@pg_detect@@
(which postgres psql 2>/dev/null || true)
systemctl list-units --type=service --state=running --no-pager 2>/dev/null | grep -i postgres || true
ps -eo args 2>/dev/null | grep -vE '@@ports@@|bash -c' | grep -E '[p]ostgres|[p]ostmaster' | head -n 5 || true
echo @@pg_conf@@
PG_DATA=$(ps -eo args 2>/dev/null | grep -vE '@@ports@@|bash -c' | sed -n 's/.*postgres.*-D[[:space:]]\+\([^[:space:]]\+\).*/\1/p' | head -n 1)
PG_CONF=""
if [ -n "$PG_DATA" ] && [ -f "$PG_DATA/postgresql.conf" ]; then PG_CONF="$PG_DATA/postgresql.conf"; fi
if [ -z "$PG_CONF" ]; then PG_CONF=$(find /var/lib/pgsql /etc/postgresql /data -maxdepth 4 -name 'postgresql.conf' 2>/dev/null | head -n 1); fi
if [ -n "$PG_CONF" ]; then echo "FILE=$PG_CONF"; grep -E '^[[:space:]]*(listen_addresses|ssl|password_encryption|logging_collector|log_connections|log_disconnections|log_statement|log_min_duration_statement)' "$PG_CONF" 2>/dev/null | head -n 60; fi
echo @@pg_hba@@
PG_HBA=""
if [ -n "$PG_DATA" ] && [ -f "$PG_DATA/pg_hba.conf" ]; then PG_HBA="$PG_DATA/pg_hba.conf"; fi
if [ -z "$PG_HBA" ]; then PG_HBA=$(find /var/lib/pgsql /etc/postgresql /data -maxdepth 4 -name 'pg_hba.conf' 2>/dev/null | head -n 1); fi
if [ -n "$PG_HBA" ]; then echo "FILE=$PG_HBA"; grep -vE '^[[:space:]]*(#|$)' "$PG_HBA" 2>/dev/null | head -n 60; fi
echo @@redis_detect@@
(which redis-server 2>/dev/null || true)
systemctl is-active redis redis-server 2>/dev/null || true
ps -eo args 2>/dev/null | grep -vE '@@ports@@|bash -c' | grep -E '[r]edis-server' | head -n 5 || true
echo @@redis_conf@@
cat /etc/redis.conf /etc/redis/redis.conf 2>/dev/null | grep -E '^[[:space:]]*(bind|protected-mode|requirepass|user |rename-command|tls-port|logfile)' | head -n 80 || true
python3 -c "import socket; s=socket.create_connection(('127.0.0.1',6379),1.5); s.sendall(b'PING\r\n'); print('REDIS_PING=' + s.recv(128).decode('utf-8','ignore').strip()); s.close()" 2>/dev/null || true
echo @@nginx_detect@@
(which nginx 2>/dev/null || true)
systemctl is-active nginx 2>/dev/null || true
if command -v nginx >/dev/null 2>&1; then nginx -v 2>&1 || true; fi
echo @@nginx_conf@@
(nginx -T 2>/dev/null || cat /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf 2>/dev/null || true) | grep -E '^[[:space:]]*(server_tokens|ssl_protocols|ssl_ciphers|access_log|error_log|autoindex|add_header|listen)' | head -n 120 || true
echo @@tomcat_detect@@
ps -eo args 2>/dev/null | grep -vE '@@ports@@|bash -c' | grep -E '[c]atalina|[t]omcat' | head -n 5 || true
systemctl is-active tomcat tomcat9 tomcat10 httpd 2>/dev/null || true
echo @@tomcat_conf@@
TC_XML=$(find /etc/tomcat* /usr/share/tomcat* /opt /usr/local -maxdepth 4 -name 'server.xml' 2>/dev/null | head -n 1)
if [ -n "$TC_XML" ]; then echo "FILE=$TC_XML"; grep -E '(Server port=|shutdown=|Connector |AccessLogValve|AJP|SSLEnabled)' "$TC_XML" 2>/dev/null | head -n 60; fi
echo @@httpd_conf@@
cat /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null | grep -E '^[[:space:]]*(ServerTokens|ServerSignature|Options |CustomLog|ErrorLog|SSLProtocol)' | head -n 60 || true
"""


def collect_db_mw_over_ssh(
    host: str,
    port: int,
    username: str,
    password: str | None,
    key_path: str | None,
    key_text: str | None = None,
) -> dict[str, str]:
    """通过只读 SSH 采集主机上的数据库与中间件配置片段。"""
    client = _connect(host, port, username, password, key_path, key_text)
    try:
        _, stdout, stderr = client.exec_command(DB_MW_READONLY_SCRIPT, timeout=45)
        text = (stdout.read() + stderr.read()).decode("utf-8", errors="replace")
    finally:
        client.close()
    return split_sections(text)


def parse_db_mw_baseline(outputs: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    """解析数据库与中间件只读采集结果，输出标准化等保三级证据。"""
    evidences: list[dict[str, Any]] = []
    evidences.extend(_check_mysql(outputs, asset_id))
    evidences.extend(_check_postgres(outputs, asset_id))
    evidences.extend(_check_redis(outputs, asset_id))
    evidences.extend(_check_nginx(outputs, asset_id))
    evidences.extend(_check_tomcat_httpd(outputs, asset_id))
    return evidences


def _item(
    asset_id: str,
    source_tool: str,
    passed: bool,
    severity: str,
    title: str,
    text: str,
    hints: list[str],
    port: str = "",
) -> dict[str, Any]:
    return {
        "asset_id": asset_id,
        "source_tool": source_tool,
        "evidence_type": "BASELINE_PASS" if passed else "BASELINE_FAIL",
        "severity": "info" if passed else severity,
        "cve_or_cwe": None,
        "title": title,
        "port": port,
        "detail": {"text": text, "clause_hints": hints},
        "origin": "live",
        "clause_hints": hints,
    }


def _has_service(detect_text: str, ports_text: str, docker_text: str, keywords: tuple[str, ...], port_nums: tuple[str, ...]) -> bool:
    """精确识别服务是否真实存在，避免将 'inactive' 或 'command not found' 误判为在运行。"""
    noise_tokens = ("command not found", "not found", "no such file", "inactive", "dead", "unknown", "failed", "could not be found")
    for raw_line in (detect_text or "").splitlines():
        line = raw_line.strip().lower()
        if not line or any(tok in line for tok in noise_tokens):
            continue
        if line == "active":
            return True
        if any(f"/{k}" in line or line.startswith(f"{k} ") or line.startswith(f"{k}/") or f"{k}/" in line or f" {k}" in line for k in keywords):
            return True
    low_docker = (docker_text or "").lower()
    if any(k in low_docker for k in keywords):
        return True
    for p in port_nums:
        if re.search(rf":{p}\b", ports_text or ""):
            return True
    return False


def _check_mysql(out: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    detect = out.get("mysql_detect", "")
    ports = out.get("ports", "")
    docker = out.get("docker_ps", "")
    conf = out.get("mysql_conf", "")
    vars_text = out.get("mysql_vars", "")
    users_text = out.get("mysql_users", "")
    plugins_text = out.get("mysql_plugins", "")

    present = (
        bool(vars_text.strip())
        or bool(users_text.strip())
        or _has_service(detect, ports, docker, ("mysqld", "mariadbd", "mysql", "mariadb"), ("3306",))
    )
    if not present:
        return []

    rows: list[dict[str, Any]] = []
    kv: dict[str, str] = {}
    for line in vars_text.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2:
            kv[parts[0].strip().lower()] = parts[1].strip()
    conf_low = conf.lower()

    # 1. 监听地址与暴露面
    bind_val = kv.get("bind_address") or ""
    if not bind_val:
        m = re.search(r"bind-address\s*=\s*([^\s#]+)", conf_low)
        bind_val = m.group(1) if m else ""
    exposed_3306 = bool(re.search(r"(0\.0\.0\.0|\*|\[::\]):3306\b", ports)) or bind_val in {"0.0.0.0", "*"}
    if exposed_3306:
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "MySQL/MariaDB 监听全网地址（3306 暴露面过大）",
            f"检测到数据库监听地址为 {bind_val or '0.0.0.0/*'}，建议收窄为内网业务网段或 127.0.0.1 并结合防火墙白名单限制源地址。",
            ["8.1.4.4-b", "8.1.4.4-c"], port="3306",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "MySQL/MariaDB 监听地址已收敛",
            f"数据库未对全网任意地址开放 3306 端口（bind_address={bind_val or '受限'}）。",
            ["8.1.4.4-b", "8.1.4.4-c"], port="3306",
        ))

    # 2. 传输加密 SSL/TLS
    req_ssl = kv.get("require_secure_transport", "").upper()
    have_ssl = kv.get("have_ssl", "").upper()
    ssl_ok = req_ssl in {"ON", "1"} or "require_secure_transport" in conf_low and "=on" in conf_low.replace(" ", "")
    if ssl_ok:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "MySQL/MariaDB 已强制启用 TLS/SSL 加密传输",
            "已配置 require_secure_transport=ON，客户端鉴别与业务数据通信均走加密信道。",
            ["8.1.2.2-b", "8.1.4.1-c", "8.1.4.8-a"], port="3306",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "MySQL/MariaDB 未强制开启 SSL/TLS 传输加密",
            f"当前 require_secure_transport={req_ssl or '未配置'}、have_ssl={have_ssl or '未知'}，远程连接存在明文传输风险。",
            ["8.1.2.2-b", "8.1.4.1-c", "8.1.4.8-a"], port="3306",
        ))

    # 3. 审计日志与口令复杂度/登录失败控制插件
    has_audit_plugin = "audit" in plugins_text.lower() or "server_audit" in conf_low or "audit_log" in conf_low
    general_log_on = kv.get("general_log", "").upper() in {"ON", "1"} or "general_log=1" in conf_low.replace(" ", "")
    if has_audit_plugin or general_log_on:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "MySQL/MariaDB 已启用数据库审计或操作日志",
            "已检测到数据库审计插件或操作日志开启，建议同时核对审计记录防篡改与六个月以上留存。",
            ["8.1.4.3-a", "8.1.4.3-b", "8.1.4.3-c"], port="3306",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "MySQL/MariaDB 未启用审计插件或查询审计日志",
            "未检测到 server_audit/audit_log 插件或 general_log 开启，难以满足数据库级用户行为与重要安全事件审计要求。",
            ["8.1.4.3-a", "8.1.4.3-b", "8.1.4.3-c"], port="3306",
        ))

    # 4. 账号与口令安全（若本地 socket 可读 mysql.user）
    if users_text.strip():
        empty_users: list[str] = []
        anon_users: list[str] = []
        remote_root: list[str] = []
        for line in users_text.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            u, h, pwd_state = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if not u:
                anon_users.append(f"''@{h}")
            if pwd_state == "EMPTY" and u not in {"mysql.sys", "mysql.session", "mysql.infoschema", "mariadb.sys"}:
                empty_users.append(f"{u}@{h}")
            if u == "root" and h in {"%", "0.0.0.0"}:
                remote_root.append(f"{u}@{h}")
        if empty_users or anon_users:
            rows.append(_item(
                asset_id, "db_baseline", False, "critical",
                "MySQL/MariaDB 存在空口令或匿名账户",
                f"发现空口令账户 {empty_users or '无'}、匿名账户 {anon_users or '无'}，属于等保三级直接高风险问题。",
                ["8.1.4.1-a", "8.1.4.2-b", "8.1.4.2-c"], port="3306",
            ))
        else:
            rows.append(_item(
                asset_id, "db_baseline", True, "info",
                "MySQL/MariaDB 无空口令或匿名账户",
                "已核对 mysql.user 表，未发现业务空口令或匿名账号。",
                ["8.1.4.1-a", "8.1.4.2-b", "8.1.4.2-c"], port="3306",
            ))
        if remote_root:
            rows.append(_item(
                asset_id, "db_baseline", False, "high",
                "MySQL/MariaDB 允许 root 账户任意主机远程登录",
                f"检测到特权账户 {', '.join(remote_root)} 允许从任意源地址远程登录，建议限定仅本地或堡垒机网段管理。",
                ["8.1.4.2-d", "8.1.4.4-c"], port="3306",
            ))

    has_pw_plugin = "validate_password" in plugins_text.lower() or "simple_password_check" in plugins_text.lower() or "validate_password" in conf_low
    if not has_pw_plugin:
        rows.append(_item(
            asset_id, "db_baseline", False, "medium",
            "MySQL/MariaDB 未启用口令复杂度校验插件",
            "未检测到 validate_password/simple_password_check 插件启用，建议启用口令长度与字符种类复杂度校验策略。",
            ["8.1.4.1-a"], port="3306",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "MySQL/MariaDB 已启用口令复杂度校验插件",
            "已检测到口令策略校验插件处于启用状态。",
            ["8.1.4.1-a"], port="3306",
        ))

    if kv.get("local_infile", "").upper() in {"ON", "1"} or "local-infile=1" in conf_low.replace(" ", ""):
        rows.append(_item(
            asset_id, "db_baseline", False, "medium",
            "MySQL/MariaDB 开启了 local_infile（存在本地文件读取隐患）",
            "建议在配置中显式设置 local_infile=0，遵循最小权限与攻击面收敛原则。",
            ["8.1.4.2-f", "8.1.4.4-a"], port="3306",
        ))
    return rows


def _check_postgres(out: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    detect = out.get("pg_detect", "")
    ports = out.get("ports", "")
    docker = out.get("docker_ps", "")
    conf = out.get("pg_conf", "")
    hba = out.get("pg_hba", "")

    present = (
        "FILE=" in conf
        or "FILE=" in hba
        or _has_service(detect, ports, docker, ("postgres", "postgresql", "postmaster"), ("5432",))
    )
    if not present:
        return []

    rows: list[dict[str, Any]] = []
    conf_low = conf.lower()
    hba_lines = [ln.strip() for ln in hba.splitlines() if ln.strip() and not ln.startswith("FILE=")]

    # 1. pg_hba 认证方式（区分远程网络 trust 与仅本机/回环 trust，避免定级夸大）
    remote_trust: list[str] = []
    local_trust: list[str] = []
    md5_lines: list[str] = []
    for ln in hba_lines:
        parts = ln.split()
        if len(parts) < 4:
            continue
        rule_type = parts[0].lower()
        method = parts[-1].lower()
        if method == "trust":
            if rule_type == "local":
                local_trust.append(ln)
            else:
                addr = parts[3].lower() if len(parts) >= 5 else ""
                if addr in {"127.0.0.1/32", "::1/128", "localhost", "127.0.0.1"}:
                    local_trust.append(ln)
                else:
                    remote_trust.append(ln)
        elif method == "md5":
            md5_lines.append(ln)

    if remote_trust:
        sample = "；".join(remote_trust[:3])[:180]
        rows.append(_item(
            asset_id, "db_baseline", False, "critical",
            "PostgreSQL pg_hba.conf 存在远程网络 trust 免密认证规则",
            f"检测到 {len(remote_trust)} 条面向非回环地址的 trust 免密规则（样例：{sample}），允许网络来源无口令登录数据库，属于直接高风险，需立即改为 scram-sha-256 并收紧源网段。",
            ["8.1.4.1-a", "8.1.4.2-b"], port="5432",
        ))
    elif local_trust:
        sample = "；".join(local_trust[:3])[:180]
        rows.append(_item(
            asset_id, "db_baseline", False, "medium",
            "PostgreSQL pg_hba.conf 存在本机/回环 trust 免密认证规则",
            f"检测到 {len(local_trust)} 条仅限 local 或 127.0.0.1/::1 回环的 trust 免密规则（样例：{sample}），未直接面向远程网络暴露，但本地低权限账户可免密连接数据库，建议改为 peer 或 scram-sha-256。",
            ["8.1.4.1-a", "8.1.4.2-b"], port="5432",
        ))
    elif md5_lines:
        rows.append(_item(
            asset_id, "db_baseline", False, "medium",
            "PostgreSQL pg_hba.conf 仍使用 md5 弱口令鉴别方式",
            f"检测到 {len(md5_lines)} 条 md5 认证规则，建议统一升级为 scram-sha-256 强鉴别算法。",
            ["8.1.4.1-a", "8.1.4.8-b"], port="5432",
        ))
    elif hba_lines:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "PostgreSQL pg_hba.conf 未发现 trust 免密规则",
            "已核对 pg_hba.conf 访问控制规则，未发现免密 trust 配置。",
            ["8.1.4.1-a", "8.1.4.2-a"], port="5432",
        ))

    # 2. SSL 加密传输
    if re.search(r"^\s*ssl\s*=\s*on\b", conf_low, re.M):
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "PostgreSQL 已开启 SSL 加密传输",
            "postgresql.conf 已配置 ssl = on，支持客户端加密通信。",
            ["8.1.2.2-b", "8.1.4.8-a"], port="5432",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "PostgreSQL 未启用 SSL 传输加密",
            "postgresql.conf 未检测到 ssl = on，建议配置服务端证书并在 pg_hba.conf 中使用 hostssl 强制加密。",
            ["8.1.2.2-b", "8.1.4.1-c", "8.1.4.8-a"], port="5432",
        ))

    # 3. 审计日志
    has_log = bool(re.search(r"logging_collector\s*=\s*on", conf_low)) and bool(re.search(r"log_connections\s*=\s*on", conf_low))
    if has_log:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "PostgreSQL 已开启连接与运行日志审计",
            "已配置 logging_collector=on 及 log_connections=on，建议同时确认开启 log_disconnections、DDL 审计与集中日志转发。",
            ["8.1.4.3-a", "8.1.4.3-b"], port="5432",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "PostgreSQL 审计日志配置不完整",
            "未同时开启 logging_collector、log_connections 与语句级审计（log_statement/pgaudit），建议完善后接入集中日志平台。",
            ["8.1.4.3-a", "8.1.4.3-b", "8.1.4.3-c"], port="5432",
        ))

    # 4. 监听地址
    if re.search(r"listen_addresses\s*=\s*['\"]?\*", conf_low) or re.search(r"(0\.0\.0\.0|\*):5432\b", ports):
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "PostgreSQL 监听全网地址（5432 暴露面过大）",
            "检测到 PostgreSQL 监听 '*' 或 0.0.0.0:5432，建议收窄监听地址并结合防火墙限制仅应用服务器访问。",
            ["8.1.4.4-b", "8.1.4.4-c"], port="5432",
        ))
    return rows


def _check_redis(out: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    detect = out.get("redis_detect", "")
    ports = out.get("ports", "")
    docker = out.get("docker_ps", "")
    conf = out.get("redis_conf", "")

    present = (
        bool(conf.strip())
        or _has_service(detect, ports, docker, ("redis-server", "redis", "valkey"), ("6379",))
    )
    if not present:
        return []

    rows: list[dict[str, Any]] = []
    conf_low = conf.lower()

    # 1. 认证口令 / ACL（结合配置文件、启动参数与 6379 本地 PING 响应）
    ping_noauth = "redis_ping=-noauth" in conf_low or "noauth authentication required" in conf_low
    has_auth = bool(re.search(r"^\s*(requirepass|user\s+\S+\s+on)\b", conf_low, re.M)) or "--requirepass" in detect.lower() or ping_noauth
    if has_auth:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "Redis 已配置访问认证口令/ACL",
            "已检测到 requirepass/ACL 或 6379 端口返回 NOAUTH 认证要求（已具备口令认证，重点收敛网络监听暴露面与高危命令）。",
            ["8.1.4.1-a", "8.1.4.2-b"], port="6379",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", False, "critical",
            "Redis 未配置访问口令（存在未授权访问高风险）",
            "未检测到 requirepass 或 ACL 强制认证配置，存在未授权读取或写入公钥/恶意脚本的高危隐患。",
            ["8.1.4.1-a", "8.1.4.2-b", "8.1.4.4-b"], port="6379",
        ))

    # 2. 网络监听暴露面（与 protected-mode 独立拆项，事实精确）
    exposed_6379 = bool(re.search(r"(0\.0\.0\.0|\*|\[::\]):6379\b", ports)) or bool(re.search(r"^\s*bind\s+0\.0\.0\.0", conf_low, re.M))
    if exposed_6379:
        auth_note = "（已启用访问认证，但仍建议将监听/容器端口映射收敛至 127.0.0.1 或内网业务网段并叠加防火墙白名单）" if has_auth else "（且未配置访问口令，存在极高风险）"
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "Redis 监听全网地址（6379 暴露面过大）",
            f"检测到 Redis 监听 0.0.0.0:6379 或 [::]:6379{auth_note}。",
            ["8.1.4.4-b", "8.1.4.4-c"], port="6379",
        ))
    else:
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "Redis 监听地址已收敛",
            "未检测到 Redis 对 0.0.0.0 全网暴露 6379 端口。",
            ["8.1.4.4-b"], port="6379",
        ))

    # 3. protected-mode 独立检查（仅在配置文件显式关闭时判定不通过）
    if re.search(r"^\s*protected-mode\s+no\b", conf_low, re.M):
        rows.append(_item(
            asset_id, "db_baseline", False, "high",
            "Redis 显式关闭了保护模式（protected-mode no）",
            "配置文件中检测到 protected-mode no，建议改为 protected-mode yes 并限定受信任私网绑定地址。",
            ["8.1.4.4-b", "8.1.4.4-c"], port="6379",
        ))
    elif re.search(r"^\s*protected-mode\s+yes\b", conf_low, re.M):
        rows.append(_item(
            asset_id, "db_baseline", True, "info",
            "Redis 已启用保护模式（protected-mode yes）",
            "配置文件已启用 protected-mode yes。",
            ["8.1.4.4-b"], port="6379",
        ))

    # 4. 高危命令禁用
    if "rename-command" not in conf_low:
        rows.append(_item(
            asset_id, "db_baseline", False, "medium",
            "Redis 未禁用 FLUSHALL / CONFIG 等高危运维命令",
            "建议通过 rename-command 禁用或重命名 FLUSHALL、FLUSHDB、CONFIG、EVAL 等高危命令。",
            ["8.1.4.2-d", "8.1.4.4-b"], port="6379",
        ))
    return rows


def _check_nginx(out: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    detect = out.get("nginx_detect", "")
    ports = out.get("ports", "")
    docker = out.get("docker_ps", "")
    conf = out.get("nginx_conf", "")

    present = (
        bool(conf.strip())
        or "nginx/" in detect.lower()
        or _has_service(detect, ports, docker, ("nginx",), ())
    )
    if not present:
        return []
    # 若未读到任何 Nginx 配置文本（例如仅容器内运行且宿主机无配置），不误判为未隐藏版本/未开日志
    if not conf.strip():
        return []

    rows: list[dict[str, Any]] = []
    conf_low = conf.lower()

    if "server_tokens off" in conf_low:
        rows.append(_item(
            asset_id, "mw_baseline", True, "info",
            "Nginx 已隐藏版本号（server_tokens off）",
            "已配置 server_tokens off，降低中间件版本指纹泄露风险。",
            ["8.1.4.4-b"], port="80",
        ))
    else:
        rows.append(_item(
            asset_id, "mw_baseline", False, "medium",
            "Nginx 未隐藏版本信息（缺少 server_tokens off）",
            "建议在 http 块中配置 server_tokens off，避免响应头与错误页暴露 Nginx 版本号。",
            ["8.1.4.4-b"], port="80",
        ))

    if "ssl_protocols" in conf_low:
        weak_tls = bool(re.search(r"ssl_protocols[^;]*(sslv2|sslv3|tlsv1(\.0)?\b|tlsv1\.1\b)", conf_low))
        if weak_tls:
            rows.append(_item(
                asset_id, "mw_baseline", False, "high",
                "Nginx 启用了不安全的旧版 TLS/SSL 协议",
                "检测到 ssl_protocols 包含 TLSv1/TLSv1.1 或 SSLv3，建议仅保留 TLSv1.2 TLSv1.3。",
                ["8.1.2.2-a", "8.1.2.2-b", "8.1.4.8-a"], port="443",
            ))
        else:
            rows.append(_item(
                asset_id, "mw_baseline", True, "info",
                "Nginx TLS 协议版本基线合规",
                "ssl_protocols 未启用 SSLv3/TLSv1.0/TLSv1.1 等弱协议。",
                ["8.1.2.2-a", "8.1.2.2-b", "8.1.4.8-a"], port="443",
            ))

    if "access_log" in conf_low and "access_log off" not in conf_low:
        rows.append(_item(
            asset_id, "mw_baseline", True, "info",
            "Nginx 已开启访问审计日志",
            "已检测到 access_log 配置，建议同步接入集中日志审计平台保存不少于六个月。",
            ["8.1.4.3-a", "8.1.4.3-b"], port="80",
        ))
    else:
        rows.append(_item(
            asset_id, "mw_baseline", False, "medium",
            "Nginx 访问日志未开启或被显式关闭",
            "建议开启 access_log 与 error_log 记录完整请求时间、源地址、状态码与路径信息。",
            ["8.1.4.3-a", "8.1.4.3-b"], port="80",
        ))

    if "autoindex on" in conf_low:
        rows.append(_item(
            asset_id, "mw_baseline", False, "medium",
            "Nginx 开启了目录浏览（autoindex on）",
            "存在敏感文件目录泄露风险，建议将 autoindex 设为 off。",
            ["8.1.4.2-f", "8.1.4.4-b"], port="80",
        ))
    return rows


def _check_tomcat_httpd(out: dict[str, str], asset_id: str) -> list[dict[str, Any]]:
    detect = out.get("tomcat_detect", "")
    docker = out.get("docker_ps", "")
    tc_conf = out.get("tomcat_conf", "")
    httpd_conf = out.get("httpd_conf", "")
    rows: list[dict[str, Any]] = []

    if "FILE=" in tc_conf or "catalina" in detect.lower() or "tomcat" in docker.lower():
        if 'shutdown="SHUTDOWN"' in tc_conf:
            rows.append(_item(
                asset_id, "mw_baseline", False, "high",
                "Tomcat 使用默认 SHUTDOWN 关闭口令",
                "server.xml 中 Server 节点仍使用默认 shutdown=\"SHUTDOWN\"，建议将 port 设为 -1 或使用高强度随机字符串。",
                ["8.1.4.2-b", "8.1.4.4-b"], port="8005",
            ))
        if "AccessLogValve" in tc_conf:
            rows.append(_item(
                asset_id, "mw_baseline", True, "info",
                "Tomcat 已启用 AccessLogValve 访问审计日志",
                "server.xml 已启用 AccessLogValve，建议确认日志集中外发与留存周期。",
                ["8.1.4.3-a", "8.1.4.3-b"], port="8080",
            ))
        else:
            rows.append(_item(
                asset_id, "mw_baseline", False, "medium",
                "Tomcat 未检测到 AccessLogValve 访问审计配置",
                "建议在 server.xml 中启用 AccessLogValve 记录访问时间、来源 IP、URL 与响应码。",
                ["8.1.4.3-a", "8.1.4.3-b"], port="8080",
            ))
        if "AJP/1.3" in tc_conf:
            rows.append(_item(
                asset_id, "mw_baseline", False, "high",
                "Tomcat 启用了 AJP/1.3 连接器（存在 Ghostcat 风险面）",
                "如无必需建议注释关闭 AJP 连接器，或限定仅本机监听并配置 secret。",
                ["8.1.4.4-b", "8.1.4.4-e"], port="8009",
            ))

    if httpd_conf.strip():
        low = httpd_conf.lower()
        if "servertokens prod" in low and "serversignature off" in low:
            rows.append(_item(
                asset_id, "mw_baseline", True, "info",
                "Apache HTTPD 已隐藏版本指纹",
                "已配置 ServerTokens Prod 与 ServerSignature Off。",
                ["8.1.4.4-b"], port="80",
            ))
        else:
            rows.append(_item(
                asset_id, "mw_baseline", False, "medium",
                "Apache HTTPD 未隐藏服务器版本信息",
                "建议配置 ServerTokens Prod 与 ServerSignature Off 减少信息泄露。",
                ["8.1.4.4-b"], port="80",
            ))
    return rows
