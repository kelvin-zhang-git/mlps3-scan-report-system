"""网络与安全设备脱敏配置离线解析器。

支持华为 VRP/USG、华三 H3C Comware、思科 Cisco IOS/ASA、飞塔 FortiGate 以及 Linux iptables/nftables
脱敏配置文本解析，自动核对默认拒绝策略、宽泛 Any 放行、明文远程管理、会话超时、集中日志外发、
NTP 时间同步、入侵防御/防病毒模块及 HA 冗余，填补安全通信网络与安全区域边界的实测空白。
"""
from __future__ import annotations

import re
from typing import Any

SAMPLE_NETDEV_CONFIG = """! 示例：边界防火墙 / 核心交换机脱敏配置片段（Huawei USG / Cisco IOS 风格）
sysname FW-BORDER-01
#
ntp-service unicast-server 10.0.0.10
info-center loghost 10.0.0.20
#
stelnet server enable
ssh server-source -i GigabitEthernet0/0/0
user-interface vty 0 4
 authentication-mode aaa
 idle-timeout 10 0
 protocol inbound ssh
#
security-policy
 default action deny
 rule name permit_web_in
  source-zone untrust
  destination-zone dmz
  destination-address 172.16.10.0 24
  service https
  action permit
 rule name temp_any_allow
  source-zone trust
  destination-zone untrust
  source-address any
  destination-address any
  action permit
#
hrp enable
"""


def parse_netdev_config(
    config_text: str,
    asset_id: str,
    *,
    device_name: str = "边界网络/安全设备",
    device_role: str = "security_device",
) -> list[dict[str, Any]]:
    """解析网络/安全设备脱敏配置文本，输出等保三级标准化核查证据。"""
    text = (config_text or "").strip()
    if not text:
        return []
    low = text.lower()
    vendor = _detect_vendor(low)
    prefix = f"[{device_name} / {vendor}]"
    source_tool = "netdev_config"
    rows: list[dict[str, Any]] = []

    def add(passed: bool, severity: str, title: str, detail: str, hints: list[str]) -> None:
        rows.append({
            "asset_id": asset_id,
            "source_tool": source_tool,
            "evidence_type": "BASELINE_PASS" if passed else "BASELINE_FAIL",
            "severity": "info" if passed else severity,
            "cve_or_cwe": None,
            "title": f"{prefix} {title}",
            "port": "",
            "detail": {
                "text": detail,
                "device_name": device_name,
                "device_role": device_role,
                "vendor": vendor,
                "clause_hints": hints,
            },
            "origin": "imported",
            "clause_hints": hints,
        })

    # 1. 默认拒绝策略（8.1.3.2-a）
    has_default_deny = bool(re.search(
        r"(default\s+action\s+deny|default-action\s+deny|policy\s+default\s+deny|deny\s+ip\s+any\s+any|:input\s+drop|policy\s+drop|set\s+action\s+deny)",
        low,
    ))
    if has_default_deny:
        add(
            True, "info",
            "已配置默认拒绝访问控制策略",
            "配置中明确存在默认拒绝（default action deny / INPUT DROP / deny ip any any）兜底规则。",
            ["8.1.3.2-a", "8.1.3.1-a"],
        )
    else:
        add(
            False, "high",
            "未检测到显式默认拒绝访问控制策略",
            "未发现 default action deny / deny ip any any / INPUT DROP 等默认拒绝配置，建议在边界策略末尾显式配置默认拒绝。",
            ["8.1.3.2-a", "8.1.3.1-a"],
        )

    # 2. 宽泛 Any-to-Any 放行规则（8.1.3.2-a, 8.1.3.2-b, 8.1.3.2-c）
    any_allow_patterns = [
        r"permit\s+(ip|any)\s+any\s+any",
        r"rule\s+.*permit\s+.*source\s+any\s+.*destination\s+any",
        r"source-address\s+any[\s\S]{0,120}destination-address\s+any[\s\S]{0,120}action\s+permit",
        r"set\s+srcaddr\s+[\"']?all[\"']?[\s\S]{0,160}set\s+dstaddr\s+[\"']?all[\"']?[\s\S]{0,160}set\s+action\s+accept",
        r"-j\s+accept\b(?!.*-s\s)(?!.*--dport)",
    ]
    any_hits = sum(len(re.findall(p, low)) for p in any_allow_patterns)
    if any_hits > 0:
        add(
            False, "high",
            f"存在 {any_hits} 条宽泛 Any-to-Any 放行策略",
            "配置中检测到源地址和目的地址均为 any/all 的允许规则，违背最小授权与五元组精细化控制原则，需收敛为具体业务网段与端口。",
            ["8.1.3.2-a", "8.1.3.2-b", "8.1.3.2-c"],
        )
    else:
        add(
            True, "info",
            "未检测到宽泛 Any-to-Any 放行规则",
            "已核对访问控制策略文本，未发现源目地址均为 any/all 的放行规则。",
            ["8.1.3.2-b", "8.1.3.2-c"],
        )

    # 3. 明文管理协议（Telnet / HTTP / 默认 SNMP 团体字）
    telnet_on = bool(re.search(r"(^\s*telnet\s+server\s+enable|protocol\s+inbound\s+(all|telnet)|transport\s+input\s+(all|telnet))", low, re.M))
    http_mgmt_on = bool(re.search(r"(^\s*ip\s+http\s+server\b|^\s*http\s+server\s+enable\b)", low, re.M)) and not bool(re.search(r"undo\s+http\s+server|no\s+ip\s+http\s+server", low))
    weak_snmp = bool(re.search(r"snmp-?(agent|server)\s+community\s+.*(public|private)\b", low))
    if telnet_on or http_mgmt_on:
        proto = "、".join(p for p, flag in (("Telnet", telnet_on), ("HTTP 明文管理", http_mgmt_on)) if flag)
        add(
            False, "high",
            f"启用了明文远程管理协议（{proto}）",
            f"设备配置中仍允许 {proto} 远程管理，鉴别凭据与配置存在明文窃听风险，建议仅保留 SSHv2 / HTTPS。",
            ["8.1.2.2-b", "8.1.4.1-c", "8.1.5.4-b"],
        )
    else:
        has_ssh = bool(re.search(r"(stelnet\s+server\s+enable|protocol\s+inbound\s+ssh|transport\s+input\s+ssh|ip\s+ssh\s+version\s+2|ssh\s+server)", low))
        if has_ssh:
            add(
                True, "info",
                "远程管理已采用 SSH 加密协议",
                "配置已启用 SSH 加密管理且未发现 Telnet/HTTP 明文管理通道。",
                ["8.1.2.2-b", "8.1.4.1-c", "8.1.5.4-b"],
            )
    if weak_snmp:
        add(
            False, "high",
            "SNMP 使用默认弱团体字（public/private）",
            "检测到 SNMP 配置使用默认团体字，建议升级至 SNMPv3 鉴权加密模式或更换高强度团体字并限定源 IP。",
            ["8.1.4.2-b", "8.1.5.4-b"],
        )

    # 4. 管理会话空闲超时（8.1.4.1-b）
    has_timeout = bool(re.search(r"(idle-timeout\s+[1-9]|exec-timeout\s+[1-9]|admintimeout\s+[1-9])", low))
    if has_timeout:
        add(
            True, "info",
            "已配置管理终端空闲超时自动退出",
            "设备 VTY/管理台已设置空闲超时断开参数，符合会话超时控制要求。",
            ["8.1.4.1-b"],
        )
    else:
        add(
            False, "medium",
            "未检测到管理终端空闲超时配置",
            "未发现 idle-timeout / exec-timeout 配置，建议设置 5~15 分钟无操作自动断开。",
            ["8.1.4.1-b"],
        )

    # 5. 集中日志外发与时间同步（8.1.3.5-a, 8.1.3.5-c, 8.1.5.4-d）
    has_syslog = bool(re.search(r"(info-center\s+loghost|logging\s+(host\s+)?\d|config\s+log\s+syslogd|syslog\s+host)", low))
    has_ntp = bool(re.search(r"(ntp-service|ntp\s+server|clock\s+protocol\s+ntp|config\s+system\s+ntp)", low))
    if has_syslog:
        add(
            True, "info",
            "已配置集中日志服务器（Syslog）外发",
            "设备已配置外部 Syslog 日志服务器，建议同时确认集中审计平台留存周期不少于六个月。",
            ["8.1.3.5-a", "8.1.3.5-c", "8.1.5.4-d"],
        )
    else:
        add(
            False, "high",
            "未配置边界/网络设备审计日志集中外发",
            "配置中未发现 info-center loghost / logging host 等 Syslog 外发项，本地日志易被覆盖或篡改。",
            ["8.1.3.5-a", "8.1.3.5-c", "8.1.5.4-d"],
        )
    if not has_ntp:
        add(
            False, "medium",
            "未检测到 NTP 统一时钟同步配置",
            "建议配置内网统一 NTP 时钟源，保障跨设备安全审计时间戳一致可溯源。",
            ["8.1.3.5-b", "8.1.5.4-d"],
        )

    # 6. 入侵防御 / 防病毒模块与高可用冗余（8.1.3.3-a, 8.1.3.4-a, 8.1.2.1-e）
    if re.search(r"(profile\s+ips|ips-sensor|utm-profile|intrusion-prevention)", low):
        add(
            True, "info",
            "已配置边界入侵防御（IPS）安全策略",
            "配置中检测到 IPS/UTM 安全防护策略引用。",
            ["8.1.3.3-a", "8.1.3.3-d"],
        )
    if re.search(r"(hrp\s+enable|vrrp\s+vrid|standby\s+\d|failover\s+lan|config\s+system\s+ha)", low):
        add(
            True, "info",
            "关键网络/边界设备已配置双机热备冗余（HA/VRRP/HRP）",
            "配置中检测到双机热备/主备切换配置，支撑关键网络设备硬件冗余要求。",
            ["8.1.2.1-e"],
        )
    return rows


def _detect_vendor(low: str) -> str:
    if "sysname " in low or "info-center" in low or "hrp enable" in low or "stelnet" in low:
        return "Huawei/H3C"
    if "config firewall policy" in low or "config system ha" in low:
        return "FortiGate"
    if "access-list " in low or "line vty" in low or "crypto isakmp" in low:
        return "Cisco"
    if "-a input" in low or "table inet" in low:
        return "Linux Netfilter"
    return "通用网络/安全设备"
