"""云平台只读安全核查导入器（支持阿里云、腾讯云、华为云、AWS 及通用脱敏 JSON 导出的云基线）。

覆盖云计算安全扩展要求（8.2.x）及通用边界/鉴别条款：
- 基础设施与数据境内合规（region）
- 安全组高危端口全网开放（0.0.0.0/0 -> 22/3389/3306/5432/6379/ALL）
- VPC 租户虚拟网络隔离
- IAM / RAM 主账号 MFA、高权策略与长期闲置 AccessKey
- 云操作审计（ActionTrail / CloudTrail / CTS）开启状态与留存周期
- KMS 密钥管理、镜像/快照加密与云上数据本地备份策略
"""
from __future__ import annotations

from typing import Any

HIGH_RISK_PORTS = {"22", "3389", "3306", "5432", "6379", "27017", "1433", "1521", "ALL", "-1/-1", "1/65535"}

SAMPLE_CLOUD_AUDIT: dict[str, Any] = {
    "provider": "Aliyun",
    "region": "cn-hangzhou",
    "platform_mlps_level": 3,
    "vpc_isolated": True,
    "security_groups": [
        {
            "group_id": "sg-prod-web",
            "direction": "ingress",
            "cidr": "0.0.0.0/0",
            "port_range": "443/443",
            "policy": "accept",
        },
        {
            "group_id": "sg-prod-db",
            "direction": "ingress",
            "cidr": "0.0.0.0/0",
            "port_range": "3306/3306",
            "policy": "accept",
        },
    ],
    "iam": {
        "root_mfa_enabled": True,
        "admin_users_without_mfa": ["ops_backup_01"],
        "wildcard_admin_policies": 1,
        "stale_access_keys": 2,
    },
    "audit_trail": {
        "enabled": True,
        "multi_region": True,
        "retention_days": 180,
        "alert_enabled": True,
    },
    "encryption": {
        "kms_enabled": True,
        "byok_supported": True,
        "image_encrypted": False,
        "snapshot_integrity_check": True,
    },
    "backup": {
        "local_backup_enabled": False,
        "multi_replica": True,
    },
}


def parse_cloud_audit(payload: dict[str, Any], asset_id: str) -> list[dict[str, Any]]:
    """解析云平台只读核查 JSON，输出标准化等保三级（含云计算扩展 8.2.x）证据。"""
    if not isinstance(payload, dict) or not payload:
        return []
    provider = str(payload.get("provider") or "云平台")
    region = str(payload.get("region") or "").strip()
    prefix = f"[{provider}{(' / ' + region) if region else ''}]"
    rows: list[dict[str, Any]] = []

    def add(passed: bool, severity: str, title: str, text: str, hints: list[str], port: str = "") -> None:
        rows.append({
            "asset_id": asset_id,
            "source_tool": "cloud_audit",
            "evidence_type": "BASELINE_PASS" if passed else "BASELINE_FAIL",
            "severity": "info" if passed else severity,
            "cve_or_cwe": None,
            "title": f"{prefix} {title}",
            "port": port,
            "detail": {"text": text, "provider": provider, "region": region, "clause_hints": hints},
            "origin": "imported",
            "clause_hints": hints,
        })

    # 1. 境内合规与云平台定级匹配（8.2.1.1-a, 8.2.4.5-a, 8.2.7.1-a, 8.2.2.1-a）
    if region:
        is_cn = region.lower().startswith(("cn-", "china")) or any(k in region for k in ("华东", "华北", "华南", "西南", "北京", "上海", "杭州", "深圳", "广州"))
        if is_cn:
            add(
                True, "info",
                f"云基础设施与数据存储地域位于中国境内（{region}）",
                "已核对云控制台地域配置，基础设施及核心业务数据落盘均位于中国境内。",
                ["8.2.1.1-a", "8.2.4.5-a", "8.2.7.1-a"],
            )
        else:
            add(
                False, "critical",
                f"云基础设施或数据存储地域位于境外（{region}）",
                "检测到云资源地域不属于中国境内区域，存在违反云计算基础设施与数据境内合规红线的风险。",
                ["8.2.1.1-a", "8.2.4.5-a", "8.2.7.1-a"],
            )

    if "platform_mlps_level" in payload:
        lvl = int(payload.get("platform_mlps_level") or 0)
        if lvl >= 3:
            add(
                True, "info",
                f"底层云计算平台已具备等保 {lvl} 级保护能力",
                f"云平台等保定级为第 {lvl} 级，满足不承载高于其安全保护等级业务系统的要求。",
                ["8.2.2.1-a", "8.2.6.1-a"],
            )
        else:
            add(
                False, "critical",
                f"底层云平台安全保护等级不足（当前记录：{lvl} 级）",
                "承载等保三级业务系统的云计算平台自身须通过等保三级或以上备案测评。",
                ["8.2.2.1-a", "8.2.6.1-a"],
            )

    if "vpc_isolated" in payload:
        if payload.get("vpc_isolated"):
            add(
                True, "info",
                "已启用 VPC 专有网络实现云租户虚拟网络隔离",
                "云资源部署在独立 VPC 专有网络内，并与公网及其他租户逻辑隔离。",
                ["8.2.2.1-b", "8.2.2.1-d"],
            )
        else:
            add(
                False, "high",
                "未确认 VPC 专有网络隔离",
                "建议将全部业务云主机与数据库迁移至独立 VPC 并划分安全子网。",
                ["8.2.2.1-b", "8.2.2.1-d"],
            )

    # 2. 云安全组入站高危放行（8.2.3.1-a, 8.2.3.1-b, 8.2.4.2-b, 8.1.3.2-a）
    sgs = payload.get("security_groups")
    if isinstance(sgs, list):
        risky_rules: list[str] = []
        for rule in sgs:
            if not isinstance(rule, dict):
                continue
            direction = str(rule.get("direction") or "ingress").lower()
            policy = str(rule.get("policy") or "accept").lower()
            cidr = str(rule.get("cidr") or "").strip()
            port_range = str(rule.get("port_range") or rule.get("port") or "").strip()
            gid = str(rule.get("group_id") or "sg")
            if direction == "ingress" and policy in {"accept", "allow", "permit"} and cidr in {"0.0.0.0/0", "::/0", "any"}:
                normalized_port = port_range.split("/")[0] if "/" in port_range and port_range.split("/")[0] == port_range.split("/")[1] else port_range
                if normalized_port.upper() in HIGH_RISK_PORTS or port_range in {"-1/-1", "1/65535", "0/65535", "ALL", "*"}:
                    risky_rules.append(f"{gid}({cidr} -> {port_range})")
        if risky_rules:
            add(
                False, "high",
                f"云安全组存在 {len(risky_rules)} 条高危端口全网放行规则",
                f"检测到对 0.0.0.0/0 放行管理或数据库高危端口：{', '.join(risky_rules[:8])}，需立即收敛为最小源地址白名单。",
                ["8.2.3.1-a", "8.2.3.1-b", "8.2.4.2-b", "8.1.3.2-a", "8.1.3.2-c"],
            )
        else:
            add(
                True, "info",
                f"云安全组入站策略核查通过（已检 {len(sgs)} 条规则）",
                "未发现安全组对全网（0.0.0.0/0）直接开放 SSH/RDP/数据库等高危端口。",
                ["8.2.3.1-a", "8.2.3.1-b", "8.2.4.2-b"],
            )

    # 3. IAM / RAM 身份与权限（8.2.4.1-a, 8.2.4.5-b, 8.1.4.1-d, 8.1.4.2-d）
    iam = payload.get("iam")
    if isinstance(iam, dict):
        root_mfa = bool(iam.get("root_mfa_enabled"))
        no_mfa_admins = iam.get("admin_users_without_mfa") or []
        if root_mfa and not no_mfa_admins:
            add(
                True, "info",
                "云控制台主账号及特权子账号均已启用 MFA 双因子认证",
                "云平台远程管理具备口令加动态令牌/硬件 MFA 组合认证。",
                ["8.2.4.1-a", "8.1.4.1-d"],
            )
        else:
            add(
                False, "high",
                "云平台管理账号缺少 MFA 双因子鉴别",
                f"主账号 MFA={'已开启' if root_mfa else '未开启'}，未启用 MFA 的特权子账号：{no_mfa_admins or '无'}。",
                ["8.2.4.1-a", "8.1.4.1-d"],
            )
        wildcard = int(iam.get("wildcard_admin_policies") or 0)
        stale_ak = int(iam.get("stale_access_keys") or 0)
        if wildcard > 0 or stale_ak > 0:
            add(
                False, "high",
                f"云 IAM 存在过度授权或长期未轮换 AccessKey（高权策略 {wildcard}、过期 AK {stale_ak}）",
                "建议按最小权限拆分 RAM/IAM 角色，清理闲置 AccessKey 并落实 90 天密钥轮换。",
                ["8.1.4.2-c", "8.1.4.2-d", "8.2.4.5-b"],
            )
        else:
            add(
                True, "info",
                "云 IAM 最小权限与 AccessKey 治理状态良好",
                "未发现通配符高权策略泛滥或长期闲置未轮换的访问密钥。",
                ["8.1.4.2-d", "8.2.4.5-b"],
            )

    # 4. 云操作审计（ActionTrail / CloudTrail / CTS）
    trail = payload.get("audit_trail")
    if isinstance(trail, dict):
        enabled = bool(trail.get("enabled"))
        retention = int(trail.get("retention_days") or 0)
        if enabled and retention >= 180:
            add(
                True, "info",
                f"云操作审计已开启且日志留存 {retention} 天（满足六个月要求）",
                "可完整审计虚拟机创建/重启/删除及安全组变更等特权操作。",
                ["8.2.3.3-a", "8.2.5.1-c", "8.1.5.4-d"],
            )
        else:
            add(
                False, "high",
                f"云操作审计未开启或留存不足 180 天（开启={enabled}，留存={retention} 天）",
                "需开启全地域操作审计并将日志持久化转存至对象存储/日志服务留存不少于六个月。",
                ["8.2.3.3-a", "8.2.5.1-c", "8.1.5.4-d"],
            )
        if not trail.get("alert_enabled"):
            add(
                False, "medium",
                "云平台未启用非授权建机与高危变更实时告警",
                "建议针对非授权新建/重启虚拟机、安全组放行与 IAM 变更配置实时告警通知。",
                ["8.2.3.2-d", "8.2.4.3-b"],
            )

    # 5. KMS 密钥管理与镜像/快照保护（8.2.4.4-a/b/c, 8.2.4.5-d）
    enc = payload.get("encryption")
    if isinstance(enc, dict):
        if enc.get("kms_enabled") and enc.get("byok_supported", True):
            add(
                True, "info",
                "已启用云 KMS 密钥管理服务并支持租户自主密钥控制",
                "满足云服务客户自主管理加解密密钥的要求。",
                ["8.2.4.5-d", "8.1.4.8-b"],
            )
        else:
            add(
                False, "high",
                "未启用云 KMS 密钥管理或租户自主加密方案",
                "建议启用云 KMS/BYOK 或云密码机保障核心数据与云盘密钥由租户自主控制。",
                ["8.2.4.5-d", "8.1.4.8-b"],
            )
        if enc.get("image_encrypted") is False:
            add(
                False, "high",
                "虚拟机私有镜像或快照未开启加密保护",
                "建议对自定义镜像与系统/数据盘快照开启 KMS 加密并配置完整性哈希校验。",
                ["8.2.4.4-b", "8.2.4.4-c"],
            )
        elif enc.get("image_encrypted") is True:
            add(
                True, "info",
                "虚拟机镜像与快照已开启加密及完整性保护",
                "已启用镜像/快照加密存储与完整性校验机制。",
                ["8.2.4.4-b", "8.2.4.4-c"],
            )

    # 6. 云数据本地备份与多副本（8.2.4.6-a, 8.2.4.6-c）
    bak = payload.get("backup")
    if isinstance(bak, dict):
        if bak.get("local_backup_enabled"):
            add(
                True, "info",
                "云上重要业务数据已落实本地备份留存",
                "已定期将云上核心数据拉取至本地机房或独立灾备域留存，符合云扩展备份要求。",
                ["8.2.4.6-a", "8.1.4.9-a"],
            )
        else:
            add(
                False, "high",
                "云上核心业务数据缺少本地备份副本",
                "GB/T 22239-2019 第 8.2.4.6-a 要求云服务客户应在本地保存业务数据备份，建议配置定期回拉备份与恢复验证。",
                ["8.2.4.6-a", "8.1.4.9-a"],
            )
    return rows
