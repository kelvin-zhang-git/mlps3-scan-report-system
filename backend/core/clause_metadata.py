"""GB/T 22239-2019 第三级测评对象标签、T/ISEAA 001-2020 高风险判例与加权计分权重定义。"""
from __future__ import annotations

from typing import Any

# 技术测评对象（7 类，对标正式等级测评报告的测评对象维度）
TECH_OBJECTS: tuple[tuple[str, str], ...] = (
    ("host_os", "主机操作系统"),
    ("network_device", "网络设备"),
    ("security_device", "安全设备"),
    ("database", "数据库"),
    ("middleware", "中间件"),
    ("application", "业务应用"),
    ("cloud_platform", "云平台"),
)

# 全部对象字典（含物理机房与安全管理体系，便于条款筛选与展示）
ALL_OBJECTS: tuple[tuple[str, str], ...] = TECH_OBJECTS + (
    ("physical_room", "物理机房"),
    ("org_management", "安全管理体系"),
)

OBJECT_LABELS: dict[str, str] = dict(ALL_OBJECTS)
TECH_OBJECT_KEYS: set[str] = {k for k, _ in TECH_OBJECTS}

# 风险权重（贴近《测评报告模板（2021 版）》按高/中/低重要程度差异化扣分思路）
RISK_WEIGHTS: dict[str, float] = {
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}

# 细粒度条款 -> 适用测评对象映射覆盖（未显式列出的条款按控制点/安全域推导）
_CLAUSE_OBJECT_OVERRIDES: dict[str, list[str]] = {
    # 8.1.2 安全通信网络
    "8.1.2.1-a": ["network_device", "security_device"],
    "8.1.2.1-b": ["network_device"],
    "8.1.2.1-c": ["network_device", "security_device"],
    "8.1.2.1-d": ["network_device", "security_device"],
    "8.1.2.1-e": ["network_device", "security_device", "host_os"],
    "8.1.2.2-a": ["network_device", "host_os", "middleware", "application"],
    "8.1.2.2-b": ["network_device", "host_os", "middleware", "application"],
    "8.1.2.3-a": ["network_device"],
    # 8.1.3 安全区域边界
    "8.1.3.1-a": ["network_device", "security_device"],
    "8.1.3.1-b": ["network_device", "security_device"],
    "8.1.3.1-c": ["security_device", "network_device", "host_os"],
    "8.1.3.1-d": ["network_device", "security_device"],
    "8.1.3.2-a": ["security_device", "network_device", "host_os"],
    "8.1.3.2-b": ["security_device", "network_device", "host_os"],
    "8.1.3.2-c": ["security_device", "network_device", "host_os"],
    "8.1.3.2-d": ["security_device"],
    "8.1.3.2-e": ["security_device", "application"],
    "8.1.3.3-a": ["security_device", "application"],
    "8.1.3.3-b": ["security_device", "network_device"],
    "8.1.3.3-c": ["security_device"],
    "8.1.3.3-d": ["security_device"],
    "8.1.3.4-a": ["security_device"],
    "8.1.3.4-b": ["security_device"],
    "8.1.3.5-a": ["security_device", "network_device"],
    "8.1.3.5-b": ["security_device", "network_device"],
    "8.1.3.5-c": ["security_device", "network_device"],
    "8.1.3.5-d": ["security_device", "network_device"],
    "8.1.3.6-a": ["security_device"],
    # 8.1.4 安全计算环境
    "8.1.4.1-a": ["host_os", "database", "middleware", "application"],
    "8.1.4.1-b": ["host_os", "database", "middleware", "application"],
    "8.1.4.1-c": ["host_os", "database", "middleware", "application"],
    "8.1.4.1-d": ["host_os", "database", "application", "security_device"],
    "8.1.4.2-a": ["host_os", "database", "middleware", "application"],
    "8.1.4.2-b": ["host_os", "database", "middleware", "application"],
    "8.1.4.2-c": ["host_os", "database", "middleware", "application"],
    "8.1.4.2-d": ["host_os", "database", "middleware", "application"],
    "8.1.4.2-e": ["host_os", "database", "application"],
    "8.1.4.2-f": ["host_os", "database", "application"],
    "8.1.4.2-g": ["host_os", "database", "application"],
    "8.1.4.3-a": ["host_os", "database", "middleware", "application"],
    "8.1.4.3-b": ["host_os", "database", "middleware", "application"],
    "8.1.4.3-c": ["host_os", "database", "middleware", "application"],
    "8.1.4.3-d": ["host_os", "database", "application"],
    "8.1.4.4-a": ["host_os", "middleware"],
    "8.1.4.4-b": ["host_os", "database", "middleware"],
    "8.1.4.4-c": ["host_os", "database", "middleware", "security_device"],
    "8.1.4.4-d": ["application"],
    "8.1.4.4-e": ["host_os", "database", "middleware", "application"],
    "8.1.4.4-f": ["host_os", "security_device"],
    "8.1.4.5-a": ["host_os"],
    "8.1.4.6-a": ["host_os"],
    "8.1.4.7-a": ["application", "middleware", "database", "host_os"],
    "8.1.4.7-b": ["database", "application", "host_os"],
    "8.1.4.8-a": ["application", "middleware", "database", "host_os"],
    "8.1.4.8-b": ["database", "application", "host_os"],
    "8.1.4.9-a": ["database", "host_os", "application"],
    "8.1.4.9-b": ["database", "application"],
    "8.1.4.9-c": ["database", "host_os", "application"],
    "8.1.4.10-a": ["host_os", "database", "application"],
    "8.1.4.10-b": ["host_os", "database", "application"],
    "8.1.4.11-a": ["application", "database"],
    "8.1.4.11-b": ["application", "database"],
    # 8.1.5 安全管理中心
    "8.1.5.1-a": ["security_device", "host_os", "database", "application"],
    "8.1.5.1-b": ["security_device", "host_os", "database"],
    "8.1.5.2-a": ["security_device", "host_os", "database", "application"],
    "8.1.5.2-b": ["security_device"],
    "8.1.5.3-a": ["security_device", "host_os", "database", "application"],
    "8.1.5.3-b": ["security_device"],
    "8.1.5.4-a": ["network_device", "security_device"],
    "8.1.5.4-b": ["network_device", "security_device", "host_os"],
    "8.1.5.4-c": ["network_device", "security_device", "host_os"],
    "8.1.5.4-d": ["security_device", "network_device", "host_os", "database"],
    "8.1.5.4-e": ["security_device", "host_os"],
    "8.1.5.4-f": ["security_device"],
    # 8.2 云计算安全扩展
    "8.2.2.1-b": ["cloud_platform", "network_device"],
    "8.2.2.1-d": ["cloud_platform", "security_device"],
    "8.2.3.1-a": ["cloud_platform", "security_device"],
    "8.2.3.1-b": ["cloud_platform", "security_device"],
    "8.2.3.2-a": ["cloud_platform", "security_device"],
    "8.2.3.2-b": ["cloud_platform", "security_device"],
    "8.2.3.2-c": ["cloud_platform", "security_device"],
    "8.2.3.2-d": ["cloud_platform", "security_device"],
    "8.2.3.3-a": ["cloud_platform", "security_device"],
    "8.2.3.3-b": ["cloud_platform"],
    "8.2.4.1-a": ["cloud_platform", "security_device"],
    "8.2.4.2-a": ["cloud_platform", "host_os"],
    "8.2.4.2-b": ["cloud_platform", "host_os"],
    "8.2.4.3-a": ["cloud_platform", "host_os"],
    "8.2.4.3-b": ["cloud_platform"],
    "8.2.4.3-c": ["cloud_platform", "host_os"],
    "8.2.4.4-a": ["cloud_platform", "host_os"],
    "8.2.4.4-b": ["cloud_platform", "host_os"],
    "8.2.4.4-c": ["cloud_platform", "host_os"],
    "8.2.4.5-a": ["cloud_platform", "database"],
    "8.2.4.5-b": ["cloud_platform", "database"],
    "8.2.4.5-c": ["cloud_platform", "host_os"],
    "8.2.4.5-d": ["cloud_platform", "database"],
    "8.2.4.6-a": ["cloud_platform", "database"],
    "8.2.4.6-b": ["cloud_platform", "database"],
    "8.2.4.6-c": ["cloud_platform", "database"],
    "8.2.4.6-d": ["cloud_platform", "database"],
    "8.2.4.7-a": ["cloud_platform", "host_os"],
    "8.2.4.7-b": ["cloud_platform", "database"],
}

# T/ISEAA 001-2020 高风险判例模板库（按判例分类组织，确保全部 106 项高风险条款均有精准依据与弥补参考）
_PRECEDENT_TEMPLATES: dict[str, dict[str, Any]] = {
    "PHY_ACCESS": {
        "precedent_code": "HR-PHY-01",
        "category": "机房物理访问与监控失效",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "机房出入口未部署电子门禁或监控报警失效，外部无关人员可不受控进入核心设备区域。",
        "compensating_controls": [
            "机房所在大楼已实施 24 小时安保值守、双人陪同及完整纸质/视频出入登记台账",
            "核心业务部署于已通过等保三级测评的云数据中心或托管 IDC，并留存有效的机房合规证明",
        ],
    },
    "PHY_FIRE_POWER": {
        "precedent_code": "HR-PHY-02",
        "category": "机房消防或备用供电缺失",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": False,
        "trigger_condition": "核心机房未配置气体自动灭火系统或缺少 UPS 备用电力，发生火灾或断电将直接导致业务长时间中断及硬件损毁。",
        "compensating_controls": [
            "关键业务具备异地实时容灾集群可在单机房断电时秒级接管，并出具机房消防整改排期",
        ],
    },
    "NET_ISOLATION": {
        "precedent_code": "HR-NET-01",
        "category": "网络区域隔离失效或重要区暴露边界",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "数据库区或核心业务区直接暴露于互联网或 DMZ 边界，或缺乏关键网络链路与设备冗余。",
        "compensating_controls": [
            "在网络边界部署严格白名单防火墙及 WAF，仅允许指定堡垒机或应用网段经代理访问核心区",
            "通过云平台多可用区负载均衡与弹性路由实现链路级冗余保障",
        ],
    },
    "NET_CRYPTO": {
        "precedent_code": "HR-NET-02",
        "category": "网络通信明文传输或弱加密协议",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": False,
        "trigger_condition": "跨边界通信、业务入口或远程管理采用 HTTP/Telnet 明文或 TLS 1.0/1.1、弱加密套件，存在窃听与中间人篡改风险。",
        "compensating_controls": [
            "外层已建立合规 IPSec VPN 或国密 SSL VPN 加密隧道承载全部跨网段流量（内部仍需尽快关闭弱协议）",
        ],
    },
    "BND_ACL": {
        "precedent_code": "HR-BND-01",
        "category": "边界访问控制缺失或存在宽泛放行策略",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "网络边界或安全组存在 Any-to-Any 宽泛放行、未遵循默认拒绝原则，或服务器未受控直接外联互联网。",
        "compensating_controls": [
            "边界安全组已收敛至最小端口白名单，同时在主机防火墙层面补充源 IP 与端口双层限制",
            "核心业务服务器禁止直接出网，仅允许经受控正向代理或 NAT 网关白名单访问指定更新源",
        ],
    },
    "BND_IDS_AUDIT": {
        "precedent_code": "HR-BND-02",
        "category": "边界入侵防护、防病毒或审计留存不足",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "关键网络边界缺少外部/内部入侵检测拦截、恶意代码过滤，或边界设备审计日志未集中备份且留存不足六个月。",
        "compensating_controls": [
            "虽未独立部署硬件 IPS，但已启用下一代防火墙（NGFW）入侵防御模块及云 WAF 并保持特征库自动更新",
            "通过主机侧 HIDS/EDR 与流量探针组合覆盖东西向攻击监测，且日志已统一外发至 SIEM 留存 180 天以上",
        ],
    },
    "HOST_AUTH": {
        "precedent_code": "HR-AUTH-01",
        "category": "身份鉴别薄弱、空口令或缺少双因子认证",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "存在空口令/弱口令、未配置登录失败锁定与超时断开，或管理员远程管理未使用口令+密码技术的双因子鉴别。",
        "compensating_controls": [
            "所有运维人员必须经堡垒机（已启用动态口令/数字证书双因子认证）跳转登录，且主机网络层仅放行堡垒机源 IP",
            "操作系统禁用口令登录，强制使用带口令保护的 SSH 密钥对认证并结合堡垒机 MFA",
        ],
    },
    "HOST_ACCESS": {
        "precedent_code": "HR-ACC-01",
        "category": "默认账户未清理、共享特权或权限未分离",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "存在未修改默认口令的账户、多余/共享高权账户、无限制 sudo 免密提权，或未实现系统/安全/审计三员权限分离。",
        "compensating_controls": [
            "通过堡垒机实名账户与工单审批实现单人单账号审计映射，并计划在进场前拆分主机本地三员与 sudo 最小权限",
        ],
    },
    "HOST_AUDIT": {
        "precedent_code": "HR-AUD-01",
        "category": "安全审计未开启或审计记录未受保护",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "操作系统、数据库或关键应用未开启审计，审计进程可被非授权中断，或日志仅存本地未集中外发保护且不足六个月。",
        "compensating_controls": [
            "已在堡垒机与数据库审计网关旁路完整留存操作与 SQL 审计记录（180 天以上），主机侧补充开启 auditd 不可变规则与 rsyslog 外发",
        ],
    },
    "HOST_VULN": {
        "precedent_code": "HR-VULN-01",
        "category": "存在高危/严重已知漏洞或非必要高危端口暴露",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "操作系统软件包、中间件或业务应用存在可被远程利用的高危/严重已知漏洞（CVE），或高危管理端口对非授权网段开放。",
        "compensating_controls": [
            "若因业务兼容短期无法升级，已在边界 WAF/IPS 启用针对该 CVE 的虚拟补丁拦截规则，并限定仅内部白名单源 IP 可达，附带明确升级时间表",
        ],
    },
    "HOST_MALWARE": {
        "precedent_code": "HR-MAL-01",
        "category": "主机入侵检测或恶意代码防范缺失",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "重要服务器未部署主机入侵检测（HIDS）或防病毒/EDR 防护措施，无法及时发现并阻断恶意代码与异常提权。",
        "compensating_controls": [
            "Linux 服务器已部署云安全中心 Agent/ClamAV 定时查杀与文件完整性监控（AIDE），并在边界防火墙开启防病毒过滤",
        ],
    },
    "DATA_CRYPTO_PRIVACY": {
        "precedent_code": "HR-DATA-01",
        "category": "重要数据明文存储/传输或个人信息越权访问",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": False,
        "trigger_condition": "鉴别数据、业务核心数据或用户个人信息未采取密码技术保证传输/存储机密性与完整性，或存在未授权访问、过度采集与明文泄露风险。",
        "compensating_controls": [
            "底层存储卷已开启全盘加密（TDE/磁盘加密）且接口层实施严格 RBAC 鉴权与前端脱敏展示，同时限期完成敏感字段应用层国密改造",
        ],
    },
    "DATA_BACKUP": {
        "precedent_code": "HR-BAK-01",
        "category": "缺少本地备份或异地实时备份能力",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "未建立核心数据库与业务数据的本地定时备份与可验证恢复机制，或未按三级要求提供异地实时/准实时容灾备份。",
        "compensating_controls": [
            "核心数据已完成每日定时全量与日志增量备份，并定期推送至跨地域对象存储/异地灾备中心（RPO 满足业务容忍指标），同时留存恢复演练记录",
        ],
    },
    "MGMT_CENTER": {
        "precedent_code": "HR-MGT-01",
        "category": "集中管控缺失或管理通道未独立加密",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "三员管理操作未经过独立鉴权与审计、未划设运维管理区、集中日志留存不足六个月或缺乏安全事件告警分析能力。",
        "compensating_controls": [
            "通过逻辑独立 VLAN 与堡垒机建立加密带外管理通道，并将各设备日志统一汇聚至集中日志审计平台留存 180 天以上",
        ],
    },
    "ORG_COMPLIANCE": {
        "precedent_code": "HR-ORG-01",
        "category": "关键安全管理与合规红线缺失",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": False,
        "trigger_condition": "未完成公安机关等保定级备案、未开展年度等级测评、未配备专职安全管理员、离岗/外包权限未及时回收，或生产与开发测试环境未物理隔离。",
        "compensating_controls": [
            "已启动备案/整改流程并出具管理层签批的过渡期管控措施（如临时专人审批、测试数据全面脱敏），但正式进场测评前须完成闭环",
        ],
    },
    "OPS_SEC": {
        "precedent_code": "HR-OPS-01",
        "category": "运维变更、远程运维、密码或应急演练失控",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "生产变更与远程运维未经审批及审计留痕、采用不合规密码产品、重要事件无专项预案或长期未开展应急演练与恢复验证。",
        "compensating_controls": [
            "已通过堡垒机工单审批强制接管全部远程运维通道，并在正式测评前补齐本年度应急演练与日志分析周报留痕",
        ],
    },
    "CLOUD_REDLINE": {
        "precedent_code": "HR-CLD-01",
        "category": "云计算基础设施境内合规、租户隔离或数据主权风险",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": False,
        "trigger_condition": "云计算基础设施或客户数据存储/运维位于境外且未履行合规手续、云平台本身未达到第三级保护要求，或云租户间虚拟网络与资源隔离存在缺陷。",
        "compensating_controls": [
            "引用已通过等保三级及以上测评的国内合规云服务商测评结论（责任共担边界内的基础设施条款可复用云商报告）",
        ],
    },
    "CLOUD_SEC": {
        "precedent_code": "HR-CLD-02",
        "category": "云边界控制、镜像快照安全或云上审计缺失",
        "direct_high_risk": True,
        "can_downgrade_with_compensation": True,
        "trigger_condition": "云虚拟边界缺少最小化安全组规则、未开启云操作审计与异常流量告警、未使用加固与签名校验镜像，或云上数据缺少本地备份与密钥自主管理。",
        "compensating_controls": [
            "结合云安全中心、云防火墙与操作审计（ActionTrail/CloudTrail）实现日志集中留存，并定期拉取云数据库快照至本地归档",
        ],
    },
}

# 高风险条款编号前缀/精确编号 -> 判例模板映射
_HIGH_RISK_MAP: dict[str, str] = {
    # 物理
    "8.1.1.2-a": "PHY_ACCESS",
    "8.1.1.3-c": "PHY_ACCESS",
    "8.1.1.5-a": "PHY_FIRE_POWER",
    "8.1.1.9-b": "PHY_FIRE_POWER",
    # 通信网络
    "8.1.2.1-d": "NET_ISOLATION",
    "8.1.2.1-e": "NET_ISOLATION",
    "8.1.2.2-a": "NET_CRYPTO",
    "8.1.2.2-b": "NET_CRYPTO",
    # 区域边界
    "8.1.3.1-a": "BND_ACL",
    "8.1.3.1-c": "BND_ACL",
    "8.1.3.2-a": "BND_ACL",
    "8.1.3.2-c": "BND_ACL",
    "8.1.3.3-a": "BND_IDS_AUDIT",
    "8.1.3.3-b": "BND_IDS_AUDIT",
    "8.1.3.3-d": "BND_IDS_AUDIT",
    "8.1.3.4-a": "BND_IDS_AUDIT",
    "8.1.3.5-a": "BND_IDS_AUDIT",
    "8.1.3.5-c": "BND_IDS_AUDIT",
    # 计算环境
    "8.1.4.1-a": "HOST_AUTH",
    "8.1.4.1-b": "HOST_AUTH",
    "8.1.4.1-c": "NET_CRYPTO",
    "8.1.4.1-d": "HOST_AUTH",
    "8.1.4.2-b": "HOST_ACCESS",
    "8.1.4.2-c": "HOST_ACCESS",
    "8.1.4.2-d": "HOST_ACCESS",
    "8.1.4.3-a": "HOST_AUDIT",
    "8.1.4.3-c": "HOST_AUDIT",
    "8.1.4.3-d": "HOST_AUDIT",
    "8.1.4.4-b": "HOST_VULN",
    "8.1.4.4-c": "BND_ACL",
    "8.1.4.4-e": "HOST_VULN",
    "8.1.4.4-f": "HOST_MALWARE",
    "8.1.4.5-a": "HOST_MALWARE",
    "8.1.4.7-a": "DATA_CRYPTO_PRIVACY",
    "8.1.4.7-b": "DATA_CRYPTO_PRIVACY",
    "8.1.4.8-a": "DATA_CRYPTO_PRIVACY",
    "8.1.4.8-b": "DATA_CRYPTO_PRIVACY",
    "8.1.4.9-a": "DATA_BACKUP",
    "8.1.4.9-b": "DATA_BACKUP",
    "8.1.4.11-a": "DATA_CRYPTO_PRIVACY",
    "8.1.4.11-b": "DATA_CRYPTO_PRIVACY",
    # 安全管理中心
    "8.1.5.1-a": "MGMT_CENTER",
    "8.1.5.2-a": "MGMT_CENTER",
    "8.1.5.3-a": "MGMT_CENTER",
    "8.1.5.4-a": "MGMT_CENTER",
    "8.1.5.4-b": "NET_CRYPTO",
    "8.1.5.4-d": "MGMT_CENTER",
    "8.1.5.4-f": "MGMT_CENTER",
    # 组织与建设管理（对照 T/ISEAA 001-2020 补齐安全管理制度与领导小组/审批红线）
    "8.1.6.2-a": "ORG_COMPLIANCE",
    "8.1.7.1-a": "ORG_COMPLIANCE",
    "8.1.7.1-c": "ORG_COMPLIANCE",
    "8.1.7.2-b": "ORG_COMPLIANCE",
    "8.1.7.3-b": "ORG_COMPLIANCE",
    "8.1.8.1-c": "ORG_COMPLIANCE",
    "8.1.8.2-a": "ORG_COMPLIANCE",
    "8.1.8.4-b": "ORG_COMPLIANCE",
    "8.1.8.4-c": "ORG_COMPLIANCE",
    "8.1.9.1-a": "ORG_COMPLIANCE",
    "8.1.9.1-d": "ORG_COMPLIANCE",
    "8.1.9.2-b": "ORG_COMPLIANCE",
    "8.1.9.3-b": "OPS_SEC",
    "8.1.9.4-a": "ORG_COMPLIANCE",
    "8.1.9.4-e": "HOST_VULN",
    "8.1.9.5-c": "ORG_COMPLIANCE",
    "8.1.9.7-b": "OPS_SEC",
    "8.1.9.9-a": "ORG_COMPLIANCE",
    # 安全运维管理
    "8.1.10.4-d": "DATA_CRYPTO_PRIVACY",
    "8.1.10.5-a": "HOST_VULN",
    "8.1.10.5-b": "OPS_SEC",
    "8.1.10.6-f": "OPS_SEC",
    "8.1.10.6-g": "OPS_SEC",
    "8.1.10.6-i": "OPS_SEC",
    "8.1.10.9-a": "OPS_SEC",
    "8.1.10.9-b": "OPS_SEC",
    "8.1.10.11-c": "DATA_BACKUP",
    "8.1.10.12-b": "OPS_SEC",
    "8.1.10.12-d": "OPS_SEC",
    "8.1.10.13-b": "OPS_SEC",
    "8.1.10.13-c": "OPS_SEC",
    "8.1.10.14-d": "OPS_SEC",
    # 云计算安全扩展
    "8.2.1.1-a": "CLOUD_REDLINE",
    "8.2.2.1-a": "CLOUD_REDLINE",
    "8.2.2.1-b": "CLOUD_REDLINE",
    "8.2.4.5-a": "CLOUD_REDLINE",
    "8.2.4.5-b": "CLOUD_REDLINE",
    "8.2.5.1-b": "CLOUD_REDLINE",
    "8.2.6.1-a": "CLOUD_REDLINE",
    "8.2.6.1-c": "CLOUD_REDLINE",
    "8.2.6.1-d": "CLOUD_REDLINE",
    "8.2.7.1-a": "CLOUD_REDLINE",
}


def applicable_objects_for(clause_id: str, domain: str, extension_type: str = "GENERAL") -> list[str]:
    """返回条款适用的标准测评对象编码列表。"""
    if clause_id in _CLAUSE_OBJECT_OVERRIDES:
        return list(_CLAUSE_OBJECT_OVERRIDES[clause_id])
    if domain == "安全物理环境":
        return ["physical_room"]
    if extension_type == "CLOUD" or domain == "云计算安全扩展":
        return ["cloud_platform"]
    if domain in {"安全通信网络", "安全区域边界"}:
        return ["network_device", "security_device"]
    if domain == "安全计算环境":
        return ["host_os", "database", "application"]
    if domain == "安全管理中心":
        return ["security_device", "host_os"]
    return ["org_management"]


def risk_weight_level_for(clause_id: str, domain: str, control_point: str, high_risk: bool) -> str:
    """根据标准重要程度划分高/中/低权重级别，用于加权计分。"""
    if high_risk:
        return "high"
    if control_point in {"可信验证", "防静电", "电磁防护", "温湿度控制", "防水和防潮", "防雷击", "物理位置选择", "防盗窃和防破坏"}:
        return "low"
    if domain in {"安全物理环境", "安全管理制度"} and clause_id not in {"8.1.6.1-a", "8.1.6.2-a"}:
        return "low"
    return "medium"


def high_risk_precedent_for(clause_id: str, domain: str, high_risk: bool) -> dict[str, Any] | None:
    """为高风险条款提供对照 T/ISEAA 001-2020 的判例类别与弥补控制参考。"""
    if not high_risk:
        return None
    template_key = _HIGH_RISK_MAP.get(clause_id)
    if not template_key:
        if domain == "云计算安全扩展" or clause_id.startswith("8.2."):
            template_key = "CLOUD_SEC"
        elif domain == "安全物理环境":
            template_key = "PHY_ACCESS"
        elif domain in {"安全通信网络", "安全区域边界"}:
            template_key = "BND_ACL"
        elif domain == "安全计算环境":
            template_key = "HOST_AUTH"
        elif domain == "安全管理中心":
            template_key = "MGMT_CENTER"
        else:
            template_key = "ORG_COMPLIANCE"
    template = _PRECEDENT_TEMPLATES[template_key]
    return {
        "standard_ref": "T/ISEAA 001-2020",
        "precedent_code": template["precedent_code"],
        "category": template["category"],
        "direct_high_risk": bool(template["direct_high_risk"]),
        "can_downgrade_with_compensation": bool(template["can_downgrade_with_compensation"]),
        "trigger_condition": template["trigger_condition"],
        "compensating_controls": list(template["compensating_controls"]),
    }


def enrich_clause(clause: dict[str, Any]) -> dict[str, Any]:
    """向条款字典补充测评对象标签、风险权重与高风险判例（幂等）。"""
    clause_id = str(clause.get("clause_id") or "")
    domain = str(clause.get("domain") or "")
    control_point = str(clause.get("control_point") or "")
    ext = str(clause.get("extension_type") or "GENERAL").upper()
    high_risk = bool(clause.get("high_risk"))

    objects = clause.get("applicable_objects") or applicable_objects_for(clause_id, domain, ext)
    weight_level = clause.get("risk_weight_level") or risk_weight_level_for(clause_id, domain, control_point, high_risk)
    precedent = clause.get("high_risk_precedent")
    if precedent is None and high_risk:
        precedent = high_risk_precedent_for(clause_id, domain, high_risk)

    enriched = dict(clause)
    enriched["applicable_objects"] = list(objects)
    enriched["applicable_object_labels"] = [OBJECT_LABELS.get(key, key) for key in objects]
    enriched["risk_weight_level"] = weight_level
    enriched["risk_weight"] = RISK_WEIGHTS.get(weight_level, 2.0)
    enriched["high_risk_precedent"] = precedent
    return enriched
