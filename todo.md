# 部署待办

- [x] 扫描机与靶机探活，避开 Cognee 占用的 3000/8000
- [x] 在 192.168.1.250 部署控制面（13000）和 API（本机 18000）
- [x] 启动 DefectDojo（8080）并打通扫描结果自动导入
- [x] 启动 CISO Assistant（8443）并修复前端重启与 Caddy TLS 握手
- [x] 开放防火墙 13000/8080/8443，不动 Cognee
- [x] 跑通 SSH 基线 / Nmap / Nuclei / Trivy 容器扫描与超时销毁机制
- [x] 在靶机 3000 端口部署 Juice Shop，保留原有 Apache
- [x] 核对脱敏零泄漏检查、人工确认、Gemini 条款映射与报告导出
