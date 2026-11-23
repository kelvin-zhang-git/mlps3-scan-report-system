# 项目摘要

等保三级扫描与报告系统部署在扫描机 `192.168.1.250`。控制面、接口和两套协同平台都避开了 Cognee 正在使用的 3000 和 8000 端口，原有服务保持运行。

工作台入口是 http://192.168.1.250:13000 。接口只监听扫描机本机的 `127.0.0.1:18000`，由 Nginx 反向代理。DefectDojo 在 http://192.168.1.250:8080 ，管理员用户是 `admin`，口令写在 `.env` 的 `DEFECTDOJO_ADMIN_PASSWORD`。CISO Assistant 在 https://192.168.1.250:8443 ，证书是自签名的，浏览器第一次访问时需要确认信任。靶机上的 Juice Shop 在 http://192.168.1.220:3000 ，原来的 Apache 仍占用 80 端口。

登录工作台使用 `.env` 里的 `ADMIN_EMAIL` 和 `ADMIN_PASSWORD`。评估项目当前使用 `gemini_paid`，跨境请求经过 `OUTBOUND_PROXY`。扫描范围是白名单 `192.168.1.220/32`，扫描机 `192.168.1.250/32` 不在这个范围里。

全链路已经核对过一遍。SSH 基线、Nmap、Nuclei（排除 dos、fuzz、intrusive、bruteforce，并关闭 interactsh）、Trivy、二次去重和 DefectDojo 导入都能跑完。脱敏结果要通过零泄漏检查并经人工确认，之后才会交给 Gemini 做条款映射，并生成 HTML 报告。
