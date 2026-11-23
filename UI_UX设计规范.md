# 等保三级合规工厂 — UI/UX 设计规范（Enterprise SDF 经典红白体系）

> **设计参考基准**：Enterprise SDF 智能应用工厂（瑞士精密工业网格 + 经典红白治理工作台风格）  
> **适用范围**：React 18 + Vite + TypeScript + Tailwind CSS 前端控制面（`frontend/`）及 WeasyPrint 导出 PDF 差距报告（`backend/templates/gap_report.html.j2`）  
> **核心理念**：克制留白、1px 精密网格边界、双语等宽微型眉标、红色斜纹警戒视觉锚点、高可读性治理指标与三套可切换主题。

---

## 1. 视觉识别与 Design Tokens（设计变量体系）

### 1.1 三套主题切换系统（支持无刷新实时切换）
侧边栏底部与登录页右上角提供一键主题切换胶囊，状态通过 Zustand 持久化至 `localStorage` 与 `document.documentElement.dataset.theme`（并同步 `PATCH /api/auth/theme` 落库 SQLite）：

| Design Token | 经典红白（默认主推 `classic_red`） | 极地蓝白（`arctic_blue`） | 暗夜深空（`midnight_dark`） | 用途说明 |
| :--- | :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#F7F8FA` | `#F6F8FB` | `#0B1120` | 主工作区画布背景 |
| `--bg-surface` | `#FFFFFF` | `#FFFFFF` | `#111827` | 卡片、侧边栏、表单容器背景 |
| `--bg-subtle` | `#F3F4F6` | `#EFF6FF` | `#1E293B` | 分段控制器底色、标签未选中悬停态 |
| `--border-hairline` | `#E5E7EB` | `#E2E8F0` | `#273244` | 1px 极细网格边框与模块分割线 |
| `--accent-primary` | `#D91E2A` | `#1D4ED8` | `#EF4444` | 主按钮、状态胶囊、图标高亮、警戒斜纹 |
| `--accent-hover` | `#B91C1C` | `#1E40AF` | `#DC2626` | 主按钮悬停态 |
| `--accent-soft-bg` | `#FEF2F2` | `#EFF6FF` | `rgba(239,68,68,0.14)` | 左侧导航选中胶囊底色、提示浅底 |
| `--text-primary` | `#111827` | `#0F172A` | `#F8FAFC` | 主标题、KPI 大数字、核心正文 |
| `--text-secondary` | `#4B5563` | `#475569` | `#94A3B8` | 辅助描述、摘要正文 |
| `--text-muted` | `#6B7280` | `#64748B` | `#64748B` | 英文微型眉标、次级元信息、时间戳 |
| `--grid-line` | `rgba(17,24,39,0.04)` | `rgba(15,23,42,0.04)` | `rgba(248,250,252,0.04)` | 登录页左区 24px 方格底纹线条色 |

### 1.2 标志性视觉元素（Signature Visuals）
1. **红色斜纹警戒分割条（Hazard Stripe Divider）**：
   * 高度 `4px ~ 5px`，用于登录页英雄区与能力矩阵之间、以及左侧导航栏底部用户信息区上方。
   * CSS 实现：
     ```css
     .mlps-hazard-stripe {
       height: 5px;
       width: 100%;
       background: repeating-linear-gradient(
         -45deg,
         var(--accent-primary) 0px,
         var(--accent-primary) 6px,
         transparent 6px,
         transparent 12px
       );
       opacity: 0.78;
     }
     ```
2. **双语等宽微型眉标（Bilingual Monospace Eyebrow）**：
   * 形式：`ENGLISH LABEL · 中文语义` 或纯英文眉标（如 `ASSESSMENT WORKSPACE`、`PII REDACTION · 敏感脱敏`、`COMPLIANCE FLOW METRICS`）。
   * 样式：`font-family: "JetBrains Mono", "Consolas", monospace; font-size: 11px; font-weight: 600; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-muted);`（英雄区或关键警告使用 `var(--accent-primary)`）。
3. **极简 1px 网格卡片（Zero-Shadow Hairline Card）**：
   * 卡片保持平面：`background: var(--bg-surface); border: 1px solid var(--border-hairline); border-radius: 8px; box-shadow: none;`。渐变和重阴影会把网格冲掉，这里不用。
4. **24px 工程方格底纹（Engineering Grid Background）**：
   * 用于登录页左侧核心价值宣导面板：
     ```css
     .mlps-grid-canvas {
       background-color: var(--bg-surface);
       background-image:
         linear-gradient(to right, var(--grid-line) 1px, transparent 1px),
         linear-gradient(to bottom, var(--grid-line) 1px, transparent 1px);
       background-size: 24px 24px;
     }
     ```

### 1.3 字体与数值排版规范
* **中文字体栈**：`"PingFang SC", "Microsoft YaHei", "Noto Sans SC", sans-serif`
* **数字与眉标字体栈**：`"Inter", "JetBrains Mono", "Consolas", monospace`，全部数字指标开启 `font-variant-numeric: tabular-nums;` 确保对齐。
* **字号层级**：
  * 登录页大标题：`32px ~ 36px`，`font-weight: 800`，`line-height: 1.25`
  * 工作空间项目主标题：`22px ~ 24px`，`font-weight: 700`
  * KPI 大号等宽数字：`24px ~ 28px`，`font-weight: 700`
  * 卡片区块标题：`15px ~ 16px`，`font-weight: 600`
  * 正文与说明：`13px ~ 14px`，`line-height: 1.6`
  * 微型眉标与状态胶囊：`11px ~ 12px`

---

## 2. 核心页面结构与线框设计

### 2.1 页面一：登录与能力宣导页（Split Auth & Capabilities Landing）
> 对标参考截图二，用于系统首次认证入口（密码存储严格使用 `bcrypt` 哈希校验）。

```text
+--------------------------------------------------------------------------------------+
| [品牌标志] MLPS 3.0 | 等保三级合规工厂                                [ 经典红白 v ]  |
+--------------------------------------------------------------------------------------+
|                                                                                      |
|   +--------------------------------------------+   +-----------------------------+   |
|   | (24px 浅灰工程方格底纹)                     |   | WORKBENCH ACCESS            |   |
|   | MLPS 3.0 COMPLIANCE FACTORY                |   | 登录工作台                   |   |
|   |                                            |   | 使用企业邮箱与口令进入受治理  |   |
|   | 把等保三级合规评估纳入统一治理，             |   | 的等保合规评估工作空间        |   |
|   | 从自动探测直达整改闭环。                    |   |                             |   |
|   |                                            |   | [   登录   |   注册/初始化 ] |   |
|   | 多源安全探测、保拓扑脱敏与双轨大模型协同，   |   |                             |   |
|   | 自动化完成 GB/T 22239 条款映射与路径推演；   |   | 邮箱                        |   |
|   | 安全负责人在关键确认处复核，全链路留痕。   |   | [ security@company.com    ] |   |
|   |                                            |   |                             |   |
|   | //// //// //// //// //// //// //// ////    |   | 密码                        |   |
|   |                                            |   | [ 至少 8 位字符            ] |   |
|   | FACTORY CAPABILITIES                       |   |                             |   |
|   | +------------+------------+------------+   |   | [        登录  ->         ] |   |
|   | | [图标]     | [图标]     | [图标]     |   |   |   (满宽品牌红 #D91E2A 主按钮)|   |
|   | | 多源探测去重| 保拓扑脱敏 | 双轨模型网关|   |   +-----------------------------+   |
|   | | DefectDojo | 安全域映射 | LiteLLM    |   |                                     |
|   | +------------+------------+------------+   |                                     |
|   | | [图标]     | [图标]     | [图标]     |   |                                     |
|   | | 等保条款映射| 攻击路径推演| 人机混合报告|   |                                     |
|   | | GB/T 22239 | 跨组件研判 | CISO+PDF   |   |                                     |
|   | +------------+------------+------------+   |                                     |
|   +--------------------------------------------+                                     |
+--------------------------------------------------------------------------------------+
```

**左侧 3×2 能力矩阵（6 张无缝 1px 线框格）具体文案**：
1. **多源探测与去重**：集成 Nmap、Nuclei、Trivy、Kubescape 与 SSH 等保基线，经 DefectDojo 归一化与二次聚合去重。
2. **保拓扑可逆脱敏**：按安全域生成确定性资产代号，裁剪敏感 HTTP 报文与个人信息，送出模型之前先做零泄漏检查。
3. **LiteLLM 双轨网关**：内网涉敏自动锁定国内/本地模型，测试与获批跨境支持 Gemini 付费层与 Context Caching。
4. **GB/T 22239 条款映射**：内置等保三级通用与云计算扩展指标。能由证据得出结论的条款和必须人工核查的条款分开。证据没到的条款，先停在待人工。
5. **跨组件攻击路径推演**：基于脱敏拓扑自动推演横向移动与提权攻击链，直接输出可复用的加固命令与补丁建议。
6. **人机混合治理报告**：与 CISO Assistant 双向同步人工管理制度证据，一键渲染打印级 PDF 差距报告与整改工单。

---

### 2.2 页面二：企业级工作空间外壳（Workbench Shell & 评估项目总览）
> 对标参考截图一，采用“左侧固定窄导航栏（236px） + 右侧居中呼吸感内容容器（max-width: 1120px）”。

#### A. 左侧固定侧边栏结构（`WorkbenchShell.tsx` + `lucide-react` 线框图标）
* **顶部品牌区**：红色小字标识 + `MLPS 3.0 | 等保三级合规工厂`
* **快捷检索框**：`全局搜索条款 / 资产 / CVE...`（右侧附 `Ctrl K` 徽标）
* **分组标签**：`FACTORY MODULES`（等宽大写浅灰）
* **一级导航菜单**（选中态为淡红底 `#FEF2F2` + 红色图标与红字 `#D91E2A`，圆角 `6px`）：
  1. `全局大盘`（跨项目合规达标率、高危趋势）
  2. `我的待办`（待人工核查条款、待放行脱敏任务、超期整改单）
  3. `评估项目`（核心工作空间，进入二级水平 Tabs）
  4. `扫描工作流`（定时调度、白名单策略与熔断监控）
  5. `等保条款库`（GB/T 22239-2019 三级通用 + 云扩展字典浏览）
  6. `AI 评审引擎`（LiteLLM 通道配置、模型调用审计与成本统计）
  7. `工具连接器`（DefectDojo / CISO Assistant / 移动云 OpenAPI / godlp / Akto 连通性状态）
  8. `系统管理`（用户角色、bcrypt 账号管理、加密 Vault 密钥轮换）
* **底部固定区**：
  * **红色斜纹警戒分割条**（`mlps-hazard-stripe`）
  * **三主题切换胶囊组**：`[● 经典红白]` `[● 极地蓝白]` `[● 暗夜深空]`（选中态带细边框白底）
  * **当前用户卡片**：用户名（如 `security_lead`）+ 角色（`安全管理员 / 等保负责人`）
  * **底部双操作**：`切换视角` | `退出登录`

#### B. 右侧主工作区结构（“评估项目”空间）
1. **顶部项目摘要头卡片（Workspace Header Card）**：
   * 左侧：`ASSESSMENT WORKSPACE`（微型眉标） -> **项目名称**（例如：`移动云跨境业务平台-等保三级预评估`） -> **范围说明**（例如：“对 DMZ、应用、数据库和移动云上的核心资产做只读核查。高风险项还没关闭时，先不提交测评；内网数据使用国内或本地通道。”）
   * 右侧胶囊组：
     * 阶段徽章：红底白字胶囊 `预评估期`（或绿底 `已达标` / 灰底 `已归档`）
     * 密级徽章：白底 1px 灰框胶囊 `密级：内部 · 留在境内`
2. **二级水平胶囊导航栏（Sub-Navigation Tabs）**：
   * 紧贴头卡片下方，包含 9 个清晰标签：
     `概览` | `资产白名单` | `扫描采集` | `漏洞与基线` | `脱敏审计` | `AI 条款映射` | `攻击路径` | `人工证据` | `报告制品` | `设置`
   * 交互样式：选中态白底 + 1px 边框 + 加粗黑字；未选中透明底 + 灰字，悬停浅灰底。
3. **4 列核心治理状态条（Metadata Strip Card）**（位于“概览”页顶部）：
   * 单张横向白底卡片，内部由 3 条 `1px` 竖线均分为 4 栏，每栏顶部采用双语等宽眉标：
     * `LIFECYCLE · 评估阶段` -> **整改复测中**
     * `BASELINE · 测评基线` -> **GB/T 22239-2019 (三级+云)**
     * `LLM ROUTE · 合规通道` -> **国内合规通道 (LiteLLM)**
     * `PII REDACTION · 敏感脱敏` -> **已开启（零泄漏检查）**
4. **评估版本时间线卡片（`ASSESSMENT TIMELINE`）**：
   * 左上标题 `评估版本`，右上微型英文标 `ASSESSMENT TIMELINE`。
   * 展示历次预评估批次（如 `v1.0 初测` -> `v1.1 复测`），标明时间、触发人、综合达标率变化及高危清零数；无记录时呈现克制的空状态提示（如“还没有评估快照记录，点击前往「扫描采集」发起首次只读核查。”）。
5. **合规流水线指标卡片（`COMPLIANCE FLOW METRICS`）**：
   * 左上标题 `合规交付流`，右上 `COMPLIANCE FLOW METRICS`。
   * 4 等分 1px 网格大数字指标卡：
     * **本轮耗时**：`18 分钟`（下方小字：`执行任务 6`）
     * **条款覆盖率**：`64.2%`（下方小字：`自动 92 / 辅助 48 / 人工 78`）
     * **高风险项清零**：`83.3%`（下方小字：`已闭环 5/6，剩余 1 项阻断`）
     * **流水线阶段**：`5`（下方小字：`采集 8m、去重 1m、脱敏 0.2m、AI 6m、同步 0.5m`）
6. **交付制品卡片（`DELIVERABLE ARTIFACTS`）**：
   * 集中展示本轮生成的交付物列表（支持一键预览或下载）：
     * 《等保三级预评估差距报告（脱敏分享版）.pdf》
     * 《等保三级预评估差距报告（内部受控还原版）.pdf》
     * 《P0/P1 整改工单清单.md》
     * 《CISO Assistant 同步回执快照.json》

---

## 3. 其余核心二级标签页交互设计

为确保所有功能页保持与截图完全一致的视觉秩序，每个二级标签页均遵循“**1px 网格白卡 + 双语等宽眉标 + 状态胶囊 + 表格/双栏对比**”设计规范：

| 二级标签页 | 核心布局模式 | 关键交互与安全防呆设计 |
| :--- | :--- | :--- |
| **资产白名单** | 顶部白名单 CIDR 警示卡 + 下方 1px 资产明细表 | 标明每台主机的 `安全域(DMZ/APP/DB)`、`模式锁(READONLY/ACTIVE)`；切换为 `ACTIVE_SCAN` 时弹出红色二次确认框 |
| **扫描采集** | 顶部一键触发控制栏 + 工具执行状态矩阵卡 | 每个扫描器独立展示状态胶囊、限速参数与基于 SSE (`EventSource`) 实时刷新的进度条与日志流；强制标红显示已排除的 `dos/fuzz/intrusive` 标签 |
| **漏洞与基线** | 顶部筛选胶囊（按来源/严重度/去重状态）+ 统一证据表 | 展示 DefectDojo 二次去重后的跨工具标记（如 `Trivy + Nuclei`）及 SSH/移动云正向合规证据（绿色 `PASS` 胶囊） |
| **脱敏审计** | **左右双栏对照** + 顶部零泄漏检查状态 | 左侧是原始摘要，只有授权角色能看；右侧是保拓扑脱敏后的文本，高亮 `ZONE_DMZ_HOST_01`。确认检查通过之后，再开始 AI 评审。 |
| **AI 条款映射** | 左侧按安全域筛选，右侧是条款卡片 | 每张卡片展示条款编号、高风险标记、模型意见、关联证据和加固命令。仅人工条款用灰底，结论等人工核对后再写成符合。 |
| **攻击路径** | 顶部 Mermaid 拓扑路径图卡 + 下方 Top 5 风险链步骤卡 | 展示保拓扑安全域之间的横向移动链路与修复优先级（P0/P1/P2），点击可一键复制加固脚本 |
| **人工证据** | 左侧待核查管理制度清单 + 右侧证据上传与 CISO 同步卡 | 支持上传物理机房/移动云等保证明、22 类管理制度 PDF/图片，填写复核意见并一键回写 CISO Assistant |
| **报告制品** | 左侧报告配置项 + 右侧 HTML 实时预览与导出按钮 | 选择“脱敏版”或“内部受控还原版”（触发审计日志记录），一键通过 WeasyPrint 生成同风格红白网格 PDF |

---

## 4. React + Vite + TypeScript 高保真工程落地策略

使用 **React 18 + Vite + TypeScript + Tailwind CSS + Lucide Icons + TanStack Query + Zustand** 可实现对参考截图像素级的工业极简还原，工程落地方案如下：

1. **三主题变量系统（`frontend/src/styles/tokens.css`）**：
   * 在 `:root`、`[data-theme="classic_red"]`、`[data-theme="arctic_blue"]`、`[data-theme="midnight_dark"]` 下完整定义所有 Design Tokens；
   * 在 `tailwind.config.ts` 中将颜色语义映射到 CSS 变量（如 `bg-canvas: "var(--bg-canvas)"`、`text-accent: "var(--accent-primary)"`、`border-hairline: "var(--border-hairline)"`），确保切换主题零闪烁、零组件重渲染抖动。
   * 定义 `.mlps-hazard-stripe`（红色斜纹警戒分割条）与 `.mlps-grid-canvas`（24px 工程方格底纹）工具类。
2. **原子化 UI 组件库（`frontend/src/components/ui/`）**：
   * `HazardStripe.tsx`：标志性 5px 红色斜纹警戒分割条。
   * `WorkspaceHeader.tsx`：项目摘要头卡片（`ASSESSMENT WORKSPACE` 等宽眉标 + 主标题 + 治理红线摘要 + 右侧红底阶段胶囊 & 灰框密级胶囊）。
   * `MetadataStrip.tsx`：1px 垂直分割的 4 列双语等宽眉标状态条（`LIFECYCLE · 评估阶段`、`BASELINE · 测评基线`、`LLM ROUTE · 合规通道`、`PII REDACTION · 敏感脱敏`）。
   * `MetricsGrid.tsx`：4 列等宽 `tabular-nums` 合规交付流 KPI 指标卡。
   * `CapabilityMatrix.tsx`：登录页左侧 3×2 无缝 1px 线框能力矩阵卡片。
   * `StatusPill.tsx`：统一语义胶囊组件（`danger | neutral | success | warning`）。
   * `SubNavTabs.tsx`：工作空间二级水平胶囊导航栏（支持 URL Query/Nested Route 同步，刷新不丢状态）。
3. **全局外壳与高频交互组件（`frontend/src/components/layout/`）**：
   * `WorkbenchShell.tsx`：固定 `236px` 左侧窄栏（顶部 Logo、检索框、`FACTORY MODULES` 一级导航淡红选中胶囊、底部斜纹分割条 + 三主题胶囊切换器 + 用户角色卡）+ 右侧居中定宽主画布（`max-w-[1120px]`）。
   * `CommandPalette.tsx`：监听 `Ctrl+K` / `Cmd+K` 快捷键，支持跨等保条款编号、资产 IP 代号、CVE 编号瞬间跳转定位。
4. **前后端强类型契约与实时交互（`frontend/src/api/`）**：
   * `types/api.ts` 与 FastAPI Pydantic v2 Schema 严格一一对应，编译期拦截字段不匹配。
   * 扫描任务与 AI 评审通过 `EventSource` 订阅 `/api/scans/{job_id}/stream` SSE 事件流，无闪烁更新阶段进度与耗时；全局 API 错误统一通过顶部极简红框 Toast 提示。
5. **PDF 报告视觉同源（`backend/templates/gap_report.html.j2`）**：
   * WeasyPrint PDF 报告直接复用本规范的**经典红白瑞士网格 Design Tokens**（白色纸面 + 1px `#E5E7EB` 表格线 + 红色斜纹页眉装饰线 + 双语等宽章眉标 + 红/灰状态胶囊），保证从 React 工作台到正式 PDF 差距报告拥有完全一致的高端企业级品牌质感。
