# 本地 Issue：复用原生上游能力，最小接入强制登录

> 历史准备快照。现行正式需求为 [GitHub Issue #3](https://github.com/qq550723504/openbrowser-platform/issues/3)。下文“尚未发布/本批不实施”描述草拟时的状态，不能替代正式 Issue 或当前授权；本地实现先于正式 Issue 开始的事实保留。

**LOCAL DRAFT，尚未发布 GitHub Issue；无 remote，不建仓库、不写远端。**

基础为干净上游 `61feab721f71d65301dfa45397cb9e15e28e8fd8` 加 busy 补丁
`2e75ad2e5c3b8146ad8e97e9d6136fd50dec2442`。本批仅只读准备/草稿，业务代码、备份、
冻结 EXE/ZIP 未改；未运行产品/GUI/内核、登录、身份预检或凭据/IAM 操作。

## 当前证据

修复包的原生 B→新 C、C 回收恢复、A 合成 Cookie/localStorage 重开、正常退出均
PASS；原生配置/复制、A/B 隔离等也有各自限定历史证据。22 项回归及构建 PASS。
这些不是完整全功能验收：代理真实连通、完整云备份/自动化、发行等未完成；GUI2
历史退出仍 UNKNOWN，分组最终显示未验收，内核完整 stderr/全局零出站未独立证明。
当前基础没有强制登录。详见[本轮实测](/C:/Users/Henry/code/ant-browser/build/trial/evidence/busyfix-2e75ad2-round1/RESULT.md)。

## 最小实现边界（本批不实施）

| 边界 | 最小落点与要求 |
| --- | --- |
| 统一身份权威 | 复用 `internal/desktopauth/{config,manager,jwt,json}.go` 的内存 OIDC/失效/generation 核心。主体由 Go 验证，不接收 renderer 伪造身份；无免登录开关、client secret、持久 token 或 TLS 跳过。 |
| Wails 全入口 | 当前 main.App 提升 backend.App，静态 195 个唯一方法与 App.js 完全对应。新增 backend 内有类型的薄鉴权转发门面/显式策略表；main.go 不再提升未门控 core，11 个主包覆盖转发也必须经过门面。缺分类默认拒绝，不修改 Wails、不造通用 Invoke、不重写原业务方法。 |
| 前端 | App.tsx 增加薄登录壳，登录后挂载原 Layout/AppRoutes；统一现有 11 处直接桥入口，复用 AuthViewGuard/BusyScope。跨 await 的预览、确认、任务捕获原代次，失效后不借新身份继续提交，迟到结果不能解锁新 busy。静态说明/主题/auth 状态及安全退出仍可用，业务视图和快捷启动不提前读取数据。 |
| HTTP/CDP | 在 launchcode 的现有总 handler 覆盖所有业务路由及根 CDP 转发/升级，不能只保护 `/api/`。现有可选 API-key 在关闭/空 key 时放行，不能当用户登录。复用 key 格式但要求当前登录者明确授予本代次内存调用能力；缺 key、无登录、过期或旧授权均拒绝，不把桌面 signed_in 当任意本机请求身份。退出/过期撤销代理连接，不终止浏览器。最小 health 只报非敏感存活信息。 |
| 后台/启动 | app_startup.go、app_backup_scheduler.go 及测速/自动化派发点复用同一准入。代理残留终止、到期回收清理、下载/预热/调度等不能在未登录时旁路；宿主静态 UI/日志等必要准备不一概封死。旧任务不能在新登录后自动重放。 |
| 退出/正常收尾 | Logout/过期不调用 ForceQuit/StopAll。保留 QuitAppOnly；需要应用内收尾时，仅允许服务端本进程持有的实例回执，核实 monitor、PID/创建时间、用户目录/CDP 归属后请求正常关闭，不接受任意 PID/端口、不回退强杀、不开放匿名 HTTP 停止。 |

网络、文件框、长任务不能整个包在旧 Manager.WithIdentity 锁内；复用其验证与失效逻辑，
在准入和实际副作用边界做小型适配。已提交写入保留真实回执，不改报成“从未执行”，
未知结果不自动重试。原 manager/profile 库、启停、内核、备份等业务实现继续复用。

## auth 复用事实

两份安全备份中选定的 10 个相关源码/测试均存在；原字节因 CRLF/LF 不同，统一
换行后 **10/10 一致**，见 `auth-reuse-receipts.json`、`auth-reuse-normalized.json`。
可提取四个纯 Go 核心文件、manager/jwt/callback 相关回归及前端 viewGuard/busyScope。
旧 desktop.go 的 auth 接线可局部提取，但 Desktop 自身耦合 Workspace/进程监督器，
不能整体移植；旧 go.auth.mod、AuthDesktop 业务壳、local runner/CAS 等不带回。
本批只查相关源码和测试名，未重跑旧测试，不能记作新集成 PASS。

## 未核实的公开配置（一次列齐）

已核实历史配置入口是 `ABFREE_OIDC_ISSUER`、`ABFREE_OIDC_CLIENT_ID`。历史文档
提到 ZITADEL 和 `https://localhost:35443`；早期“缺 Native ID”已被后续“Native 客户端
创建/历史登录完成”的文档覆盖，不能据旧待办要求重新注册。后续公开文档刻意不保存
client ID；当前基础没有可核实的当前身份配置，本批不读环境、凭据库或敏感原始诊断补齐。

真实登录/集成验收需提供或指出非敏感来源：

1. 当前批准的精确 HTTPS issuer、public **Native** client_id。
2. 同一注册的回调匹配依据：客户端请求 `http://127.0.0.1:<临时端口>/oauth/callback`，以及 `openid profile`、code/S256、RS256、public token endpoint auth 的兼容配置；如实际匹配范围更宽须如实记录。
3. 当前正常系统 HTTPS 信任/可达性的依据；本批未探测，不自动装 CA、跳过 TLS、创建服务或改 IAM。

只需要公开值或配置路径，**不要提供密码、secret、token 或私钥**。这些是真实登录依赖，
不阻止本草稿完成或以后另行授权的离线实施；本 Issue 不授权外部注册、登录或运行。

## 验收标准

- [ ] 195 个 Wails 入口及实际 Bind 对象完整覆盖：未登录/缺配置/过期/退出/旧代次直接调用均拒绝，core 不产生副作用；不能从另一绑定或导出 getter 绕过。
- [ ] 登录后仍走原上游页面/API/manager；当前22项回归、类型和构建继续通过，busy 修复保留。静态 UI 可读但业务数据不提前读取。
- [ ] HTTP/API、根 CDP/升级连接、排队任务和后台调度无旁路，空/禁用 key 不放行，旧授权/旧任务不继承新身份。
- [ ] 适配并通过原 auth 的 PKCE/claims/签名、取消/重放、过期及异步竞争回归；令牌不进 renderer/日志/持久文件，旧视图/预览/忙状态不能污染新会话。
- [ ] 退出/过期阻断新业务且不擅自结束既有实例；安全 app-only 退出与精确归属正常收尾可用，无任意停止或强杀回退。
- [ ] 原数据/设置保持，真实 IdP/原生验收与离线证据分开记录；本批实现、测试执行、产品/登录均 NOT_RUN。

## 非目标与必须保留的边界

不引回旧 workspace/runtime/CAS/账号映射数据库，不做云工作区、RBAC/租户平台、
业务重写、无登录分支、凭据/IAM 注册、权限调整或远端写入。

App 门控不等于锁住已经运行的 Chromium 窗口或它独立的原生 CDP；保留实例且不改调试
通道时，不能保证本机用户无法直接使用浏览器。若目标包含这层需另定边界，不能用
代理鉴权伪称直接端口已受保护。本阶段也不宣称不同登录账号间的本机档案隔离。

源位置、准确调用链、文件级细节及历史证据区别见 `PREPARATION-NOTES.md` 和入口清单。
