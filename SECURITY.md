# 安全策略（SECURITY）

本文件说明 schedprobe 的安全设计、已知边界，以及如何报告漏洞。
文中每条设计断言都来自对源码的核对（并标注文件/符号）；文档与代码不一致时以代码为准。

## 1. 报告漏洞

**请勿为安全漏洞开公开 issue。** 请使用以下私密渠道：

* 安全联系邮箱：`security@example.invalid`

> 这是**占位邮箱**，项目正式公开前必须替换为真实可用的私密渠道（并建议同时启用平台提供的
> private vulnerability reporting）。在替换完成前，请不要把本文件当作可用的联系方式。

### 报告内容建议

1. 受影响的版本/提交（`schedprobe version` 的输出，或源码 SHA-256）；
2. 复现命令与最小输入（配置文件、CLI 参数、证据日志片段）；
3. 预期行为与实际行为；
4. 影响评估（例如：scope 校验被绕过、脱敏失效、证据链校验被绕过、崩溃/拒绝服务、信息泄露）；
5. 若涉及第三方数据，请先脱敏：`--redact` 只能伪名化主机标识（见 §3.4），
   请不要把真实目标的完整清单或凭据发给我们。

### 我们的处理方式

* 确认收到后，维护者会尽力在合理时间内给出初步判断（这是**尽力而为**的承诺，不是 SLA）；
* 修复期间默认**协调披露**：在修复版本可用前不公开细节；具体时间线由双方协商；
* 修复后会在 CHANGELOG/发布说明中致谢（如你希望匿名，请在报告中说明）。

### 范围

**属于本项目的范围**：本仓库代码与其 CLI 行为的问题，例如 scope 校验可被绕过、脱敏不生效、
证据链校验可被绕过（含伪造记录仍能通过校验）、畸形输入导致的崩溃、路径处理缺陷、
CLI 参数注入、以及 `SECURITY.md`/文档中安全承诺与实现不符。

**不属于本项目范围**：你在测试第三方资产时把本工具当武器产生的问题；第三方目标本身的漏洞；
上游 Python 标准库的缺陷（请报给 CPython）；把你自己的测试目标清单/凭据泄露给你自己的风险
（本工具不保存凭据，但会把你给它的目标写进产物，见 §3.4）。

## 2. 支持版本策略

* 当前仓库版本为 **0.1.0**（`pyproject.toml`），`Development Status :: 3 - Alpha`。
* 仓库内目前**没有** `CHANGELOG.md`、没有 LICENSE 文件（`pyproject.toml` 以文本形式声明
  `Apache-2.0`），也没有已标记的发布版本；因此当前策略是：
  **只对最新代码提供修复**，不承诺维护旧版本分支。
* 一旦开始打 tag/发布，本策略应更新为"支持最新 minor 与上一个 minor"之类的明确规则，
  并同步维护 CHANGELOG。

## 3. 安全设计说明

### 3.1 Scope 校验（目标范围）

判定目标是否在允许范围内，当前实现分三层：

1. **类别门控** — `targets.validate_targets()`：把每个目标解析成 IP；回环地址受
   `safety.allow_loopback` 控制，私有/链路本地地址受 `safety.allow_private` 控制，
   组播/保留/未指定地址**无条件拒绝**，其余（公网）地址必须显式开启 `--allow-public`
   （`SafetyConfig.allow_public`，默认 `false`）。主机名目标受 `safety.allow_dns` 控制，
   并且必须匹配 RFC 1123 形式的正则。
2. **配置校验** — `config.ScanConfig.validate()`：规范化目标（`models.normalize_target`，
   不做 DNS 解析）、去重、检查 `network.max_hosts` / `max_ports` 上限，
   并在 `safety.max_span_ratio < 1.0` 时检查预算是否够覆盖请求的跨度。
3. **后端兜底** — `backends/base.py:ScopedProbeBackend._assert_scoped()`：每次探测前做一次
   允许集合（由 `build_backend` 注入已验证的主机列表）查找，越界抛 `BackendError`。
   这是"防御纵深"：即使库调用方绕过配置校验直接构造后端，也不会越界发包。

**已知边界（重要）**：

* **主机名目标的地址类别不会在解析后被复核**。`validate_targets` 对主机名只做语法检查；
  解析发生在真实后端的 `RealTcpBackend._resolve()`（带 `resolve_timeout_s` 与进程内缓存），
  解析结果不会再次按 public/private 分类。因此当你允许 DNS（注意 `SafetyConfig.allow_dns`
  **默认为 True**）时，"只扫内网"的期望可能被解析结果绕过。只扫 IP 字面量可以完全避免这一点。
* 主机名目标在证据日志里只记录主机名，**不记录解析出的 IP**（`real._resolve` 的结果不进入
  `ProbeResult`），因此事后审计无法从日志确认当时连到了哪个地址。
* CLI 帮助里 `-t/--target` 声称支持 CIDR，但当前 `validate_targets()` 会拒绝形如
  `10.0.0.0/30` 的目标（它有 `/`，既不是 IP 字面量也不是 RFC 1123 主机名），
  于是配置校验阶段报 `TargetValidationError`。`targets.expand_targets()` 本身是支持 CIDR 的，
  两个函数目前不一致。

### 3.2 没有命令执行面

安全设计基线：**不调用 shell、不启动外部进程、不做不安全反序列化**。核对结果：

* 包内（`src/schedprobe/**`）没有 `subprocess`、`os.system`、`os.popen`、`eval`、`exec`、
  `pickle`、`marshal`、`yaml`、`ctypes`、`shutil`；CLI 参数是结构化解析（`argparse`），
  不拼接命令行；`targets.expand_targets` 还会拒绝含 shell 元字符的输入（`SHELL_METACHARS`），
  主机名必须匹配 RFC 1123 正则。
* 唯一的"执行面"是网络客户端：`asyncio.open_connection()`（仅出站连接）、
  `socket.inet_pton()`、`asyncio.get_running_loop().getaddrinfo()`。程序**不监听端口**、
  不构造原始报文（不使用 raw socket）、不需要特权。
* 唯一的反序列化面是 JSON：`json.loads` / `tomllib.loads`；证据日志按行解析并逐条校验字段，
  不执行任何来自文件的内容。
* 建议：把不可信的配置文件/证据日志当作**数据**处理。当前实现对配置文件/日志大小没有上限检查，
  对超大文件会等比例消耗内存（这是已知的可用性边界，不是执行面）。

### 3.3 产物与日志中的敏感信息

* 工具**不接收也不保存凭据**：没有任何 token / 密码参数，环境变量只用于
  `--no-artifacts` 的临时目录（`os.environ.get("TEMP")`）与 `util.env_flag()`（当前无人调用）。
* `manifest` 内记录 `argv` 时会过滤凭据式参数（`engine._safe_argv`）：
  `--token/--password/--api-key/--secret` 的**下一个参数**会被替换为 `<redacted>`，
  形如 `password=`/`token=`/`api_key=`/`apikey=` 的值整体替换为 `<redacted>`。
* `--notes` 与 `--authorization` 会**原样**写入 run-header（`engine.run` 的 `run-header` 记录），
  不要把它们当作机密字段。
* 目标清单、端口、时间戳、结果都写进 `evidence.jsonl` / `manifest.json`。这两个文件是**证据**，
  默认是明文；分享前请按需处理（见下）。

### 3.4 脱敏（`--redact`）的能力与边界

`--redact` 的做法是：run-header 记录 `host_display: "hashed"`，控制台结果与
`results.*` 文件用 `ScanRun.display_host()` 输出伪名 `h:<12 hex>`，
伪名由 `util.hash_pair(host, 0, salt=run_id)` 生成（HMAC-SHA256，密钥是**运行 id**）。

由此得到的能力边界：

* **跨运行不可关联**：不同运行（不同 `run_id`）对同一主机给出不同伪名，可用于"不要把两次扫描
  关联起来"的展示场景；
* **不是加密匿名**：盐（run_id）就写在同一条产物里，任何拿到产物的人都可以用候选主机名
  （例如枚举一个 /24）暴力反推伪名。请把 `--redact` 当作"避免直接暴露"的便利功能，
  而不是机密保护；
* **不覆盖 stderr 日志**：`cli/main.py:main()` 只调用 `configure_logging(level)`，没有把
  `--redact` 传成 `hide_ips`/`salt`。`util.configure_logging()` 本身支持日志脱敏过滤器
  （`SecretFilter` + `redact`），但 CLI 目前没有接线。因此即使加了 `--redact`，
  WARNING/DEBUG 日志行仍可能以明文出现主机信息（例如
  `evidence log already closed; dropping record for ('10.0.9.9', 80)`）。
* 证据日志本体（`evidence.jsonl`）始终记录真实目标：`--redact` 影响的是**展示层**与
  `results.*`，不影响证据本身的设计取向。

### 3.5 证据链：防篡改**证据**，不是防篡改**证明**

`evidence.py` 为每条记录维护
`hash = sha256(canonical_json(seq/kind/data/ts/run_id/prev))`，并把前一条的 `hash` 写进
`prev`；首条记录的 `prev = sha256("schedprobe-genesis:" + run_id)`。
`verify_chain()` 会重算整条链并定位**第一条**被改动/删除/重排的记录；
`file_digest()` 计算整文件 sha256；`manifest.json` 保存该摘要，`schedprobe verify` 在
manifest 存在时会比对它（不匹配则以退出码 3 结束）。

以下行为已实测（对 `runs/` 产物做等价复制后修改）：

| 攻击者动作 | `verify_chain` 结果 |
|---|---|
| 修改记录内容 | **检出**：`record digest mismatch` |
| 删除中间记录 | **检出**：`sequence discontinuity` |
| 交换两条记录 | **检出**：`sequence discontinuity` |
| **删除末尾若干条记录（截断）** | **未检出**：仍是一条合法的链前缀 |
| **整体重写（改 run_id + 重算全部 hash/prev）** | **未检出**：整条链自洽 |

结论与使用要求：

* 哈希链只能证明"**记录序列内部自洽**"，它无法阻止：截断、整链重写、以及重放旧文件。
  它是**防篡改证据**（tamper evidence），不是**防篡改证明**（tamper proof）；
* 真正的外部锚是 `manifest.json` 里的 `evidence_sha256`。**请把 manifest 与日志分开保存/传递**
  （例如 manifest 走另一条通道，或对它另做签名/时间戳）：只有持有一个独立的摘要，
  截断与整链重写才会暴露；
* 校验 manifest 时请注意：如果 `manifest.json` 不是合法 JSON，`schedprobe verify` 目前会抛出
  未捕获的 `JSONDecodeError`（表现为"内部错误"与退出码 1），而不是干净的证据错误（退出码 3）——
  这是已知缺陷，修复方向是把 manifest 解析包成 `EvidenceError`；
* 证据的**完整性**还依赖引擎把每次探测都写进日志。当前实现存在一个已知缺陷：主循环在一次等待
  窗口内创建的派发任务可能脱离跟踪，导致运行提前结束时该探测的记录被丢弃
  （stderr 会出现 `evidence log already closed; dropping record ...`，且
  `manifest.backend_stats.probes` 会大于日志中的 `probe` 记录数）。因此**在修复前，不要仅凭
  证据日志判断"实际没有发生过对目标的探测"**；请同时检查 stderr。

### 3.6 终端与日志注入

* `reporting.sanitize()` 会丢弃 Unicode 类别为 `Cc/Cf/Cs/Co/Cn` 的字符（含 `\x1b`、`\r`、`\n`、
  bidi 控制符），并把长度截断到指定上限；表格渲染不使用 ANSI 转义。
  已知边界：`Zl/Zp` 类别（`U+2028`、`U+2029`）不在过滤集合内。
* 真实后端的 banner 是**不可信远端数据**：`backends/real.py:_sanitize_banner()` 只保留可打印
  ASCII（`0x20–0x7E`）并以 `.` 替换其它字节，读取上限 128 字节、只保留前 64 字符，
  且 banner 抓取是**只读**的（不发送任何应用层载荷）。banner 连接目前不受 `RateLimiter` 限制、
  也不复用 `_resolve()` 的解析结果，且失败时静默返回空串。
* banner 默认关闭（`--grab-banner` 显式开启），仅在真实后端生效。

### 3.7 落盘位置与 `--no-artifacts`

* 正常运行时产物写在 `output.out_dir`（默认 `runs/`）下的 `<run_id>/` 目录；
  引擎以 `EvidenceLog(..., truncate=True)` 打开日志，因此 **run_id 相同（或被显式指定为同名）
  时旧日志会被截断覆盖**；`write_manifest()` 用临时文件 + `os.replace` 原子替换 manifest。
* `--no-artifacts` **并不是"不落盘"**：它把 `out_dir` 改写成
  `%TEMP%/schedprobe-scratch-<pid>/`（Windows）或 `/tmp/schedprobe-scratch-<pid>/`（其它平台），
  产物仍会写入，且**运行结束后不会自动清理**（包内没有 `tempfile`/删除逻辑）。
  该路径可预测，在共享主机上建议改用 `--out-dir` 指向你自己的私有目录，并在用完后自行清理。
* `demo` / `bench` 不受 `--no-artifacts` 影响（该开关只在 `scan` 中生效）。

### 3.8 对目标的影响（操作安全）

* 真实后端是普通 TCP connect：不发送应用层载荷（`--grab-banner` 时也只是读取），
  不会造成目标服务的数据变更；
* `--rate-limit`（每秒探测数上限，`RateLimiter` 令牌桶，0 = 不限速）用于降低对目标的压迫；
  使用真实后端且未设置限速时 CLI 会打印 warning；
* 并发上限由 `network.concurrency` 决定（默认 128，配置校验上限 4096）；
  预算上限由 `planner.cost_budget` 决定（真实后端以毫秒计的成本单位）。

## 4. 使用授权

本工具面向**已获授权**的测试场景。工具提供的 scope 门控（§3.1）是操作者的辅助手段，
它不能代替授权本身：`--allow-public`、`--allow-dns` 等开关由使用者显式打开，
并且使用者要对"这些目标是否在授权范围内"负责。

## 5. 已知缺陷（安全相关，供修复跟踪）

1. 主机名解析后不复核地址类别（§3.1）；
2. `--redact` 不覆盖 stderr 日志；伪名盐为公开的 run_id（§3.4）；
3. 证据日志可被截断或整链重写而不被 `verify_chain` 发现——必须依赖单独保存的 manifest（§3.5）；
4. manifest 损坏时 `verify` 报"内部错误"而非证据错误（§3.5）；
5. 已知派发任务脱离跟踪 → 记录被丢弃、`backend_stats.probes` 与日志不一致（§3.5）；
6. `sanitize()` 未过滤 `Zl/Zp`（§3.6）；
7. `--no-artifacts` 仍落盘到可预测路径且不清理（§3.7）；
8. CIDR 目标在配置校验阶段被拒绝，与 CLI 帮助/`expand_targets` 的能力不一致（§3.1）。

## 6. 证据工件：脱敏边界与篡改检测能力（0.2 开发期复核）

本节是对 `--redact`、`evidence.jsonl`、`manifest.json` 与哈希链的**实测**复核结果，
可用仓库内脚本重现（`python scripts/audit_redaction.py`）。

### 6.1 `--redact` 的覆盖范围

| 工件 | `--redact` 下 | 理由 |
|---|---|---|
| 控制台表格 | 伪名化 | 展示层 |
| `results.json` / `.jsonl` / `.csv` | 伪名化 | 对外交付物 |
| `manifest.json` | 伪名化 | 摘要，非回放输入 |
| `evidence.jsonl` | **保留明文** | 回放的输入 |

`evidence.jsonl` 保留明文**不是遗漏**：回放需要从主机地址重新推导 /24 网段
（`segment_of`），伪名化会改变日志本该复现的那次调度。该例外写在日志自身的 run-header
`redaction` 块中，机器可读，附带 `reason` 与 `warning`。

伪名化算法为 `hmac_sha256(key=run_id, msg="host:0")[:12]`，前缀 `h:`。以 run_id 作盐意味着
同一目标在不同 run 中映射到不同伪名，因此**同一客户的两份日志无法按主机字段关联**。

### 6.2 哈希链能检测什么

| 编辑方式 | 能否检测 | 机制 |
|---|---|---|
| 修改某条记录的字段 | ✅ | 记录自身摘要不匹配 |
| 删除中间的记录 | ✅ | `prev` 链断裂 |
| 交换两条记录顺序 | ✅ | `prev` 链断裂 + 序号不连续 |
| 日志中出现非法 JSON | ✅ | 解析失败（`verify` 报 `unreadable at line N`）|
| 混入其他 run 的记录 | ✅ | run_id 与创世哈希不匹配 |
| **截断末尾若干条** | ❌ **仅凭日志无法检测** | 剩余前缀仍是一条自洽的链 |
| **整份重写** | ❌ **无法检测** | 哈希未加盐，能写文件的人也能重算全部哈希 |

最后两行是**能力边界，不是待修项的疏忽**。缓解措施：

- 截断：`manifest.json` 记录整份日志的 `evidence_sha256` 与字节数。**必须与日志分开保存/
  分开传递**才有外部锚定意义——若攻击者能同时改写两者，这层保护不存在。
- 整份重写：需要外部锚定（把 manifest 摘要发布到别处、或用带外签名）。当前版本不提供签名。

**结论：哈希链提供的是篡改"证据"（tamper-evidence），不是篡改"证明"（tamper-proof）。**
链的内部一致**不能**被当作数据来源真实性的证据。

### 6.3 其他会随工件一起离开的敏感内容

`--label`、`--notes`、`--authorization` 都是自由文本，原样写入证据日志的 run-header。
`--authorization` 会被并入 `notes` 字段。放入其中的任何内容都应视为**会进入审计记录**。

## 7. `schedprobe export`：可分享的派生副本（0.2 开发期新增）

证据日志是审计记录，它保留明文地址是为了逐字节回放。这使它成为**唯一不能直接交给第三方**的产物。
`schedprobe export` 写出一份**派生副本**，并且不冒充原件。

```bash
schedprobe export runs/<run> -o share/case-014.jsonl
```

### 7.1 派生副本与 `--redact` 的关系

两者都做伪名化，但**密钥来源不同**，这决定了安全性：

| | `--redact`（控制台/结果/manifest） | `export`（派生副本） |
|---|---|---|
| 伪名密钥 | `run_id` | **随机盐，不写入派生文件** |
| 密钥是否可获取 | **是**——`run_id` 就在日志里 | 否，只发布 `sha256(盐)` 承诺 |
| 读者能否穷举反推 /24 | **能**（256 次尝试）| 不能 |

这不是理论差别，有测试固定：`tests/test_export.py::test_pseudonyms_resist_a_brute_force_over_the_owning_slash_24`
用 `run_id` 对 `10.77.88.0/24` 穷举**必须失败**，再用导出报告的盐穷举**必须命中**——后半段证明穷举本身有效，
所以前半段的空结果不是循环写错了。

要用可复现的伪名（例如与某次控制台输出对照），显式传 `--salt`。

### 7.2 默认丢弃的自由文本

`--label`、`--notes`、`--authorization` 的内容在派生副本里替换为长度标记（`<redacted: N chars>`），
`--keep-notes` 可保留。**这是默认行为，因为导出这份文件的目的通常就是给外部人看。**

顺带修掉的一个真实泄漏：**证据日志会记录完整命令行**（`manifest.argv`），而
`_safe_argv()` 原先只过滤 `--token` 一类，**工具自己定义的 `--label` / `--notes` /
`--authorization` 的值是明文入库的**。现在 flag 名保留、值丢弃（`--flag value` 与 `--flag=value`
两种写法都覆盖）。**旧版本写出的日志里仍有明文 argv**，所以导出时会**再次**应用该规则，
而不是相信写入方已经处理过。

### 7.3 派生副本不是什么

- **不可回放**，并且文件自己声明这一点（`replayable: false` + `replay_note`）。
  `replay` 会（按设计）报分歧——这不是缺陷。
- **它的哈希链只对"脱敏后的内容"有效**，不是"原始日志未被篡改"的证据。
- **时间戳与原端口号不变**：`ts` 会暴露扫描发生的时间；异常端口组合有时能重新识别主机。
- `derivative_of` 记录原日志的整份摘要，使持有两者的人可以验证派生关系。

### 7.4 拒绝条件

- 源日志**验链失败**时拒绝导出——把损坏的记录洗成一份看起来干净的派生副本，是比拒绝更糟的结果。
- 目标文件已存在时拒绝覆盖。
