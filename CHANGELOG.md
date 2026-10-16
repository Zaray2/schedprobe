# Changelog

本文件遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 的结构与
[语义化版本](https://semver.org/lang/zh-CN/) 的编号规则。

本仓库当前**没有 `.git` 元数据、没有 tag、也没有发布到 PyPI**：
版本号 `0.1.0` 只在 `pyproject.toml` 与 `src/schedprobe/__init__.py:__version__` 两处出现。
因此下面这一节的状态是 **Unreleased（未发布）**。

条目原则：**只记录能从代码里核实的事实**（函数/常量名、文件、注释里写明的原因、以及本仓库存在的用例名）。
凡是本次核对无法验证的，写进末尾的「未验证」而不是写成一个肯定的结论。

## [0.1.0] — 未发布（Unreleased）

### 安全

- **`--redact` 之前没有覆盖 `manifest.json`。** 摘要清单里的 `segments[].hosts`、
  `segments[].segment` 与 `summary.first_open` 都是明文地址。manifest 只是摘要，**不是**
  `replay` 的输入（回放读的是 evidence 日志），因此对它做伪名化没有任何代价。现在
  `--redact` 覆盖 console、结果文件与 manifest，并新增 `scripts/audit_redaction.py`
  用植入式 canary 逐文件核对覆盖范围。
- **run-header 里 `"host_display": "hashed"` 是一个会误导人的字段。** 它对 console 和结果文件
  成立，却写在一个自身含明文 `targets`、并且把 `--notes`（连同其中的 `--authorization` 引用）
  原样保留的记录里。已替换为 `redaction` 块，按作用域逐项说明：覆盖了哪些产物、证据日志为何
  必须保留明文、以及对外分享时需要注意什么。
- **`evidence.jsonl` 的明文保留现在是一个被论证的例外，而不是被忽略的缺口。** 理由记录在
  日志自身的 run-header 里：逐字节回放需要从主机地址重新推导 /24 网段，把地址伪名化会改变
  日志本该复现的那次调度。没有声称脱敏后的证据仍是原件副本——反过来，明确写了它不是。

### 修复

- **`verify_chain()` 在日志损坏时抛异常，而不是返回失败状态。** 一个"有时返回状态、有时抛异常"
  的 API 是坏契约，而最容易暴露这一点的场景恰恰最重要：日志已损坏。现在它是全函数
  （total），损坏的日志返回 `ok=False` 并给出 `unreadable at line N`；CLI 的 `verify` 因此
  从打印堆栈改为打印一行 `FAIL`，退出码仍为 3。`read_records()` 保持抛异常——请求记录行的
  调用方确实无法继续，只有"给出裁决"的包装层吞掉它。
- **证据日志现在以 UTF-8 中文可读。** `canonical_json` 原先 `ensure_ascii=True`，因此
  `--notes "已授权"` 在日志里被写成 `\u5df2\u6388\u6743`。改为 `ensure_ascii=False`：字节
  一致性不变（同一个序列化器既写盘也参与哈希，`sha256_hex` 对同一字符串按 UTF-8 编码），
  但审计日志对中文使用者重新变得可读。

### 变更

- 新增 `tests/test_evidence_integrity.py`（17 项）：脱敏覆盖矩阵，以及篡改检测的**边界**——
  哪些编辑会被发现，哪些在设计上无法发现。
- 新增 `scripts/audit_redaction.py`：可复现的脱敏覆盖审计。


### 修复

- **CI 首次运行失败（ruff 250 条违规）。** 作者环境未安装 ruff，因此仓库带着 250 条 lint
  违规被推送。已逐类修复：删除一次性迁移脚本（57 条）、`ruff check --fix` 修正 121 条、
  手工修复其余（导入提升到模块顶层、行宽、`raise ... from None` 链、`SIM`/`B`/`RUF` 各类），
  并在 `pyproject.toml` 中为三处**刻意**的惰性导入加了有注释的 per-file ignore。
- **`ruff format` 与 `mypy` 在此之前从未运行过。** 现已格式化全部 45 个文件，并将 mypy 的
  25 条报错全部修掉——其中 4 条是真实缺陷而非注解缺失：
  `replay.py` 中 `recorded_live` 与同函数内一个 `dict[tuple[str, int], float]` 同名不同义；
  `engine.py` 的 `os.sys.argv`（依赖 `os` 恰好重导出 `sys`）；
  `real.py` 把 `getaddrinfo` 的 sockaddr 联合类型直接当 `str` 用；
  `evidence.py` 两处对未校验 JSON 直接 `int()`。
- **dev extra 收紧版本区间**：`ruff>=0.17,<0.18`。ruff 0.17 新增的规则集（含 `PLC0415`）
  本身就是首次 CI 失败的原因之一，不锁版本会让 CI 结果随上游漂移。


### 新增

* **调度器核心**：`ScanEngine`（`engine.py`）——并发探测、预算记账、按派发槽位顺序提交观测、
  每条记录落盘证据日志后再继续主循环；`ScanRun` / `RunSummary` 汇总。
* **四个规划器**（`planners/`）：`adaptive`（段自适应，默认）、`fixed`（输入顺序）、
  `random`（同一 seed 可复现的乱序）、`fixed-longtimeout`（固定长超时）。
  注册表 `PLANNER_CLASSES` + `build_planner()`；`config.PLANNER_KINDS` 与之一致。
* **两个后端**（`backends/`）：`FakeBackend`（确定性仿真，`cost_unit = "sim-unit"`，6 个内置场景），
  `RealTcpBackend`（`asyncio.open_connection`，不需要特权，`cost_unit = "ms"`，可选的只读 banner 抓取）。
  二者共享 `ScopedProbeBackend` 的 allow-list 检查与 `confidence_for()` 置信度函数。
* **哈希链证据日志**（`evidence.py`）：`EvidenceLog`（追加写 + 每条 flush/fsync）、
  `verify_chain()`（定位第一条坏记录）、`file_digest()`、`write_manifest()`（临时文件 + `os.replace` 原子写）、
  `observation_timeline()` / `decision_timeline()` / `reason_histogram()`。
* **离线回放**（`replay.py` + `frontier.py`）：`replay_chain()` 从日志重建 planner，
  `CostLedger` / `Frontier` 与引擎解耦，可脱离 `ScanEngine` 用手写记录做单元测试。
* **运行对比**（`diff.py`）：`diff_runs()` / `diff_states()`，输出
  `new` / `disappeared` / `changed` / `unstable` / `not-probed`，规则版本 `RULES_VERSION = "2024-11-anti-flap-1"`。
* **可复现基准**（`bench.py` + `scripts/run_published_bench.py`）：`run_benchmark()` / `budget_sweep()` /
  `compare()`；输出 `docs/research/benchmark-raw.json`，stdout 即 `bench-published.txt`
  （后者按 `.gitignore` 设计为本地/构建产物，不入库）。
* **示例配置**（`examples/`）：`lab-config.toml`（`backend = "fake"` + `scenario = "blackhole-segment"`，
  跑它不产生任何网络流量）与 `authorized-engagement.toml`（授权测试模板，含 `allow_public` 与工单号写法）。
  两者都能通过 `schedprobe config validate`。
* **CLI**（`cli/`）：`scan` / `demo` / `bench` / `verify` / `replay` / `explain` / `diff` / `hostinfo` /
  `config init|validate|show` / `version`；`--json` 机器可读输出；`--authorization REF` 把授权工单号写进 run-header。
* **退出码契约**（`cli/console.py`）：`0` 成功、`1` 内部错误、`2` 用法/配置/目标范围、`3` 证据完整性、
  `4` 回放分歧、`5` 环境能力不可用（保留，当前无路径返回）、`130` 中断。
* **范围安全校验**（`targets.py`）：CIDR 展开后再判定公网/私网/回环；拒绝 shell 元字符与非法主机名；
  `--allow-public` 才允许公网地址；保留/多播/未指定地址即使加了 `--allow-public` 也拒绝。
* **测试套件**（`tests/`，标准库 `unittest`，不需要 pytest）：`test_config.py`（配置校验/加载）、
  `test_engine.py`（段记账、健康度、RTT、规划器策略、堆不变式、账本、前沿重建、确定性/回放、预算不变量、
  引擎安全、仿真确定性）、`test_evidence.py`（哈希链、篡改检出、manifest、时间线、脱敏文本）、
  `test_reporting_cli.py`（diff 反抖动分类、渲染净化和 `write_results`、`Emitter`、退出码映射、
  `main()` 层的 CLI 契约与 bench/demo smoke）、`test_targets.py`（端口解析、CIDR 展开、scope 校验、分段）。
  运行：`python -m unittest discover -s tests -t . -v`。
* **开发期脚本**（`scripts/`，不属于发布包）：`run_published_bench.py`（跑公开基准并写
  `docs/research/benchmark-raw.json`）、`verify_invariants.py`（跨场景交叉检查预算/在飞/链/回放不变量）、
  `loopback_fixture.py`（本机回环上的真实后端端到端验证）、`diagnose_replay.py` / `diagnose_frontier.py` /
  `diagnose_trace.py`（排查回放与前沿问题的诊断工具）。
* **文档**：`docs/architecture.md`（模块地图/数据流/六条不变量/扩展方式）、
  `docs/research/prior-art.md`（先验研究，附研究限制声明）、`CONTRIBUTING.md`、`SECURITY.md`、
  `CODE_OF_CONDUCT.md`、本 CHANGELOG 与 `README.md`。

### 修复

以下每一条都是开发过程中被**基准实验、审计或回放校验**发现并改掉的真实缺陷。
「现象」来自代码注释与提交时的实测记录；「现状」是本次核对代码时看到的行为。

1. **预算硬上限被突破（150k 预算跑出 152k+）** — 现象：确认探测按配置的预算槽（`budget_slot_ms`）预留，
   但它的实际超时是基准超时的 `confirm_timeout_multiplier` 倍，于是单次探测消耗大于它预留的量；
   注释记录为「跑完比 150k 预算多出约 2.5k，而每一项单独的检查都还报告成功」。
   现状：`engine._reserve_and_check()` 改为 `worst_case = max(_reservation_slot(), int(plan.timeout_s * 1000))`，
   即租约取「预算槽」与「该探测自身最坏耗时」的**较大者**。
   覆盖：`tests/test_engine.py::TestBudgetInvariant::test_committed_cost_never_exceeds_the_budget`、
   `test_in_flight_never_exceeds_the_configured_concurrency`。
2. **并发下观察顺序不确定，回放无法复现** — 现象：探测并发执行，完成顺序由网络决定；
   若按完成顺序把观测喂给规划器，前沿内容与后续决策就会依赖「哪个 socket 先响应」。
   现状：每个探测在派发时拿到单调递增的槽位号（`next_slot`），完成时放进 `pending[slot]`，
   由 `_flush_ready()` 从 `flush_cursor` 起**只按槽位顺序**折叠进规划器；
   `observe → peek → plan_next → take` 全程在 `commit_lock` 之下完成。
   覆盖：`tests/test_engine.py::TestDeterminism::test_replay_reproduces_the_schedule`。
3. **惰性堆在整段评分变化后不重建** — 现象：一次观测会重算整个段的分数，但堆里仍是旧键，
   堆序与 `_live` 不一致，`peek()` 可能返回**不是最小评分**的 pair；这种错误在输出里看不出来，
   只表现为「调度无法复现」。现状：`Planner.mark_heap_dirty()` 在评分变化时标记重建，
   `peek()` 遇到过期键或脏标记即 O(n) `reheap()`；可选的 O(n) 不变量校验
   （`_check_heap_invariant`，由 `PlannerConfig.verify_heap` 开启）会把堆序违规记成 WARNING。
   覆盖：`tests/test_engine.py::TestPeekInvariant`（`test_peek_returns_the_live_minimum_after_a_segment_rescale`、
   `test_verify_heap_flag_detects_nothing_on_a_healthy_planner`）与
   `TestAdaptivePolicy::test_mark_heap_dirty_is_cleared_by_reheap`。
4. **`asyncio.wait` 的返回值重绑定丢掉了被跟踪的任务** — 现象：旧主循环写成
   `done, inflight = await asyncio.wait(inflight, ...)`，把返回值里的「等待中集合**快照**」赋回了 `inflight`；
   在 `await` 期间新派发的探测就不在任何被跟踪的集合里，运行可能在它仍在飞行时结束、
   关闭证据日志，于是那些探测的结果被丢弃（只留一条 `evidence log already closed` 警告）。
   现状：改为原地 `inflight.difference_update(done)`；另外用 `spawned` 记录**所有**任务，
   `finally` 里 `gather` 未完成任务并把异常收集进 manifest 的 `probe_errors`。
5. **`ScanConfig.from_dict` 对 slots dataclass 取类属性默认值导致 `scan` 崩溃** —
   现象：`cls.targets` 在 slots dataclass 上是 `member_descriptor`，`tuple(...)` 会抛 `TypeError`，
   于是**不带 `--config`** 的 `schedprobe scan -t HOST -p PORT` 在任何网络活动之前就崩了。
   现状：`ScanConfig.from_dict` 改为 `defaults = cls()`（从**实例**取默认值）。
   覆盖：`tests/test_config.py::TestScanConfig::test_unknown_keys_rejected`（该用例传入的字典不含
   `targets`/`ports`，正好走这条默认值路径）。
6. **`build_backend` 把 `scenario=` 透传给真实后端** — 现象：`ScanEngine._backend()` 统一传
   `scenario=` 与 `grab_banner=`，旧实现把整包关键字参数原样转发，于是 `RealTcpBackend.__init__()`
   抛 `TypeError: unexpected keyword argument 'scenario'`，`--backend real` 完全不可用。
   现状：`build_backend()` 按分支各取所需（`fake` 取 `scenario`，`real` 取 `grab_banner` / `rate_limit_pps`），
   其余丢弃。（该路径目前没有专项单元测试；真实后端的端到端验证脚本是 `scripts/loopback_fixture.py`。）
7. **`confirm_min_attempts` 恒为真，确认探测的「更长超时」未接线** — 现象：旧实现先 `pop` 计数器再询问
   「还有额度吗」，于是答案永远是「有」，重试没有上限；同时 `AdaptivePlanner.confirmation_timeout()`
   （确认探测用更长的超时）从未被任何代码路径调用。现状：
   `AdaptivePlanner.observe()` 在计数器用尽后把 pair 记入 `_exhausted`（同一对不能重开重试周期）；
   `Planner._confirmation_budget_available()` 同时检查 `_exhausted` 与计数；
   `AdaptivePlanner.timeout_for()` 覆盖父类实现，对 reason 以 `confirm` 开头的 pair 应用
   `confirmation_timeout()`（`min(max_timeout_s, base × confirm_timeout_multiplier)`），
   使超时成为**记录在案的决策**、因而可回放。
   覆盖：`tests/test_engine.py::TestAdaptivePolicy::test_confirmation_is_bounded`、
   `test_confirmation_uses_a_longer_timeout`。
8. **run-header 的 `reserved` 被同名变量遮蔽写成 `{}`** — 现象：`engine.run()` 先算出整数预留额，
   随后又用同名局部变量表示「在飞租约账本」这个 dict，头部捕获到的是后者，
   于是每个产物都声称 `"reserved": {}`。现状：run-header 记录整数 `reserved_allowance`，
   逐条 probe 记录记录 `reservations`（在飞 pair → 租约的映射）与 `reserved_units`，
   `startup` 记录带 `in_flight` + `leases` 边界快照。
   **仍未修**：`reserved_ratio` 依旧不参与派发判定（见「已知问题」第 1 条）。
9. **`bench --save` 忽略文件名** — 现象：旧实现只把父目录传给写盘函数，永远产出 `benchmark.json`，
   调用方要的 `results/run-7.json` 被静默换成了别的文件。现状：`bench.write_results()`
   在路径以 `.json` 结尾时**用这个名字**，否则才把它当目录并在其中写 `benchmark.json`。
10. **`replay --strict` 没有效果** — 现状：`cmd_replay()` 在重放报告 `ok` 为假时，
    不加 `--strict` 返回 `EXIT_EVIDENCE`(3)、加 `--strict` 返回 `EXIT_REPLAY`(4)；
    库调用方还可以用 `replay_chain(path, strict=True)` 直接抛 `EvidenceError`。
    也就是说「日志是有效记录但调度不可复现」和「这是一次失败的回放」现在是两种不同的退出码。
11. **`verify` 遇到损坏的 manifest 报内部错误** — 现状：`cmd_verify()` 捕获 `JSONDecodeError` 与 `OSError`，
    转成 `EvidenceError`（退出码 3，信息里带上 manifest 路径），不再走「internal error + traceback」路径。
12. **`diff` 把「预算不足没扫到」误报为新增端口** — 现象：把 4k 预算的运行与 150k 预算的运行对比，
    会得到几十个「新开放端口」，其实只是第一次运行**买不起**那些探测。
    现状：`diff.scope_from_chains()` 取两次运行**都实际观察到**的 pair 交集，
    交集之外的记为 `not-probed`（`PortDelta.kind = "not-probed"`，severity `info`），
    不再冒充 `new` / `disappeared`。
13. **CIDR 目标被范围校验拒绝** — 现象：早期实现对**未展开**的目标列表做 scope 判定，
    于是 `-t 10.0.0.0/24` 被当成主机名并报 `hostname does not look like an RFC 1123 name`。
    现状：`ScanConfig.validate()` 先 `expand_targets()` 再做 `validate_targets()`，
    判定对象是真正会被探测的具体地址（也因此能挡住跨私网/公网的 CIDR）。
    覆盖：`tests/test_targets.py::TestScanConfigScopeIntegration::test_cidr_target_accepted_and_scope_checked_after_expansion`、
    `test_public_cidr_refused`。
14. **`hostinfo` 秒/毫秒混用** — 现象：样本里存的是秒，却拿去和 `--timeout`（秒）比较完再宣称「有应答」，
    于是一个被过滤的主机也可能被报告为健康。现状：`cmd_hostinfo()` 把每次探测的
    `cost_units`（毫秒）显式换算成秒后再比较、排序、算 median/p95，并据此给出
    `--base-timeout/--min-timeout/--max-timeout` 的建议值（p95 的 3 倍，上限 4 倍）。
15. **日志净化只允许 ASCII** — 现象：第一版 `sanitize()` 只放行 ASCII，在 zh-CN 主机上把每个非拉丁标签
    静默变成 `?`。现状：允许 Unicode 认定的可打印字符，按 `unicodedata.category` 丢弃
    `Cc/Cf/Cs/Co/Cn/Zl/Zp`（涵盖 `\r`、`\n`、`\x1b` 等可劫持终端的字符），并限制长度。
16. **段健康度公式被基准证伪后重写** — 现象：旧公式
    `confidence_ema * sqrt(1 + productive) - timeout_penalty * waste_ratio` 被基准证明是**有害的**
    ——它把「被过滤段里少数健康主机」推到了队首。现状：当前公式（`models.SegmentState.health_score`）
    把只出超时的段排到最后、把已被答复的段排在未测试段之前，并按该段烧在超时上的比例缩放惩罚项；
    另加一个 ≤0.2 的 coverage 项，理由是被基准记录的「前 22 次探测里有 20 次落进那个死掉 /24」。
    覆盖：`tests/test_engine.py::TestHealthScore`（6 个用例）。
17. **启动波次吃光预算** — 现象：当预算小于「超时 × 并发」时，启动批次会把预算全花在一个尚未测量的段上，
    健康主机再也排不上（注释记录的召回从 70% 掉到 20%）。现状：`_wave_size()` 让启动批次从窄开始，
    并随**已答复段的数量**（证据，而不是时钟）逐步放宽。
18. **`--json` 曾经是空操作** — 现象：`Emitter.data()` 的两个分支曾经完全一样，`--json` 只是换了变量名。
    现状：`data()` 稳定输出 `json.dumps(..., indent=2, sort_keys=True, ensure_ascii=False)`，
    `say()` 在 json 模式下静默，`warn()` 走 stderr。
19. **Windows 中文控制台编码** — 现象：Python stdout 默认落到 `gbk` 代码页时，非 ASCII 字符会变成 `?`
    或直接抛 `UnicodeEncodeError`。现状：`cli/console.configure_stdio()` 尝试把 stdout/stderr
    重配置为 UTF-8，失败则退回可降级的净化输出（`reporting.sanitize`）。
20. **run-header 记录疑似凭据的参数** — 现状：`engine._safe_argv()` 在写入 manifest 时丢弃
    `--token/--password/--api-key/--secret` 之后的值，并把 `password=`/`token=`/`api_key=` 形状的参数替换为
    `<redacted>`。
21. **确认探测的优先级与段评分用了两套定义** — 现象：确认探测把「一个特殊数值」直接写进 `_live`，
    而 `score()` 仍在按段重算，于是堆与 `score()` 对同一个 pair 给出不同答案：
    `peek()` 返回的**不是最小评分**的 pair，回放校验器于是报告了并不存在的调度差异。
    现状：按 pair 的覆盖值集中在 `Planner._priorities`，`Planner.score()` 先查覆盖、再回落到
    `base_score()`（段策略），因此一个 pair 的优先级只有一处定义。
    覆盖：`tests/test_engine.py::TestPeekInvariant`（`peek` 在整段重评分后仍返回 live 最小值）。
22. **「运行前取消」分支下的变量作用域错误** — 现象：为「操作者取消后不得接触任何目标」新增的启动前
    检查里，`startup_limit` 只在非取消分支被赋值，而写 `startup` 记录时无条件引用它，
    于是「取消后再跑」这条路径直接抛 `UnboundLocalError`（`cancelled` 分支连启动记录都写不出来）。
    现状：`startup_limit` 在分支之前计算，取消分支只把 `startup_pairs` 置空并写 `cancelled` 记录。
    覆盖：`tests/test_engine.py::TestEngineSafety::test_cancel_before_run_produces_no_probes`。

### 变更

* **默认剪枝语义 `drop` → `defer`**（`PlannerConfig.prune_mode`，默认 `"defer"`）：
  剪枝不再直接丢弃该段的 pair，而是把它降权沉底（`deferred_penalty = 2.0`）。
  依据：`adaptive.py` / `config.py` 的注释记录，在 `blackhole-segment` 上从 `drop` 改到 `defer`
  把召回从 60% 恢复到 100%，同时相对固定顺序仍省约 25% 成本。
* **预算记账改为固定整数槽**（`PlannerConfig.budget_slot_ms = 600`）：
  早期实现用「自适应超时」作为预留量，使预算规则变成 RTT 估计器的函数——而 RTT 估计器按**完成顺序**推进，
  离线回放无法重新推导「为什么这次派发被拒绝」。设 `0` 可回退到旧行为
  （`max(1, base_timeout_s * 1000)`），保留用于回归对照。
* **确认探测的默认次数 2 → 1**（`PlannerConfig.confirm_min_attempts = 1`）：
  注释记录在 `wide-sweep` 场景下旧值 2 对结果有可测量的损害。
* 目录/产物约定：`runs/<run_id>/{evidence.jsonl,manifest.json,results.*}`；
  `demo` 与 `bench` 使用**固定** `run_id`（如 `demo-blackhole-segment-seed1337`），因此同名运行会被覆盖。
* `pyproject.toml`：`requires-python = ">=3.11"`、`dependencies = []`（零运行时依赖，刻意如此）、
  `[project.optional-dependencies] dev = [pytest, ruff, mypy]`、`py.typed` 随包发布。

### 已知问题（未修复；不要当成「已完成」）

按本次代码核对的顺序：

1. **`reserved_ratio` 只是记录**：`engine._has_headroom()` 比较的仍是完整 `budget`
   （`cost_spent + reserved + worst_case <= budget`）；`reserved_allowance` / `sweep_allowance`
   只出现在 run-header、probe 记录与 `budget-stop` 里，**不参与派发判定**。
2. **段「捐赠预算」是自循环**：`AdaptivePlanner.observe()` 里 `_donated += max(0, state.extra_budget)`
   之后再把份额写回 `extra_budget`，而 `extra_budget` 初始为 0 且只被这段代码赋值，
   因此**首次剪枝永远捐赠 0**。（`docs/architecture.md` §4.1 里提到的 `SegmentBook.donated_budget`
   在 `planners/base.py` 中并不存在。）
3. **堆不变式校验没有 CLI 开关**：`planners/base.py` 的 docstring 提到 `--verify-heap`，
   但 `cli/main.py` 没有该参数；只能通过配置文件 `[planner] verify_heap = true` 开启。
4. **未接线的后端注册表**：`backends/base.py` 的 `BACKEND_REGISTRY` / `register_backend()`
   没有被 `build_backend()` 使用（后者是 `if kind == "fake" / "real"` 的硬编码分支），
   因此新增后端必须改代码而不是注册。
5. **文档引用了不存在的文件**：`diff.py` 提到 `tests/test_diff.py`、`backends/fake.py` 提到
   `tests/test_fake_backend.py`、`planners/adaptive.py` 提到 `tests/test_adaptive_planner.py`——
   这三个文件不存在（不过 diff 的反抖动规则实际由 `tests/test_reporting_cli.py::TestDiffClassification`
   覆盖）；`models.py` 与 `bench.py` 引用的 `docs/research/benchmark-results.md`、
   `prior-art.md` 引用的 `docs/research/benchmark-design.md` 也不存在。
   另外 `bench.py` 没有自己的测试文件。
6. **`docs/architecture.md` §4.1 部分过时**：该节第 1 条（`reserved_ratio` 只记录）与
   第 6 条（`extra_budget` 自循环）与代码一致，仍然成立；第 2、3、4、5 条描述的行为
   （run-header 的 `reserved` 遮蔽、`confirm_min_attempts` 不生效、`Frontier.admit` 的 `dispatched`
   死参数、`asyncio.wait` 返回值的重绑定）**已在代码中修好**，见上文「修复」第 2、4、7、8 条。
   `CONTRIBUTING.md` 里「`tests/` 目录目前为空」的说法同样已过时。
7. **`--redact` 不覆盖证据日志**：只影响渲染层（结果表与 `results.*` 的 `host` 字段，形如 `h:<12 位 hex>`）；
   `evidence.jsonl` / `manifest.json` 中仍是明文主机标识。注意
   `tests/test_reporting_cli.py::TestCliContract::test_redacted_scan_hides_the_host_in_artifacts`
   虽然叫「in artifacts」，实际只断言了 `results.json`。

### 未验证（本次核对无法确认的事项）

* **CI 从未运行过**：仓库不含 `.git`，`.github/workflows/ci.yml` 是本次新增的定义，
  没有 GitHub Actions 的运行记录。
* **静态检查未实测**：本机未安装 `ruff` / `mypy` / `pytest`，因此 `ruff check .`、
  `ruff format --check .`、`mypy src/schedprobe` 的结果**未验证**。
  另需注意：`ruff check .` 会把 `scripts/*.py` 当应用代码检查
  （`pyproject.toml` 的 per-file-ignores 只豁免 `tests/*` 与 `bench/*`）。
* **测试套件的通过率以你本地运行为准**：本文件核对期间工作树在被并发修改，同一命令先后观察到
  `Ran 164 tests … OK`、`Ran 223 tests … failures=2, errors=2`、`Ran 225 tests … failures=4`、
  以及定稿时的 `Ran 225 tests … OK`（均在本机 Python 3.14 上）。这里记录这些观察是为了说明
  「该仓库当时的测试状态在快速变化」，**不作为发布质量声明**；请运行
  `python -m unittest discover -s tests -t . -v` 得到属于你的结论。
  （作为交叉检查，`python scripts/verify_invariants.py` 在本次核对时输出 `violations: none`：
  6 场景 × 2 剪枝模式 × 2 预算 × 3 规划器，逐条断言预算硬上限、在飞数上限、链校验、回放与探测错误。）
* **真实后端没有在本次核对中复跑**：仓库提供 `scripts/loopback_fixture.py`（在本机回环上 bind 端口、
  用真实后端探测、断言开放端口被发现且 banner 被净化），但本次只读了脚本、没有执行它；
  也没有在公网、客户网络或任何第三方目标上运行过本工具。
* **`pip install -e .` 未实测**：本次核对是用 `PYTHONPATH=src python -m schedprobe …` 直接跑源码的；
  CI 的安装步骤会覆盖这条路径。
* **不含任何第三方工具的实测对比**：`docs/research/prior-art.md` 明确声明其上游对比基于搜索摘要与
  PyPI JSON API，不含星标数 / Issue 号 / CVE 号；`bench` 的全部数字都来自本仓库的确定性仿真后端。

<!--
链接说明：pyproject.toml 里的 [project.urls] 使用占位符 OWNER（Homepage/Issues/Changelog），
因此这里不写任何「已发布」的 tag 链接——0.1.0 尚未发布，也没有 tag 存在。
-->
