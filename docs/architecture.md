# schedprobe 架构说明

> **核对基准**：本文件按 2026-10-17 00:12:32 的代码状态逐模块核对（`engine.py` SHA-256 前缀
> `1042519E1765`、`planners/base.py` 前缀 `89164072C72F`、`config.py` 前缀 `A538A0471F92`）。
> 文中每个行为断言都来自对源码的阅读与实测（`runs/` 内的证据日志、`schedprobe demo/verify/replay`
> 实跑）。若本文件与当前代码不一致，**以代码为准**。

## 1. 这个项目做什么

`schedprobe` 是一个**预算感知、可审计的 TCP 探测调度器**：它不是"更快的端口扫描器"，
而是把"扫描调度决策"本身做成可验证产物（见 `docs/research/prior-art.md` 的定位说明）。

代码事实（均可在源码中核对）：

* 纯标准库实现，`pyproject.toml` 的 `dependencies = []`；`requires-python = ">=3.11"`。
* 两个后端：确定性仿真后端 `FakeBackend`（`backends/fake.py`，无网络访问、成本以抽象整数计）
  与真实 TCP connect 后端 `RealTcpBackend`（`backends/real.py`，`asyncio.open_connection`，成本以毫秒计）。
* 四个规划器：`adaptive`（默认）、`fixed`、`random`、`fixed-longtimeout`（`planners/adaptive.py`）。
* 每次运行产出一条哈希链证据日志 `evidence.jsonl` 与一份 `manifest.json`（`engine.py`、`evidence.py`）。
* CLI 子命令：`scan` / `demo` / `bench` / `verify` / `replay` / `explain` / `diff` / `hostinfo` /
  `config` / `version`（`cli/main.py`）。

## 2. 模块地图

| 模块 | 职责 | 关键符号 |
|---|---|---|
| `schedprobe/__init__.py` | 公共 API 出口与 `__version__` | `ScanEngine`、`ScanConfig`、`load_config`、`PortState`、`ProbeResult` … |
| `errors.py` | 异常层次；每个异常带机器可读 `code` 与 `exit_code` | `SchedProbeError`、`ConfigError`、`TargetValidationError`、`BudgetError`、`EvidenceError`、`BackendError`、`PolicyError` |
| `models.py` | 领域模型（不可变值对象）与目标/网段规范化 | `PortState`、`Verdict`、`ProbeResult`、`PlannedProbe`、`SegmentState`、`normalize_target`、`segment_of` |
| `util.py` | 确定性哈希与 RNG、日志脱敏 | `canonical_json`、`sha256_hex`、`seed_bytes`、`derive_rng`、`hash_pair`、`redact`、`SecretFilter`、`configure_logging`、`clamp` |
| `config.py` | 配置模型（planner/network/output/safety）、TOML/JSON 加载、校验 | `ScanConfig`、`PlannerConfig`、`NetworkConfig`、`OutputConfig`、`SafetyConfig`、`load_config`、`config_from_dict` |
| `targets.py` | 把用户输入变成目标集合；端口解析；scope 校验 | `expand_targets`、`parse_ports`、`validate_targets`、`segment_map`、`COMMON_PORTS`、`SHELL_METACHARS` |
| `planners/base.py` | 规划器基类、共享记账与 RTT 估计 | `Planner`、`SegmentBook`、`RttTracker`、`ProbePlan`、`RankUpdate`、`LiveSetChange` |
| `planners/adaptive.py` | 段自适应规划器（项目核心策略）与三个基线 | `AdaptivePlanner`、`FixedOrderPlanner`、`RandomOrderPlanner`、`FixedLongTimeoutPlanner` |
| `planners/__init__.py` | 规划器注册与构造 | `PLANNER_CLASSES`、`build_planner` |
| `backends/base.py` | 后端协议、scope 混入、置信度函数、限速器 | `Backend`、`ScopedProbeBackend`、`BackendStats`、`RateLimiter`、`ProbeRequest`、`confidence_for`、`merge_stats`、`build_backend` |
| `backends/fake.py` | 确定性仿真后端与内置场景 | `FakeBackend`、`NetworkScenario`、`scenario_from_dict`、`builtin_scenarios` |
| `backends/real.py` | 真实 TCP connect 探测、DNS 缓存、只读 banner 抓取 | `RealTcpBackend`、`_sanitize_banner`、`_classify_oserror` |
| `engine.py` | 调度主循环、并发、预算、证据写入、manifest | `ScanEngine`、`ScanRun`、`RunSummary`、`_budget_slot`、`_fill_summary` |
| `evidence.py` | 哈希链日志读写、链校验、时间线/直方图提取、manifest 落盘 | `EvidenceLog`、`EvidenceRecord`、`read_records`、`verify_chain`、`ChainStatus`、`file_digest`、`write_manifest`、`decision_timeline`、`observation_timeline`、`reason_histogram` |
| `frontier.py` | 回放侧的账本与前沿重建（与引擎解耦） | `CostLedger`、`Frontier` |
| `replay.py` | 离线重放并逐条比对调度决策 | `replay_chain`、`ReplayReport`、`first_divergence` |
| `diff.py` | 两次运行对比 + 反抖动分类 | `diff_runs`、`diff_states`、`states_from_chain`、`PortDelta`、`DiffReport`、`RULES_VERSION` |
| `bench.py` | 可复现基准 harness（仿真后端） | `BenchmarkCase`、`BenchmarkResult`、`run_benchmark`、`compare`、`default_case`、`all_cases`、`write_results`、`environment` |
| `reporting.py` | 控制台/文件渲染与文本净化 | `render_summary`、`render_run_table`、`render_verify`、`render_replay`、`render_benchmark_table`、`render_diff`、`sanitize`、`write_results` |
| `cli/console.py` | 退出码契约、输出 `Emitter`、事件循环入口、错误格式化 | `EXIT_*`、`Emitter`、`run_async`、`exit_code_for`、`configure_stdio` |
| `cli/main.py` | argparse 定义与全部子命令实现 | `build_parser`、`dispatch`、`main`、`cmd_scan`/`cmd_demo`/`cmd_bench`/`cmd_verify`/`cmd_replay`/`cmd_explain`/`cmd_diff`/`cmd_hostinfo`/`cmd_config`/`cmd_version` |

仓库中还有两处**不属于包**的内容：`scripts/`（开发期诊断脚本，如 `diagnose_replay.py`、
`_diag*.py`、`_trace_*.py`）与 `runs/`、`runs-trace/`（运行产物）。`pyproject.toml` 只把
`src/schedprobe` 打进包（`[tool.setuptools.packages.find] where = ["src"]`）。

## 3. 数据流

### 3.1 `scan`：一次运行的主链路

1. **参数 → 配置**：`cli/main.py:_config_from_args` 收集 CLI 覆盖项（点号键，如
   `planner.cost_budget`），交给 `config.load_config(path, overrides)`；后者做 TOML/JSON 解析、
   未知键拒绝（`ScanConfig.from_dict` / `_sub`），最后 `ScanConfig.validate()`。
2. **校验**：`ScanConfig.validate()` 依次调用四个子配置的 `validate()`，规范化目标
   （`models.normalize_target`）与端口，检查数量上限，最后调用 `targets.validate_targets`
   做 scope 门控。
3. **运行**：`ScanEngine.run()`（`engine.py`）：
   1. `_hosts()` → `targets.expand_targets`（CIDR 展开、去重、上限检查）；
   2. `build_planner(kind, hosts, ports, planner_cfg)` 与 `build_backend(...)`；
   3. `EvidenceLog(evidence_path, run_id, truncate=True)` 打开日志（`O_APPEND`/`"a"`，但新运行用
      `truncate=True` 覆盖同名 run_id）；
   4. 依次写 `run-header` → `config` → `plan`（含初始 frontier 及每对的 score/reason）；
   5. 启动批次：`_peek_plan()` + `_dispatch_pair()` 循环，随后写 `startup` 记录（记录本批次实际
      派发的 pair 列表与 `wave_cap`）；
   6. 调度循环：每个探测完成 → 缓冲区（`pending`，按派发槽位编号）→ `_flush_ready()` 按槽位顺序
      依次 `planner.observe()` → `_peek_plan()` → `_dispatch_pair(decision)` → `_top_up(...)` →
      `_record_probe()` 写一条 `probe` 记录；
   7. 结束条件：无在飞任务（`not inflight`）→ 写 `budget-stop`（含 reason / cost_spent / budget /
      allowance / work_remaining）；被 `cancel()` 中断则写 `cancelled`；
   8. `_fill_summary()` 汇总 → 写 `summary`；`_internal_verify()` 立即重算一次链 → 写 `manifest`
      记录（argv/平台信息）；
   9. 关闭日志 → `file_digest()` 计算文件摘要 → `write_manifest()` 原子写 `manifest.json`。
4. **呈现**：`cli/main.py:_report_run` 用 `reporting.render_summary` / `render_run_table` 打印；
   当 `--format` 为 `json|jsonl|csv` 时额外用 `reporting.write_results` 写 `results.<fmt>`。

### 3.2 证据 → 校验 / 回放 / 对比 / 解释

* **verify**（`evidence.verify_chain`）：逐条重算 `sha256(canonical_json(body))`、比对 `prev`
  与 `seq` 连续性，定位"第一条坏记录"。`cli/main.py:cmd_verify` 再检查同目录 `manifest.json`
  中的 `evidence_sha256` 是否等于当前文件摘要。
* **replay**（`replay.replay_chain`）：只读日志（零网络）。从 `run-header`/`config` 重建
  planner，用 `frontier.Frontier` + `frontier.CostLedger` 重建在飞集合与预算账本，把每条
  `probe` 记录中的 `observation` 依次喂给 `planner.observe()`，并比对：
  `rank_updates`/`live_changes` 增量、下一条决策（`decision`）的 pair/reason/timeout/priority、
  `decision_dispatched`、`extra_dispatched`、`inflight_pairs`、`reservations`，最后比对
  `segments` 与 `live_pairs` 数量。
* **diff**（`diff.states_from_chain` + `diff_states`）：每个 pair 取**最后一次观察**为"当前状态"，
  并把完整观察序列交给反抖动规则（`_confirmed`：至少两条结论一致的非 `UNDETERMINED` 观察才算
  "确认"），输出 `new`/`disappeared`/`changed`/`unstable` 四类增量。
* **explain**（`evidence.decision_timeline` + `reason_histogram`）：把每条 `probe` 记录里的
  `dispatched`（实际执行的探测）与 `decision`（调度器给出的下一条决策）摊平成一张表。
* **bench**（`bench.run_benchmark`）：对同一 `BenchmarkCase` 依次用四个规划器跑仿真后端，
  以场景的 ground truth 计算 `recall`/`precision`/`waste_ratio`/`ttfo` 等指标，`compare()` 以
  `fixed` 为基线给出差值。

### 3.3 产物布局

```
runs/<run_id>/evidence.jsonl      # 哈希链日志，每行一条记录（canonical JSON）
runs/<run_id>/manifest.json       # 摘要 + 文件 sha256 + 链头 + 统计（原子写入）
runs/<run_id>/results.{json,jsonl,csv}   # 可选，仅当 --format 非 table
```

`run_id` 默认由 `engine.ScanEngine._new_run_id()` 生成（UTC 时间戳 + 6 位随机 hex）；
`cmd_demo` / `cmd_bench` 会显式指定 `run_id`，使同名运行可重复覆盖。

### 3.4 证据记录种类（实测自 `runs/demo-blackhole-segment-seed1337`）

| kind | 出现次数 | 关键字段 |
|---|---|---|
| `run-header` | 1 | `tool`、`run_id`、`label`、`notes`、`backend`（后端 `describe()`）、`planner`、`seed`、`budget`、`targets`、`ports`、`cost_unit`、`host_display`、`concurrency`、`budget_slot_ms`、`budget_check`、`wave_rule`、`reserved` |
| `config` | 1 | `ScanConfig.to_dict()` 全量配置 |
| `plan` | 1 | `pairs`、`segments`、`frontier`（每对 host/port/score/reason） |
| `startup` | 1 | `wave_cap`、`pairs`（本批次实际派发的 pair 列表）、`budget_slot_ms` |
| `probe` | 每观测 1 条 | `dispatched`（含 `executed_timeout_s`/`attempt`）、`decision`、`decision_dispatched`、`extra_dispatched`、`frontier_preview`、`wave_cap`、`planner_generation`、`observation`、`rank_updates`、`live_changes`、`cost_spent`、`budget`、`reserved_units`、`reservations`、`sweep_allowance`、`live_pairs`、`inflight_pairs`、`rtt_estimates`、`segments`（可选 `plan_refresh`） |
| `budget-stop` | 1 | `reason`、`cost_spent`、`budget`、`allowance`、`work_remaining` |
| `cancelled` | 仅中断时 | `cost_spent`、`in_flight`、`reserved` |
| `summary` | 1 | `RunSummary.to_dict()` |
| `manifest` | 1 | `run_id`、`argv`（经 `_safe_argv` 过滤）、`cwd`、`python`、`platform` |

哈希链格式（`evidence.py`）：每条记录的 `hash = "sha256:" + sha256(canonical_json(record.body()))`，
`body` 为除 `hash` 外的全部字段（`seq/kind/data/ts/run_id/prev`）；首条记录的 `prev` 是
`GENESIS_PREFIX + sha256(run_id)`（`sha256:schedprobe-genesis:<hex>`），因此不同 run_id 不可能共享链头。
`canonical_json`（`util.py`）使用 `sort_keys=True, separators=(",", ":"), ensure_ascii=True`，
写盘与哈希共用同一个序列化器（`EvidenceRecord.to_json`）。

`manifest.json` 关键字段：`evidence_sha256`、`evidence_bytes`、`evidence_records`、`chain_head`、
`chain_verified`、`summary`、`segments`、`backend_stats`、`probe_errors`、`generated_at`。

## 4. 关键不变量

### I1「观察按派发槽位顺序提交」（dispatch-slot order）

**内容**：每个探测在派发时拿到一个单调递增的槽位号 `slot`（`engine.py:_dispatch_pair` 里的
`next_slot`）。探测完成时不直接改规划器状态，而是把观测放进缓冲区
`pending[slot]`（`engine.py:dispatch`），由 `_flush_ready()` 从 `flush_cursor` 开始，
**只按槽位顺序**把观测折叠进规划器。

**原因**（工程理由，见 `engine.py` 中该函数与预算函数的注释）：探测是并发执行的，完成顺序由网络
（或仿真的调度）决定，不可复现。如果按完成顺序喂给规划器，前沿内容与后续决策就会依赖"哪个 socket
先响应"，`replay` 将无法从日志重放出同一串决策——那样"重放"就退化成"再扫一次"。为此，
`observe → peek → plan_next → take` 必须在一次不间断的步骤内完成：整个 `_flush_ready()` 在
`commit_lock` 内执行（`engine.py:commit_lock`），并发只存在于探测侧。

**维护方式**：任何会改变规划器状态的代码都必须放在 `_flush_ready()` 内、`commit_lock` 之下；
`_record_probe` 只被 `_flush_ready` 调用。

### I2「预算槽记账」（budget slot accounting）

**内容**：每个派发中的探测在 `reserved` 账本中占一个**固定整数槽**
`_budget_slot(cfg, planner_cfg)`（默认 `PlannerConfig.budget_slot_ms = 600`，单位是后端成本单位，
对真实后端即毫秒）。派发前判定用唯一一条规则 `_has_headroom`：

```
cost_spent + sum(reserved.values()) - charged + _reservation_slot() <= budget
```

探测完成后释放该对占用的槽，并把真实成本累加到 `cost_spent`。

**原因**（`config.py:PlannerConfig.budget_slot_ms` 的注释写得很直白）：更早的实现用"自适应超时"
作为预留量，于是预算规则变成 RTT 估计器的函数——而 RTT 估计器是按探测**完成顺序**推进的，
离线重放无法重新推导"为什么这次派发被拒绝"。把预留量固定成常量后，预算规则退化为纯整数计数，
重放可以用同一套算术复现每一次拒绝。检测质量仍然由超时决定，两者被有意解耦。
`budget_slot_ms = 0` 时回退到 `max(1, base_timeout_s * 1000)`（历史行为，保留用于回归对照）。

**维护方式**：回放侧必须实现**同一条**规则：`frontier.CostLedger.may_dispatch` +
`Frontier._worst_case`（后者优先读取 `planner.config.budget_slot_ms`）。两处实现要保持一致，
否则 `replay` 会报 "budget rejection mismatch"。

### 其他不变量

* **I3 规划器无时钟、无模块级随机**：决策只依赖 `(config, seed, 观察序列)`。`random` 只在
  `RandomOrderPlanner.plan()` 里用 `random.Random(f"schedprobe-random-order:{seed}")`
  生成初始顺序；`RttTracker` 只做观测成本上的算术（`planners/base.py:RttTracker`）。
* **I4 成本单位由后端声明并被记录**：`Backend.cost_unit`（fake=`sim-unit`、real=`ms`）写入
  run-header 与 manifest，警告读者不要跨后端比较成本。
* **I5 `UNDETERMINED` 是一等结果**：`PortState.is_conclusive` 把未定与其它状态分开；
  `ProbeResult.decisive` 要求 `state != UNDETERMINED` 且 `confidence >= 0.5`。规划器不会把
  未定"降级"为 closed。
* **I6 置信度提升有界**：`backends.base.confidence_for(verdict, attempt)` 用
  `base + (1-base) * min(1, (attempt-1) * 0.5)`，第 3 次尝试即饱和到 1.0——重试不能无限制造"确定性"。
* **I7 链头唯一且 manifest 分离**：链头由 `run_id` 派生（见上）；`manifest.json` 单独落盘，
  其 `evidence_sha256` 是日志的"外部锚"（`cli/main.py:cmd_verify` 会比对它）。
* **I8 回放零网络**：`replay_chain` 只调用 `read_records` 与 planner/ledger 代码，不构造任何后端。

### 4.1 与设计意图不一致的当前实现（已核对，供修复跟踪）

本节记录"文档/注释声称的行为"与"代码实际行为"的差异。**它是活文档**：修好一条就删一条。

**当前无未决差异。** 下列条目曾在此列出，均已修复并有回归测试，保留记录以便追溯：

| 曾记录的问题 | 现状 | 证据 |
|---|---|---|
| `run-header` 的 `reserved` 被同名变量遮蔽、写成 `{}` | 已修：整数改名 `reserved_allowance`，并新增 `sweep_allowance` | `tests/test_engine.py::TestBudgetInvariant` |
| `reserved_ratio` 只被记录、不参与派发 | 已修：sweep 阶段的上限是 `budget - reserved_allowance`，确认探测时才放开到完整预算；回放按同一事件切换 | `engine._has_headroom`、`replay`（`CostLedger.sweep_cap`） |
| `confirm_min_attempts` 因提前 `pop` 计数而恒为真 | 已修：计数由 `_push_front` 消费，耗尽的 pair 进入 `_exhausted` | `tests/test_engine.py::TestAdaptivePolicy::test_confirmation_is_bounded` |
| `confirmation_timeout()` 定义了但从未被调用 | 已修：`AdaptivePlanner.timeout_for` 重写，确认探测用乘数后的超时 | `::test_confirmation_uses_a_longer_timeout` |
| `Frontier.admit(dispatched=...)` 是死参数、回放自行重推 | 已修：按记录值决定，分歧时抛 `EvidenceError` 并记为 divergence | `tests/test_engine.py::TestFrontierReconstruction` |
| 主循环 `done, inflight = await asyncio.wait(...)` 重绑定丢跟踪任务 | 已修：原地 `difference_update` + `spawned` 集合全量收尾；`manifest.probe_errors` 不再是 0 以外即静默 | `::TestEngineSafety::test_manifest_records_the_chain_and_verifies` |
| `SegmentBook.donated_budget` / `extra_budget` 的自我循环 | 已修：死代码删除；剪枝后按存活段数重分配额度 | `planners/adaptive.py` |

另有一处**行为取舍**（不是缺陷，但需要读者知道）：`--redact` 只伪名化控制台表格与结果文件，
**不**伪名化 `evidence.jsonl`。证据日志是审计记录，且回放校验需要真实主机名，因此它保留明文。
需要彻底脱敏的场景应把产物放在受控目录，而不是依赖该开关——见 `SECURITY.md`。

## 5. 扩展方式

### 5.1 新增一个 planner

接口（`planners/base.py`，`Planner` 子类必须实现 2 个方法）：

```python
class MyPlanner(Planner):
    name = "my-planner"  # 唯一名字；PLANNER_CLASSES 的键

    def plan(self) -> list[tuple[str, int]]:
        """返回全量在范围内 pair 的确定性初始顺序。"""

    def score(self, host: str, port: int) -> float:
        """越小越先派发；必须是当前规划器状态的纯函数。"""
```

可选覆盖的钩子与它们的契约：

```python
def observe(self, result: ProbeResult) -> tuple[list[RankUpdate], list[LiveSetChange]]:
    """把一条观测折叠进状态，并返回 (评分变化, 前沿成员变化)。
    必须自己调用 self.book.observe(result) 与 self._note_rtt(result)，
    并让 self.generation += 1（参考 AdaptivePlanner.observe 的实现）。"""


def timeout_for(self, pair: tuple[str, int]) -> float: ...  # 默认返回 rtt.current(host)
def initial_reason(self) -> str: ...  # 初始 reason 标记
```

注册与启用（三处，缺一不可）：

1. `planners/__init__.py:PLANNER_CLASSES` 增加 `MyPlanner.name: MyPlanner`；
2. `config.py:PLANNER_KINDS` 增加名字（否则 `PlannerConfig.validate()` 会在 CLI 解析阶段拒绝）；
3. 如需在 `bench`/`--planners` 中使用，无需额外注册（它读 `PLANNER_CLASSES`）。

义务：决策期不得读时钟/文件/随机（`RandomOrderPlanner` 仅在 `plan()` 用种子）；所有记账走
`SegmentBook`，以便与其它规划器的预算统计可比；必须能被 `replay` 逐条复现（见 §3.2 的比对项）。

### 5.2 新增一个 backend

协议（`backends/base.py:Backend`）：

```python
class Backend(Protocol):
    name: str  # 写入 run-header / manifest
    cost_unit: str  # 成本单位字符串，如 "ms"

    async def setup(self) -> None: ...
    async def probe(self, request: ProbeRequest) -> ProbeResult: ...
    async def teardown(self) -> None: ...
    def stats(self) -> BackendStats: ...
```

推荐继承 `ScopedProbeBackend`（`backends/base.py`）：它在 `__init__(allow=...)` 里保存允许的
主机集合，`_assert_scoped(host)` 在每次探测前做一次集合查找，越界即抛 `BackendError`；
它同时提供 `setup/teardown/stats` 的默认实现（统计耗时）与 `merge_stats` 的用法示例。

约定：

* **不要为普通探测结局抛异常**（timeout / refused / DNS 失败都是 `ProbeResult` 的一种）；
  只有基础设施故障才抛 `SchedProbeError` 的子类（`BackendError`），引擎会把它转成
  `UNDETERMINED`/`ERROR` 结果并在 `summary`/`manifest` 里可见（`engine.dispatch`）。
* `ProbeResult.cost_units` 必须 `>= 0`；语义由 `cost_unit` 声明。
* 必须为每次探测调用 `merge_stats(self._stats, result)`，否则 manifest 的 `backend_stats` 会失真。

注册（**当前实现的一个现实约束**）：`backends/base.py` 里的 `BACKEND_REGISTRY` /
`register_backend()` 目前**没有被 `build_backend` 使用**（该函数是 `if kind == "fake" / "real"`
的硬编码分支）。因此新增后端必须：

1. 在 `config.py:BACKEND_KINDS` 增加名字；
2. 在 `backends/base.py:build_backend` 增加分支（或先把 registry 接上，再走注册路径）；
3. 注意 `ScanEngine._backend()` 会统一传入 `scenario=` 与 `grab_banner=` 两个关键字参数——
   新后端的 `__init__` 要么接受它们，要么让 `build_backend` 在分支里过滤掉（当前
   `RealTcpBackend` 正好因此无法通过 `build_backend` 构造）。

### 5.3 新增 CLI 子命令

在 `cli/main.py` 写一个 `_add_xxx(subparsers)` 定义参数并 `set_defaults(func=cmd_xxx)`，
再实现 `def cmd_xxx(args: argparse.Namespace, emitter: Emitter) -> int`。约定：

* 只返回 `cli/console.py` 中定义的退出码常量（0/1/2/3/4/5/130）；
* 用 `emitter.say/data/warn/error` 输出，`--json` 模式下 `say()` 自动静默、`data()` 输出机器可读
  JSON；
* 抛出的 `SchedProbeError` 子类由 `main()` 统一映射为退出码（`exit_code_for`），不要自己
  `sys.exit()`；
* 需要事件循环时调用 `console.run_async(coro)`（它把 Ctrl-C 转成退出码 130）。

### 5.4 新增配置键

在对应的 dataclass 上加字段 → 在它的 `validate()` 里加约束 → 在 `cli/main.py:_config_template()`
里补一行示例（可选）。注意 `ScanConfig.from_dict` 会**拒绝未知键**（这是有意的：避免把拼错的键
静默忽略），所以配置文件与代码必须同步；`config.py:load_config` 的覆盖项用点号路径
（`"planner.cost_budget"`）。

### 5.5 改证据格式的规矩

* `canonical_json` 是唯一序列化器：新增字段时不要在别处再写一个 JSON 序列化路径；
* 已存在键的**语义**不要改（`replay`/`verify`/`diff`/`explain` 与外部读者都依赖它们）；
* 新增键必须同时考虑：`replay_chain` 的比对逻辑、`diff`/`explain` 的读取、以及本文档 §3.4；
* `kind` 字符串是公共契约；新增一种记录时，`verify_chain`/`reason_histogram` 与
  `replay_chain` 里按 `kind` 查找记录的分支（`run-header`/`config`/`plan`/`startup`）都要一起更新。

## 6. 建议的阅读顺序与常用命令

阅读顺序：`models.py` → `config.py` + `targets.py` → `planners/base.py` → `planners/adaptive.py`
→ `engine.py` → `evidence.py` + `frontier.py` + `replay.py` → `backends/*` → `cli/*` + `reporting.py`。

```bash
# 端到端演示（无网络访问、确定性）
python -m schedprobe demo --scenario blackhole-segment --budget 4000
# 校验证据链（同目录有 manifest.json 时会比对文件摘要）
python -m schedprobe verify runs/demo-blackhole-segment-seed1337
# 离线重放调度决策
python -m schedprobe replay runs/demo-blackhole-segment-seed1337
# 看一次运行为什么这么调度
python -m schedprobe explain runs/demo-blackhole-segment-seed1337 --top 20
# 四规划器对比（仿真后端）
python -m schedprobe bench --scenario healthy --budget 3000
```

（需要在未安装包时直接跑源码：设置 `PYTHONPATH=src`。）
