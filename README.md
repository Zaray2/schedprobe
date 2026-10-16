# schedprobe

**预算感知、可审计的 TCP 探测调度器**：面向**授权**渗透测试与攻防演练的资产探测阶段，
把「扫描调度决策」本身做成可验证、可回放、可解释的一等产物。

* 零运行时依赖（纯标准库，`pyproject.toml` 里 `dependencies = []`），Python **>= 3.11**。
* 默认后端是确定性**仿真**后端（无任何网络访问），真实后端是 `asyncio` TCP connect（不需要特权）。
* 每次运行产出**哈希链证据日志** `evidence.jsonl` + `manifest.json`，可 `verify`、可 `replay`、可 `explain`。

## 状态说明（本仓库不放徽章）

本 README **不包含任何徽章**，因为未经验证的数字与绿灯图会让读者误判项目状态。事实如下：

| 项目 | 事实 |
|---|---|
| CI 定义 | 存在于 [`.github/workflows/ci.yml`](.github/workflows/ci.yml)：Python 3.11 / 3.12 / 3.13 矩阵，`pip install -e ".[dev]"` → `python -m unittest discover -s tests -t . -v` → `ruff check .` → `ruff format --check .` → `mypy src/schedprobe` → `python scripts/run_published_bench.py`（smoke，产物写 `bench/`） |
| CI 运行结果 | **未验证**：本仓库当前不含 `.git`，该 workflow 从未在 GitHub 上执行过 |
| 本地测试套件 | 5 个测试文件（`tests/test_config.py`、`test_engine.py`、`test_evidence.py`、`test_reporting_cli.py`、`test_targets.py`），共 225 个 `unittest` 用例。**不依赖 pytest**：`python -m unittest discover -s tests -t .`。定稿实测（本机、Python 3.14）：`Ran 225 tests … OK`；工作树仍在演进，请以你自己运行的结果为准 |
| 不变量交叉检查 | `python scripts/verify_invariants.py`：6 场景 × 2 剪枝模式 × 2 预算 × 3 规划器（72 次仿真运行），逐条断言「预算硬上限 / 在飞数不超过并发 / 链可校验 / 可回放 / 无探测错误」。本次核对实测输出为 `violations: none` |
| 本地静态检查 | **未验证**：本机未安装 `ruff` / `mypy` / `pytest`，README 中的 lint/type 命令只与 `pyproject.toml` 的配置一致，未实测。另注意 `ruff check .` 会把 `scripts/*.py` 当应用代码检查（per-file-ignores 只豁免 `tests/*` 与 `bench/*`） |
| 安装步骤 | **未验证**：本次核对是直接用 `PYTHONPATH=src python -m schedprobe …` 跑源码，没有执行 `pip install -e .`；CI 的第一个安装步骤就是它，跑一次 CI 即可验证 |
| 星标 / 用户数 / CVE / 下载量 | 不声称、不引用。本文件不包含任何未实测的此类数字 |

## 它解决什么问题

授权测试里，端口探测阶段有三个可复现的工程痛点（引自 [`docs/research/prior-art.md`](docs/research/prior-art.md)）：

* **P1 预算浪费**：目标网段里若有一整段被静默丢包（filtered），固定调度器会把大量预算花在
  「等待超时」上，真正有服务的主机被挤到预算耗尽之后。用户看到的现象是「扫到一半停了」。
* **P2 结论不可复核**：现有工具输出的是一张 `host/port/state` 结果表。三个月后回头看报告，
  无法回答「这个 443 为什么判为 filtered 而不是 closed」「当时的超时是多少」。
* **P3 重跑不可复现**：同一目标扫两次结果不同，无法区分是**目标变了**还是**调度器变了**。

`docs/research/prior-art.md` 的对比矩阵覆盖 Nmap / Masscan / ZMap / RustScan / Naabu / Scantron /
SocketScout，结论是：**本项目不与它们竞争速度或端口覆盖**（那是 ZMap / Masscan / RustScan 的赛道），
**也不做分布式编排**（那是 Scantron 的赛道），而是选一个没有被现有开源工具当作一等公民的维度：

> 把「扫描调度决策」本身变成**可验证、可回放、可解释**的产物。

未声称的东西（同样来自 `prior-art.md` §4）：不声称全球首创；不声称比 Nmap 快或准；不替代
Nmap / Nuclei。基准实验只测**本项目内 4 种调度策略之间的相对差异**。

`prior-art.md` 自身也标注了研究限制：撰写时本机无法直连 `github.com` / `raw.githubusercontent.com`，
因此上游对比基于搜索摘要 + PyPI JSON API，**不含**星标数、Issue 号、CVE 号。

## 三个差异化设计

### ① 段自适应预算重规划（Segment-Aware Adaptive Replanning）

* **实现**：[`src/schedprobe/planners/adaptive.py`](src/schedprobe/planners/adaptive.py)（`AdaptivePlanner` 的四条规则 R1–R4）、
  [`src/schedprobe/planners/base.py`](src/schedprobe/planners/base.py)（`SegmentBook` / `RttTracker` / 惰性堆 `peek`）、
  [`src/schedprobe/models.py`](src/schedprobe/models.py)（`SegmentState.health_score`）。
* **做什么**：按段（默认 /24，`planner.prefix_len`）维护健康度与置信度；某段连续超时达阈值即剪枝
  （`prune_mode = defer` 默认：把该段的 pair「降权沉底」而不是丢弃，`drop` 则移出前沿）；
  `undetermined` 或置信度低于 `confidence_threshold` 的判定会以**更长的超时**做有界确认探测；
  `cost_budget` 是硬上限，`--budget` 之外还有 `reserved_ratio` 记录为确认探测预留的额度。
* **与 Nmap `-T` 的区别**：Nmap 调的是节奏参数（超时/并发模板）；本项目调的是**预算在段之间的
  分配与剪枝**，并且每一步都留下依据。
* **测试**：[`tests/test_engine.py`](tests/test_engine.py) 中的 `TestAdaptivePolicy`（剪枝 / defer / drop /
  确认探测有界 / 确认探测超时更长）、`TestHealthScore`、`TestSegmentBook`、`TestPeekInvariant`、
  `TestRttTracker`。
* **可复现命令**：`python -m schedprobe demo --scenario blackhole-segment --budget 4000`（本机实测，见下）
  与 `python -m schedprobe bench --scenario blackhole-segment --budget 80000`。

### ② 确定性回放 + 哈希链证据日志（Deterministic Replay & Hash-Chained Evidence Log）

* **实现**：[`src/schedprobe/evidence.py`](src/schedprobe/evidence.py)（`EvidenceLog` / `verify_chain` / `write_manifest`）、
  [`src/schedprobe/replay.py`](src/schedprobe/replay.py)（`replay_chain`）、
  [`src/schedprobe/frontier.py`](src/schedprobe/frontier.py)（`CostLedger` / `Frontier`，与引擎**解耦**、
  可用手写记录做单元测试）。
* **做什么**：每条记录是 `{"seq","hash","prev","kind","run_id","ts","data"}` 一行 JSON，
  `hash = sha256(canonical_json(record_without_hash))`，`prev` 是上一条的 `hash`，
  首条的 `prev` 由 `run_id` 派生（`sha256:schedprobe-genesis:<hex>`），因此不同 run 不可能共享链头。
  `replay` **零网络访问**：从 `run-header` + `config` + `plan` + `startup` 重建 planner，
  用 `Frontier` 重建在飞集合与预算账本，按**派发槽位顺序**重放每条观测，逐条比对
  `rank_updates` / `live_changes` / 下一条决策（pair、reason、timeout、priority）/ `decision_dispatched` /
  `extra_dispatched` / `inflight_pairs` / `reservations`，最后比对段状态与前沿大小。
* **测试**：[`tests/test_evidence.py`](tests/test_evidence.py)（`TestEvidenceLog`、`TestChainVerification` 含
  改行/删行/换序/改创世/中途改 run_id 的检出、`TestManifest`、`TestTimelines`、`TestRedaction`）；
  [`tests/test_engine.py`](tests/test_engine.py) 的 `TestDeterminism`（同配置两次运行决策相同、
  `replay` 复现调度、篡改日志后 `replay` 报分歧）、`TestFrontierReconstruction`、`TestCostLedger`。
* **可复现命令**：`python -m schedprobe verify runs/<run-id>`、
  `python -m schedprobe replay runs/<run-id> --strict`、`python -m schedprobe explain runs/<run-id> --top 20`。
* **注意**：哈希链是防篡改**证据**而不是**证明**——能重写整个文件的人也能重写整条链；
  `manifest.json` 里的文件摘要必须与日志**分开保存**才有外部锚定意义（见「已知限制」）。

### ③ 可复现基准（Reproducible Benchmark Harness）

* **实现**：[`src/schedprobe/bench.py`](src/schedprobe/bench.py)（`BenchmarkCase` / `run_benchmark` /
  `budget_sweep` / `compare` / `default_case`）、
  [`scripts/run_published_bench.py`](scripts/run_published_bench.py)（跑全套并写
  `docs/research/benchmark-raw.json`）、[`src/schedprobe/backends/fake.py`](src/schedprobe/backends/fake.py)（确定性世界模型）。
* **做什么**：同一场景、同一 seed、同一预算，横向对比 4 种策略（adaptive / fixed / random /
  fixed-longtimeout），指标：开放端口召回、精度、`cost_spent`、**花在 filtered 上的代价** `waste_ratio`、
  首次发现代价 `ttfo`、**达到全召回的代价** `cost_to_full_recall`。仿真后端用
  `sha256(seed|host|port)` 派生每对抖动，**与探测顺序无关**，因此数字可复现。
* **不做什么**：不与 Nmap / Masscan / RustScan / Naabu **同台**比较——那些工具在这里没有被运行过。
  `bench` 的 payload 里也写着这句话（`note` 字段）。
* **测试**：**没有**针对 `bench.py` 的独立测试文件（未验证项，见「已知限制」第 8 条）；
  可依赖的覆盖是：仿真后端的确定性（[`tests/test_engine.py`](tests/test_engine.py) 的
  `TestBackendDeterminism`——同一对在不同探测顺序下成本相同、`loss_rate` 只会让正向证据退化为超时）
  与 CLI 层 smoke（[`tests/test_reporting_cli.py`](tests/test_reporting_cli.py) 的
  `TestCliContract::test_bench_smoke` / `test_bench_honours_the_save_path`）。
* **可复现命令**：`python scripts/run_published_bench.py`（本机与任何机器上同样可跑，无需网络）。

## 快速开始

```bash
# 1. 安装（可编辑模式；零运行时依赖）
python -m pip install -e .

# 或者完全不安装，直接从源码运行（src/ 布局）
#   Windows PowerShell:  $env:PYTHONPATH = "src"; python -m schedprobe --help
#   POSIX:               PYTHONPATH=src python -m schedprobe --help

# 2. 端到端演示：无网络访问、确定性、一次跑完 scan → verify → replay → explain
schedprobe demo --scenario blackhole-segment --budget 4000 --seed 1337

# 3. 真实 TCP connect 扫描（默认只允许回环/私有地址；公网目标必须显式 --allow-public）
schedprobe scan -t 127.0.0.1 -p 80,443 --backend real --rate-limit 50 --format json

# 4. 四规划器对比（仿真后端，确定性）
schedprobe bench --scenario blackhole-segment --budget 80000 --save bench/blackhole.json

# 5. 证据链与调度决策的可验证性
schedprobe verify runs/<run-id>
schedprobe replay runs/<run-id> --strict
schedprobe explain runs/<run-id> --pair 10.0.20.5:80 --top 20
schedprobe diff runs/<run-id-old> runs/<run-id-new>
```

**本项目不需要任何环境变量**，因此仓库里**没有** `.env.example`。全库只有一处读取环境变量：
Windows 下 `--no-artifacts` 用 `TEMP` 选临时目录（`cli/main.py`）；
`cli/console.py:env_default()` 是给嵌入方的 helper，包内没有任何调用点。
工具不接受也不读取任何凭据。

## 命令与参数（与 `cli/main.py` 的 argparse 定义一致）

全局（写在子命令**之前**）：`--version`、`-q/--quiet`、`--json`、
`--log-level {DEBUG,INFO,WARNING,ERROR}`（默认 `WARNING`）。

| 子命令 | 用途 |
|---|---|
| `scan` | 对已校验目标跑一次探测，产出证据日志与 manifest |
| `demo` | 端到端演示（仿真后端，无网络访问） |
| `bench` | 在一个确定性场景上对比规划器 |
| `verify` | 校验哈希链，并（可选）与 manifest 的文件摘要比对 |
| `export <run>` | 写出可分享的**脱敏派生件**（默认随机盐，读者无法穷举反推；不可回放，文件自己声明这一点） | `schedprobe export runs/<run> -o share.jsonl` |
| `replay` | 离线重放并逐条比对调度决策 |
| `explain` | 展示一次运行的决策时间线 |
| `diff` | 两次运行对比，带反抖动分类 |
| `hostinfo` | 量一个主机的往返行为，用来选超时 |
| `config` | `init` / `validate` / `show` 配置文件 |
| `version` | 打印版本与运行环境信息 |

### `scan`

| 参数 | 说明（缺省值） |
|---|---|
| `-t, --target HOST` | 主机、域名或 CIDR；可重复，也可用逗号分隔 |
| `-p, --ports SPEC` | `80,443`、`1-1024`，或预设 `top50` / `all`；缺省 `top50`（`targets.COMMON_PORTS`，50 个端口） |
| `-c, --config FILE` | TOML 或 JSON 配置文件 |
| `--planner NAME` | `adaptive` \| `fixed` \| `random` \| `fixed-longtimeout`（缺省取配置文件里的值，默认 `adaptive`） |
| `--budget UNITS` | 探测成本的**硬上限**（单位由后端决定） |
| `--seed INT` | 确定性种子（默认 1337） |
| `--prefix-len INT` | 段前缀长度（默认 24，允许 8–32） |
| `--base-timeout S` / `--min-timeout S` / `--max-timeout S` | 超时下限/基准/上限（默认 0.15 / 0.6 / 3.0） |
| `--concurrency INT` | 并发上限（默认 128，允许 1–4096） |
| `--rate-limit PPS` | 每秒探测上限，`0` = 不限速（真实后端建议设置） |
| `--confirm-attempts N` | 不确定结果的额外重试次数（默认 1） |
| `--confidence-threshold F` | 低于该置信度视为不确定（默认 0.7） |
| `--prune-after N` | 段内连续超时多少次后剪枝（默认 3） |
| `--out-dir DIR` | 产物目录（默认 `runs`） |
| `--label` / `--notes` / `--authorization REF` | 写入 run-header 的标签、备注、授权工单号（审计用） |
| `--redact` | 在渲染输出中伪名化主机标识（见「已知限制」第 4 条） |
| `--format {table,json,jsonl,csv}` | 控制台/结果文件格式（默认 `table`） |
| `--include-closed` | 结果表里也列出 closed 端口 |
| `--max-rows N` / `--max-results N` | 控制台行数上限（默认 200，0 = 不限）/ 结果文件行数上限（默认 0） |
| `--allow-public` | 允许公网地址（**仅限你有授权的资产**） |
| `--allow-dns` | 允许域名目标 |
| `--no-artifacts` | 不把运行产物写到磁盘（改用系统临时目录） |
| `--backend {fake,real}` | `fake` = 仿真（默认），`real` = 真实 TCP connect |
| `--scenario NAME` | 仿真场景（仅 `fake`）：`healthy` \| `blackhole-segment` \| `segmented-filtered` \| `segmented-sweep` \| `mixed-lossy` \| `wide-sweep` |
| `--grab-banner` | 对开放端口做一次**只读** banner 抓取（仅 `real`，可选） |

### 其他子命令

* `demo [--scenario NAME] [--budget INT] [--seed INT] [--out-dir DIR] [--format {table,json}]`
  —— 缺省 `blackhole-segment` / `4000` / `1337` / `runs` / `table`。
* `bench [--scenario NAME] [--budget INT] [--seed INT] [--planners a,b,c] [--out-dir DIR] [--format {table,json}] [--save FILE]`
  —— `--planners` 缺省 `adaptive,fixed,random,fixed-longtimeout`；`--save` 写完整 JSON
  （文件名以 `.json` 结尾则**用这个名字**，否则在该目录下写 `benchmark.json`）。
* `verify RUN [--manifest FILE]` —— `RUN` 是运行目录或 `evidence.jsonl`；缺省用同目录的 `manifest.json`。
* `replay RUN [--strict]` —— 有分歧时：不加 `--strict` 以退出码 `3` 报告，加 `--strict` 以退出码 `4` 报告。
* `explain RUN [--pair HOST:PORT] [--top N] [--reasons]` —— `--top` 默认 25，`0` = 全部；`--reasons` 只打印原因直方图。
* `diff LEFT RIGHT [--save FILE]` —— `LEFT` 较旧、`RIGHT` 较新，输出 `new` / `disappeared` / `changed` /
  `unstable` / `not-probed` 分类（反抖动规则版本见 `diff.RULES_VERSION`）。
* `hostinfo -t HOST [-p SPEC] [--samples N] [--timeout S] [--allow-public] [--out-dir DIR]`
  —— `-t` 必填，`-p` 缺省 `80,443`，`--samples` 缺省 3，`--timeout` 缺省 1.0；给出
  `--base-timeout/--min-timeout/--max-timeout` 的建议值（p95 往返的 3 倍，上限 4 倍）。
* `config init [PATH] [--force]` / `config validate PATH` / `config show`
  —— `init` 缺省写 `schedprobe.toml`，已存在时拒绝覆盖（除非 `--force`）。
* `version` —— 打印工具版本、Python 版本、可用规划器与后端、`runtime_dependencies: []`。

### 配置文件与示例

`examples/` 里有两个可以直接用的 TOML（本次核对时都通过 `schedprobe config validate`）：

* [`examples/lab-config.toml`](examples/lab-config.toml) —— **仿真**配置（`backend = "fake"`、
  `scenario = "blackhole-segment"`），跑它不会发出任何网络流量：
  `schedprobe scan -c examples/lab-config.toml`（实测：8 目标 × 7 端口，`cost_spent=23861` ≤ `budget=60000`）。
* [`examples/authorized-engagement.toml`](examples/authorized-engagement.toml) —— 授权测试的模板：
  `targets` 用 RFC 5737 文档地址，**用前必须换成授权书里的资产**，并把 `safety.allow_public` 置
  `true`（默认为 `false`，从不把「忘记设置」变成一次未授权扫描），同时把工单号留在 `notes` 里。

配置里能写的东西与 CLI 的关系：`scan` 的每个开关都对应配置里的一个点号键
（`--budget` → `planner.cost_budget`、`--rate-limit` → `network.rate_limit_pps` …），
**CLI 覆盖文件**；`scenario` 也可以写在配置里（CLI 的 `--scenario` 优先）。
生成一份带全部注释的模板：`schedprobe config init my.toml`（缺省写 `schedprobe.toml`，
已存在时拒绝覆盖，除非加 `--force`）。注意：配置解析**拒绝未知键**
（拼错的键会被报错而不是被静默忽略），所以 `config init` 的模板与代码是同步的起点。

模板（35 个键）**不是**完整清单：本次核对时它没有列出
`planner.prune_mode`、`planner.deferred_penalty`、`planner.confirm_max_drop_ratio`、
`planner.budget_slot_ms`、`planner.verify_heap`、`planner.stale_window`、`safety.allow_ulist`
这些只写在配置文件里、**没有 CLI 开关**的键（`scenario` 两种方式都支持，CLI 的 `--scenario` 优先）。
要拿完整清单，以 `src/schedprobe/config.py` 的 dataclass 字段为准：

```bash
python -c "import dataclasses, schedprobe.config as c; print([f.name for f in dataclasses.fields(c.PlannerConfig)])"
```

## 真实运行输出示例

### A. 基准（`docs/research/benchmark-raw.json`）

下面的数字抄自 [`docs/research/benchmark-raw.json`](docs/research/benchmark-raw.json) 的 `headline` 段
（结构化、可机读；该文件不在 `.gitignore` 里，会随仓库一起发布）。同一次运行的 stdout 存档是 `bench-published.txt`
（`python scripts/run_published_bench.py > bench-published.txt`），但它被 `.gitignore` 忽略
（见 [`.gitignore`](.gitignore)：benchmark 输出按设计只作为构建产物/本地文件存在），
所以在 GitHub 上可能看不到这个文件——重跑脚本即可重建，或者直接看构建产物里的 `bench-published.ci.txt`（CI 上传）。
两者数字来自同一次运行；若它们与代码不符，以你本地重跑的结果为准。

```
### blackhole-segment budget=80000 (17 hosts x 7 ports)
  adaptive           recall=100.0% cost=   77783 waste= 99.8% opens=10/10 full_recall_cost=28908
  fixed              recall=100.0% cost=   50519 waste= 99.8% opens=10/10 full_recall_cost=50501
  random             recall=100.0% cost=   50519 waste= 99.8% opens=10/10 full_recall_cost=48717
  fixed-longtimeout  recall=100.0% cost=   50519 waste= 99.8% opens=10/10 full_recall_cost=50501
```

```
### segmented-sweep budget=150000 (17 hosts x 64 ports)
  adaptive           recall=100.0% cost=  149142 waste= 98.9% opens=3/3 full_recall_cost=16606
  fixed              recall=  0.0% cost=  150000 waste=100.0% opens=0/3 full_recall_cost=None
  random             recall=  0.0% cost=  149409 waste= 99.6% opens=0/3 full_recall_cost=None
  fixed-longtimeout  recall=  0.0% cost=  150000 waste=100.0% opens=0/3 full_recall_cost=None
```

```
### segmented-filtered budget=40000 (29 hosts x 7 ports)
  adaptive           recall= 91.7% cost=   39840 waste= 99.8% opens=11/12 full_recall_cost=None
  fixed              recall= 58.3% cost=   39649 waste= 99.9% opens=7/12 full_recall_cost=None
```

```
### wide-sweep budget=60000 (3 hosts x 1024 ports)
  adaptive           recall= 33.3% cost=   59401 waste=100.0% opens=1/3 full_recall_cost=None
  fixed              recall= 66.7% cost=   59402 waste=100.0% opens=2/3 full_recall_cost=None
```

**怎么读这些数字**：`full_recall_cost` 是「第 n 个开放端口被观察到时的累计代价」（n = 该场景的开放端口总数），
也就是**找到全部答案要付多少钱**——在这两组数据里 adaptive 是 28908 / 16606，而 `fixed` 是 50501 /
（150000 预算内根本没找全）。`waste` 高不代表策略差：`defer` 模式在健康段扫完后**仍会**去探那一段
被丢弃的静默丢包主机，代价都记在 `waste` 里，这是「不丢召回」的代价；而 `cost_spent` 高、`recall` 也高
正是这个设计的预期形态。反过来，`wide-sweep` 一段是 adaptive **输**的场景，一并列出。

**数据来源与环境**：`docs/research/benchmark-raw.json` 的 `environment` 字段为
`{"machine": "AMD64", "platform": "Windows", "python": "3.14.0", "schedprobe": "0.1.0"}`。
全部数字来自**确定性仿真后端**（seed 1337，`prune_mode=defer`），既不是真实网络的测量，
也不是与第三方扫描器的对比。

### B. `demo`（本机实测）

```console
$ python -m schedprobe demo --scenario blackhole-segment --budget 4000 --seed 1337
=== schedprobe demo (no network access, deterministic) ===
scenario : blackhole-segment (one healthy /24, one fully filtered /24, one small mixed /24)
budget   : 4000 cost units, seed 1337

[step 1/4 scan]
  planner              : adaptive
  backend              : fake
  cost_unit            : sim-unit
  pairs_total          : 119
  dispatched           : 41
  budget               : 4000
  cost_spent           : 3719
  budget_used_ratio    : 93.0%
  cost_of_filtered     : 3600
  waste_ratio          : 96.8%
  open                 : 10
  closed               : 25
  filtered             : 6
  pruned_segments      : 1

OK   evidence chain: runs/demo-blackhole-segment-seed1337/evidence.jsonl
      records      : 48
      record kinds : budget-stop=1, config=1, manifest=1, plan=1, probe=41, run-header=1, startup=1, summary=1

OK   replay: demo-blackhole-segment-seed1337 (planner=adaptive)
      observations  : 41
      decisions     : 41
      rank updates  : 805
      live changes  : 0
      frontier match: True
      segments match: True

[step 4/4 explain] why the sweep went where it went
  decisions recorded : 41
  reason histogram   : {"sweep-segment-first": 41}
  pruned segment     : 10.0.20.0/24 after 6 probes (3 consecutive timeouts after 3 probes)
```

（输出为节选；实际输出还会打印逐端口结果表与 `reproduce this exact run with:` 命令行。
本次实测用 `--out-dir <临时目录>` 运行，上面的路径行按缺省形式写成 `runs/...`，其余数字逐字来自该次运行。
`cost_spent=3719` 相对于预算 4000 的差额，是因为该场景在 41 次探测后已无事可做而提前停止；
同一命令在确定性仿真后端上是可复现的，但**代码改动会改变这些数字**——上面就是本次核对时的实际输出，
不是从别处抄来的。）

## 退出码

契约定义在 [`src/schedprobe/cli/console.py`](src/schedprobe/cli/console.py)，并由 `schedprobe --help` 的 epilog 复述：

| 码 | 含义 | 由谁返回 |
|---|---|---|
| `0` | 成功 | 所有子命令的正常路径 |
| `1` | 未预期的内部错误（stderr 打印 `internal error:` 与 traceback） | `main()` 的最后一道 except |
| `2` | 用法 / 配置 / 目标范围非法（`ConfigError`、`TargetValidationError`、`BudgetError`、`PolicyError`、`BackendError`，以及其它 `SchedProbeError`）、argparse 参数错误 | `exit_code_for()` / argparse |
| `3` | 证据完整性失败（哈希链断裂、manifest 摘要不匹配）；`replay` 有分歧但未加 `--strict` 时也用它报告 | `cmd_verify` / `cmd_replay` / `cmd_scan` |
| `4` | 回放分歧（`replay --strict`、`demo` 的重放步骤） | `cmd_replay` / `cmd_demo` |
| `5` | 环境能力不可用（常量已定义并导出，但**当前没有任何代码路径返回它**） | —（保留） |
| `130` | 被操作者中断（Ctrl-C） | `run_async()` → `exit_code_for()` |

## 架构（一页）

```text
        ┌──────────────────── CLI：cli/main.py（argparse，全部子命令）────────────────────┐
        │ scan · demo · bench · verify · replay · explain · diff · hostinfo · config · version │
        └───────────────────────────────┬───────────────────────────────────────────────────┘
                                        │ ScanConfig（config.py：planner / network / output / safety 校验）
                                        ▼
  targets.py ──expand+scope 校验──► engine.ScanEngine.run()
                                        │
                                        ├─ planners/   adaptive | fixed | random | fixed-longtimeout
                                        │              └─ SegmentBook + RttTracker + 惰性堆（peek 不变式）
                                        ├─ backends/   fake（确定性仿真，cost_unit=sim-unit）
                                        │              real（asyncio TCP connect，cost_unit=ms）
                                        └─ 每条观测 → 按派发槽位顺序提交（_flush_ready，commit_lock 之下）
                                        ▼
        runs/<run_id>/evidence.jsonl   ← 哈希链：sha256(canonical_json(body)) + prev（首条由 run_id 派生）
        runs/<run_id>/manifest.json    ← 文件 sha256 / 字节数 / 链头 / 摘要 / 后端统计（原子写）
        runs/<run_id>/results.{json,jsonl,csv}   ← 仅当 --format 非 table
                                        │
     ┌──────────────────────┬───────────┴───────────────┬────────────────────────┐
     ▼                      ▼                           ▼                        ▼
 verify_chain          replay_chain                 diff_runs           decision_timeline
 （链校验，退出码 3）   （Frontier+CostLedger 重建   （反抖动分类 +       + reason_histogram
                         在飞集合与账本，退出码 4）   not-probed 区分）    （explain / --reasons）
```

数据流、六条关键不变量（槽位顺序提交、预算槽记账、规划器无时钟、成本单位、`UNDETERMINED` 是一等结果、
链头唯一且 manifest 分离）以及「新增 planner / backend / 子命令 / 配置键 / 证据字段」的规矩，
都在 [`docs/architecture.md`](docs/architecture.md) 里逐条说明。

## 创新点 → 证据映射

| # | 创新点 | 实现文件 | 测试文件 | 可复现命令 |
|---|---|---|---|---|
| ① | 段自适应预算重规划 | [`planners/adaptive.py`](src/schedprobe/planners/adaptive.py)、[`planners/base.py`](src/schedprobe/planners/base.py)、[`models.py`](src/schedprobe/models.py)（`health_score`） | [`tests/test_engine.py`](tests/test_engine.py) `TestAdaptivePolicy` / `TestHealthScore` / `TestSegmentBook` / `TestPeekInvariant` / `TestRttTracker` | `python -m schedprobe demo --scenario blackhole-segment --budget 4000`；`python -m schedprobe bench --scenario blackhole-segment --budget 80000` |
| ② | 确定性回放 + 哈希链证据日志 | [`evidence.py`](src/schedprobe/evidence.py)、[`replay.py`](src/schedprobe/replay.py)、[`frontier.py`](src/schedprobe/frontier.py) | [`tests/test_evidence.py`](tests/test_evidence.py)（全部 5 个类）、[`tests/test_engine.py`](tests/test_engine.py) `TestDeterminism` / `TestFrontierReconstruction` / `TestCostLedger` / `TestBudgetInvariant`、[`tests/test_reporting_cli.py`](tests/test_reporting_cli.py) `TestCliContract`（`scan → verify → replay --strict` 全链路、篡改日志后 `verify` 必须报错） | `python -m schedprobe verify runs/<id>`；`python -m schedprobe replay runs/<id> --strict`；`python scripts/verify_invariants.py`（6 场景 × 2 模式 × 2 预算 × 3 规划器，逐条断言预算/在飞/链/回放，本次实测 `violations: none`） |
| ③ | 可复现基准 | [`bench.py`](src/schedprobe/bench.py)、[`scripts/run_published_bench.py`](scripts/run_published_bench.py)、[`backends/fake.py`](src/schedprobe/backends/fake.py) | 无独立测试文件；CLI 层由 [`tests/test_reporting_cli.py`](tests/test_reporting_cli.py) `TestCliContract::test_bench_smoke` / `test_bench_honours_the_save_path` 覆盖，仿真确定性由 [`tests/test_engine.py`](tests/test_engine.py) `TestBackendDeterminism` 覆盖 | `python scripts/run_published_bench.py`（写 `docs/research/benchmark-raw.json`） |
| ④ | 目标/范围安全校验（CIDR 展开后再做 scope 判定、拒绝 shell 元字符） | [`targets.py`](src/schedprobe/targets.py)、[`config.py`](src/schedprobe/config.py)（`validate`） | [`tests/test_targets.py`](tests/test_targets.py)（`TestValidateTargets`、`TestScanConfigScopeIntegration`、`TestExpandTargets`） | `python -m schedprobe scan -t 10.0.0.0/30 -p 80 --budget 500`；`python -m schedprobe scan -t 8.8.8.8 -p 80`（应被拒绝，退出码 2） |
| ⑤ | 配置校验（拒绝未知键、拒绝静默修复） | [`config.py`](src/schedprobe/config.py) | [`tests/test_config.py`](tests/test_config.py)（全部 5 个类） | `python -m schedprobe config validate schedprobe.toml` |
| ⑥ | 运行对比 + 渲染净化 + 退出码契约 | [`diff.py`](src/schedprobe/diff.py)、[`reporting.py`](src/schedprobe/reporting.py)、[`cli/console.py`](src/schedprobe/cli/console.py) | [`tests/test_reporting_cli.py`](tests/test_reporting_cli.py)（`TestDiffClassification`、`TestSanitize`、`TestRenderers`、`TestWriteResults`、`TestEmitter`、`TestExitCodes`、`TestCliContract`） | `python -m schedprobe diff runs/<old> runs/<new>` |

## 已知限制

1. **只有 TCP connect 扫描**。真实后端用 `asyncio.open_connection`（`backends/real.py`）：**没有**
   SYN / 半开扫描、**没有** UDP，也不需要特权。除可选的一次只读 banner 抓取外不做服务识别、
   不做版本探测、不做 OS 指纹。
2. **仿真后端是模型，不是真实网络**。`docs/research/benchmark-raw.json`（以及作为其 stdout 存档的
   `bench-published.txt`）里的**所有**数字都来自确定性仿真（成本模型是 `latency_ms`
   + 每条 pair 由 `sha256(seed|host|port)` 派生的抖动，丢包只作用于正向证据）。
   这些数字不能外推到真实网络，也不能用来对比第三方工具。
3. **哈希链是防篡改证据，不是证明**。能重写整个 `evidence.jsonl` 的人也能重写整条链，
   所以 `manifest.json` 里的 `evidence_sha256` 必须与日志**分开保存/分开传递**才有外部锚定意义。
   另外：**从日志本身无法检测「末尾被截断」**——截断只剩前缀时链依然自洽（
   `tests/test_evidence.py::TestChainVerification.test_truncation_is_not_detectable_from_the_log_alone`
   把这条限制固定成了用例）。
4. **`--redact` 是伪名化，不是加密，而且不覆盖证据日志——但另有工具补这个缺口。**
   `--redact` 只影响渲染层（控制台表格、`results.json/jsonl/csv` 的 `host` 字段）与 `manifest.json`；
   `evidence.jsonl` 保留明文主机，因为回放要从地址重新推导 /24 网段。**这一例外现在是机器可读地声明的**
   （run-header 的 `redaction` 块，含 `reason` 与 `warning`）。
   要对外分享，用 **`schedprobe export`**：它写出声明的派生件（`derivative: true`、
   `replayable: false`、`derivative_of: <原摘要>`），**用一个不写入文件的随机盐做伪名**——
   因此读者无法像 `--redact` 那样用日志里的 `run_id` 对 /24 穷举 256 次反推地址。
   该性质由 `tests/test_export.py` 的穷举测试固定。**但派生件仍不是原件**：时间戳与端口不变，
   且它的哈希链只对脱敏后的内容有效。详见 `SECURITY.md` §6–7。

5. **`wide-sweep` 上自适应更差，但这个数字撑不起关于策略的结论。** 该场景 adaptive recall
   33.3%、`fixed` 66.7%。看起来是剪枝的锅，但**实验已证伪**：关掉剪枝 / 延迟剪枝 / 提高最小
   样本量，召回率一个字节都没变（剪枝在该场景几乎不触发）；覆盖缺口对每个策略都是 ~2900/3072，
   由预算上限而非策略造成。真正的原因是**该场景只有 3 个开放端口，且全在同一主机的 3 个最低
   端口上**——67% 与 33% 就是"命中 2 个"与"命中 1 个"。
   把开放端口数提高到可测量量级（24–36 个，轮转分布在多台主机上）后，adaptive 在 4 组配置上
   以 **75–100% 对 0–12.5%** 胜出，6 种子极差 0.0%。完整数据与复现命令见
   [`docs/research/adaptive-analysis.md`](docs/research/adaptive-analysis.md)。
   **本次调查没有修改任何调度算法**——证据不支持，剪枝不是原因。修的是基准的分辨率。

6. **预算预留现在是"阶段式"生效的。** `reserved_ratio` 的生效方式：扫描阶段的上限是
   `budget − reserved_allowance`，一旦有确认探测被决定，上限放开到完整 `budget`
   （`engine._has_headroom` / `frontier.CostLedger.sweep_cap`）。这在实测中会改变结果：同一场景
   `reserved_ratio=0.15` 花 32,690、`0.5` 花 19,127（两者都找到 10 个开放端口）。
   副作用需要注意：**预留越大，扫描阶段可用的预算越小**，小预算配大预留会明显减少覆盖。
7. **`verify_heap` 只能通过配置文件开启。** 它是 O(n) 的堆不变式校验（每次 `peek` 都比较其
   返回值与真实最小评分对），作用是把"前沿顺序错了"从静默的调度差异变成一条警告。
   CLI 没有对应开关，只能在 TOML/JSON 里写 `[planner] verify_heap = true`。
8. **`bench.py` 没有独立的测试文件。** 基准代码由 `scripts/run_published_bench.py` 端到端执行，
   并由 `tests/test_reporting_cli.py::TestCliContract::test_bench_smoke` 覆盖 CLI 入口；但
   `BenchmarkCase` / `budget_sweep` 本身没有逐函数用例，策略比较的正确性依赖
   `scripts/verify_invariants.py` 的 72 组组合校验。（此前指向 `tests/test_diff.py`、
   `tests/test_fake_backend.py`、`tests/test_adaptive_planner.py`、
   `docs/research/benchmark-design.md` 的引用已修正。）
9. **CI 的静态检查现已在本机跑通，但只在 Python 3.14 上。** 仓库首次推送时
   `ruff check .` 失败（250 条违规）——原因正是作者环境没装 ruff。现在 `ruff check`、
   `ruff format --check`、`mypy src/schedprobe` 与 225 项测试**全部在本地通过**，
   相关工具版本已在 `pyproject.toml` 的 dev extra 中收紧（`ruff>=0.17,<0.18`，
   因为 ruff 0.17 新增的规则集正是首次失败的原因之一）。
   仍**未验证**的是 CI 矩阵里的 Python 3.11 / 3.12 两条腿——本机只有 3.14。
10. **真实后端只在回环上验证过。** [`scripts/loopback_fixture.py`](scripts/loopback_fixture.py)
    在本机 bind 两个回环端口、用真实后端探测、并断言：开放端口被判为 `open`、未监听端口不被误判为
    open、抓到的 banner 中控制字符被剥离、证据链通过、回放零分歧（实测输出
    `chain ok: True | replay ok: True | divergences: 0`）。**没有**在公网、客户网络或真实速度链路
    上跑过；DNS 解析、限速、跨网段超时行为都未在真实网络错误条件下验证。

## 路线图

按「已核实的缺口」排序，而不是按愿望清单。

**已完成**（0.1.0 开发期间由审计与基准发现，逐条见 `CHANGELOG.md`）：

- ✅ `reserved_ratio` 接入预算规则：扫描阶段上限 = `budget − reserve`，确认阶段放开。
- ✅ 删除剪枝捐赠的自循环死代码；改为按存活段数重分配额度。
- ✅ 修正指向不存在文件的文档引用；补齐 `docs/research/benchmark-results.md`。
- ✅ `--redact` 的帮助文本改为如实描述（仅渲染层伪名化）。

**待办**：

1. **`--redact` 覆盖证据日志。** 现在 `evidence.jsonl` 保留明文主机，因为回放校验需要它们。
   可行方案是增加 `--export-redacted`：输出一份主机已伪名化、并显式声明"不可回放"的副本。
2. **`bench.py` 的单元测试。** 目前只有 CLI 冒烟与 72 组组合校验，缺少对 `budget_sweep`、
   `BenchmarkResult` 聚合逻辑的直接用例。
3. **`--verify-heap` CLI 开关**，或明确它只能通过配置文件开启（当前状态）。
4. **真实网络下的验证**：DNS 解析、限速、非回环 RTT 下的超时估计，都需要在授权环境里跑一遍。
5. **IPv6 段语义**：`segment_of` 对 IPv6 强制 /64 下限，未在真实双栈环境验证。
