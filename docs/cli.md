# 命令参考

与 `src/schedprobe/cli/main.py` 的 argparse 定义逐条对应。下面每个例子都可用
`PYTHONPATH=src python -m schedprobe …` 直接运行（无需安装）。

```bash
# 两种等价的调用方式
schedprobe <command> ...              # 安装后
PYTHONPATH=src python -m schedprobe <command> ...   # 不安装，从源码
```

全局选项（放在子命令**之前或之后**都行——两者等价，有回归测试固定）：

| 选项 | 说明 |
|---|---|
| `-q`, `--quiet` | 抑制进度输出；错误仍会打印到 stderr |
| `--json` | 只输出一份可解析的 JSON 到 stdout。在 JSON 模式下**不打印任何人类文本** |
| `--log-level {DEBUG,INFO,WARNING,ERROR}` | 日志级别 |
| `--version` | 版本 |

> `--json` 的契约是"stdout 上恰好一份可解析 JSON"，由 `tests/test_cli_json_mode.py`
> 对**每个子命令**断言。若你写脚本，用 `schedprobe --json <cmd> | jq` 是安全的。

---

## `scan`

主命令：对目标执行预算受限的 TCP 探测。

```bash
schedprobe scan -t 10.0.0.5 -p 22,80,443 --budget 50000 --out-dir runs
schedprobe scan -t 10.0.0.0/28 -p 1-1024 --planner fixed --backend real
schedprobe scan -c examples/lab-config.toml          # 从配置文件
```

| 选项 | 默认 | 说明 |
|---|---|---|
| `-t`, `--target HOST` | — | 主机、主机名或 CIDR。可重复、可逗号分隔 |
| `-p`, `--ports SPEC` | `top50` | `80,443` / `1-1024` / 预设 `top50` \| `all` |
| `-c`, `--config FILE` | — | TOML 或 JSON 配置文件 |
| `--planner {adaptive,fixed,random,fixed-longtimeout}` | `adaptive` | 调度策略 |
| `--budget UNITS` | `100000` | 探测成本**硬上限** |
| `--seed SEED` | `1337` | 确定性种子 |
| `--prefix-len PREFIX_LEN` | `24` | 自适应规划的网段前缀长度 |
| `--base-timeout S` / `--min-timeout S` / `--max-timeout S` | `0.6` / `0.15` / `3.0` | 超时初值 / 下限 / 上限 |
| `--concurrency N` | `128` | 并发探测上限 |
| `--rate-limit PPS` | `0` | 探测速率上限，`0` = 不限 |
| `--confirm-attempts N` | `1` | 不确定结果的额外重试次数 |
| `--confidence-threshold F` | `0.7` | 低于此置信度视为需要确认 |
| `--prune-after N` | `3` | 连续多少次超时后剪枝该网段 |
| `--out-dir DIR` | `runs` | 产物目录 |
| `--label LABEL` | — | 短标签，写入 run header |
| `--notes NOTES` | — | 自由文本备注，写入 run header |
| `--authorization REF` | — | 授权单号（会并入 notes） |
| `--redact` | 关 | 对**控制台、结果文件、manifest** 伪名化主机标识。证据日志保留明文（见下） |
| `--format {table,json,jsonl,csv}` | `table` | 结果文件格式 |
| `--include-closed` | 关 | 表格里也列出 closed 端口 |
| `--max-rows N` / `--max-results N` | `0` | 表格行数 / 结果文件行数上限，`0` = 不限 |
| `--allow-public` | 关 | 允许公网地址。**只对你已获授权的资产使用** |
| `--allow-dns` | 开 | 允许主机名目标 |
| `--no-artifacts` | 关 | 不写任何文件（仍打印结果） |
| `--backend {fake,real}` | `fake` | `fake` 是确定性仿真，零网络访问 |
| `--scenario NAME` | — | 仿真场景（仅 `--backend fake`） |
| `--grab-banner` | 关 | 连接后做一次只读 banner 抓取并净化控制字符 |

**作用域校验**（`validate_targets`）按此顺序：回环 → 未指定/多播/保留 → 私有/链路本地 → 公网。
公网必须显式 `--allow-public`；不设开关默认拒绝，是刻意的。

### `--redact` 的真实覆盖范围

| 产物 | 是否伪名化 |
|---|---|
| 控制台表格 | 是 |
| `results.json` / `.jsonl` / `.csv` | 是 |
| `manifest.json` | 是 |
| `evidence.jsonl` | **否，保留明文** |

证据日志保留明文是**有理由的例外**：逐字节回放需要从主机地址重新推导 `/24` 网段
（`segment_of`），伪名化会改变日志本该复现的那次调度。该例外写在日志自己的
`redaction` 块里，机器可读，含 `reason` 与 `warning`。

要对外分享，用 `schedprobe export`（见下），不要手工裁剪证据日志。

---

## `demo`

零网络访问、确定性的一次完整演示，跑完 `scan → verify → replay → explain`。

```bash
schedprobe demo --scenario blackhole-segment --budget 20000
schedprobe demo --scenario segmented-sweep --budget 150000
```

产物写到临时目录并在结束时清理。

---

## `verify`

校验证据哈希链，并与 `manifest.json` 的整份摘要比对。

```bash
schedprobe verify runs/<run>                 # 目录或 evidence.jsonl 路径
schedprobe verify runs/<run>/evidence.jsonl
schedprobe verify runs/<run> --json | jq .ok
```

- 日志损坏时**不抛异常**：返回 `ok=false` 并给出 `unreadable at line N`，退出码 3。
- `manifest.json` 的 `evidence_sha256` 是**截断检测的锚**——链本身检不出末尾被删，
  必须与日志分开保存/传递才有意义。详见 [`SECURITY.md`](../SECURITY.md) §6.2。

---

## `replay`

从证据日志离线重新推导调度，逐条比对。

```bash
schedprobe replay runs/<run>/evidence.jsonl
schedprobe replay runs/<run>/evidence.jsonl --strict    # 有分歧则退出码 4
```

零分歧时退出 0。`--strict` 适合放进 CI：调度一旦不可复现就失败。

---

## `explain`

逐条给出调度决策的解释：下一个探测为什么是它、当时评分多少、所在网段健康度如何。

```bash
schedprobe explain runs/<run>/evidence.jsonl
schedprobe explain runs/<run>/evidence.jsonl --top 5
schedprobe explain runs/<run>/evidence.jsonl --pair 10.0.0.5:443
schedprobe explain runs/<run>/evidence.jsonl --reasons      # 只看原因分布
```

---

## `diff`

比较两次运行，区分"目标变了"和"覆盖范围变了"。

```bash
schedprobe diff runs/<old> runs/<new>
schedprobe diff runs/<old> runs/<new> --min-severity high
```

分类：`changed` / `new` / `disappeared` / `unstable` / `not-probed`。
对同一目标重复运行结果不同时，`unstable` 会告诉你那是抖动还是真实变化
（反抖动规则版本 `2024-11-anti-flap-1`）。

---

## `export`

写出证据日志的**可分享派生件**。

```bash
schedprobe export runs/<run> -o share/case-014.jsonl
schedprobe export runs/<run> --keep-notes
schedprobe export runs/<run> --salt deadbeef -o reproducible.jsonl
```

| 选项 | 说明 |
|---|---|
| `-o`, `--out` | 输出文件或目录。默认 `<日志>.redacted.jsonl` |
| `--salt HEX` | 伪名用的盐。**省略时用随机盐且不写入派生件**，读者无法穷举反推地址 |
| `--keep-notes` | 保留 `--label` / `--notes` / `--authorization` 原文（默认替换为长度标记） |

派生件与原件的关系：

- 头部声明 `derivative: true`、`replayable: false`、`derivative_of: <原日志整份摘要>`。
- **不可回放**——`replay` 会报分歧，这是设计而非缺陷（伪名化移除了回放用来推导网段的地址）。
- 它的哈希链只对**脱敏后的内容**有效，**不是**"原日志未被篡改"的证据。
- 时间戳与原端口号不变。
- 源日志**验链失败时拒绝导出**——把损坏的记录洗成一份看起来干净的副本，比拒绝更糟。

为什么这比 `--redact` 更适合外发：`--redact` 的伪名以 `run_id` 为盐，**而 `run_id` 就在日志里**，
所以读者可以对 `/24` 穷举 256 次还原地址。`export` 用不写入文件的随机盐。
该性质由 `tests/test_export.py` 的穷举测试固定。详见 [`SECURITY.md`](../SECURITY.md) §7。

---

## `bench`

四种规划器在同一仿真场景下的对比。

```bash
schedprobe bench --scenario blackhole-segment --budget 80000
schedprobe bench --scenario healthy --budget 5000 --save results/bench.json
```

基准工具本身有单测（`tests/test_bench.py`），并且会用固定种子验证"同一用例两次运行逐位相同"。

---

## `hostinfo`

输出运行环境信息（Python、平台、可用后端、规划器、运行时依赖），便于附在问题报告里。

```bash
schedprobe hostinfo
schedprobe hostinfo --json
```

---

## `config`

```bash
schedprobe config show                    # 打印当前生效的默认配置
schedprobe config init [PATH] [--force]   # 写出配置模板（已存在时拒绝覆盖）
schedprobe config validate FILE           # 校验配置文件
```

示例配置见 [`examples/`](../examples/)：`lab-config.toml`（仿真，零网络）
与 `authorized-engagement.toml`（真实目标，含 `allow_public` 与限速）。

---

## `version`

```bash
schedprobe version           # 版本、平台、Python、可用后端、运行时依赖
schedprobe version --json
```

---

## 退出码

| 码 | 含义 |
|---|---|
| `0` | 成功 |
| `1` | 内部错误（未预期的异常） |
| `2` | 用法 / 配置错误（含目标作用域拒绝、预算与规划器参数非法） |
| `3` | 证据问题（日志缺失、链断裂、无法解析、manifest 摘要不匹配） |
| `4` | 回放分歧（仅 `replay --strict`） |
| `130` | 被中断（Ctrl-C） |

> 曾经声明过 `EXIT_UNAVAILABLE = 5`（"环境能力不可用"），但**没有任何代码路径会返回它**。
> 一个到不了的接口不该出现在公开常量里，已在 0.2 开发期删除。将来若加入需要特权的后端，
> 再按实际条件重新引入。

---

## 环境变量

本项目**不需要任何环境变量**。唯一的例外是 `--no-artifacts` 会读 `TEMP` / `TMPDIR`
来决定临时目录位置，未设置时由标准库提供默认值。
