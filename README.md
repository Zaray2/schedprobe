# schedprobe

**把扫描的"调度决策"变成可验证、可回放、可解释的产物。**

它不是更快的扫描器。Nmap 回答"443 开不开"；schedprobe 回答"这 6 万单位预算花在哪些
探测上、为什么是这个顺序、以及这个顺序能否被第三方离线复核"。

```console
$ python -m schedprobe scan -t 127.0.0.1 -p 18711-18714 --backend real --grab-banner
  host       | port  | state    | verdict   | cost(ms) | detail
  127.0.0.1  | 18711 | open     | connected | 1        | banner=SSH-2.0-test..]0;evil.
  127.0.0.1  | 18713 | filtered | timeout   | 606      | no response within 0.600s

$ python -m schedprobe verify runs/<run>      # 链是否完整
$ python -m schedprobe replay runs/<run>/evidence.jsonl --strict   # 调度能否被重放
```

上面这段是**真实 socket 测量**（不是仿真），用 `scripts/loopback_fixture.py` 复现：
两个监听端口被正确识别、未监听端口不误判、抓到的 banner 里 ESC 控制字符被剥离、
证据链通过、回放 0 分歧。

---

## 它解决什么

三件事，每件都有测试与可复现命令：

1. **预算是硬上限。** 每次探测必须先取得租约才能启动。不变量
   `cost_spent + reserved_units <= budget` **从日志本身断言**，而不是从内部计数器——
   因此第三方不必运行这个工具就能核对。
2. **调度可回放。** 观察严格按派发槽位顺序折叠进规划器；回放从日志重新推导每条决策，
   任何分歧都被记为 divergence 并定位到具体记录号。重跑结果不一样时，你能区分是**目标变了**
   还是**工具变了**。
3. **决策可解释。** `explain` 逐条给出"为什么下一个探测选它、当时它的评分是多少、
   所在网段的健康度如何"。

**谁需要这个：** 在授权范围内做扫描、并且需要向对方（或向未来的自己）证明
"只碰了范围内的东西、结果可复核"的人。以及**调试自己的扫描器**的人——
扫描结果异常时，回放能把"网络抖动"和"调度 bug"分开。

---

## 快速开始

零运行时依赖，不装也能跑：

```bash
git clone https://github.com/Zaray2/schedprobe && cd schedprobe

# 1. 完全离线、确定性的一次完整演示（scan → verify → replay → explain）
PYTHONPATH=src python -m schedprobe demo --scenario blackhole-segment --budget 20000

# 2. 真实 TCP 扫描（默认只允许回环/私有地址；公网必须显式 --allow-public）
PYTHONPATH=src python -m schedprobe scan -t 127.0.0.1 -p 22,80,443 --backend real

# 3. 跑测试（只用标准库 unittest）
PYTHONPATH=src python -m unittest discover -s tests -t .
```

或者正常安装（需要能取到构建后端）：

```bash
pip install -e ".[dev]"     # dev 额外装 ruff / mypy / pytest
schedprobe --help
```

完整命令参考：[`docs/cli.md`](docs/cli.md)。

---

## 它明确**不**做的事

这一节放在前面，因为选错工具比配错参数更贵。

| 不做 | 说明 |
|---|---|
| **SYN / 半开扫描** | 只有 TCP connect（`asyncio.open_connection`）。**没有 raw socket、没有 stealth**。需要 SYN 扫描就用 `nmap -sS`。 |
| **UDP** | 不支持。 |
| **追求速度或覆盖** | 不声称比 Nmap / Masscan / ZMap / RustScan / Naabu 快或全。**没有与它们做过任何性能对比**——它们未在本环境运行过。 |
| **分布式编排** | 单进程。 |
| **服务/版本识别、OS 指纹** | `--grab-banner` 只做一次只读 banner 抓取，不做识别。 |
| **未授权目标** | 公网地址必须显式 `--allow-public`；默认拒绝。这是刻意的——一个没设的开关不应该变成一次未授权的扫描。 |

TCP connect 意味着**不需要特权**，也意味着在渗透场景里只能替代 `nmap -sT`。
这是取舍，不是疏忽：跨平台无特权的代价就是放弃半开扫描。

---

## 一个诚实的例子：被自己基准推翻的结论

`wide-sweep` 场景上，自适应策略的召回率是 33.3%，而固定顺序是 66.7%。这个数字一度被
本项目自己写成"自适应策略在该场景输给固定顺序"。

后来做了单变量对照实验，发现**解释是错的**：关掉剪枝、延迟剪枝、把最小样本量提到 64，
召回率**逐位不变**——剪枝在该场景几乎不触发。真实原因是**该场景只有 3 个开放端口，
且全在同一台主机的 3 个最低端口上**，所以 67% 与 33% 就是"命中 2 个"与"命中 1 个"。

把开放端口数提高到可测量量级（24–36 个，轮转分布在多台主机上）后：

| 场景（6 种子） | adaptive | fixed | random | fixed-longtimeout | 极差 |
|---|---|---|---|---|---|
| 8×1024 全活 b120k | **87.5%** | 12.5% | 2.1% | 12.5% | 0.0% |
| 8×1024 全活 b300k | **100%** | 12.5% | 4.9% | 12.5% | 0.0% |
| 8×1024 75% 死段 b300k | **100%** | 0% | 5.6% | 0% | 0.0% |
| 16×512 50% 死段 b300k | **75%** | 0% | 2.1% | 0% | 0.0% |

**没有修改任何调度算法**——实验证据不支持，剪枝不是原因。修的是基准的分辨率。
`wide-sweep` 被原样保留并标注其分辨率不足，因为删掉它只会剩下对自家策略有利的场景。

完整调查（含被证伪的假设、覆盖缺口数据、复现命令）：
[`docs/research/adaptive-analysis.md`](docs/research/adaptive-analysis.md)。

> **这些数字来自确定性仿真，不是真实网络测量。** 仿真能做的只有"在同一模型下比较两种策略"，
> 它不能外推到真实网络，也不能用来对比第三方工具。真实的 socket 测量目前只有上面回环那一段。

---

## 已知问题

（不是"未验证"。每一条都写清当前状态与影响。）

1. **不能做 SYN 扫描。** 见上表。这是设计取舍，不是待办项。
2. **哈希链是篡改证据，不是篡改证明。** 链用未加盐的 SHA-256，能写文件的人也能重算全部哈希。
   具体边界（哪些能检出、哪些**不能**）见 [`SECURITY.md`](SECURITY.md) §6.2，
   并由 `tests/test_evidence_integrity.py` 按能力边界断言：
   - 检出：改字段、删中段、换序、非法 JSON、混入其他 run 的记录
   - **不检出：截断末尾、整份重写**
3. **`evidence.jsonl` 保留明文主机地址。** 这是刻意的：回放需要从地址重新推导 /24 网段。
   该例外写在日志自身的 `redaction` 块里（机器可读，含原因与警告）。
   要对外分享用 `schedprobe export`——它写出的派生件**不可回放**，且伪名用不写入文件的随机盐，
   因此读者无法像 `--redact` 那样用日志里的 `run_id` 对 /24 穷举反推。详见 [`SECURITY.md`](SECURITY.md) §7。
4. **`wide-sweep` 的分辨率不足。** 3 个开放端口 / 3072 对，见上节。
5. **仿真基准不能外推。** 见上节脚注。
6. **未在真实网络（非回环）验证过。** DNS 解析、限速、跨网段超时都只在回环上跑过。
7. **IPv6 段语义**（强制 /64）未在真实双栈环境验证。
8. **项目名与一个 2023 年的同名仓库重复**（[`jacquetpi/schedprobe`](https://github.com/jacquetpi/schedprobe)，
   Jupyter Notebook，导出调度器统计到 CSV，3 天后停止更新）。两者功能无关，但 GitHub 搜索里
   它排在前面。名字从未做过唯一性检查——这是一个真实的疏漏。
   `schedprobe` 在系统追踪语境下另有含义（Linux 内核的 `sched_probe` 探针），所以这个名字
   天然有歧义。

---

## 项目状态

| 项 | 状态 |
|---|---|
| 测试 | **307 项通过**（`python -m unittest discover -s tests -t .`） |
| CI | **通过**——GitHub Actions，Python 3.11 / 3.12 / 3.13 三条腿各 10 步全绿 |
| 静态检查 | `ruff check` / `ruff format --check` / `mypy src/schedprobe` 全部干净 |
| 不变量矩阵 | 72 组组合（6 场景 × 2 剪枝模式 × 2 预算 × 3 规划器），无违规 |
| 运行时依赖 | **零**（纯标准库） |
| 许可证 | Apache-2.0 |

CI 徽章：见仓库页面的 Actions 标签。README 顶部不放徽章是因为徽章会与上面的表格重复，
而表格能写清"在哪条腿、跑了什么"。

---

## 文档

| 文件 | 内容 |
|---|---|
| [`docs/cli.md`](docs/cli.md) | 完整命令与参数、退出码、配置示例 |
| [`docs/architecture.md`](docs/architecture.md) | 两条关键不变量与它们的理由、模块职责、扩展规矩 |
| [`SECURITY.md`](SECURITY.md) | 脱敏边界、哈希链能检测什么（含**不能**检测什么）、导出派生件 |
| [`docs/research/adaptive-analysis.md`](docs/research/adaptive-analysis.md) | 被推翻的结论与复现命令 |
| [`docs/research/benchmark-results.md`](docs/research/benchmark-results.md) | 全部基准数据（含对本项目不利的） |
| [`docs/research/prior-art.md`](docs/research/prior-art.md) | 与 6 个现有项目的对比与差距 |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | 开发环境、测试约定、新增 planner/backend 的规矩 |
| [`CHANGELOG.md`](CHANGELOG.md) | 每个版本修了什么、为什么 |

---

## 许可

Apache-2.0，见 [`LICENSE`](LICENSE)。

本项目面向**已获授权**的资产。使用者有责任确认自己有书面授权。
