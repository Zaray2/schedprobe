# 先验研究与差异化定位（Prior Art Review）

> **研究限制声明（必须如实阅读）**
>
> 本机所在网络环境对 `github.com` 与 `raw.githubusercontent.com` 的直连抓取均返回 `fetch failed`，
> 因此本文件中的对比**没有基于对源码仓库的直接克隆与逐行阅读**，而是基于：
>
> 1. 通过网络搜索检索到的公开资料摘要（各条已标注链接）；
> 2. PyPI 官方 JSON API 的真实返回值（可验证，见下方 `socketscout` 一项）；
> 3. 作者自身的既往工程经验（凡是这部分内容，均标注为 **[训练知识，未在本机验证]**）。
>
> 本文件**不包含**任何星标数、Issue 编号、CVE 编号、贡献者数量的具体数字，
> 因为没有一项在本环境中被真实抓取验证。任何未标注来源的具体数字都视为不可信。
> 使用者若要引用本项目的研究结论，应自行复核对应上游项目的当前状态。

---

## 1. 为什么要做这个方向

授权渗透测试和攻防演练中，资产发现/端口探测阶段有一个被广泛忽略的工程问题：

**扫描器几乎不解释自己为什么这么扫，也不保存单个探测判定为什么是"closed"而不是"filtered"。**

这带来三个具体、可复现的痛点（不是我的主观感受，而是可被实验验证的假设，见 `docs/research/benchmark-results.md`）：

- **P1 预算浪费**：一次扫描的 `--cost-budget` 是全局限额。如果目标网段里有一整段是被防火墙
  静默丢包（filtered）的，固定调度器会把大量预算花在"等待超时"上，真正有服务的主机会被挤到
  预算耗尽之后才轮到。用户看到的失败现象是"扫到一半停了，重要的主机没扫完"。
- **P2 结论不可复核**：现有工具输出的是一张结果表（host/port/state）。三个月后回头看报告，
  无法回答"这个 443 为什么判定为 filtered 而不是 closed"、"当时的超时是多少"、"重跑一次会不会一样"。
- **P3 重跑不可复现**：同一个目标扫两次得到不同结果时，无法区分是**目标变了**还是**调度器的随机性变了**。

## 2. 对比矩阵

| 项目 | 定位 | 技术路线 | 许可证 | 与本项目相关的不足 / 差异化机会 | 来源 |
|---|---|---|---|---|---|
| **Nmap** | 通用端口/服务扫描基线 | C/C++，libpcap，SYN/connect 扫描；`-T0..-T5` 时间模板、`--min-rtt-timeout/--max-rtt-timeout/--initial-rtt-timeout` 自适应 RTT 超时、并行度按网络质量上下调 | NPSL（非 OSI 批准，衍生作品有约束）**[训练知识，未在本机验证]** | 它**有**自适应超时（本项目不声称在这点上首创）。差距在于：(a) 决策过程不落盘，`-d` 调试日志是给人看的、不稳定、不可校验；(b) 许可证对再分发/集成有额外约束；(c) 没有"扫描会话可验证回放"的概念。 | [nmap 时间与性能章节（搜索命中）](https://raw.githubusercontent.com/r0kk0/nmap_tutorial/refs/heads/master/sections/performance_and_timing.md)、[nmap 手册超时参数（搜索命中）](http://man.m.sourcentral.org/ubuntu1204/1+nmap?pdf#9#6) |
| **Masscan** | 全网段高速 SYN 扫描 | 自有 TCP/IP 栈，异步无状态发包 | AGPL-3.0 **[训练知识，未在本机验证]** | 为速度牺牲状态；不做 per-host 判定质量评估；不产出可审计的决策轨迹。AGPL 对闭源集成不友好。 | [ZMap 论文中与 Nmap 状态维护的对比（搜索命中）](https://jyx.jyu.fi/bitstreams/6f168a52-e0b6-4bac-a4ca-327290a1e498/download#13#6) |
| **ZMap** | 互联网级单包扫描（学术） | 无状态探测 + 单包，论文报告可在 45 分钟内扫完整个 IPv4 地址空间 | Apache-2.0 **[训练知识，未在本机验证]** | 明确为"无状态、不重传"设计，因此对丢包/限速场景的判定质量不做承诺；目标是覆盖率而非"每个端口的结论可信度"。 | [ZMap 项目页](https://zmap.io/about)、[ZMap 论文条目](https://zmap.io/zmap-placeholder.pdf) |
| **RustScan** | 快速端口发现前置器 | Rust，多线程，大范围端口 + 小批量自适应；常与 Nmap 串联 | GPL-3.0 **[训练知识，未在本机验证]** | 定位是"快"和"简单"，调度是启发式批大小，没有段级预算概念，也没有决策留痕与回放。 | [RustScan 仓库（搜索命中）](https://github.com/bee-san/RustScan)、[RustScan 源码分析（搜索命中）](https://qwrdxer.github.io/2023/10/05/%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90/RustScan%E6%BA%90%E4%BB%A3%E7%A0%81%E5%88%86%E6%9E%90/) |
| **Naabu** | 现代端口扫描器（ProjectDiscovery 生态） | Go，SYN/connect 双模式，支持被动模式、CDN 排除、与 httpx/nuclei 流水线衔接 | MIT **[训练知识，未在本机验证]** | 生态衔接很好，但输出的仍是"结果集"；调度参数是静态开关（`-rate`、`-timeout`、`-retries`），没有基于已观察证据的在线重规划，也没有可校验的审计链。 | [naabu README（搜索命中，raw 链接）](https://raw.githubusercontent.com/projectdiscovery/naabu/d5a355b67a9408538e2065ff838636542f4ba4f1/README.md)、[naabu 使用文档](https://docs.projectdiscovery.io/opensource/naabu/usage) |
| **Scantron** | 分布式 nmap/masscan 编排框架 | Python/Flask + Celery + Redis + Postgres，含扫描调度、引擎池、多轮端口 diff、API 客户端 | 需自行复核（仓库未抓取成功） | 它在**编排层面**做了调度和 diff，方向最近。但它是重型分布式服务（要 Redis+Postgres+Celery），单机/离线场景成本高；决策依据落在数据库行里，不是可独立校验的证据链；没有"用一个种子精确回放整次扫描"的能力。 | [opsdisk/scantron（搜索命中）](https://github.com/opsdisk/scantron)、[scantron-2024 fork（搜索命中）](https://github.com/basmicait/scantron-2024) |
| **SocketScout** | asyncio 并发端口扫描 + banner | Python，asyncio 流水线，per-host 状态隔离，可选 Scapy SYN；依赖 `scapy/aiohttp/tabulate`，需 root/libpcap | PyPI 元数据声明 `GPL-3.0`，同时 PyPI 描述文本自称 MIT（**上游自相矛盾**，需自行复核） | 与它最接近，但它的定位是"学习异步 IO 与系统设计的教学项目"，自述为 work in progress；无调度预算、无审计链、无基准实验。可作为编排参考，不作为竞品对标核心。 | [PyPI JSON API 实际返回，本机抓取成功](https://pypi.org/pypi/socketscout/json) |

对照组还检索到但不作为核心对标（定位差异较大）：[RAPTR 协作平台（搜到简介）](https://blog.compass-security.com/2026/05/introducing-raptr/)、[RedSEC 日志聚合与 ATT&CK 映射（搜索命中）](https://github.com/alisalive/RedSec)。

## 3. 差异化定位结论

综合上表，本项目**不**去竞争"最快"或"端口覆盖最广"（那是 ZMap/Masscan/RustScan 的赛道），
也不去竞争"分布式编排"（那是 Scantron 的赛道），而是选一个**没有被现有开源工具当作一等公民**的维度：

> **把"扫描调度决策"本身变成可验证、可回放、可解释的一等产物。**

三个必须落地的差异化设计（每一项都有对应代码与测试，见 README 的"创新点—证据"映射表）：

1. **段自适应预算重规划（Segment-Aware Adaptive Replanning）**
   - 不是全局固定超时 + 固定并发，而是按 /24 段维护健康度与置信度；
   - 当某段用较小代价持续超时时，**主动剪枝该段并释放其剩余预算给健康段**；
   - 对结论置信度不足的判定，追加"确认探测"（更长超时的有界重试），把 filtered 与
     closed 的误判率显式降低，而不是把未定状态直接当成 closed 输出。
   - 与 Nmap 的 `-T` 系列的区别：Nmap 调的是**节奏参数**；本项目调的是**预算在区段之间的分配与剪枝**，
     并保留每一步的依据。

2. **确定性回放 + 哈希链证据日志（Deterministic Replay & Hash-Chained Evidence Log）**
   - 每次探测、每个调度决策、每次段状态跃迁都写进 append-only JSONL；
   - 每条记录包含前一条的 SHA-256，形成防篡改链，`verify` 可检出任何中间行被改动；
   - 调度器完全由 `seed` 驱动，`replay` 在**零网络访问**的情况下重跑同一决策序列，
     与原始日志逐条比对，从而把"结果变了"归因到"目标变了"还是"调度变了"。

3. **可复现基准实验框架（Reproducible Benchmark Harness）**
   - 同一网络拓扑、同一随机种子，横向对比 4 种调度策略（自适应 / 固定顺序 / 随机顺序 / 固定长超时）；
   - 指标：开放端口召回、首发现延迟、总代价、**浪费在 filtered 上的代价**、判定精确率；
   - 目标端是本地 fixture（`127.0.0.x` 上的真实 bound socket）或确定性模拟后端，**不依赖任何外部目标**。

## 4. 明确不声称的东西

- 不声称"全球首创"。段自适应调度、置信度重试、可复现扫描在学术界与工业界都有相关工作；
  本项目的贡献是**把这三者组合成一个可安装、零运行时依赖、可被第三方独立验证的工程实现**，
  并给出可复现的对比数据。
- 不声称"比 Nmap 快/准"。基准实验测的是**本项目内部 4 种调度策略之间的相对差异**，
  这是本项目能自证的范围（见 `docs/research/benchmark-results.md`）。
- 不声称替代 Nmap/Nuclei。本项目的设计意图是"**调度与审计层**"，可与现有扫描器互补。
