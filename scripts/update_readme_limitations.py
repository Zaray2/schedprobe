"""Update the README's 'known limitations' and 'roadmap' to match the current code.

One-shot maintenance script kept in the repository on purpose: it documents exactly which
claims were corrected and why, so a reviewer can diff the intent against the shipped text.
Re-running it is a no-op once the README has been updated.

    python scripts/update_readme_limitations.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"

REPLACEMENTS: list[tuple[str, str]] = [
    (
        r"6\. \*\*`reserved_ratio` 目前不参与派发判定\*\*。.*?确认探测的预留额度目前只是\*\*记录\*\*。",
        """6. **预算预留现在是"阶段式"生效的。** `reserved_ratio` 的生效方式：扫描阶段的上限是
   `budget − reserved_allowance`，一旦有确认探测被决定，上限放开到完整 `budget`
   （`engine._has_headroom` / `frontier.CostLedger.sweep_cap`）。这在实测中会改变结果：同一场景
   `reserved_ratio=0.15` 花 32,690、`0.5` 花 19,127（两者都找到 10 个开放端口）。
   副作用需要注意：**预留越大，扫描阶段可用的预算越小**，小预算配大预留会明显减少覆盖。""",
    ),
    (
        r"7\. \*\*`verify_heap` 只能通过配置文件开启\*\*。.*?`\[planner\] verify_heap = true`。",
        """7. **`verify_heap` 只能通过配置文件开启。** 它是 O(n) 的堆不变式校验（每次 `peek` 都比较其
   返回值与真实最小评分对），作用是把"前沿顺序错了"从静默的调度差异变成一条警告。
   CLI 没有对应开关，只能在 TOML/JSON 里写 `[planner] verify_heap = true`。""",
    ),
    (
        r"8\. \*\*文档里有指向不存在文件的引用\*\*。.*?`bench\.py` 自身没有独立的测试文件。",
        """8. **`bench.py` 没有独立的测试文件。** 基准代码由 `scripts/run_published_bench.py` 端到端执行，
   并由 `tests/test_reporting_cli.py::TestCliContract::test_bench_smoke` 覆盖 CLI 入口；但
   `BenchmarkCase` / `budget_sweep` 本身没有逐函数用例，策略比较的正确性依赖
   `scripts/verify_invariants.py` 的 72 组组合校验。（此前指向 `tests/test_diff.py`、
   `tests/test_fake_backend.py`、`tests/test_adaptive_planner.py`、
   `docs/research/benchmark-design.md` 的引用已修正。）""",
    ),
    (
        r"9\. \*\*CI 与静态检查未验证\*\*。.*?其余四条已在代码中修好（以代码为准）。",
        """9. **CI 与静态检查未在本机验证。** 本机没有 `.git`、没有安装 `ruff` / `mypy` / `pytest`，
   `.github/workflows/ci.yml` 从未在 GitHub 上跑过。测试套件本身**只用标准库**，因此
   `python -m unittest discover -s tests -t .` 在干净环境里可直接执行（本机实测通过）。
   另注：`ruff check .` 会把 `scripts/*.py` 当应用代码检查（per-file-ignores 只豁免
   `tests/*` 与 `bench/*`）。""",
    ),
    (
        r"10\. \*\*真实后端本次没有复跑验证\*\*。.*?不建议在没有书面授权的情况下这么做。",
        """10. **真实后端只在回环上验证过。** [`scripts/loopback_fixture.py`](scripts/loopback_fixture.py)
    在本机 bind 两个回环端口、用真实后端探测、并断言：开放端口被判为 `open`、未监听端口不被误判为
    open、抓到的 banner 中控制字符被剥离、证据链通过、回放零分歧（实测输出
    `chain ok: True | replay ok: True | divergences: 0`）。**没有**在公网、客户网络或真实速度链路
    上跑过；DNS 解析、限速、跨网段超时行为都未在真实网络错误条件下验证。""",
    ),
]

ROADMAP = """## 路线图

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
5. **IPv6 段语义**：`segment_of` 对 IPv6 强制 /64 下限，未在真实双栈环境验证。"""


def main() -> int:
    text = README.read_text(encoding="utf-8")
    changed = 0
    for pattern, replacement in REPLACEMENTS:
        text, count = re.subn(pattern, replacement, text, flags=re.S)
        if count:
            changed += count
    text, count = re.subn(r"## 路线图\n\n按「已核实的缺口」排序.*", ROADMAP + "\n", text, flags=re.S)
    changed += count
    README.write_text(text, encoding="utf-8")
    print(f"README: {changed} section(s) updated, {len(text)} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
