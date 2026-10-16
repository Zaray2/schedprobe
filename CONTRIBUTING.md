# 贡献指南（CONTRIBUTING）

感谢你考虑为 schedprobe 贡献代码。本文件描述**当前仓库真实的**开发方式；如果它和
`pyproject.toml` 或代码不一致，以 `pyproject.toml` 与代码为准。

## 1. 开发环境

| 项目 | 要求 | 依据 |
|---|---|---|
| Python | **>= 3.11** | `pyproject.toml: requires-python` |
| 运行时依赖 | **零依赖**（刻意如此：`dependencies = []`） | `pyproject.toml`；注释说明"需要依赖树的安全工具更难审计" |
| 可选开发依赖 | `pytest>=8.0`、`ruff>=0.6`、`mypy>=1.11` | `[project.optional-dependencies] dev` |
| 构建后端 | setuptools（`package-dir = {"" = "src"}`） | `pyproject.toml [build-system]` |
| 平台 | 纯标准库，Windows / Linux / macOS 均可；真实后端用 `asyncio.open_connection`，不需要特权 | `src/schedprobe/backends/real.py` |

安装（可编辑模式，含开发依赖）：

```bash
python -m pip install -e ".[dev]"
```

不想安装也可以直接从源码跑（`src/` 布局）：

```bash
# Windows PowerShell
$env:PYTHONPATH = "src"; python -m schedprobe --help
# POSIX
PYTHONPATH=src python -m schedprobe --help
```

**注意**：不要给包增加运行时依赖。如果某个功能需要第三方库，请先在 issue/讨论里说明理由——
"零运行时依赖"是这个项目可审计性主张的一部分（见 `docs/architecture.md` §1）。

## 2. 运行测试

测试用**标准库 `unittest`** 编写，因此不装任何东西也能跑：

```bash
python -m unittest discover -s tests -t . -v      # 全量（推荐）
python -m unittest tests.test_engine -v           # 单个模块
```

`pytest` 也能跑（用例是普通 `unittest.TestCase`），`pyproject.toml` 里已配好：

```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"
filterwarnings = ["error::DeprecationWarning"]
markers = ["slow: ...", "network: ..."]
```

```bash
python -m pytest                      # 全量
python -m pytest -m "not slow"        # 跳过真实 socket I/O 的用例
python -m pytest -m network           # 只跑需要本机网络栈的用例（仍然禁止外部主机）
```

关于仓库当前状态，有两点需要如实说明：

* `tests/` 目录下已有覆盖配置、目标校验、证据链、调度器、回放、对比与 CLI 的用例；新增测试请放在 `tests/test_*.py`，并优先复用 `tests/test_engine.py` 里的 `_config`/`_run` 辅助函数。
* 标记 `slow`（本机回环上的真实 socket I/O）与 `network`（需要本机网络栈、**不得访问外部主机**）
  已在 `pyproject.toml` 里声明，写真实 I/O 的用例请挂上对应标记。

写测试的几条约定（与代码结构有关）：

* 调度/预算/回放相关的测试请用 `FakeBackend`（确定性、零网络、成本以整数计），不要用真实后端；
* 断言异常时用异常的 `code` 属性（`errors.py` 的 `SchedProbeError.code`），不要断言消息文本；
* 不要依赖 `runs/` 里的历史产物做断言——那些文件会被新的运行覆盖；需要夹具时在测试里现生成
  （`ScanEngine(..., run_id=..., out_dir=tmp_path)`）。

## 3. 代码风格

静态检查配置全部在 `pyproject.toml` 里（不要另建配置文件）：

* **ruff**：`line-length = 108`、`target-version = "py311"`、`src = ["src", "tests"]`；
  `select = ["E","F","W","I","N","UP","B","C4","SIM","RET","PL","RUF"]`，
  并有意忽略 `PLR0911` / `PLR0912` / `PLR0915` / `PLR2004` / `SIM108`
  （`tests/*` 额外忽略 `PLR2004`、`SLF001`；`bench/*` 忽略 `T201`）。
  注意 `UP` 已启用：请用 `set[str]`、`X | None` 这类现代写法，不要用 `typing.Set` / `typing.Optional`。
* **mypy**：`packages = ["schedprobe"]`、`mypy_path = "src"`、`disallow_untyped_defs`、
  `disallow_incomplete_defs`、`check_untyped_defs`、`no_implicit_optional`、`strict_equality`。
  也就是说**新函数必须带完整类型标注**；包内有 `py.typed`，面向使用者的签名要标注准确。
* 命令（本机请自行安装 dev 依赖后执行）：

  ```bash
  python -m ruff check src tests
  python -m mypy
  ```

* 文档字符串：模块级 docstring 说明"这个模块负责什么、以及为什么这样设计"；函数 docstring 写
  契约与理由（现有代码大量采用这种"写清理由"的风格，例如 `config.py:PlannerConfig.budget_slot_ms`
  与 `engine.py:_flush_ready`）；注释用英文或中文均可，但请保持一致。

设计层面的硬规则（改代码前请先读 `docs/architecture.md` §4）：

1. **不要破坏"观察按派发槽位顺序提交"**：所有会改变规划器状态的逻辑都必须留在
   `engine._flush_ready()` 内、`commit_lock` 之下；
2. **不要破坏"预算槽记账"**：派发判定只有 `engine._has_headroom` 一条规则，回放侧对应
   `frontier.CostLedger.may_dispatch` + `Frontier._worst_case`；改一处必须同步另一处；
3. **规划器保持确定性**：决策期不读时钟/文件、不用模块级随机；`seed` 只用于初始顺序；
4. **证据格式是公共契约**：参见 `docs/architecture.md` §5.5。

## 4. 提交规范

仓库当前没有版本控制元数据（不含 `.git`），因此这里给出的是**建议采用的约定**，
便于将来接入 git 时保持一致：

* 提交信息用祈使句、英文短语，格式 `type(scope): subject`，例如：

  ```
  fix(engine): keep in-flight tasks tracked across asyncio.wait
  feat(planners): add a cost-aware rotation planner
  docs(architecture): document the budget-slot invariant
  test(replay): cover startup-batch replay for the blackhole scenario
  ```

  常用 `type`：`feat` / `fix` / `perf` / `refactor` / `docs` / `test` / `build` / `chore`。
* 一个提交只做一件事；不要混入无关的格式化（大范围重排会让 diff 无法审阅）。
* 提交前请确认：没有把真实目标信息、客户名称、凭据、或未经同意的第三方数据写进代码、测试、
  文档或 `runs/` 产物。`runs/`、`runs-trace/` 与 `scripts/` 的内容同样会进入仓库，请按这个标准检查。
* 运行产物的更新请说明**生成命令**（例如 `schedprobe demo --scenario blackhole-segment --budget 4000`），
  因为同一个 `run_id` 会被后续运行覆盖。

## 5. PR 检查清单

提交 PR 前逐条确认：

- [ ] `python -m unittest discover -s tests -t .` 通过（这是 CI 实际执行的那一条）。
- [ ] `python -m ruff check src tests` 与 `python -m mypy` 无新增告警。
- [ ] 新函数/新参数有完整类型标注与 docstring（含"为什么"）。
- [ ] **未破坏** `docs/architecture.md` §4 的 I1（槽位顺序提交）与 I2（预算槽记账）；
      如必须改动，请在同一 PR 内更新 `frontier.py`/`replay.py` 的对应实现与文档。
- [ ] 涉及 planner / engine / evidence 的改动，已用 `schedprobe demo`（固定 seed）+ `schedprobe replay`
      验证过新产生的运行可以重放；证据格式有变化时同时更新 `verify`/`diff` 的读取路径。
- [ ] 涉及 planner 策略的改动，附上 `schedprobe bench`（同一 scenario/预算/seed）的前后对比数据，
      并说明指标口径（`recall`/`precision`/`waste_ratio`/`ttfo`）来自哪个场景。
- [ ] 没有新增运行时依赖；没有引入 `subprocess`/`os.system`/`eval`/`exec`/`pickle` 之类的执行或
      反序列化面（这些是本项目的安全设计基线，见 `SECURITY.md`）。
- [ ] 文档同步：`docs/architecture.md`（结构/不变量）、`SECURITY.md`（安全相关行为）、
      `pyproject.toml`（配置项）。
- [ ] 不使用真实外部主机做测试；真实网络用例只允许本机回环或以 local fixture 形式提供。

## 6. 报告问题

* 安全问题：请走 `SECURITY.md` 的私密渠道，不要开公开 issue。
* 行为不一致（文档 vs 代码）：这是本仓库特别在意的缺陷类型，请附上"文档说的 / 代码做的 /
  复现命令"三要素。
