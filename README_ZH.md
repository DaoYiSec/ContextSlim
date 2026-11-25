# context-slim

[English](README.md) | [中文说明](README_ZH.md)

面向**渗透测试**、**代码审计**与**日常代码开发**的跨 Agent 省 Token Skill 与零依赖工具集（完全兼容 `agentskills.io` 开放标准）。

可在 **Claude Code**、**OpenAI Codex CLI**、**Cursor**、**Gemini CLI**、**Antigravity**、**OpenCode** 等主流编码 Agent 中直接使用。

---

## 为什么需要 `context-slim`？

通用省 token 套路在安全和工程实战中经常“省错地方”：
1. **渗透扫目录用截断会丢洞**：`ffuf` / `gobuster` 跑出 5,000 条 `403`，中间夹着 2 条 `200 OK`——常规首尾截断直接把真漏洞丢进省略区。
2. **代码审计按修改行数排 Diff 会漏高危**：大段业务重构把“删掉 1 行鉴权检查 (`- if not is_admin: return 403`)”挤出预算，且依赖 lockfile 一刀切排除会漏掉供应链 CVE 变动。
3. **日常开发只看函数片段容易改错返工**：不看文件顶部 `imports` 与类型定义就动手改函数，写错→测试挂→回读文件，反而多花几倍 token。
4. **长上下文无脑 Fork 子代理反向烧钱**：在 >100k 会话里全量 Fork 继承高价模型和完整历史，成本远高于“状态外置账本 + Fresh 轻量子代理”。

---

## 核心特性

- **零三方依赖**：全部工具基于 Python 3.9+ 标准库实现，复制或软链即可使用。
- **跨 Agent 原生兼容**：核心 `SKILL.md`、`references/` 与 `scripts/` 不依赖任何单一厂商私有字段或私有环境变量；提供 `cslim` 统一 CLI。
- **三大场景专项压缩引擎 (`cslim compress`)**（默认开启 `--max-line-chars 320` 防单行压缩 JS/Base64 炸窗）：
  - `--mode anomaly`（渗透）：对 `ffuf` / `gobuster` / `feroxbuster` / `dirsearch` / `httpx` 的 JSON/JSONL/文本按 `(status, length_bucket, words)` 聚类，支持路径反射型 403/404 自动归并，**100% 保留离群异常项**。
  - `--mode nmap` / `--mode sqlmap`（渗透）：过滤 `nmap`（stdout/`-oG`/`-oX`）下线主机与关闭端口噪声，以及 `sqlmap` `[INFO] testing` 探针刷屏，精准保留开放端口、Payload、DBMS 与表数据。
  - `--mode sast`（审计）：解析 Semgrep / Nuclei / Bandit / Trivy / SARIF JSON，剥离长篇规则科普，按 `(rule_id, file)` 聚合输出紧凑四元组。
  - `--mode http`（渗透）：裁剪 `curl -i` / HTML 响应中的 `<style>`/`<svg>`/大段脚本与超长 ViewState 值，保留响应头、`<form>`/`<input>`、JS API 路径与错误文本。
  - `--mode grep`（审计/开发）：将 `rg`/`grep` 结果按文件聚行，自动过滤注释命中并折叠 `tests/`/`mocks/` 噪声。
  - `--mode testlog`（开发）：剔除 `PASS` / Docker/pip/npm 构建与 `pytest warnings summary` 刷屏，精准抓取首个 Root Error 及其堆栈窗口与汇总。
  - `--mode skeleton`（通用）：提取多语言符号、安全注解（`@PreAuthorize`、`@csrf_exempt`、K8s/Nginx）、JSON 顶层键与 Markdown 标题，并标注 `[Header/Imports: L1-Lx]` 行段。
- **单次多段切片与命令包装（省输出更省轮次）**：
  - `cslim slice <file> --symbols fn1,fn2`（或 `--ranges`）：**1 条命令**合并拉取顶部 `Imports` + 多个分散函数体，消灭多次 `Read` 往返。
  - `cslim run -- <cmd>`：透传真实退出码；小输出原样直出，大输出自动压缩并保存原始日志到 `/tmp`。
- **安全感知 Diff 裁剪 (`cslim diff --profile dev|audit`)**：
  - 按完整 hunk 边界裁剪，绝不腰斩 `@@` 块；
  - `audit` 模式自动压缩依赖清单版本变化（支持 `package-lock.json` v2/v3、`Cargo.lock`、`go.sum`、`pom.xml`），并对 1–5 行安全敏感/删减条件分支变更给予最高权重保护。
- **外置状态账本 (`cslim ledger`)**：
  - 维护 `.context-slim/ledger.md`，记录资产面、有效 Cookie/Token、已确认漏洞、**已排除死胡同**、Source-to-Sink 追踪链、`scan-map --entrypoints` 项目与路由索引。
- **Claude Code 可选强化 Hook (`adapters/claude-code/hooks/`)**：
  - `bash_guard.py`：拦截未重定向/未压缩的扫描器、`find .` 与大文件 `cat`，自动限制无界 `git log`、`rg --max-columns` 与 `grep -r --exclude-dir`；
  - `read_guard.py`：拦截大文件无范围 `Read`，并在 `stderr` 直接返回符号骨架与 `cslim slice` 提示；
  - `context_monitor.py`：同时挂载 `UserPromptSubmit`、`PostToolUse`（长循环内实时预警）与 `PreCompact`（压缩前账本保留提醒）；
  - `dispatch_guard.py`：禁止子代理嵌套递归，并约束 scoped 子代理显式指定模型。

---

## 快速安装

```bash
git clone https://github.com/DaoYiSec/ContextSlim.git
cd ContextSlim

# 1. 标准安装到 ~/.agents/skills/context-slim + 安装 `cslim` 到 ~/.local/bin/
./install.sh

# 2. 一键链接到本机所有常见 Agent（Claude Code / Codex / Cursor / Gemini CLI / Antigravity / OpenCode）
./install.sh --target all

# 3. 如果使用 Claude Code 且需要硬拦截 Hook：
./install.sh --target claude --with-claude-hooks
# 卸载 Hook（保留原有设置并生成 .bak 备份）：
./install.sh --uninstall-claude-hooks

# 4. 仅安装到当前项目仓库（团队共享）：
./install.sh --project /path/to/your-repo
```

> 对于不原生支持 Hook 的 Agent（Codex / Cursor / Gemini CLI / Antigravity / OpenCode），除了自动加载 Skill 外，还可以将 [`adapters/AGENTS.md.snippet`](adapters/AGENTS.md.snippet) 的内容追加到项目或全局 `AGENTS.md` / `GEMINI.md` / `.cursor/rules/` 中作为常驻轻量提醒。

---

## 日常使用速查

```bash
# 渗透目录爆破结果去噪（保留所有状态码/长度离群项）
ffuf -u https://target/FUZZ -w words.txt -of json -o /tmp/ffuf.json -s
cslim compress --mode anomaly --input /tmp/ffuf.json

# 代码审计压缩 SAST 报告 & 审查安全补丁
semgrep --config auto --json -o /tmp/semgrep.json .
cslim compress --mode sast --input /tmp/semgrep.json
git diff origin/main...HEAD | cslim diff --profile audit --budget 8000

# 日常开发提取测试首错 & 缓存项目骨架地图
pytest -q 2>&1 | cslim compress --mode testlog
cslim ledger init && cslim ledger scan-map --root .
```

## 自测

```bash
python3 -m unittest discover -s tests -v
```
