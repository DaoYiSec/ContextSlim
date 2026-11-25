# context-slim

[English](README.md) | [中文说明](README_ZH.md)

A cross-agent **Agent Skill** (`agentskills.io` compatible) + zero-dependency Python CLI toolkit that slashes token waste across **penetration testing**, **code auditing**, and **daily software development**.

Works out of the box with **Claude Code**, **OpenAI Codex CLI**, **Cursor**, **Gemini CLI**, **Antigravity**, **OpenCode**, and any agent supporting the `SKILL.md` standard.

---

## Why `context-slim`?

Generic token-saving prompts break down in real security and engineering work:
- **Naive `truncate` kills real pentest findings**: `ffuf` / `gobuster` often hide two `200 OK` hits inside 5,000 `403` lines—middle truncation drops the vulnerabilities.
- **Density-sorted diffs hide security regressions**: Removing 1 line (`- if not user.is_admin: return 403`) gets pushed past budget by a 400-line refactor.
- **Blind skeleton-only reads cause dev rework**: Reading only lines `L120-L160` without seeing file imports/types triggers failed edit-test loops.
- **High-context subagent forks amplify cost**: Forking a 180k session on a flagship model multiplies prefix replay cost; fresh lightweight subagents + an external state ledger are often an order of magnitude cheaper.

`context-slim` solves all four with deterministic Python stdlib scripts, workflow-specific playbooks, and optional runtime guard hooks.

---

## Core Capabilities

| Component | What It Does |
|---|---|
| `SKILL.md` + `references/` | Portable `agentskills.io` skill split into `pentest-flow.md`, `audit-flow.md`, `dev-flow.md`, and `delegation-budget.md` |
| `cslim compress --mode anomaly` | Clusters `ffuf` / `gobuster` / `feroxbuster` / `dirsearch` / `httpx` JSON/JSONL/text by `(status, length_bucket, words)` + path-reflection collapse—preserves **100% of outliers** |
| `cslim compress --mode nmap\|sqlmap` | Strips `nmap` down hosts/closed-port chatter (stdout/`-oG`/`-oX`) and `sqlmap` `[INFO] testing` noise while preserving open ports, payloads, DBMS, and dumps |
| `cslim compress --mode sast` | Compresses Semgrep, Nuclei, Bandit, Trivy, and SARIF JSON into compact `[SEV] rule_id \| path:lines \| snippet` tuples |
| `cslim compress --mode http` | Strips CSS/SVG/JS bloat & huge ViewState values from `curl -i` / HTML responses while keeping headers, `<form>`/`<input>`, API paths, and errors |
| `cslim compress --mode grep` | Groups `rg`/`grep` `file:line:match` output by file, skips comment hits, and folds `tests/`/`mocks/` matches |
| `cslim compress --mode testlog` | Strips passing `pytest` / `jest` / `go test` / `cargo` / `docker build` / `pip` / `pytest warnings` chatter, caps minified lines (`--max-line-chars 320`), and extracts root tracebacks + summary |
| `cslim compress --mode skeleton` | Multi-language symbol + security annotation (`@PreAuthorize`, `@csrf_exempt`, K8s/Nginx) + JSON key/Markdown extractor with `[Header/Imports: L1-Lx]` |
| `cslim slice` | Extracts `[Header/Imports]` + multiple target `--ranges` or `--symbols` in **1 tool call** (eliminates multi-turn `Read` round-trips) |
| `cslim run -- <cmd>` | Exit-code-preserving wrapper: passes small output verbatim, compresses large logs, and saves raw logs to `/tmp` |
| `cslim diff --profile dev\|audit` | Hunk-safe diff budgeter; `audit` mode summarizes lockfile version deltas (`package-lock.json` v2/v3, `Cargo.lock`, `go.sum`, `pom.xml`) and prioritizes 1–5 line auth/sink/guard changes |
| `cslim ledger` | Maintains `.context-slim/ledger.md` across turns/sessions (targets, auth tokens, findings, dead-ends, taint chains, repo map + `--entrypoints`) |
| `adapters/claude-code/hooks/` | Optional `PreToolUse` (`Bash`, `Read`, `Agent`) + `UserPromptSubmit`/`PostToolUse`/`PreCompact` token monitor for Claude Code |

---

## Installation

### Option 1: Universal Skill Install (`agentskills.io` / `skills` CLI)

```bash
git clone https://github.com/DaoYiSec/ContextSlim.git
cd ContextSlim

# Install to ~/.agents/skills/context-slim + ~/.local/bin/cslim
./install.sh

# Or link into all detected agent homes (Claude, Codex, Cursor, Gemini, Antigravity, OpenCode)
./install.sh --target all

# Or install per-project into ./.agents/skills/context-slim
./install.sh --project /path/to/repo
```

### Option 2: Optional Claude Code Hard Guardrails (Hooks)

If you use **Claude Code** and want deterministic enforcement even after 100k+ tokens:

```bash
./install.sh --target claude --with-claude-hooks
# Remove hooks cleanly later:
./install.sh --uninstall-claude-hooks
```

What the hooks enforce:
- `bash_guard.py`: Blocks raw `ffuf`/`nuclei`/`semgrep`/`nmap` stdout floods, blocks unbounded `find` and large `cat`, and auto-bounds bare `git log`, `rg --max-columns 240`, and recursive `grep --exclude-dir`.
- `read_guard.py`: Blocks unbounded `Read` on files >200 lines and emits the symbol skeleton directly in `stderr` (plus `cslim slice` hint) so the next read succeeds in one shot.
- `context_monitor.py`: Reads real API `usage` tokens from `transcript_path` JSONL across `UserPromptSubmit`, `PostToolUse` (autonomous loops), and `PreCompact` (ledger preservation reminder).
- `dispatch_guard.py`: Prevents nested subagent recursion (`agent_id` present) and nudges explicit `model` selection on scoped subagents.

### Option 3: Non-Hook Agents (Codex / Cursor / Gemini CLI / Antigravity / OpenCode)

All core skill features work automatically once the skill folder is linked. Optionally append [`adapters/AGENTS.md.snippet`](adapters/AGENTS.md.snippet) into your `AGENTS.md`, `GEMINI.md`, or `.cursor/rules/` for always-on discipline.

---

## Configuration

Create `.context-slim.json` in your project root (or `.claude/context-slim.json`) to override [`assets/config-template.json`](assets/config-template.json).
Switch `"active_preset": "1m"` if your primary model uses a 1M context window (`"200k"` is the default).

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
