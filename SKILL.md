---
name: context-slim
description: >
  Token and context budget controller for penetration testing, code auditing,
  and software development. Use when reading large files, running noisy scans
  or tests, reviewing diffs, delegating multi-target work, or managing long
  sessions. Enforces skeleton-first reads, multi-range slicing, deterministic
  script offloading, compact state ledgers, and cost-aware subagent delegation.
license: MIT
compatibility: Requires Python 3.9+ (standard library only, zero third-party packages).
metadata:
  author: context-slim
  version: "1.0.0"
---

# context-slim

Control **what enters the context window, in what granularity, and when**.
Works identically across Claude Code, Codex, Cursor, Gemini CLI, Antigravity, and OpenCode.

## Tool Resolution

Prefer `cslim` if installed on `PATH`; otherwise locate `scripts/` inside this skill's directory (check active skill path, `.agents/skills/context-slim/scripts/`, `~/.agents/skills/context-slim/scripts/`, or `~/.<agent>/skills/context-slim/scripts/`):

- `cslim compress ...` ≡ `python3 <skill-dir>/scripts/compress_output.py ...`
- `cslim slice ...` ≡ `python3 <skill-dir>/scripts/slice_file.py ...`
- `cslim run -- ...` ≡ `python3 <skill-dir>/scripts/run_cmd.py -- ...`
- `cslim diff ...` ≡ `python3 <skill-dir>/scripts/diff_budget.py ...`
- `cslim ledger ...` ≡ `python3 <skill-dir>/scripts/ledger_tool.py ...`

## Stage Routing (compose phases as needed, never load irrelevant references)

Match the current action. Load ONLY the reference needed for the active stage:

| Stage / Trigger | Reference to Load | Core Action |
|---|---|---|
| Pentest scans (`nmap`, `ffuf`, `nuclei`, `httpx`, `sqlmap`, `curl`), HTTP fuzzing, or engagement tracking | `references/pentest-flow.md` | Force file output + `--mode anomaly` / `nmap` / `sqlmap` / `http`; track state in `.context-slim/ledger.md` |
| Code auditing, SAST triage (`semgrep`, `trivy`, `bandit`, SARIF), security diff review, or source-to-sink tracing | `references/audit-flow.md` | Check configs/routes first; slice with `cslim slice`; use `--mode grep` + `diff --profile audit` |
| Daily dev: editing large files, fixing failing tests/builds, or exploring unfamiliar repos | `references/dev-flow.md` | Slice Imports + target symbols in 1 call; use `cslim run` / `--mode testlog`; cache repo map |
| Spawning subagents or deciding between script loop vs fresh/forked subagent | `references/delegation-budget.md` | Use scripts for batch probing; prefer fresh lightweight subagents over heavy forks |

If a small single-file edit (<150 lines) needs no tooling or delegation, act directly without loading extra references.

## Hard Rules (Always Active)

1. **Never dump raw high-noise CLI output into context.** Use `cslim run -- <cmd>` (preserves exit code, auto-compresses large output and saves raw logs), redirect scans to a temp file, or pipe through `compress_output.py`:
   - Fuzz/enum outputs (`ffuf`, `gobuster`, `feroxbuster`, `dirsearch`, `httpx`) → `--mode anomaly` (never `truncate`).
   - Network/SQLi scans → `--mode nmap` (`nmap`) / `--mode sqlmap` (`sqlmap`).
   - SAST/scanner JSON/SARIF (`semgrep`, `nuclei`, `trivy`) → `--mode sast`; raw HTTP/HTML (`curl -i`) → `--mode http`.
   - Test/build/Docker logs (`pytest`, `jest`, `go test`, `cargo`, `docker build`) → `--mode testlog`; noisy `rg`/`grep` → `--mode grep`.
2. **Never blind-read large files.** Run `rg -n` or `cslim compress --mode skeleton` first, then read `[Header/Imports]` + target symbols/ranges in **one call** via `cslim slice <file> --symbols ...` (or bounded `Read` offset/limit). Exempt files ≤150 lines.
3. **Never sort security diffs by change size.** When reviewing patches for vulnerabilities, run `cslim diff --profile audit` so 1-line auth/guard removals are prioritized over large refactors and dependency versions are summarized.
4. **Never use an LLM subagent for deterministic batch loops.** Probing 50 URLs, checking 30 parameters, or grepping 200 files belongs in one shell/Python script, not multi-turn subagent tool calls.
5. **Externalize state before context bloats.** Persist confirmed targets, auth tokens/cookies, tested dead-ends, source-to-sink paths, and repo/entrypoint maps in `.context-slim/ledger.md` via `cslim ledger`. Never re-read 100k+ history to recall prior discoveries.
6. **Do not load `assets/config-template.json` into context.** Configuration is read automatically by scripts and optional hooks.
