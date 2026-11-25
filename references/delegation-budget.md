# Subagent Delegation & Context Cost Model

Subagents save main-thread context **only** when chosen and scoped correctly. Spawning the wrong kind of subagent at high context multiplies cost instead of reducing it.

## 1. Decision Matrix: Script vs Fresh Subagent vs Forked Subagent

| Task Shape | Best Mechanism | Why |
|---|---|---|
| Deterministic multi-target check (test 50 URLs, scan 200 files for regex, parse JSONL) | **Shell / Python script** | 1 turn, zero LLM per-item tax |
| Self-contained exploration, single-module audit, running & fixing isolated unit tests | **Fresh Subagent** (clean history + lighter/cheaper model if agent supports model selection + pointer to `.context-slim/ledger.md`) | Starts at ~2k–5k tokens instead of copying a bloated 150k main history |
| Task deeply coupled to complex prior multi-turn reasoning that cannot be summarized in ≤500 tokens | **History-inheriting / Forked Subagent** (where runtime supports it) | Shares existing prefix cache (~90% cache-read discount on initial prompt) without rewriting context |

## 2. The High-Context Fork Trap (>100k Tokens)

**Never assume "fork mode is always cheap" when main context exceeds 100k.**
- Prompt caching discounts cached *reads* (~90% off base input), **not to zero**, and forked agents inherit the **parent's expensive model** plus the **entire 100k–200k+ conversation history**.
- Running 5 parallel forks through 8 tool turns each replays that massive prefix dozens of times; if subagent cache TTL (often 5 minutes) expires mid-loop, you pay full cache-write cost.
- Therefore, above 100k tokens: **dump key facts into `.context-slim/ledger.md` first**, then dispatch **fresh, scoped subagents** on lighter models reading only the ledger + target slice.

## 3. Mandatory Delegation Prompt Contract

Every subagent prompt—across any agent framework—must include:
1. **Exact scope**: specific files, endpoints, or ledger section to inspect.
2. **Hard output budget**: e.g. `Return structured findings only, max 1,500 tokens.`
3. **No narration**: `Do not narrate intermediate tool steps or paste raw tool logs.`
4. **No recursive delegation**: delegated workers execute directly and return findings; they must not spawn child agents.

## 4. Session Handoff Thresholds

Watch context consumption:
- **Standard 200k window**: prepare state ledger dump at ~120k; compact or hand off cleanly to a fresh session with `.context-slim/ledger.md` by ~170k.
- **1M window**: warn at ~200k; hand off by ~400k.
