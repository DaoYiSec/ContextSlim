# Daily Dev Flow — Zero-Rework Context Strategy

Daily coding wastes tokens in four ways: editing without seeing imports or callers (causing failed edit-test loops), dumping passing/warning chatter, running the full test suite on every debug step, and re-exploring repo structure every session.

## 1. Slice Imports + Target Symbols Together (And Check Callers Before Signature Changes)

Reading *only* lines `L120-L160` without checking imports, types, or callers causes hallucinated signatures and multi-turn fix loops.
1. Fetch `[Header/Imports]` + target symbol(s) in **one call** via `cslim slice`:
   ```bash
   cslim slice path/to/file.py --symbols target_func,HelperClass
   ```
   Or get the skeleton first via `cslim compress --mode skeleton --input path/to/file.py`, then read `[Header/Imports]` + target ranges.
2. **Before changing any public function/method signature**, locate all callers once (`rg -n "target_func\(" | cslim compress --mode grep`) so you update call sites in the same edit pass.

## 2. Target Failing Tests First & Compress Logs (Preserving Exit Code)

- **Narrow loop while debugging**: run **only** the failing test file/case (`pytest tests/test_x.py -k test_y -q`) during iterations; run the full suite once at the end.
- Wrap noisy test/build/Docker commands with `cslim run`:

```bash
cslim run --mode testlog -- pytest -q
```

`cslim run` preserves the exact exit code, passes small output (`<=40` lines) verbatim, and compresses huge logs (saving raw logs to `/tmp`) while capping minified lines (`--max-line-chars 320`). `--mode testlog` strips `PASS`/`OK`/Docker/pip/pytest `warnings summary` chatter and extracts up to 3 root tracebacks + summary. Do **not** use `--mode truncate` on test logs.

## 3. Diff Budgeting Before Commit / PR Review

Start with `git diff --stat` for orientation; for large diffs run:

```bash
git diff | cslim diff --profile dev --budget 8000
```

`--profile dev` drops lockfiles, minified assets, `dist/`, `build/`, and snapshot churn while keeping complete hunks for source files.

## 4. Cache a Repo + Entrypoint Map Between Sessions

Avoid burning 5–10 turns running `ls` / `find` at session start:

```bash
cslim ledger init
cslim ledger scan-map --root . --entrypoints
```

This writes a compact directory & entrypoint map into `.context-slim/ledger.md` (add `.context-slim/` to `.gitignore`). Read that single file at session start instead of re-discovering the layout.
