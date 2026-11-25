# Code Audit Flow — Vulnerability-Preserving Context Control

Generic token-saving tricks break security audits when they drop config files or 1-line auth removals. Use this audit-specific workflow.

## 1. Triage Configs, Security Annotations, and Entrypoints First

High-impact bugs frequently live outside `def`/`class` bodies (CORS, `@csrf_exempt`, `@PermitAll`, `@PreAuthorize`, Nginx `alias`, Dockerfile `USER root`, K8s `privileged: true`).
1. Locate entrypoints and configs first:
   - Index routes across the repo in one pass: `cslim ledger scan-map --entrypoints`.
   - Inspect a single file's imports, routes, and security configs: `cslim compress --mode skeleton --input <file>`.
2. Read `[Header/Imports]` + target middleware/handler functions in **one call** via `cslim slice`:
   ```bash
   cslim slice path/to/routes.py --symbols auth_middleware,handle_order
   ```
   Or use bounded line offset/limit reads on your file-read tool.

## 2. Compress SAST & Sink-Grep Output Without Losing Locations

- **SAST JSON/SARIF** (`semgrep`, `trivy`, `bandit`, `nuclei`):
  ```bash
  semgrep --config auto --json -o /tmp/semgrep.json .
  cslim compress --mode sast --input /tmp/semgrep.json
  ```
  *Note*: SAST only surfaces candidate sinks; verify reachability, sanitization, and framework defenses in code before reporting.
- **Taint-sink grep noise**: exclude tests/mocks first and group hits by file with `--mode grep` (strips comment matches and folds `tests/`):
  ```bash
  rg -n "execute\(|raw\(" src/ | cslim compress --mode grep
  ```

## 3. Trace Source -> Middleware -> Sink Using Slices + Ledger

1. Run `rg -n` / `--mode grep` to map exact `file:line` across the call chain.
2. Fetch the relevant functions + imports via `cslim slice` (40–80 lines per hop, never whole files).
3. Record **both confirmed chains and verified false positives** in `.context-slim/ledger.md` so later turns/subagents never re-audit safe sinks:
   ```bash
   cslim ledger add --section audit --key "SQLi /api/orders" --value "Safe: parameterized via Dao.query() L45-L62"
   ```

## 4. Security Diff Review (`--profile audit`)

Never sort security reviews by diff size—a **1-line deletion** (`- if not user.is_admin: return 403`) gets crowded out by a 500-line refactor.

```bash
git diff origin/main...HEAD | cslim diff --profile audit --budget 8000
```

`--profile audit`:
- Keeps complete hunks (never slices mid-hunk).
- Boosts 1–5 line diffs touching auth, permissions, XSS/SSRF/deserialization/path-traversal sinks, crypto, CI/Nginx/Dockerfile paths, or removed `if` guards to highest priority.
- Summarizes lockfile/manifest deltas (`package-lock.json` v2/v3, `Cargo.lock`, `go.sum`, `pom.xml`) as `package: old -> new`.
