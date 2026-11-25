#!/usr/bin/env python3
"""Externalized compact state ledger (.context-slim/ledger.md) for cross-turn and cross-session continuity."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from compress_output import RE_ROUTE_DECORATOR  # noqa: E402

SECTIONS = {
    "targets": "## Targets & Surface",
    "auth": "## Auth & Session State",
    "findings": "## Confirmed Findings",
    "deadends": "## Dead Ends (Do Not Re-Test)",
    "audit": "## Audit Chains (Source -> Sink)",
    "dev": "## Repo Map & Dev Notes",
}

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".next",
    ".context-slim",
}

CODE_EXTS = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php", ".rs", ".cs", ".sql"}
RE_MAIN_ENTRY = re.compile(
    r"^\s*(?:if\s+__name__\s*==\s*['\"]__main__['\"]|func\s+main\s*\(|public\s+static\s+void\s+main\s*\(|"
    r"(?:app|server)\.listen\s*\(|CREATE\s+(?:OR\s+REPLACE\s+)?TABLE\s+)"
)

DEFAULT_LEDGER = """# ContextSlim State Ledger

Keep this file compact (aim for <120 lines). Read this instead of re-scanning logs or >100k history.

## Targets & Surface
- (none)

## Auth & Session State
- (none)

## Confirmed Findings
- (none)

## Dead Ends (Do Not Re-Test)
- (none)

## Audit Chains (Source -> Sink)
- (none)

## Repo Map & Dev Notes
- (none)
"""


def _ledger_path(root: str | Path | None = None) -> Path:
    base = Path(root) if root else Path(os.getcwd())
    return base / ".context-slim" / "ledger.md"


def init_ledger(root: str | Path | None = None) -> Path:
    """Create .context-slim/ledger.md if missing."""
    path = _ledger_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if not path.exists():
        path.write_text(DEFAULT_LEDGER, encoding="utf-8")
    return path


def _split_sections(text: str) -> tuple[str, dict[str, list[str]]]:
    """Parse ledger markdown into preamble + ordered section lines."""
    preamble: list[str] = []
    buckets: dict[str, list[str]] = {h: [] for h in SECTIONS.values()}
    cur_header: str | None = None
    known_headers = set(SECTIONS.values())

    for line in text.splitlines():
        s = line.strip()
        if s in known_headers:
            cur_header = s
            continue
        if cur_header is None:
            preamble.append(line)
        else:
            if s and s != "- (none)":
                buckets[cur_header].append(line)
    return "\n".join(preamble).strip(), buckets


def _render_ledger(preamble: str, buckets: dict[str, list[str]]) -> str:
    parts = [preamble or "# ContextSlim State Ledger"]
    for header in SECTIONS.values():
        parts.append("")
        parts.append(header)
        lines = buckets.get(header) or ["- (none)"]
        parts.extend(lines)
    parts.append("")
    return "\n".join(parts)


def _clean_single_line(text: str) -> str:
    return " ".join(text.splitlines()).strip()


def upsert_entry(section: str, key: str, value: str, root: str | Path | None = None) -> Path:
    """Idempotently add or update a `- **key**: value` entry in the specified section."""
    path = init_ledger(root)
    header = SECTIONS[section]
    preamble, buckets = _split_sections(path.read_text(encoding="utf-8"))

    clean_key = _clean_single_line(key)
    clean_val = _clean_single_line(value)
    entry_prefix = f"- **{clean_key}**:"
    new_line = f"{entry_prefix} {clean_val}"
    updated: list[str] = []
    replaced = False
    for line in buckets[header]:
        if line.strip().startswith(entry_prefix):
            updated.append(new_line)
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.append(new_line)

    buckets[header] = updated
    path.write_text(_render_ledger(preamble, buckets), encoding="utf-8")
    return path


def remove_entry(section: str, key: str, root: str | Path | None = None) -> tuple[Path, bool]:
    """Remove an entry matching `key` from the specified section."""
    path = init_ledger(root)
    header = SECTIONS[section]
    preamble, buckets = _split_sections(path.read_text(encoding="utf-8"))

    clean_key = _clean_single_line(key)
    entry_prefix = f"- **{clean_key}**:"
    before = len(buckets[header])
    buckets[header] = [line for line in buckets[header] if not line.strip().startswith(entry_prefix)]
    removed = len(buckets[header]) < before
    if removed:
        path.write_text(_render_ledger(preamble, buckets), encoding="utf-8")
    return path, removed


def _join_within_budget(parts: list[str], limit: int = 900) -> str:
    """Join parts with ' | ' without slicing mid-item."""
    kept: list[str] = []
    total = 0
    for idx, part in enumerate(parts):
        sep = 3 if kept else 0
        if total + sep + len(part) > limit and kept:
            kept.append(f"(+{len(parts) - idx} more)")
            break
        kept.append(part)
        total += sep + len(part)
    return " | ".join(kept)


def scan_entrypoints(base: Path, max_hits: int = 24) -> list[str]:
    """Scan workspace source files for HTTP routes, main entrypoints, and DB schemas."""
    hits: list[str] = []
    scanned_files = 0

    for cur_root, dirs, files in os.walk(base):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for fname in sorted(files):
            if fname.startswith(".") or fname.endswith((".min.js", ".min.css", ".lock")):
                continue
            fpath = Path(cur_root) / fname
            if fpath.suffix.lower() not in CODE_EXTS:
                continue
            try:
                if fpath.stat().st_size > 262144:
                    continue
                text = fpath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned_files += 1
            rel = fpath.relative_to(base).as_posix()
            for lineno, line in enumerate(text.splitlines(), start=1):
                if RE_ROUTE_DECORATOR.match(line) or RE_MAIN_ENTRY.match(line):
                    snippet = " ".join(line.split())[:70]
                    hits.append(f"{rel}:{lineno} `{snippet}`")
                    if len(hits) >= max_hits:
                        return hits
            if scanned_files >= 250:
                return hits
    return hits


def scan_repo_map(
    root: str | Path | None = None,
    max_depth: int = 2,
    include_entrypoints: bool = False,
) -> str:
    """Build a compact directory + manifest map (and optional entrypoints) under Repo Map."""
    base = Path(root or os.getcwd()).resolve()
    lines: list[str] = []

    manifests = [
        f
        for f in ("package.json", "pyproject.toml", "go.mod", "Cargo.toml", "pom.xml", "Dockerfile", "docker-compose.yml")
        if (base / f).is_file()
    ]
    if manifests:
        lines.append(f"manifests: {', '.join(manifests)}")

    dirs_summary: list[str] = []
    truncated_dirs = False
    for cur_root, dirs, files in os.walk(base):
        rel = Path(cur_root).relative_to(base)
        depth = 0 if rel == Path(".") else len(rel.parts)
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        if depth >= max_depth:
            dirs[:] = []
        if depth == 0:
            top_files = sorted(f for f in files if not f.startswith("."))[:8]
            if top_files:
                dirs_summary.append(f"./ ({', '.join(top_files)})")
        else:
            code_files = sorted(f for f in files if not f.startswith("."))[:6]
            suffix = f": {', '.join(code_files)}" if code_files else ""
            dirs_summary.append(f"{rel.as_posix()}/ ({len(files)} files{suffix})")
        if len(dirs_summary) >= 24:
            truncated_dirs = True
            break

    if truncated_dirs:
        dirs_summary.append("(... additional subdirectories omitted)")

    summary = _join_within_budget(lines + dirs_summary, limit=900)
    upsert_entry("dev", "repo_map", summary, root=base)

    if include_entrypoints:
        eps = scan_entrypoints(base)
        ep_summary = _join_within_budget(eps, limit=900) if eps else "(none detected)"
        upsert_entry("dev", "entrypoints", ep_summary, root=base)
        return f"{summary}\nentrypoints: {ep_summary}"

    return summary


def show_ledger(section: str | None = None, root: str | Path | None = None) -> str:
    path = _ledger_path(root)
    if not path.is_file():
        return "No ledger found. Run `ledger_tool.py init` first."
    text = path.read_text(encoding="utf-8")
    if not section:
        return text
    _, buckets = _split_sections(text)
    header = SECTIONS[section]
    return "\n".join([header] + (buckets.get(header) or ["- (none)"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Manage .context-slim/ledger.md compact state ledger.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_init = sub.add_parser("init", help="Initialize ledger in workspace")
    p_init.add_argument("--root", default=None)

    p_add = sub.add_parser("add", help="Add or update a ledger entry")
    p_add.add_argument("--section", choices=list(SECTIONS.keys()), required=True)
    p_add.add_argument("--key", required=True)
    p_add.add_argument("--value", required=True)
    p_add.add_argument("--root", default=None)

    p_rm = sub.add_parser("remove", help="Remove a ledger entry by key")
    p_rm.add_argument("--section", choices=list(SECTIONS.keys()), required=True)
    p_rm.add_argument("--key", required=True)
    p_rm.add_argument("--root", default=None)

    p_show = sub.add_parser("show", help="Print ledger contents")
    p_show.add_argument("--section", choices=list(SECTIONS.keys()), default=None)
    p_show.add_argument("--root", default=None)

    p_map = sub.add_parser("scan-map", help="Scan workspace layout into Repo Map section")
    p_map.add_argument("--root", default=None)
    p_map.add_argument("--depth", type=int, default=2)
    p_map.add_argument("--entrypoints", action="store_true", help="Also index routes, main entries, and SQL schemas")

    args = parser.parse_args(argv)
    if args.cmd == "init":
        p = init_ledger(args.root)
        print(f"Initialized ledger: {p}")
    elif args.cmd == "add":
        p = upsert_entry(args.section, args.key, args.value, root=args.root)
        print(f"Updated [{args.section}] in {p}")
    elif args.cmd == "remove":
        p, removed = remove_entry(args.section, args.key, root=args.root)
        msg = f"Removed `{args.key}` from [{args.section}] in {p}" if removed else f"Key `{args.key}` not found in [{args.section}]"
        print(msg)
    elif args.cmd == "show":
        print(show_ledger(args.section, root=args.root))
    elif args.cmd == "scan-map":
        summary = scan_repo_map(args.root, max_depth=args.depth, include_entrypoints=args.entrypoints)
        print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
