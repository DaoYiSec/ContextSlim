#!/usr/bin/env python3
"""Claude Code PreToolUse(Read) hook: blocks blind large-file reads and emits skeleton."""

from __future__ import annotations

import json
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from _common import inspect_text_file, is_blocked_glob, load_config  # noqa: E402
from compress_output import compress_skeleton  # noqa: E402

BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".zip", ".gz", ".exe", ".bin"}


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    if payload.get("tool_name") != "Read":
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = str(tool_input.get("file_path") or "")
    if not file_path:
        return 0

    cwd = payload.get("cwd") or "."
    cfg = load_config(cwd)
    rg = cfg.get("read_guard", {})
    max_unbounded = int(rg.get("max_unbounded_lines", 200))
    max_limit = int(rg.get("max_explicit_limit", 250))
    preview_lines = int(rg.get("skeleton_preview_lines", 60))
    blocked_globs = list(rg.get("blocked_globs", []))

    limit = tool_input.get("limit")
    valid_limit = isinstance(limit, int) and not isinstance(limit, bool) and limit > 0
    has_bounded_limit = valid_limit and limit <= max_limit

    target = Path(file_path)
    if not target.is_absolute():
        target = Path(cwd) / target

    if is_blocked_glob(str(target), str(cwd), blocked_globs) and not (valid_limit and limit <= 80):
        print(
            f"context-slim blocked Read on generated/lock file `{file_path}`. "
            "Use Grep for targeted lookup or `cslim diff --profile audit` for dependency deltas.",
            file=sys.stderr,
        )
        return 2

    if not target.is_file():
        return 0

    if target.suffix.lower() in BINARY_EXTENSIONS:
        return 0

    is_binary, total_lines, preview_text, capped = inspect_text_file(target)
    if is_binary:
        return 0

    if (total_lines > max_unbounded or capped) and not has_bounded_limit:
        skel = compress_skeleton(preview_text, max_lines=preview_lines)
        count_label = f">{total_lines:,}" if capped else str(total_lines)
        print(
            f"context-slim blocked unbounded Read on `{file_path}` ({count_label} lines > {max_unbounded}).\n"
            f"Retry Read with explicit `offset` and `limit` (<= {max_limit}) for [Header/Imports] + target range,\n"
            f"or fetch imports + multiple symbols in one shot via `cslim slice \"{file_path}\" --symbols ...`.\n\n"
            f"{skel}",
            file=sys.stderr,
        )
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
