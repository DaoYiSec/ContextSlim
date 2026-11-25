#!/usr/bin/env python3
"""Claude Code UserPromptSubmit / PostToolUse / PreCompact hook: tracks true API usage tokens."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from _common import load_config  # noqa: E402


def _scan_tail_for_usage(transcript_path: Path, max_bytes: int) -> int | None:
    try:
        size = transcript_path.stat().st_size
        read_from = max(0, size - max_bytes)
        with transcript_path.open("rb") as fh:
            fh.seek(read_from)
            tail = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None

    lines = tail.splitlines()
    if read_from > 0 and lines:
        lines = lines[1:]  # Drop partial first line

    for line in reversed(lines):
        if '"usage"' not in line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("isSidechain"):
            continue
        usage = None
        if isinstance(obj.get("message"), dict) and isinstance(obj["message"].get("usage"), dict):
            usage = obj["message"]["usage"]
        elif isinstance(obj.get("usage"), dict):
            usage = obj["usage"]
        if not usage:
            continue
        total = (
            int(usage.get("input_tokens") or 0)
            + int(usage.get("cache_read_input_tokens") or 0)
            + int(usage.get("cache_creation_input_tokens") or 0)
        )
        if total > 0:
            return total
    return None


def _latest_usage_tokens(transcript_path: Path) -> int | None:
    """Read tail of transcript JSONL to compute current context window token count."""
    if not transcript_path.is_file():
        return None
    # Fast path (256 KB) first, then widen to 1 MB if a large tool output pushed usage earlier
    res = _scan_tail_for_usage(transcript_path, 262144)
    if res is not None:
        return res
    try:
        if transcript_path.stat().st_size > 262144:
            return _scan_tail_for_usage(transcript_path, 1048576)
    except OSError:
        pass
    return None


def _emit_notice(hook_event: str, msg: str) -> None:
    if hook_event == "PostToolUse":
        print(
            json.dumps(
                {
                    "hookSpecificOutput": {
                        "hookEventName": "PostToolUse",
                        "additionalContext": msg,
                    }
                }
            )
        )
    else:
        print(msg)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    hook_event = str(payload.get("hook_event_name") or "UserPromptSubmit")
    cwd = payload.get("cwd") or "."

    if hook_event == "PreCompact":
        ledger = Path(cwd) / ".context-slim" / "ledger.md"
        if ledger.is_file():
            ln_cnt = len(ledger.read_text(encoding="utf-8", errors="replace").splitlines())
            print(
                f"[context-slim] PreCompact: `.context-slim/ledger.md` exists ({ln_cnt} lines). "
                "Reload it immediately after compaction instead of re-scanning or re-reading >100k history."
            )
        else:
            print(
                "[context-slim] PreCompact: no `.context-slim/ledger.md` found. "
                "Consider persisting targets, auth tokens, findings, and dead-ends via `cslim ledger` to prevent post-compact re-work."
            )
        return 0

    transcript_str = str(payload.get("transcript_path") or "")
    if not transcript_str:
        return 0

    total_tokens = _latest_usage_tokens(Path(transcript_str))
    if total_tokens is None:
        return 0

    cfg = load_config(cwd)
    preset_name = str(cfg.get("active_preset") or "200k")
    presets = cfg.get("context_window_presets", {})
    preset = presets.get(preset_name) or presets.get("200k") or {"warn_tokens": 120000, "hard_tokens": 170000, "rearm_step": 25000}

    warn_t = int(preset.get("warn_tokens", 120000))
    hard_t = int(preset.get("hard_tokens", 170000))
    step = int(preset.get("rearm_step", 25000))

    raw_sid = str(payload.get("session_id") or "default")
    safe_sid = re.sub(r"[^A-Za-z0-9_.-]", "_", raw_sid)[:64]
    uid = os.getuid() if hasattr(os, "getuid") else "user"
    marker_file = Path(tempfile.gettempdir()) / f"context-slim-mark-{uid}-{safe_sid}.txt"

    last_mark = 0
    if marker_file.is_file():
        try:
            last_mark = int(marker_file.read_text(encoding="utf-8").strip() or "0")
        except (OSError, ValueError):
            last_mark = 0

    # Reset marker if /compact dropped context significantly
    if total_tokens < warn_t and last_mark > 0:
        marker_file.unlink(missing_ok=True)
        return 0

    if total_tokens >= hard_t and (last_mark < hard_t or total_tokens - last_mark >= step):
        try:
            marker_file.write_text(str(total_tokens), encoding="utf-8")
        except OSError:
            pass
        _emit_notice(
            hook_event,
            f"[context-slim] Context at ~{total_tokens:,} tokens (hard threshold {hard_t:,}). "
            "Stop reading large files. Flush verified findings/targets/state into `.context-slim/ledger.md`, "
            "run `/compact` or hand off to a fresh session, and delegate self-contained tasks to fresh lightweight subagents.",
        )
    elif total_tokens >= warn_t and last_mark < warn_t:
        try:
            marker_file.write_text(str(total_tokens), encoding="utf-8")
        except OSError:
            pass
        _emit_notice(
            hook_event,
            f"[context-slim] Context at ~{total_tokens:,} tokens (warn threshold {warn_t:,}). "
            "Update `.context-slim/ledger.md` before context saturates; prefer fresh scoped subagents over heavy forks.",
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
