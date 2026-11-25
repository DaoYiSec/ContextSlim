"""Shared helpers for context-slim scripts and optional adapters."""

from __future__ import annotations

import copy
import fnmatch
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07")
SKILL_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_CONFIG: dict[str, Any] = {
    "context_window_presets": {
        "200k": {"warn_tokens": 120000, "hard_tokens": 170000, "rearm_step": 25000},
        "1m": {"warn_tokens": 200000, "hard_tokens": 400000, "rearm_step": 50000},
    },
    "active_preset": "200k",
    "read_guard": {
        "max_unbounded_lines": 200,
        "max_explicit_limit": 250,
        "skeleton_preview_lines": 60,
        "blocked_globs": [
            "*.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "*.min.js",
            "*.min.css",
            "*.map",
            "dist/*",
            "build/*",
        ],
    },
    "compress": {
        "default_max_lines": 120,
        "default_max_line_chars": 320,
        "anomaly_min_cluster": 3,
        "testlog_max_failures": 3,
        "run_passthrough_max_lines": 40,
        "run_passthrough_max_chars": 4000,
    },
    "diff_budget": {
        "default_tokens": 8000,
        "dev_exclude_globs": [
            "*.lock",
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "go.sum",
            "Cargo.lock",
            "*.min.js",
            "*.min.css",
            "*.map",
            "dist/*",
            "build/*",
            "vendor/*",
            "*.snap",
        ],
    },
    "delegation": {
        "block_nested_subagents": True,
        "require_model_on_scoped_subagents": True,
        "max_subagent_output_tokens": 2000,
    },
}


def strip_ansi(text: str) -> str:
    """Remove ANSI escape and terminal control sequences."""
    return ANSI_RE.sub("", text)


def estimate_tokens(text: str) -> int:
    """Estimate token count conservatively (~4 chars per token)."""
    if not text:
        return 0
    return max(1, (len(text) + 3) // 4)


def read_input_text(input_path: str | None) -> str:
    """Read UTF-8 text safely from file path or stdin ('-' or None)."""
    if input_path and input_path != "-":
        return Path(input_path).read_text(encoding="utf-8", errors="replace")
    if sys.stdin.isatty():
        return ""
    data = sys.stdin.buffer.read()
    return data.decode("utf-8", errors="replace")


def inspect_text_file(
    target: Path,
    max_preview_bytes: int = 1048576,
    max_count_bytes: int = 16777216,
) -> tuple[bool, int, str, bool]:
    """Safely inspect a file without loading huge files into RAM.

    Returns (is_binary, total_lines, preview_text, lines_capped).
    """
    try:
        st_size = target.stat().st_size
        with target.open("rb") as fh:
            head = fh.read(max_preview_bytes)
    except OSError:
        return True, 0, "", False

    if b"\x00" in head[:4096]:
        return True, 0, "", False

    preview_text = head.decode("utf-8", errors="replace")
    if st_size <= max_preview_bytes:
        return False, len(preview_text.splitlines()), preview_text, False

    line_count = head.count(b"\n")
    scanned = len(head)
    capped = False
    try:
        with target.open("rb") as fh:
            fh.seek(scanned)
            while True:
                chunk = fh.read(65536)
                if not chunk:
                    break
                line_count += chunk.count(b"\n")
                scanned += len(chunk)
                if scanned >= max_count_bytes:
                    capped = True
                    break
    except OSError:
        capped = True
    return False, max(line_count, 1), preview_text, capped


def is_blocked_glob(path_str: str, cwd: str | Path, globs: list[str]) -> bool:
    """Match a path against glob patterns relative to cwd, basename, or any subpath."""
    p = Path(path_str)
    candidates = [p.as_posix(), p.name]
    try:
        rel = p.resolve().relative_to(Path(cwd).resolve()).as_posix()
        candidates.append(rel)
    except (OSError, ValueError):
        pass
    for g in globs:
        if any(fnmatch.fnmatch(c, g) or fnmatch.fnmatch(c, f"*/{g}") for c in candidates):
            return True
    return False


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(merged.get(k), dict):
            merged[k] = _deep_merge(merged[k], v)
        else:
            merged[k] = v
    return merged


def load_config(cwd: str | Path | None = None) -> dict[str, Any]:
    """Load default config merged with project-level override if present."""
    cfg: dict[str, Any] = copy.deepcopy(DEFAULT_CONFIG)
    default_path = SKILL_ROOT / "assets" / "config-template.json"
    if default_path.is_file():
        try:
            tmpl = json.loads(default_path.read_text(encoding="utf-8"))
            if isinstance(tmpl, dict):
                cfg = _deep_merge(cfg, tmpl)
        except (OSError, json.JSONDecodeError):
            pass

    work_dir = Path(cwd) if cwd else Path(os.getcwd())
    candidates = [
        work_dir / ".context-slim.json",
        work_dir / ".context-slim" / "config.json",
        work_dir / ".claude" / "context-slim.json",
    ]
    for path in candidates:
        if path.is_file():
            try:
                override = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(override, dict):
                    cfg = _deep_merge(cfg, override)
                break
            except (OSError, json.JSONDecodeError):
                continue
    return cfg
