#!/usr/bin/env python3
"""Exit-code-preserving command wrapper that compresses large outputs and saves raw logs."""

from __future__ import annotations

import argparse
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _common import load_config, strip_ansi  # noqa: E402
from compress_output import run_compress  # noqa: E402


def run_and_compress(
    cmd_args: list[str],
    mode: str = "auto",
    max_lines: int = 120,
    max_line_chars: int = 320,
    threshold_lines: int = 40,
    threshold_chars: int = 4000,
) -> int:
    """Execute cmd_args, pass small output verbatim, or compress large output while preserving exit code."""
    use_shell = len(cmd_args) == 1 and any(ch in cmd_args[0] for ch in (" ", "\t", "|", "&", ";", ">", "<"))
    try:
        proc = subprocess.run(
            cmd_args[0] if use_shell else cmd_args,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except FileNotFoundError as exc:
        print(f"cslim run: command not found: {exc}", file=sys.stderr)
        return 127
    except OSError as exc:
        print(f"cslim run: failed to execute command: {exc}", file=sys.stderr)
        return 126

    raw = proc.stdout or ""
    cleaned = strip_ansi(raw)
    lines = cleaned.splitlines()
    max_single_len = max((len(ln) for ln in lines), default=0)

    is_small = (
        len(lines) <= threshold_lines
        and len(cleaned) <= threshold_chars
        and (max_line_chars <= 0 or max_single_len <= max_line_chars)
    )
    if is_small:
        if cleaned:
            print(cleaned, end="" if cleaned.endswith("\n") else "\n")
        return proc.returncode

    with tempfile.NamedTemporaryFile(
        mode="w",
        prefix="cslim-run-",
        suffix=".log",
        delete=False,
        encoding="utf-8",
    ) as tf:
        tf.write(raw)
        log_path = tf.name

    compressed = run_compress(
        cleaned,
        mode=mode,
        max_lines=max_lines,
        max_line_chars=max_line_chars,
    )
    out_lines = len(compressed.splitlines()) if compressed else 0
    if compressed:
        print(compressed)
    print(f"# [cslim run] raw log saved: {log_path} ({len(lines)} lines -> {out_lines} lines, exit={proc.returncode})")
    return proc.returncode


def main(argv: list[str] | None = None) -> int:
    cfg = load_config().get("compress", {})
    parser = argparse.ArgumentParser(description="Execute a command, compress noisy output, and preserve exit code.")
    parser.add_argument(
        "--mode",
        choices=["auto", "anomaly", "sast", "nmap", "sqlmap", "http", "grep", "testlog", "skeleton", "dedupe", "severity", "truncate"],
        default="auto",
    )
    parser.add_argument("--max-lines", type=int, default=cfg.get("default_max_lines", 120))
    parser.add_argument("--max-line-chars", type=int, default=cfg.get("default_max_line_chars", 320))
    parser.add_argument("--threshold-lines", type=int, default=cfg.get("run_passthrough_max_lines", 40))
    parser.add_argument("--threshold-chars", type=int, default=cfg.get("run_passthrough_max_chars", 4000))
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run (prefix with --)")
    args = parser.parse_args(argv)

    cmd_args = list(args.command)
    if cmd_args and cmd_args[0] == "--":
        cmd_args = cmd_args[1:]
    if not cmd_args:
        parser.print_help()
        return 2

    return run_and_compress(
        cmd_args,
        mode=args.mode,
        max_lines=args.max_lines,
        max_line_chars=args.max_line_chars,
        threshold_lines=args.threshold_lines,
        threshold_chars=args.threshold_chars,
    )


if __name__ == "__main__":
    raise SystemExit(main())
