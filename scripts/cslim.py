#!/usr/bin/env python3
"""Unified CLI wrapper for context-slim tools (`cslim compress|slice|run|diff|ledger`)."""

from __future__ import annotations

import sys
from pathlib import Path

__version__ = "1.0.0"

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import compress_output
import diff_budget
import ledger_tool
import run_cmd
import slice_file


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(
            "Usage: cslim <command> [args...]\n\n"
            "Commands:\n"
            "  compress   Compress noisy tool output (--mode auto|anomaly|sast|nmap|sqlmap|http|grep|testlog|skeleton|dedupe|severity|truncate)\n"
            "  slice      Read [Header/Imports] + target line ranges or symbols in one shot\n"
            "  run        Execute command, preserve exit code, compress large output + save raw log\n"
            "  diff       Budget git diffs cleanly (--profile dev|audit)\n"
            "  ledger     Manage compact state ledger (.context-slim/ledger.md)\n\n"
            "Options:\n"
            "  -h, --help      Show help\n"
            "  -v, --version   Show version\n"
        )
        return 0

    if args[0] in ("-v", "--version", "version"):
        print(f"cslim {__version__}")
        return 0

    cmd, rest = args[0], args[1:]
    if cmd == "compress":
        return compress_output.main(rest)
    if cmd == "slice":
        return slice_file.main(rest)
    if cmd == "run":
        return run_cmd.main(rest)
    if cmd == "diff":
        return diff_budget.main(rest)
    if cmd == "ledger":
        return ledger_tool.main(rest)

    print(f"Unknown cslim subcommand: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
