#!/usr/bin/env python3
"""Multi-range & symbol-aware file slicer: read imports + target functions in one call."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _common import load_config  # noqa: E402
from compress_output import (  # noqa: E402
    RE_C_FN,
    RE_JS_CONST_FN,
    RE_PHP_FN,
    RE_ROUTE_DECORATOR,
    RE_SYMBOL_LINE,
    _clip_line,
    _estimate_block_end,
    extract_import_span,
)


def parse_ranges(spec: str, total_lines: int) -> list[tuple[int, int]]:
    """Parse comma-separated 1-based ranges like '1-25,140-185,200'."""
    out: list[tuple[int, int]] = []
    for part in spec.split(","):
        tok = part.strip()
        if not tok:
            continue
        if "-" in tok:
            a_s, b_s = tok.split("-", 1)
            a, b = int(a_s.strip()), int(b_s.strip())
        else:
            a = b = int(tok)
        lo = max(1, min(a, b))
        hi = min(total_lines, max(a, b))
        if lo <= hi:
            out.append((lo, hi))
    return out


def _is_definition_for(line: str, symbol: str) -> bool:
    """Check whether `line` defines `symbol` using existing skeleton patterns."""
    if not (
        RE_SYMBOL_LINE.match(line)
        or RE_C_FN.match(line)
        or RE_JS_CONST_FN.match(line)
        or RE_PHP_FN.match(line)
    ):
        return False
    return re.search(rf"\b{re.escape(symbol)}\b", line) is not None


def find_symbol_ranges(
    lines: list[str],
    symbols: list[str],
    max_symbol_lines: int = 120,
) -> tuple[list[tuple[int, int]], list[str]]:
    """Locate 1-based (start, end) ranges (including leading decorators) for requested symbols."""
    total = len(lines)
    ranges: list[tuple[int, int]] = []
    found: set[str] = set()

    for idx, raw in enumerate(lines):
        for sym in symbols:
            if not _is_definition_for(raw, sym):
                continue
            found.add(sym)
            start_idx = idx
            # Include immediately preceding decorators / route annotations
            probe = idx - 1
            while probe >= 0 and idx - probe <= 5:
                st = lines[probe].strip()
                if st.startswith("@") or RE_ROUTE_DECORATOR.match(lines[probe]):
                    start_idx = probe
                    probe -= 1
                else:
                    break
            end_ln = _estimate_block_end(lines, idx)
            if end_ln is None or end_ln <= idx + 1:
                end_ln = min(total, idx + 1 + 40)
            if end_ln - (start_idx + 1) + 1 > max_symbol_lines:
                end_ln = start_idx + max_symbol_lines
            ranges.append((start_idx + 1, min(total, end_ln)))

    missing = [s for s in symbols if s not in found]
    return ranges, missing


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping or adjacent 1-based closed intervals."""
    if not ranges:
        return []
    sorted_r = sorted(ranges)
    merged = [sorted_r[0]]
    for lo, hi in sorted_r[1:]:
        prev_lo, prev_hi = merged[-1]
        if lo <= prev_hi + 1:
            merged[-1] = (prev_lo, max(prev_hi, hi))
        else:
            merged.append((lo, hi))
    return merged


def slice_text(
    text: str,
    file_label: str = "<input>",
    ranges_spec: str | None = None,
    symbols: list[str] | None = None,
    with_imports: bool = True,
    context_lines: int = 0,
    max_lines: int = 220,
    max_line_chars: int = 320,
) -> str:
    """Slice exact import + requested ranges/symbols from text in one compact block."""
    lines = text.splitlines()
    if not lines:
        return ""

    total = len(lines)
    intervals: list[tuple[int, int]] = []
    missing_syms: list[str] = []

    if with_imports:
        imp_span = extract_import_span(lines)
        if imp_span:
            intervals.append(imp_span)

    if ranges_spec:
        for lo, hi in parse_ranges(ranges_spec, total):
            intervals.append((max(1, lo - context_lines), min(total, hi + context_lines)))

    if symbols:
        sym_ranges, missing_syms = find_symbol_ranges(lines, symbols)
        for lo, hi in sym_ranges:
            intervals.append((max(1, lo - context_lines), min(total, hi + context_lines)))

    merged = merge_ranges(intervals)
    if not merged:
        msg = f"# Slice ({file_label}: {total} lines): no matching ranges/symbols"
        if missing_syms:
            msg += f" (missing: {', '.join(missing_syms)})"
        return msg

    shown_lines = sum(hi - lo + 1 for lo, hi in merged)
    out = [f"# Slice ({file_label}: {total} total lines -> {shown_lines} lines in {len(merged)} span(s))"]
    if missing_syms:
        out.append(f"# Missing symbols: {', '.join(missing_syms)}")

    line_budget = max_lines
    for lo, hi in merged:
        if len(out) >= line_budget:
            out.append("[... slice truncated at --max-lines ...]")
            break
        out.append(f"--- [L{lo}-L{hi}] ---")
        for ln in range(lo, hi + 1):
            if len(out) >= line_budget:
                out.append("[... slice truncated at --max-lines ...]")
                return "\n".join(out)
            out.append(f"L{ln}: {_clip_line(lines[ln - 1], max_line_chars)}")

    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    cfg = load_config().get("compress", {})
    parser = argparse.ArgumentParser(description="Read [Header/Imports] + multiple target line ranges/symbols in one call.")
    parser.add_argument("file", help="Target source/config file path")
    parser.add_argument("--ranges", default=None, help="Comma-separated 1-based line ranges, e.g. '1-25,140-185'")
    parser.add_argument("--symbols", action="append", default=[], help="Comma-separated symbol names to extract")
    parser.add_argument("--no-imports", action="store_true", help="Do not prepend [Header/Imports] automatically")
    parser.add_argument("--context", type=int, default=0, help="Extra context lines around each range/symbol")
    parser.add_argument("--max-lines", type=int, default=220)
    parser.add_argument("--max-line-chars", type=int, default=cfg.get("default_max_line_chars", 320))
    args = parser.parse_args(argv)

    target = Path(args.file)
    try:
        raw = target.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"Error reading `{args.file}`: {exc}", file=sys.stderr)
        return 2

    sym_list = [s.strip() for item in args.symbols for s in item.split(",") if s.strip()]
    try:
        out = slice_text(
            raw,
            file_label=args.file,
            ranges_spec=args.ranges,
            symbols=sym_list or None,
            with_imports=not args.no_imports,
            context_lines=max(0, args.context),
            max_lines=max(10, args.max_lines),
            max_line_chars=max(0, args.max_line_chars),
        )
    except ValueError as exc:
        print(f"Invalid --ranges specification: {exc}", file=sys.stderr)
        return 2
    if out:
        print(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
