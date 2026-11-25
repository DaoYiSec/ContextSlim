#!/usr/bin/env python3
"""Claude Code PreToolUse(Bash) hook: prevents raw scanner floods, unbounded search/find, and large cats."""

from __future__ import annotations

import json
import re
import shlex
import sys
from pathlib import Path

SKILL_ROOT = Path(__file__).resolve().parents[3]
SCRIPTS_DIR = SKILL_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from _common import inspect_text_file, is_blocked_glob, load_config  # noqa: E402
from compress_output import compress_skeleton  # noqa: E402

NOISY_SCANNERS = {
    "ffuf": "anomaly",
    "gobuster": "anomaly",
    "feroxbuster": "anomaly",
    "dirsearch": "anomaly",
    "httpx": "anomaly",
    "nuclei": "sast",
    "semgrep": "sast",
    "trivy": "sast",
    "bandit": "sast",
    "nmap": "nmap",
    "sqlmap": "sqlmap",
}

OUTPUT_FILE_FLAGS = {
    "-o",
    "-oX",
    "-oG",
    "-oN",
    "-oA",
    "-oJ",
    "--output",
    "-output",
    "--json-output",
    "--sarif-output",
}

BARE_GIT_LOG_RE = re.compile(r"^\s*git\s+log\s*$")
FD_REDIRECT_RE = re.compile(r"\b\d*>&\d+\b")
BROAD_FIND_TARGETS = {".", "./", "..", "../", "/", "~", "$HOME"}


def _split_shell_segments(cmd: str) -> list[str]:
    """Split a shell command on unquoted &&, ||, ;, or newlines."""
    segments: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    escaped = False
    i = 0
    n = len(cmd)

    while i < n:
        ch = cmd[i]
        if escaped:
            buf.append(ch)
            escaped = False
            i += 1
            continue
        if ch == "\\" and quote != "'":
            buf.append(ch)
            escaped = True
            i += 1
            continue
        if ch in ("'", '"'):
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
            buf.append(ch)
            i += 1
            continue
        if quote is None:
            if cmd[i : i + 2] in ("&&", "||"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
                i += 2
                continue
            if ch in (";", "\n"):
                seg = "".join(buf).strip()
                if seg:
                    segments.append(seg)
                buf.clear()
                i += 1
                continue
        buf.append(ch)
        i += 1

    tail = "".join(buf).strip()
    if tail:
        segments.append(tail)
    return segments


def _has_unquoted_pipe_or_file_redirect(seg: str) -> bool:
    """Return True if segment contains an unquoted pipe `|` or file output redirect `>`."""
    cleaned = FD_REDIRECT_RE.sub("", seg)
    quote: str | None = None
    escaped = False
    for ch in cleaned:
        if escaped:
            escaped = False
            continue
        if ch == "\\" and quote != "'":
            escaped = True
            continue
        if ch in ("'", '"'):
            if quote is None:
                quote = ch
            elif quote == ch:
                quote = None
            continue
        if quote is None and ch in ("|", ">"):
            return True
    return False


def _segment_tokens(seg: str) -> list[str]:
    try:
        return shlex.split(seg)
    except ValueError:
        return seg.strip().split()


def _command_binary_and_args(tokens: list[str]) -> tuple[str, list[str]]:
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if "=" in tok and not tok.startswith("-"):
            idx += 1
            continue
        if tok in ("sudo", "env", "timeout", "nice"):
            idx += 1
            continue
        return Path(tok).name, tokens[idx + 1 :]
    return "", []


def _scanner_output_handled(seg: str, args: list[str]) -> bool:
    if _has_unquoted_pipe_or_file_redirect(seg):
        return True
    if "compress_output.py" in seg or re.search(r"\bcslim\b", seg):
        return True
    for i, tok in enumerate(args):
        if tok in OUTPUT_FILE_FLAGS:
            if i + 1 < len(args) and args[i + 1] != "-":
                return True
        for flag in OUTPUT_FILE_FLAGS:
            if tok.startswith(f"{flag}=") and tok != f"{flag}=-":
                return True
    return False


def _emit_updated_command(tool_input: dict, new_cmd: str, reason: str) -> int:
    updated = dict(tool_input)
    updated["command"] = new_cmd
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                    "permissionDecisionReason": reason,
                    "updatedInput": updated,
                }
            }
        )
    )
    return 0


def _maybe_rewrite_search(seg: str, tool_input: dict) -> int | None:
    """Safely add column limits / ignore dirs to single-command rg or recursive grep."""
    if _has_unquoted_pipe_or_file_redirect(seg):
        return None
    tokens = _segment_tokens(seg)
    if not tokens:
        return None
    bin_name = Path(tokens[0]).name
    args = tokens[1:]

    if bin_name == "rg":
        skip_flags = {"--max-columns", "-M", "--files", "-l", "--files-with-matches", "--files-without-match", "-c", "--count", "-h", "--help", "-V", "--version"}
        if any(a in skip_flags or a.startswith("--max-columns=") for a in args):
            return None
        new_cmd = shlex.join([tokens[0], "--max-columns", "240", "--max-columns-preview", *args])
        return _emit_updated_command(tool_input, new_cmd, "context-slim added --max-columns 240 to prevent minified-line floods.")

    if bin_name == "grep":
        is_recursive = any(
            a in ("-r", "-R", "--recursive") or (a.startswith("-") and not a.startswith("--") and ("r" in a or "R" in a))
            for a in args
        )
        if not is_recursive:
            return None
        skip_flags = {"-l", "--files-with-matches", "-c", "--count", "--help", "--version"}
        if any(a in skip_flags or a.startswith("--exclude-dir") for a in args):
            return None
        excludes = [
            "--exclude-dir=.git",
            "--exclude-dir=node_modules",
            "--exclude-dir=dist",
            "--exclude-dir=build",
            "--exclude-dir=.venv",
            "--exclude-dir=__pycache__",
        ]
        new_cmd = shlex.join([tokens[0], *excludes, *args])
        return _emit_updated_command(tool_input, new_cmd, "context-slim added standard --exclude-dir guards to recursive grep.")

    if bin_name == "docker" and args and args[0] == "logs":
        sub_args = args[1:]
        bounded = any(
            a in ("--tail", "-n", "-f", "--follow", "--since", "--help")
            or a.startswith(("--tail=", "-n"))
            for a in sub_args
        )
        if not bounded:
            new_cmd = shlex.join([tokens[0], "logs", "--tail", "100", *sub_args])
            return _emit_updated_command(tool_input, new_cmd, "context-slim bounded `docker logs` to --tail 100.")

    return None


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    tool_input = payload.get("tool_input") or {}
    cmd = str(tool_input.get("command") or "").strip()
    if not cmd:
        return 0

    cwd = Path(payload.get("cwd") or ".").resolve()
    cfg = load_config(cwd)
    segments = _split_shell_segments(cmd)

    # 1. Safe single-command rewrites via updatedInput (bare git log, rg, recursive grep)
    if len(segments) == 1:
        if BARE_GIT_LOG_RE.match(cmd):
            return _emit_updated_command(
                tool_input,
                "git log --oneline -n 30",
                "context-slim bounded unbounded git log to 30 oneline entries.",
            )
        rewritten = _maybe_rewrite_search(segments[0], tool_input)
        if rewritten is not None:
            return rewritten

    eff_cwd = cwd
    rg = cfg.get("read_guard", {})
    max_lines = int(rg.get("max_unbounded_lines", 200))
    preview_lines = int(rg.get("skeleton_preview_lines", 60))
    blocked_globs = list(rg.get("blocked_globs", []))

    for seg in segments:
        tokens = _segment_tokens(seg)
        binary, args = _command_binary_and_args(tokens)
        if not binary:
            continue

        if binary == "cd" and args and not _has_unquoted_pipe_or_file_redirect(seg):
            cand = Path(args[0])
            eff_cwd = cand if cand.is_absolute() else (eff_cwd / cand)
            continue

        # 2. Prevent raw scanner stdout flooding context when unredirected & unpiped
        if binary in NOISY_SCANNERS and not _scanner_output_handled(seg, args):
            mode = NOISY_SCANNERS[binary]
            print(
                f"context-slim blocked raw `{binary}` stdout dump. Redirect to a temp file and summarize:\n"
                f"  Example: {seg} > /tmp/cs_{binary}.out 2>&1 && "
                f'python3 "{SCRIPTS_DIR}/compress_output.py" --mode {mode} --input /tmp/cs_{binary}.out',
                file=sys.stderr,
            )
            return 2

        # 3. Block unbounded `find` over broad trees without -maxdepth/-prune/pipe
        if binary == "find" and not _has_unquoted_pipe_or_file_redirect(seg):
            has_bound = any(a in ("-maxdepth", "-prune", "-quit") for a in args)
            first_path = next((a for a in args if not a.startswith("-")), ".")
            if not has_bound and first_path in BROAD_FIND_TARGETS:
                print(
                    f"context-slim blocked unbounded `find {first_path}` without `-maxdepth` or `-prune`.\n"
                    f"Use `find {first_path} -maxdepth 3 -not -path '*/node_modules/*' -not -path '*/.git/*'` or `cslim ledger scan-map`.",
                    file=sys.stderr,
                )
                return 2

        # 4. Block plain `cat <large-or-generated-file>` without pipe/redirect and emit skeleton
        if binary == "cat" and not _has_unquoted_pipe_or_file_redirect(seg):
            file_args = [a for a in args if not a.startswith("-") and a != "--"]
            for fa in file_args:
                target = Path(fa)
                if not target.is_absolute():
                    target = eff_cwd / target
                if is_blocked_glob(str(target), eff_cwd, blocked_globs):
                    print(
                        f"context-slim blocked `cat` on generated/lock file `{fa}`. "
                        "Use grep/rg or `cslim diff --profile audit` for dependency deltas.",
                        file=sys.stderr,
                    )
                    return 2
                if target.is_file():
                    is_bin, total_lines, preview, capped = inspect_text_file(target)
                    if not is_bin and (total_lines > max_lines or capped):
                        skel = compress_skeleton(preview, max_lines=preview_lines)
                        count_label = f">{total_lines:,}" if capped else str(total_lines)
                        print(
                            f"context-slim blocked `cat` on large file `{fa}` ({count_label} lines). "
                            f"Use bounded Read(offset, limit) or `cslim slice` on targeted ranges:\n\n{skel}",
                            file=sys.stderr,
                        )
                        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
