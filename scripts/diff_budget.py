#!/usr/bin/env python3
"""Mechanical git-diff budgeter with dev and security-audit profiles.

Key guarantees:
  - Preserves complete @@ hunks and diff --git headers (never slices mid-hunk).
  - In --profile audit:
      * Summarizes lockfile/manifest version changes instead of discarding supply-chain diffs.
      * Boosts 1-5 line low-density diffs touching auth/permissions/sinks or removing guards.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import sys
from dataclasses import dataclass
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _common import estimate_tokens, load_config, read_input_text, strip_ansi

DEPENDENCY_FILES = (
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "go.mod",
    "go.sum",
    "requirements.txt",
    "Cargo.toml",
    "Cargo.lock",
    "pom.xml",
)

SECURITY_KEYWORDS_RE = re.compile(
    r"\b(?:auth\w*|perm\w*|role\w*|admin|jwt|token|session|verify\w*|bypass|cors|csrf\w*|"
    r"sql\w*|query|exec\w*|eval|spawn|shell|pickle|yaml\.load|deserializ\w*|unserialize|readObject|ObjectInputStream|Marshal\.load|unsafe|"
    r"chmod|chown|sudo|secret|password|passwd|credential|signature|hmac|encrypt|md5|sha1|ECB|"
    r"innerHTML|dangerouslySetInnerHTML|v-html|document\.write|send_file|sendFile|readFile|path\.join|"
    r"redirect|allow_redirects|ssrf|XXE|ENTITY|resolve_entities|"
    r"allow_origin|rejectUnauthorized|verify_ssl|NODE_TLS_REJECT_UNAUTHORIZED|0\.0\.0\.0|permitAll|PreAuthorize|SkipAuth|allow_anonymous|insecure)\b",
    re.IGNORECASE,
)
SECURITY_PATH_RE = re.compile(
    r"(?:auth|perm|role|admin|security|middleware|policy|rbac|acl|dockerfile|nginx|ingress|\.github/workflows|terraform|\.tf$)",
    re.IGNORECASE,
)
REMOVED_GUARD_RE = re.compile(r"^-\s*(?:if|unless|assert|require|check|verify|return\s+(?:401|403|False|false|null))\b")

# Lockfile context-tracking regexes
RE_NPM_LOCK_PKG = re.compile(r'^\s*[+-]?\s*"(?:packages/)?([^"]*node_modules/([^"]+))":\s*\{')
RE_CARGO_NAME = re.compile(r'^\s*[+-]?\s*name\s*=\s*"([^"]+)"')
RE_YARN_HEADER = re.compile(r'^\s*[+-]?\s*"?(@?[^@\s",:][^@\s,:]*)(?:@[^:"]+)?"?:\s*$')
RE_POM_ARTIFACT = re.compile(r'^\s*[+-]?\s*<artifactId>([^<]+)</artifactId>')
RE_LOCK_VERSION = re.compile(r'^([+-])\s*"?(?:version)"?\s*[:=]\s*"?([^\s",]+)"?')
RE_KV_JSON = re.compile(r'^([+-])\s*"([^"]+)":\s*"([^"]+)"')
RE_GO_REQ = re.compile(r'^([+-])\s*([^\s]+)\s+(v[\d.]+[^\s]*)')
RE_PIP_REQ = re.compile(r'^([+-])\s*([A-Za-z0-9_.-]+)\s*[=~<>!]=+\s*([^\s;#]+)')


@dataclass
class HunkBlock:
    file_path: str
    file_header: str
    hunk_text: str
    order: int
    tokens: int
    score: float
    is_dep_summary: bool = False


def _matches_any(path: str, globs: list[str]) -> bool:
    name = Path(path).name
    return any(fnmatch.fnmatch(path, g) or fnmatch.fnmatch(name, g) for g in globs)


def _is_dependency_file(path: str) -> bool:
    name = Path(path).name
    return any(name == d or (name.startswith("requirements") and name.endswith(".txt")) for d in DEPENDENCY_FILES)


def _summarize_dependency_diff(file_path: str, body_lines: list[str]) -> str:
    """Extract compact pkg: old -> new version deltas from lockfile/manifest diffs."""
    removed: dict[str, str] = {}
    added: dict[str, str] = {}
    simple_changes: list[str] = []
    cur_pkg: str | None = None

    for line in body_lines:
        if line.startswith(("diff --git ", "--- ", "+++ ")):
            continue
        if line.startswith("@@ "):
            # Hunk headers sometimes carry context e.g. @@ -10,3 +10,3 @@ "node_modules/lodash": {
            m_npm = RE_NPM_LOCK_PKG.search(line)
            if m_npm:
                cur_pkg = m_npm.group(2)
            continue

        # Update enclosing package name from context or diff lines
        m_npm = RE_NPM_LOCK_PKG.match(line)
        if m_npm:
            cur_pkg = m_npm.group(2)
            continue
        m_cargo = RE_CARGO_NAME.match(line)
        if m_cargo:
            cur_pkg = m_cargo.group(1)
            continue
        m_pom = RE_POM_ARTIFACT.match(line)
        if m_pom:
            cur_pkg = m_pom.group(1)
            continue
        m_yarn = RE_YARN_HEADER.match(line)
        if m_yarn and not line.lstrip("+- ").startswith(("dependencies", "devDependencies", "packages", "resolved")):
            cur_pkg = m_yarn.group(1)
            continue

        if not line.startswith(("+", "-")):
            continue

        # 1. Context-aware lockfile `"version": "1.2.3"` / `version = "1.2.3"`
        m_ver = RE_LOCK_VERSION.match(line)
        if m_ver and cur_pkg:
            sign, ver = m_ver.group(1), m_ver.group(2)
            (removed if sign == "-" else added)[cur_pkg] = ver
            continue

        # 2. Direct `"pkg": "^1.2.3"`, `pkg v1.2.3`, or `pkg==1.2.3`
        m_kv = RE_KV_JSON.match(line)
        if m_kv:
            sign, pkg, ver = m_kv.group(1), m_kv.group(2), m_kv.group(3)
            if pkg in ("version", "resolved", "integrity", "license", "lockfileVersion"):
                continue
            (removed if sign == "-" else added)[pkg] = ver
            continue

        m_go = RE_GO_REQ.match(line)
        if m_go:
            sign, pkg, ver = m_go.group(1), m_go.group(2), m_go.group(3).removesuffix("/go.mod")
            (removed if sign == "-" else added)[pkg] = ver
            continue

        m_pip = RE_PIP_REQ.match(line)
        if m_pip:
            sign, pkg, ver = m_pip.group(1), m_pip.group(2), m_pip.group(3)
            (removed if sign == "-" else added)[pkg] = ver
            continue

        if len(simple_changes) < 12 and ("version" in line.lower() or "artifactid" in line.lower()):
            simple_changes.append(line.strip()[:100])

    deltas: list[str] = []
    for pkg in sorted(set(removed) | set(added)):
        old_v = removed.get(pkg, "none")
        new_v = added.get(pkg, "removed")
        if old_v != new_v:
            deltas.append(f"  {pkg}: {old_v} -> {new_v}")
    if not deltas:
        deltas = [f"  {c}" for c in simple_changes]
    if not deltas:
        return ""

    max_items = 25
    shown = deltas[:max_items]
    if len(deltas) > max_items:
        shown.append(f"  [... {len(deltas) - max_items} more dependency changes omitted ...]")
    return f"diff --git a/{file_path} b/{file_path}\n# Dependency version summary\n" + "\n".join(shown)


def _extract_path_from_section(lines: list[str]) -> str:
    """Resolve file path robustly even when paths contain spaces or /dev/null."""
    git_cand = ""
    minus_cand = ""
    for ln in lines[:8]:
        if ln.startswith("+++ "):
            cand = ln[4:].strip().strip('"')
            if cand and cand != "/dev/null":
                return cand[2:] if cand.startswith("b/") else cand
        elif ln.startswith("--- "):
            cand = ln[4:].strip().strip('"')
            if cand and cand != "/dev/null":
                minus_cand = cand[2:] if cand.startswith("a/") else cand
        elif ln.startswith("diff --git "):
            m = re.match(r'^diff --git\s+"?a/(.+?)"?\s+"?b/(.+?)"?$', ln)
            if m:
                git_cand = m.group(2)
            else:
                parts = ln.split()
                if len(parts) >= 4:
                    git_cand = parts[3][2:] if parts[3].startswith("b/") else parts[3]
    return minus_cand or git_cand or "unknown"


def _parse_file_sections(diff_text: str) -> list[tuple[str, str, list[str]]]:
    """Split unified diff into (file_path, file_header, list_of_hunks_or_body)."""
    sections: list[tuple[str, str, list[str]]] = []
    cur_lines: list[str] = []

    def _flush(lines: list[str]) -> None:
        if not lines:
            return
        file_path = _extract_path_from_section(lines)
        header_lines: list[str] = []
        hunks: list[str] = []
        cur_hunk: list[str] = []
        in_hunk = False
        for ln in lines:
            if ln.startswith("@@ "):
                if cur_hunk:
                    hunks.append("\n".join(cur_hunk))
                cur_hunk = [ln]
                in_hunk = True
            elif in_hunk:
                cur_hunk.append(ln)
            else:
                header_lines.append(ln)
        if cur_hunk:
            hunks.append("\n".join(cur_hunk))
        if not hunks and lines:
            hunks = ["\n".join(header_lines)]
            header_lines = []
        sections.append((file_path, "\n".join(header_lines), hunks))

    for ln in diff_text.splitlines():
        if ln.startswith("diff --git ") and cur_lines:
            _flush(cur_lines)
            cur_lines = [ln]
        else:
            cur_lines.append(ln)
    _flush(cur_lines)
    return sections


def _score_hunk(
    hunk_text: str,
    file_path: str,
    profile: str,
    include_re: re.Pattern[str] | None,
) -> float:
    changed = [ln for ln in hunk_text.splitlines() if ln.startswith(("+", "-")) and not ln.startswith(("+++", "---"))]
    change_cnt = len(changed)
    if change_cnt == 0:
        return 0.1

    score = min(float(change_cnt), 20.0) if profile == "dev" else 5.0
    if include_re and include_re.search(hunk_text):
        score += 40.0

    if profile == "audit":
        sec_hits = sum(1 for ln in changed if SECURITY_KEYWORDS_RE.search(ln))
        guard_removals = sum(1 for ln in changed if REMOVED_GUARD_RE.search(ln))
        path_boost = 15.0 if (SECURITY_KEYWORDS_RE.search(file_path) or SECURITY_PATH_RE.search(file_path)) else 0.0
        # Explicitly protect low-density (1-5 line) security changes against huge refactors
        low_density_boost = 30.0 if (change_cnt <= 5 and (sec_hits > 0 or guard_removals > 0)) else 0.0
        score += sec_hits * 25.0 + guard_removals * 45.0 + path_boost + low_density_boost
    return score


def budget_diff(
    diff_text: str,
    budget_tokens: int = 8000,
    profile: str = "dev",
    exclude_globs: list[str] | None = None,
    include_keywords: str | None = None,
) -> str:
    """Filter and prioritize complete hunks within token budget."""
    cleaned = strip_ansi(diff_text)
    if not cleaned.strip():
        return ""

    cfg = load_config().get("diff_budget", {})
    excludes = list(exclude_globs) if exclude_globs is not None else list(cfg.get("dev_exclude_globs", []))
    include_re = re.compile(include_keywords, re.IGNORECASE) if include_keywords else None

    blocks: list[HunkBlock] = []
    skipped_files: list[str] = []
    order = 0

    for file_path, file_header, hunks in _parse_file_sections(cleaned):
        if profile == "audit" and _is_dependency_file(file_path):
            body_lines = "\n".join(hunks).splitlines()
            summary = _summarize_dependency_diff(file_path, body_lines)
            if summary:
                blocks.append(
                    HunkBlock(
                        file_path=file_path,
                        file_header="",
                        hunk_text=summary,
                        order=order,
                        tokens=estimate_tokens(summary),
                        score=55.0,
                        is_dep_summary=True,
                    )
                )
                order += 1
            else:
                skipped_files.append(f"{file_path} (no version delta)")
            continue

        if _matches_any(file_path, excludes):
            skipped_files.append(file_path)
            continue

        for h in hunks:
            sc = _score_hunk(h, file_path, profile, include_re)
            toks = estimate_tokens(h) + (estimate_tokens(file_header) if file_header else 0)
            blocks.append(
                HunkBlock(
                    file_path=file_path,
                    file_header=file_header,
                    hunk_text=h,
                    order=order,
                    tokens=toks,
                    score=sc,
                )
            )
            order += 1

    # Prioritize by score desc, preserving original order on tie
    ranked = sorted(blocks, key=lambda b: (-b.score, b.order))
    selected: list[HunkBlock] = []
    dropped_files: list[str] = []
    used_tokens = 0
    seen_headers: set[str] = set()

    for blk in ranked:
        header_cost = 0 if (not blk.file_header or blk.file_path in seen_headers) else estimate_tokens(blk.file_header)
        hunk_cost = estimate_tokens(blk.hunk_text)
        cost = header_cost + hunk_cost
        if used_tokens + cost <= budget_tokens:
            selected.append(blk)
            used_tokens += cost
            seen_headers.add(blk.file_path)
        else:
            dropped_files.append(blk.file_path)

    # Restore original diff order for readable output
    selected.sort(key=lambda b: b.order)
    rendered: list[str] = []
    emitted_headers: set[str] = set()
    for blk in selected:
        if blk.file_header and blk.file_path not in emitted_headers:
            rendered.append(blk.file_header)
            emitted_headers.add(blk.file_path)
        rendered.append(blk.hunk_text)

    meta = [
        f"# Diff Budget ({profile}): ~{used_tokens}/{budget_tokens} tokens | kept {len(selected)}/{len(blocks)} hunks"
    ]
    if blocks and not selected:
        min_cost = min(b.tokens for b in blocks)
        meta.append(f"# Note: smallest hunk (~{min_cost} tokens) exceeds budget ({budget_tokens}); increase --budget.")
    if skipped_files:
        meta.append(f"# Excluded files ({len(skipped_files)}): {', '.join(skipped_files[:10])}")
    if dropped_files:
        uniq_dropped = list(dict.fromkeys(dropped_files))
        meta.append(f"# Over-budget dropped hunks in ({len(uniq_dropped)} files): {', '.join(uniq_dropped[:10])}")

    return "\n".join(meta + rendered)


def main(argv: list[str] | None = None) -> int:
    cfg = load_config().get("diff_budget", {})
    parser = argparse.ArgumentParser(description="Hunk-safe git diff budgeter for dev and security audit.")
    parser.add_argument("input_pos", nargs="?", default=None, help="Optional positional diff file path")
    parser.add_argument("--input", default="-", help="Unified diff file path or '-' for stdin")
    parser.add_argument("--profile", choices=["dev", "audit"], default="dev")
    parser.add_argument("--budget", type=int, default=cfg.get("default_tokens", 8000))
    parser.add_argument("--exclude", nargs="*", default=None, help="Override exclude globs")
    parser.add_argument("--include-keywords", default=None, help="Regex of keywords to prioritize")
    args = parser.parse_args(argv)

    target_input = args.input_pos if args.input_pos is not None else args.input
    try:
        raw = read_input_text(target_input)
    except OSError as exc:
        print(f"Error reading `{target_input}`: {exc}", file=sys.stderr)
        return 2
    try:
        result = budget_diff(
            raw,
            budget_tokens=args.budget,
            profile=args.profile,
            exclude_globs=args.exclude,
            include_keywords=args.include_keywords,
        )
    except re.error as exc:
        print(f"Invalid --include-keywords regex: {exc}", file=sys.stderr)
        return 2
    if result:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
