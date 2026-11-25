#!/usr/bin/env python3
"""Deterministic output compressor for pentest, code audit, and daily dev workflows.

Standard library only. Modes:
  - auto:     Detect input structure (SAST JSON/SARIF, fuzz anomaly, nmap, sqlmap, HTTP, grep, test log, or dedupe)
  - anomaly:  Cluster HTTP/directory fuzzing by (status, size bucket, words) + reflection fallback
  - sast:     Compact Semgrep / Nuclei / Trivy / Bandit / SARIF findings by (rule, file)
  - nmap:     Extract up hosts + open ports/services from nmap stdout/-oN/-oG/-oX
  - sqlmap:   Strip sqlmap testing chatter while keeping Parameter/Payload/DBMS/DB dumps
  - http:     Strip CSS/SVG/JS bloat & huge form values from curl/HTTP responses
  - grep:     Group rg/grep file:line:match results by file and fold test/comment noise
  - testlog:  Extract root failure + traceback windows, strip PASS/Docker/pip/pytest warnings chatter
  - skeleton: Multi-language symbol/route/security-config/JSON/Markdown skeleton + [Header/Imports]
  - dedupe:   Preserve first occurrence of identical lines
  - severity: Group lines by severity level while maintaining intra-level order
  - truncate: Keep bounded head + tail lines (with optional fenced block retention)
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import OrderedDict, defaultdict
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _common import load_config, read_input_text, strip_ansi

# --- Anomaly clustering patterns (ffuf / gobuster / feroxbuster / dirsearch / httpx) ---
RE_STATUS_BRACKET = re.compile(
    r"(?:\bStatus:\s*|\(Status:\s*|\bstatus[=:]\s*|\[)(\d{3})(?:\]|\b)",
    re.IGNORECASE,
)
RE_STATUS_PREFIX = re.compile(
    r"^\s*(?:\[\d{2}:\d{2}:\d{2}\]\s*)?(\d{3})\s+(?:[-|]|(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b)"
)
RE_SIZE = re.compile(
    r"(?:\bSize:\s*|\bLength:\s*|\bcontent[-_]length[=:]\s*|\bsize[=:]\s*)(\d+)\s*[bB]?",
    re.IGNORECASE,
)
RE_SIZE_BYTES = re.compile(r"(?:^|\s)(\d+)\s*([kKmM]?[bB]|c)(?=\s|$)")
RE_BRACKET_NUM = re.compile(r"\[(\d+)\]")
RE_WORDS = re.compile(r"(?:\bWords:\s*|\bwords[=:]\s*)(\d+)|\b(\d+)w\b", re.IGNORECASE)
RE_LINES_CNT = re.compile(r"(?:\bLines:\s*|\blines[=:]\s*)(\d+)|\b(\d+)l\b", re.IGNORECASE)
RE_URL_OR_PATH = re.compile(r"(https?://\S+|/\S+)")

# --- Nmap patterns ---
RE_NMAP_REPORT = re.compile(r"^Nmap scan report for\s+(.+)$")
RE_NMAP_PORT = re.compile(r"^(\d+/(?:tcp|udp))\s+(open|open\|filtered)\s+(.+)$")
RE_NMAP_SCRIPT_KEEP = re.compile(
    r"^\|_?\s*(?:http-title:|ssl-cert:\s*Subject:|Subject Alternative Name:|vulners:|"
    r"smb-vuln|http-methods:|http-server-header:|ftp-anon:|Anonymous FTP|title:|VULNERABLE)",
    re.IGNORECASE,
)
RE_NMAP_GNMAP = re.compile(r"^Host:\s+(\S+)\s*\(([^)]*)\)\s*(.*)$")

# --- Sqlmap patterns ---
RE_SQLMAP_KEEP = re.compile(
    r"(?:^(?:Parameter|Type|Title|Payload|Vector|back-end DBMS|web server|web application|"
    r"current user|current database|hostname|is DBA|available databases|Database:|Table:|\[\d+\s+entr)|"
    r"^\[(?:CRITICAL|WARNING|ERROR)\]|"
    r"^\|\s+.*\s+\||^\+-+\+|"
    r"\b(?:appears to be|might be|is vulnerable|injectable|fetched data logged)\b)",
    re.IGNORECASE,
)
RE_SQLMAP_NOISE = re.compile(
    r"^(?:\[\d{2}:\d{2}:\d{2}\]\s*)?\[(?:INFO|DEBUG|TRAFFIC)\]\s+"
    r"(?:testing\s+|heuristic\s+|checking\s+|fetching\s+|resuming\s+|using\s+)",
    re.IGNORECASE,
)

# --- Grep / ripgrep patterns ---
RE_GREP_MATCH = re.compile(r"^((?:[A-Za-z]:)?[^:\n]+):(\d+):(.*)$")
RE_TEST_PATH = re.compile(
    r"(?:^|/)(?:tests?|__tests__|__mocks__|spec|fixtures?|testdata)(?:/|$)|\.(?:test|spec)\.[^.]+$",
    re.IGNORECASE,
)
RE_COMMENT_SNIP = re.compile(r"^\s*(?://|#|/\*|\*|<!--)")

# --- HTTP / HTML patterns ---
RE_HTTP_STATUS = re.compile(r"^\s*(?:<\s*)?HTTP/(?:\d+(?:\.\d+)?)\s+\d{3}\b", re.IGNORECASE)
RE_HTTP_KEEP_HEADER = re.compile(
    r"^\s*(?:<\s*)?(?:set-cookie|location|server|x-powered-by|www-authenticate|"
    r"access-control-[\w-]+|content-security-policy|x-frame-options|content-type|content-length)\s*:",
    re.IGNORECASE,
)
RE_CURL_NOISE = re.compile(
    r"^\s*\*\s+(?:Trying|Connected to|ALPN|SSL|TLSv|Server certificate|subject:|start date:|expire date:|issuer:|SSL certificate|using HTTP|h2h3|Connection state|}\s+\[\d+|{\s+\[\d+)"
)
RE_HTML_STRIP_BLOCK = re.compile(r"<(style|svg)\b[^>]*>.*?</\1>", re.IGNORECASE | re.DOTALL)
RE_HTML_SCRIPT_BLOCK = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL)
RE_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
RE_HTML_INTERESTING_TAG = re.compile(
    r"<(?:title|form|input|textarea|select|button)\b[^>]*>(?:.*?</(?:title|button)>)?",
    re.IGNORECASE | re.DOTALL,
)
RE_HTML_LONG_VAL = re.compile(r"""(\b(?:value|data-[\w-]+)\s*=\s*)(["'])([^"']{60,})\2""", re.IGNORECASE)
RE_HTML_ATTR_SRC = re.compile(r"""\b(?:src|action|href)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
RE_HTML_TAGS = re.compile(r"<[^>]+>")
RE_JS_ENDPOINT = re.compile(r"""["'](/api/[^"'\s]{1,100}|/v\d+/[^"'\s]{1,100}|/admin[^"'\s]{0,80})["']""")
RE_HTTP_ERR_TEXT = re.compile(
    r"\b(?:error|exception|traceback|stack\s*trace|unauthorized|forbidden|sql|syntax|invalid|denied|debug|token|secret)\b",
    re.IGNORECASE,
)

# --- Test & build log patterns (pytest / unittest / jest / vitest / go test / cargo / docker / pip / npm) ---
RE_TEST_PASS = re.compile(
    r"^(?:"
    r"\s*(?:\.|ok\s+\S+|PASS\b|PASSED\b|---\s*PASS:|===\s*RUN\b|[✓✔]\s+|"
    r"Compiling\s+|Fetching\s+|Downloading\s+|Checking\s+|Building\s+|"
    r"#\d+\s+\[\d+/\d+\]\s+|Step\s+\d+/\d+\s*:|Get:\d+\s+http|"
    r"Selecting previously unselected|Preparing to unpack|Unpacking\s+\S+|Setting up\s+\S+|"
    r"Collecting\s+\S+|Using cached\s+|Requirement already satisfied:|"
    r"added \d+ packages|audited \d+ packages|\s*=\s*note:\s+required\s+by\b)|"
    r"\s*test\s+\S+.*\.\.\.\s*ok\s*$|"
    r".*\s+PASSED(?:\s+\[\s*\d+%\])?\s*$"
    r")",
    re.IGNORECASE,
)
RE_TEST_FAIL_ANCHOR = re.compile(
    r"(?:^Traceback \(most recent call last\):|^={3,}\s+FAILURES\s+={3,}$|^_{3,}\s+\S+\s+_{3,}$|"
    r"^\s*(?:FAILED|FAIL)\b|^---\s*FAIL:|^\s*●\s+|^\s*E\s+(?:assert\b|\w*(?:Error|Exception)\b)|"
    r"\b(?:AssertionError|TypeError|ReferenceError|SyntaxError|ValueError|RuntimeError|panic:)\b|"
    r"\berror(?:\[E\d+\]|\s+TS\d+):|^\s*\S+\.(?:go|rs|c|cc|cpp|ts|tsx|js|py):\d+(?::\d+)?:\s*(?:fatal\s+error:|error:|undefined:|cannot\s+)|^\s*ERROR:\s|^\s*✕\s)",
    re.IGNORECASE,
)
RE_TEST_SUMMARY = re.compile(
    r"(?:\b\d+\s+(?:failed|passed|errors?|warnings?|skipped)\b|^Test Suites:|^Tests:|^FAIL\s+\S+|"
    r"^test result:\s*(?:FAILED|ok)|^Summary:)",
    re.IGNORECASE,
)

# --- Severity patterns ---
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "ERROR": 2, "MEDIUM": 3, "WARN": 4, "WARNING": 4, "LOW": 5, "INFO": 6}
RE_SEVERITY = re.compile(r"\b(CRITICAL|HIGH|ERROR|MEDIUM|WARNING|WARN|LOW|INFO)\b", re.IGNORECASE)

# --- Multi-language skeleton & security-config patterns (linear-time) ---
RE_IMPORT = re.compile(
    r"^\s*(?:import\s+|from\s+\S+\s+import\s+|require\(|use\s+|using\s+|#include\s+|package\s+|require_once\b|include\b)"
)
RE_ROUTE_DECORATOR = re.compile(
    r"^\s*(?:"
    r"@(?:app|router|bp|blueprint|api)\.|"
    r"@(?:Get|Post|Put|Delete|Patch|Request)Mapping\b|"
    r"@(?:Controller|RestController|Route|Path|Auth|RolesAllowed|PreAuthorize|Secured|PermitAll|CrossOrigin|WebFilter|Bean|UseGuards|Public|csrf_exempt|login_required|permission_required)\b|"
    r"[A-Za-z_]\w*\.(?:get|post|put|delete|patch|use|route|handle|HandleFunc|Handle)\s*\(|"
    r"Route::(?:get|post|put|delete|patch|any|match|middleware|group)\s*\(|"
    r"http\.Handle(?:Func)?\s*\(|"
    r"(?:re_)?path\s*\(\s*['\"]"
    r")",
    re.IGNORECASE,
)
RE_SEC_CONFIG_LINE = re.compile(
    r"^\s*(?:privileged|allowPrivilegeEscalation|hostNetwork|hostPID|runAsRoot|readOnlyRootFilesystem|"
    r"proxy_pass|alias|add_header|ssl_verify|cors|allow_origin|permitAll)\s*[:\s]"
)
RE_SYMBOL_LINE = re.compile(
    r"^\s*(?:"
    r"(?:async\s+)?def\s+\w+|"
    r"(?:export\s+(?:default\s+)?)?(?:async\s+)?function\*?\s+\w+|"
    r"(?:export\s+(?:default\s+)?)?(?:abstract\s+)?class\s+\w+|"
    r"(?:export\s+)?(?:interface|type|enum|struct|trait|impl|module)\s+\w+|"
    r"func\s+(?:\([^)]+\)\s*)?\w+|"
    r"(?:pub\s+(?:\([^)]+\)\s+)?)?(?:async\s+)?fn\s+\w+|"
    r"(?:public|private|protected|internal|static|final|abstract|virtual|override|synchronized)"
    r"(?:\s+(?:public|private|protected|internal|static|final|abstract|virtual|override|synchronized|[\w<>\[\],.?&]+)){0,6}"
    r"\s+\w+\s*\([^;]*\)\s*(?:throws\s+[\w,\s]+)?\{?|"
    r"(?:CREATE\s+(?:OR\s+REPLACE\s+)?(?:TABLE|VIEW|FUNCTION|PROCEDURE|TRIGGER)\s+\S+)|"
    r"(?:FROM|ENTRYPOINT|CMD|USER|EXPOSE)\s+|"
    r"(?:server|location|upstream)\s+[^{\s]*\s*\{"
    r")"
)
RE_C_FN = re.compile(
    r"^(?!\s*(?:if|else|for|while|switch|catch|return|throw|sizeof|typeof|new|delete)\b)"
    r"[A-Za-z_][\w:*&<>\[\]]*(?:[^\S\r\n]+[A-Za-z_*&][\w:*&<>\[\]]*){1,5}\s*\([^;]*\)\s*\{"
)
RE_JS_CONST_FN = re.compile(
    r"^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?(?:\([^)]*\)|[a-zA-Z_]\w*)\s*=>"
)
_CTRL_KEYS = r"(?!if\b|else\b|elif\b|try\b|except\b|finally\b|default\b|switch\b|case\b|do\b|return\b)"
RE_YAML_TOP = re.compile(rf"^{_CTRL_KEYS}([A-Za-z0-9_.-]+):\s*(?:#.*)?$")
RE_YAML_CHILD = re.compile(rf"^  {_CTRL_KEYS}([A-Za-z0-9_.-]+):\s*(?:#.*)?$")
RE_PHP_FN = re.compile(r"^\s*(?:(?:public|protected|private|static|final|abstract)\s+)*function\s+\w+\s*\(")
RE_MD_HEADING = re.compile(r"^(#{1,3})\s+\S+")
RE_CODE_INDICATOR = re.compile(
    r"^\s*(?:import\s+|from\s+\S+\s+import\s+|def\s+|class\s+|func\s+|package\s+|#include\s+|#!/)"
)


def _clip_line(line: str, max_line_chars: int) -> str:
    """Prevent single minified/base64/JSON lines from blowing up token budgets."""
    if max_line_chars <= 0 or len(line) <= max_line_chars:
        return line
    omitted = len(line) - max_line_chars
    return f"{line[:max_line_chars]} ... [+{omitted} chars]"


def _first_present(obj: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for k in keys:
        if obj.get(k) is not None:
            return obj[k]
    return None


def _to_int_or_none(val: Any) -> int | None:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, (int, float)):
        return int(val)
    if isinstance(val, str) and val.strip().isdigit():
        return int(val.strip())
    return None


def _extract_anomaly_details(line: str) -> tuple[tuple[str, int, str] | None, int, int]:
    """Return (signature, raw_size, target_len) from a CLI scan line."""
    status: str | None = None
    status_span: tuple[int, int] | None = None
    for pat in (RE_STATUS_PREFIX, RE_STATUS_BRACKET):
        for m in pat.finditer(line):
            code = int(m.group(1))
            if 100 <= code <= 599:
                status = str(code)
                status_span = m.span(1)
                break
        if status is not None:
            break
    if status is None:
        return None, -1, 0

    size_m = RE_SIZE.search(line)
    if size_m:
        size_val = int(size_m.group(1))
    else:
        size_b = RE_SIZE_BYTES.search(line)
        if size_b:
            unit = size_b.group(2).lower()
            mult = 1024 if unit.startswith("k") else (1024 * 1024 if unit.startswith("m") else 1)
            size_val = int(size_b.group(1)) * mult
        else:
            size_val = -1
    if size_val < 0:
        for bm in RE_BRACKET_NUM.finditer(line):
            if status_span is not None and bm.span(1) == status_span:
                continue
            size_val = int(bm.group(1))
            break
    size_bucket = (size_val // 16) * 16 if size_val >= 0 else -1

    words_m = RE_WORDS.search(line) or RE_LINES_CNT.search(line)
    words_val = (words_m.group(1) or words_m.group(2)) if words_m else "-"

    url_m = RE_URL_OR_PATH.search(line)
    target_len = len(url_m.group(1)) if url_m else 0
    return (status, size_bucket, words_val), size_val, target_len


def _extract_anomaly_signature(line: str) -> tuple[str, int, str] | None:
    sig, _, _ = _extract_anomaly_details(line)
    return sig


def _anomaly_record_details(obj: dict[str, Any]) -> tuple[tuple[str, int, str] | None, int, int]:
    """Return (signature, raw_length, fuzz_len) from ffuf/httpx/feroxbuster JSON objects."""
    status = _first_present(obj, ("status", "status_code", "status-code"))
    if status is None:
        return None, -1, 0
    length_raw = _first_present(obj, ("length", "content_length", "content-length"))
    length = _to_int_or_none(length_raw)
    raw_len = length if (length is not None and length >= 0) else -1
    inp = obj.get("input")
    fuzz_str = inp.get("FUZZ") if isinstance(inp, dict) else (inp if isinstance(inp, str) else "")
    fuzz_len = len(str(fuzz_str or ""))
    # For ffuf JSON where exact FUZZ input is known, subtract reflected FUZZ length only if adjusted differs smoothly
    size_bucket = (raw_len // 16) * 16 if raw_len >= 0 else -1
    words = _first_present(obj, ("words", "word_count", "lines", "line_count"))
    return (str(status), size_bucket, str(words if words is not None else "-")), raw_len, fuzz_len


def _format_json_hit(obj: dict[str, Any]) -> str:
    inp = obj.get("input")
    fuzz_val = inp.get("FUZZ") if isinstance(inp, dict) else (inp if isinstance(inp, str) else None)
    url = _first_present(obj, ("url", "host")) or fuzz_val or "?"
    status = _first_present(obj, ("status", "status_code", "status-code"))
    status_str = str(status) if status is not None else "?"
    length = _first_present(obj, ("length", "content_length", "content-length"))
    length_str = str(length) if length is not None else "?"
    words = _first_present(obj, ("words", "word_count", "lines", "line_count"))
    words_str = str(words) if words is not None else "-"
    title = str(obj.get("title") or "")
    extra = f" | title={title[:40]}" if title else ""
    return f"[{status_str}] size={length_str} words={words_str} | {url}{extra}"


def compress_anomaly(
    text: str,
    min_cluster: int = 3,
    max_lines: int = 120,
    max_line_chars: int = 320,
) -> str:
    """Cluster repetitive HTTP/fuzzing hits (including path-reflecting pages) and keep 100% of outliers."""
    stripped = text.strip()
    if not stripped:
        return ""

    # Each record: (sig, raw_len, target_len, rendered)
    records: list[tuple[tuple[str, int, str] | None, int, int, str]] = []
    parsed_structured = False

    if stripped[0] in "{[":
        try:
            payload = json.loads(stripped)
            items: list[Any] | None = None
            if isinstance(payload, dict) and isinstance(payload.get("results"), list):
                items = payload["results"]
                parsed_structured = True
            elif isinstance(payload, list):
                items = payload
                parsed_structured = True
            if items is not None:
                for item in items:
                    if isinstance(item, dict):
                        sig, raw_len, tlen = _anomaly_record_details(item)
                        records.append((sig, raw_len, tlen, _format_json_hit(item)))
        except json.JSONDecodeError:
            pass

    if not parsed_structured:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        sig, raw_len, tlen = _anomaly_record_details(obj)
                        records.append((sig, raw_len, tlen, _format_json_hit(obj) if sig is not None else line))
                        continue
                except json.JSONDecodeError:
                    pass
            sig, raw_len, tlen = _extract_anomaly_details(line)
            records.append((sig, raw_len, tlen, line))

    counts: dict[tuple[str, int, str], int] = defaultdict(int)
    for sig, _, _, _ in records:
        if sig is not None:
            counts[sig] += 1

    # Second pass: detect path-reflecting noise among unclustered hits that share (status, words)
    # and collapse to an identical adjusted length `raw_len - target_len`
    adj_counts: dict[tuple[str, int, str], int] = defaultdict(int)
    adj_sigs: list[tuple[str, int, str] | None] = []
    for sig, raw_len, tlen, _ in records:
        if sig is not None and counts[sig] < min_cluster and raw_len >= 0 and tlen > 0 and sig[2] != "-":
            adj_len = max(0, raw_len - tlen)
            asig = (sig[0], (adj_len // 16) * 16, sig[2])
            adj_counts[asig] += 1
            adj_sigs.append(asig)
        else:
            adj_sigs.append(None)

    seen_bulk: set[tuple[str, ...]] = set()
    tagged_out: list[tuple[int, str]] = []
    suppressed_total = 0

    for idx, (sig, _, _, rendered) in enumerate(records):
        clipped = _clip_line(rendered, max_line_chars)
        if sig is None:
            tagged_out.append((0, clipped))
            continue

        cnt = counts[sig]
        asig = adj_sigs[idx]
        if cnt >= min_cluster:
            key = ("raw", sig[0], str(sig[1]), sig[2])
            if key not in seen_bulk:
                seen_bulk.add(key)
                tagged_out.append((1, clipped))
                tagged_out.append(
                    (1, f"  [×{cnt - 1} similar suppressed: status={sig[0]}, size~{sig[1]}, words={sig[2]}]")
                )
                suppressed_total += cnt - 1
        elif asig is not None and adj_counts[asig] >= min_cluster:
            acnt = adj_counts[asig]
            key = ("adj", asig[0], str(asig[1]), asig[2])
            if key not in seen_bulk:
                seen_bulk.add(key)
                tagged_out.append((1, clipped))
                tagged_out.append(
                    (1, f"  [×{acnt - 1} path-reflected similar suppressed: status={asig[0]}, base_size~{asig[1]}, words={asig[2]}]")
                )
                suppressed_total += acnt - 1
        else:
            tagged_out.append((0, clipped))

    avail = max(1, max_lines - 1)
    if len(tagged_out) > avail:
        outliers = [item for item in tagged_out if item[0] == 0]
        bulk = [item for item in tagged_out if item[0] == 1]
        keep_budget = max(1, avail - 1)
        kept = outliers[:keep_budget]
        rem = keep_budget - len(kept)
        if rem > 0:
            kept.extend(bulk[:rem])
        omitted = len(tagged_out) - len(kept)
        out = [ln for _, ln in kept] + [f"[... {omitted} additional lines omitted (increase --max-lines) ...]"]
    else:
        out = [ln for _, ln in tagged_out]

    header = f"# Anomaly Summary: {len(records)} total entries, {suppressed_total} bulk noise suppressed, {len(out)} lines shown"
    return "\n".join([header, *out])


def compress_nmap(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Extract live hosts and open ports/services from nmap stdout, -oN, -oG, or -oX XML."""
    stripped = text.strip()
    if not stripped:
        return ""

    hosts: list[tuple[str, list[str]]] = []

    # 1. Try nmap -oX XML
    if stripped.startswith("<?xml") or "<nmaprun" in stripped[:400]:
        try:
            root = ET.fromstring(stripped)
            for host_el in root.findall("host"):
                status_el = host_el.find("status")
                if status_el is not None and status_el.get("state") != "up":
                    continue
                addr_el = host_el.find("address")
                addr = addr_el.get("addr", "?") if addr_el is not None else "?"
                hn_el = host_el.find("./hostnames/hostname")
                label = f"{addr} ({hn_el.get('name')})" if (hn_el is not None and hn_el.get("name")) else addr
                ports_list: list[str] = []
                for p_el in host_el.findall("./ports/port"):
                    st = p_el.find("state")
                    if st is None or st.get("state") not in ("open", "open|filtered"):
                        continue
                    proto = p_el.get("protocol", "tcp")
                    pid = p_el.get("portid", "?")
                    svc = p_el.find("service")
                    svc_desc = ""
                    if svc is not None:
                        parts = [svc.get("name", ""), svc.get("product", ""), svc.get("version", "")]
                        svc_desc = " ".join(p for p in parts if p)
                    ports_list.append(f"{pid}/{proto} {svc_desc}".strip())
                hosts.append((label, ports_list))
        except ET.ParseError:
            hosts.clear()

    # 2. Try -oG (gnmap) or standard stdout/-oN
    if not hosts:
        gnmap_hosts: OrderedDict[str, list[str]] = OrderedDict()
        cur_host: str | None = None
        cur_ports: list[str] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m_g = RE_NMAP_GNMAP.match(line)
            if m_g:
                ip, hname, rest = m_g.group(1), m_g.group(2), m_g.group(3)
                if "Status: Down" in rest:
                    continue
                label = f"{ip} ({hname})" if hname else ip
                bucket = gnmap_hosts.setdefault(label, [])
                if "Ports:" in rest:
                    p_str = rest.split("Ports:", 1)[1].split("\t")[0]
                    for item in p_str.split(","):
                        segs = [s.strip() for s in item.strip().split("/")]
                        if len(segs) >= 5 and "open" in segs[1]:
                            entry = f"{segs[0]}/{segs[2]} {segs[4]} {segs[6] if len(segs) > 6 else ''}".strip()
                            if entry not in bucket:
                                bucket.append(entry)
                continue

            m_rep = RE_NMAP_REPORT.match(line)
            if m_rep:
                if cur_host is not None and cur_ports:
                    hosts.append((cur_host, cur_ports))
                cur_host = m_rep.group(1).strip()
                cur_ports = []
                continue
            if cur_host is not None:
                m_port = RE_NMAP_PORT.match(line)
                if m_port:
                    cur_ports.append(f"{m_port.group(1)} {' '.join(m_port.group(3).split())}")
                elif RE_NMAP_SCRIPT_KEEP.match(line):
                    cur_ports.append(f"  {line[:140]}")
        if cur_host is not None and cur_ports:
            hosts.append((cur_host, cur_ports))
        if gnmap_hosts and not hosts:
            hosts = list(gnmap_hosts.items())

    if not hosts:
        return "# Nmap Summary: 0 up hosts with open ports"

    # Group hosts sharing identical open port sets when scanning large subnets
    out = [f"# Nmap Summary: {len(hosts)} active host(s)"]
    for label, plist in hosts:
        summary = " | ".join(plist) if plist else "host up (no open ports listed)"
        out.append(_clip_line(f"{label} -> {summary}", max_line_chars))
        if len(out) >= max_lines - 1 and len(hosts) > len(out) - 1:
            out.append(f"[... {len(hosts) - (len(out) - 1)} additional hosts omitted ...]")
            break
    return "\n".join(out)


def compress_sqlmap(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Strip repetitive sqlmap [INFO] testing probes while keeping injection payloads, DBMS, and dumps."""
    kept: list[str] = []
    skipped = 0
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip():
            continue
        if RE_SQLMAP_NOISE.match(line.strip()):
            skipped += 1
            continue
        if RE_SQLMAP_KEEP.search(line.strip()) or not line.strip().startswith("["):
            kept.append(_clip_line(line, max_line_chars))
        else:
            skipped += 1

    deduped = list(OrderedDict.fromkeys(kept))
    header = f"# Sqlmap Summary: {len(deduped)} high-signal lines ({skipped} probe/info lines stripped)"
    avail = max(1, max_lines - 1)
    if len(deduped) > avail:
        show = max(1, avail - 1)
        return "\n".join([header, *deduped[:show], f"[... {len(deduped) - show} lines omitted ...]"])
    return "\n".join([header, *deduped])


def compress_grep(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Group rg/grep file:line:match results by file, strip comments, and fold test files."""
    prod_by_file: OrderedDict[str, tuple[list[str], str]] = OrderedDict()
    test_hits: dict[str, int] = defaultdict(int)
    comments_dropped = 0
    raw_matches = 0

    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        m = RE_GREP_MATCH.match(line)
        if not m:
            continue
        raw_matches += 1
        fpath, lineno, snippet = m.group(1), m.group(2), m.group(3).strip()
        if RE_COMMENT_SNIP.match(snippet):
            comments_dropped += 1
            continue
        if RE_TEST_PATH.search(fpath):
            test_hits[fpath] += 1
            continue
        if fpath not in prod_by_file:
            prod_by_file[fpath] = ([lineno], snippet)
        else:
            lns, first_snip = prod_by_file[fpath]
            if len(lns) < 12:
                lns.append(lineno)
            prod_by_file[fpath] = (lns, first_snip)

    if raw_matches == 0:
        return compress_dedupe(text, max_lines=max_lines, max_line_chars=max_line_chars)

    out = [
        f"# Grep Summary: {raw_matches} raw matches -> {len(prod_by_file)} source file(s)"
        + (f" ({comments_dropped} comments skipped)" if comments_dropped else "")
    ]
    avail = max(1, max_lines - (2 if test_hits else 1))
    items = list(prod_by_file.items())
    show = items[:avail]
    for fpath, (lns, snip) in show:
        out.append(_clip_line(f"{fpath}:{','.join(lns)} | {snip}", max_line_chars))
    if len(items) > len(show):
        out.append(f"[... {len(items) - len(show)} more source files omitted ...]")
    if test_hits:
        total_test = sum(test_hits.values())
        out.append(f"[test/mock files folded: {total_test} match(es) across {len(test_hits)} file(s)]")
    return "\n".join(out)


def _sev_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev.upper(), 9)


def _format_snip(snip: Any) -> str:
    if isinstance(snip, list):
        return ", ".join(str(x) for x in snip[:5])
    return str(snip or "")


def _extract_sast_records(text: str) -> tuple[list[tuple[str, str, str, int | str, str]], bool]:
    """Return ([(severity, rule_id, location, line, snippet)], recognized_json)."""
    stripped = text.strip()
    if not stripped:
        return [], False
    items: list[tuple[str, str, str, int | str, str]] = []

    def _add(sev: Any, rule: Any, loc: Any, line: Any, snip: Any) -> None:
        s_sev = str(sev or "INFO").upper()
        s_rule = str(rule or "unknown-rule")
        s_loc = str(loc or "?")
        s_snip = " ".join(_format_snip(snip).split())[:140]
        items.append((s_sev, s_rule, s_loc, line if line is not None else "?", s_snip))

    def _parse_finding_obj(obj: dict[str, Any]) -> bool:
        info = obj.get("info") if isinstance(obj.get("info"), dict) else {}
        extra = obj.get("extra") if isinstance(obj.get("extra"), dict) else {}
        rule = obj.get("template-id") or obj.get("rule_id") or obj.get("check_id") or obj.get("test_id") or obj.get("test_name")
        if rule is None and not info and not extra:
            return False
        sev = info.get("severity") or extra.get("severity") or obj.get("issue_severity") or obj.get("severity") or obj.get("level")
        loc = obj.get("matched-at") or obj.get("host") or obj.get("path") or obj.get("filename") or obj.get("file")
        start = obj.get("start") if isinstance(obj.get("start"), dict) else {}
        ln = start.get("line") or obj.get("line_number") or obj.get("line") or obj.get("matcher-name") or "?"
        snip = (
            obj.get("extracted-results")
            or extra.get("lines")
            or obj.get("code")
            or info.get("name")
            or extra.get("message")
            or obj.get("issue_text")
            or obj.get("message")
            or ""
        )
        _add(sev, rule, loc, ln, snip)
        return True

    if stripped[0] in "{[":
        try:
            data = json.loads(stripped)
            if isinstance(data, list):
                for entry in data:
                    if isinstance(entry, dict):
                        _parse_finding_obj(entry)
                return items, True

            if isinstance(data, dict) and isinstance(data.get("results"), list):
                for r in data["results"]:
                    if isinstance(r, dict):
                        _parse_finding_obj(r)
                return items, True

            if isinstance(data, dict) and isinstance(data.get("runs"), list):
                for run in data["runs"]:
                    if not isinstance(run, dict):
                        continue
                    for res in run.get("results") or []:
                        if not isinstance(res, dict):
                            continue
                        rule = res.get("ruleId")
                        props = res.get("properties") if isinstance(res.get("properties"), dict) else {}
                        sev = res.get("level") or props.get("severity")
                        locs = res.get("locations") or []
                        first_loc = locs[0] if locs and isinstance(locs[0], dict) else {}
                        phys = first_loc.get("physicalLocation") if isinstance(first_loc.get("physicalLocation"), dict) else {}
                        art = phys.get("artifactLocation") if isinstance(phys.get("artifactLocation"), dict) else {}
                        uri = art.get("uri", "?")
                        reg = phys.get("region") if isinstance(phys.get("region"), dict) else {}
                        line = reg.get("startLine", "?")
                        reg_snip = reg.get("snippet") if isinstance(reg.get("snippet"), dict) else {}
                        msg = res.get("message") if isinstance(res.get("message"), dict) else {}
                        snip = reg_snip.get("text") or msg.get("text", "")
                        _add(sev, rule, uri, line, snip)
                return items, True

            if isinstance(data, dict) and isinstance(data.get("Results"), list):
                for block in data["Results"]:
                    if not isinstance(block, dict):
                        continue
                    target = block.get("Target", "?")
                    for vuln in block.get("Vulnerabilities") or []:
                        if not isinstance(vuln, dict):
                            continue
                        _add(
                            vuln.get("Severity"),
                            vuln.get("VulnerabilityID"),
                            target,
                            vuln.get("PkgName", "?"),
                            f"{vuln.get('InstalledVersion', '')} -> fixed:{vuln.get('FixedVersion', 'none')}",
                        )
                    for mis in block.get("Misconfigurations") or []:
                        if not isinstance(mis, dict):
                            continue
                        cause = mis.get("CauseMetadata") if isinstance(mis.get("CauseMetadata"), dict) else {}
                        _add(
                            mis.get("Severity"),
                            mis.get("ID"),
                            target,
                            cause.get("StartLine", "?"),
                            mis.get("Title", ""),
                        )
                return items, True
        except json.JSONDecodeError:
            pass

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("{"):
            try:
                obj = json.loads(line)
                if isinstance(obj, dict) and _parse_finding_obj(obj):
                    continue
            except json.JSONDecodeError:
                pass
        m_sev = RE_SEVERITY.search(line)
        sev = m_sev.group(1) if m_sev else "INFO"
        _add(sev, "text-finding", "-", "?", line)

    return items, False


def compress_sast(text: str, max_lines: int = 120) -> str:
    """Group SAST/scanner findings by (severity, rule_id, location) and strip verbose rule prose."""
    records, recognized_json = _extract_sast_records(text)
    if not records:
        return "# SAST Summary: 0 findings" if recognized_json else ""

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for sev, rule, loc, line, snip in records:
        key = (sev, rule, loc)
        bucket = grouped.setdefault(key, {"lines": [], "snippet": snip, "count": 0})
        bucket["count"] += 1
        s_line = str(line)
        if s_line != "?" and s_line not in bucket["lines"] and len(bucket["lines"]) < 12:
            bucket["lines"].append(s_line)
        if not bucket["snippet"] and snip:
            bucket["snippet"] = snip

    sorted_keys = sorted(grouped.keys(), key=lambda k: (_sev_rank(k[0]), k[1], k[2]))
    out = [f"# SAST Summary: {len(records)} raw hits -> {len(sorted_keys)} grouped findings"]

    avail = max(1, max_lines - 1)
    show_keys = sorted_keys[: avail - 1] if len(sorted_keys) > avail else sorted_keys
    for key in show_keys:
        sev, rule, loc = key
        info = grouped[key]
        lines_str = ",".join(info["lines"]) if info["lines"] else "?"
        cnt_suffix = f" (×{info['count']})" if info["count"] > 1 else ""
        out.append(f"[{sev}] {rule} | {loc}:{lines_str}{cnt_suffix} | {info['snippet']}")

    if len(sorted_keys) > len(show_keys):
        out.append(f"[... {len(sorted_keys) - len(show_keys)} lower-priority findings omitted ...]")
    return "\n".join(out)


def compress_http(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Extract attack-surface elements from curl/HTTP/HTML responses while stripping CSS/SVG/JS bloat."""
    lines = text.splitlines()
    if not lines:
        return ""

    headers_out: list[str] = []
    body_lines: list[str] = []
    in_body = False
    seen_status = False

    for raw in lines:
        if not in_body:
            if RE_CURL_NOISE.match(raw) or raw.lstrip().startswith(("> ", "* ")):
                continue
            if RE_HTTP_STATUS.match(raw):
                headers_out.append(_clip_line(raw.strip(), max_line_chars))
                seen_status = True
                continue
            if RE_HTTP_KEEP_HEADER.match(raw):
                headers_out.append(_clip_line(raw.strip(), max_line_chars))
                continue
            cleaned_hdr = raw.lstrip("< ").strip()
            if seen_status and cleaned_hdr == "":
                in_body = True
                continue
            if raw.lstrip().startswith("<") and not raw.lstrip().startswith("< "):
                in_body = True
                body_lines.append(raw)
            elif not seen_status and ":" not in raw[:40]:
                in_body = True
                body_lines.append(raw)
        else:
            body_lines.append(raw)

    body = "\n".join(body_lines)
    stripped_blocks = 0

    def _drop_block(_m: re.Match[str]) -> str:
        nonlocal stripped_blocks
        stripped_blocks += 1
        return ""

    body_no_noise = RE_HTML_STRIP_BLOCK.sub(_drop_block, body)
    discovered_apis: list[str] = []
    script_tags: list[str] = []

    def _process_script(m: re.Match[str]) -> str:
        nonlocal stripped_blocks
        attrs, inner = m.group(1), m.group(2)
        src_m = RE_HTML_ATTR_SRC.search(attrs)
        if src_m:
            script_tags.append(f"[script src] {src_m.group(1)}")
        for api_m in RE_JS_ENDPOINT.finditer(inner):
            val = api_m.group(1)
            if val not in discovered_apis and len(discovered_apis) < 20:
                discovered_apis.append(val)
        if inner.strip():
            stripped_blocks += 1
        return ""

    body_no_noise = RE_HTML_SCRIPT_BLOCK.sub(_process_script, body_no_noise)

    comments = [" ".join(c.split())[:160] for c in RE_HTML_COMMENT.findall(body_no_noise) if c.strip()]

    def _shorten_tag_vals(tag_str: str) -> str:
        # Fold massive ViewState/CSRF/Base64 values BEFORE slicing so name=/action=/type= stay visible
        folded = RE_HTML_LONG_VAL.sub(lambda m: f"{m.group(1)}{m.group(2)}<len={len(m.group(3))}>{m.group(2)}", tag_str)
        return " ".join(folded.split())[:180]

    tags = [_shorten_tag_vals(t) for t in RE_HTML_INTERESTING_TAG.findall(body_no_noise)]

    visible_lines: list[str] = []
    text_only = html.unescape(RE_HTML_TAGS.sub(" ", RE_HTML_COMMENT.sub(" ", body_no_noise)))
    for ln in text_only.splitlines():
        compact = " ".join(ln.split())
        if not compact:
            continue
        if RE_HTTP_ERR_TEXT.search(compact) or len(visible_lines) < 25:
            visible_lines.append(_clip_line(compact, max_line_chars))

    out: list[str] = [
        f"# HTTP Extract ({len(lines)} raw lines, {stripped_blocks} style/svg/script blocks stripped)"
    ]
    if headers_out:
        out.append("## Headers")
        out.extend(headers_out[:25])
    if tags or script_tags or comments or discovered_apis:
        out.append("## Forms, Scripts & Attack Surface")
        out.extend(OrderedDict.fromkeys(tags[:30]))
        out.extend(OrderedDict.fromkeys(script_tags[:15]))
        for ep in discovered_apis:
            out.append(f"[js-endpoint] {ep}")
        for c in comments[:10]:
            out.append(f"[comment] {c}")
    if visible_lines:
        out.append("## Visible Body / Errors")
        out.extend(OrderedDict.fromkeys(visible_lines[:40]))

    if len(out) > max_lines:
        keep = max(1, max_lines - 1)
        out = out[:keep] + [f"[... {len(out) - keep} HTTP lines omitted ...]"]
    return "\n".join(out)


def compress_testlog(
    text: str,
    max_failures: int = 3,
    max_lines: int = 120,
    max_line_chars: int = 320,
) -> str:
    """Drop passing/build/pytest-warnings chatter and extract first root failure + traceback windows."""
    raw_lines = text.splitlines()
    if not raw_lines:
        return ""

    filtered: list[tuple[int, str]] = []
    in_pytest_warnings = False
    warnings_stripped = 0

    for idx, raw_line in enumerate(raw_lines, start=1):
        line = raw_line.split("\r")[-1] if "\r" in raw_line else raw_line
        st = line.strip()
        if not st:
            continue

        # Collapse pytest `=== warnings summary ===` noise block until next `=== ... ===` banner
        if re.match(r"^=+\s+warnings summary\s+=+$", st, re.IGNORECASE):
            in_pytest_warnings = True
            warnings_stripped += 1
            continue
        if in_pytest_warnings:
            if st.startswith("===") or st.startswith("-- Docs:"):
                in_pytest_warnings = False
                if st.startswith("-- Docs:"):
                    continue
            else:
                warnings_stripped += 1
                continue

        if RE_TEST_PASS.match(line) and not RE_TEST_FAIL_ANCHOR.search(line):
            continue
        filtered.append((idx, _clip_line(line, max_line_chars)))

    windows: list[str] = []
    used_indices: set[int] = set()
    next_allowed_pos = 0
    failure_count = 0

    for pos, (orig_ln, line) in enumerate(filtered):
        if RE_TEST_FAIL_ANCHOR.search(line):
            if pos in used_indices:
                continue
            failure_count += 1
            if failure_count > max_failures:
                break
            start = max(next_allowed_pos, pos - 3)
            end = min(len(filtered), pos + 25)
            windows.append(f"--- Failure #{failure_count} (around log line {orig_ln}) ---")
            for j in range(start, end):
                used_indices.add(j)
                windows.append(filtered[j][1])
            next_allowed_pos = end

    summary_lines = [line for _, line in filtered[-15:] if RE_TEST_SUMMARY.search(line)]
    if not windows:
        tail = [line for _, line in filtered[-min(len(filtered), max(1, max_lines - 1)):]]
        return "\n".join([f"# Test Log Tail ({len(raw_lines)} raw lines -> {len(tail)} shown)", *tail])

    warn_note = f"; {warnings_stripped} warning lines collapsed" if warnings_stripped else ""
    out = [f"# Test Failure Extract ({len(raw_lines)} raw lines; up to {max_failures} root failures{warn_note})"]
    out.extend(windows)
    if summary_lines:
        out.append("--- Summary ---")
        for s in OrderedDict.fromkeys(summary_lines):
            out.append(s)

    if len(out) > max_lines:
        out = out[: max(1, max_lines - 1)] + ["[... truncated to max_lines ...]"]
    return "\n".join(out)


def _estimate_block_end(lines: list[str], start_idx: int) -> int | None:
    """Heuristically estimate block end line (1-based) via brace depth, indentation, or Ruby `end`."""
    first = lines[start_idx]
    if "{" in first:
        depth = 0
        seen_open = False
        for idx in range(start_idx, min(len(lines), start_idx + 400)):
            depth += lines[idx].count("{") - lines[idx].count("}")
            if "{" in lines[idx]:
                seen_open = True
            if seen_open and depth <= 0:
                return idx + 1
        return None

    stripped = first.lstrip()
    base_indent = len(first) - len(stripped)

    sig_end_idx: int | None = None
    if stripped.endswith(":"):
        sig_end_idx = start_idx
    elif "(" in stripped and ")" not in stripped:
        for idx in range(start_idx + 1, min(len(lines), start_idx + 25)):
            if lines[idx].rstrip().endswith(":"):
                sig_end_idx = idx
                break

    if sig_end_idx is not None:
        last_non_empty = sig_end_idx
        for idx in range(sig_end_idx + 1, min(len(lines), sig_end_idx + 400)):
            cur = lines[idx]
            cur_stripped = cur.lstrip()
            if not cur_stripped or cur_stripped.startswith("#"):
                continue
            indent = len(cur) - len(cur_stripped)
            if indent <= base_indent:
                return last_non_empty + 1
            last_non_empty = idx
        return last_non_empty + 1

    if re.match(r"^(?:def|class|module)\s+\w+", stripped):
        for idx in range(start_idx + 1, min(len(lines), start_idx + 400)):
            cur = lines[idx]
            cur_stripped = cur.lstrip()
            if cur_stripped == "end" and (len(cur) - len(cur_stripped)) == base_indent:
                return idx + 1
    return None


def _extend_multiline_import(lines: list[str], start_idx: int) -> int:
    """Extend end line (1-based) if an import opens '(' without closing on the same line."""
    line = lines[start_idx]
    if "(" in line and ")" not in line:
        for idx in range(start_idx + 1, min(len(lines), start_idx + 40)):
            if ")" in lines[idx]:
                return idx + 1
    return start_idx + 1


def extract_import_span(lines: list[str]) -> tuple[int, int] | None:
    """Return 1-based (start_line, end_line) for header imports, or None."""
    import_lines: list[int] = []
    for idx, raw in enumerate(lines[:120]):
        lineno = idx + 1
        if RE_IMPORT.match(raw):
            import_lines.append(lineno)
            end_imp = _extend_multiline_import(lines, idx)
            if end_imp > lineno:
                import_lines.append(end_imp)
    if not import_lines:
        return None
    return (min(import_lines), max(import_lines))


def _json_skeleton_entries(text: str, total_lines: int) -> list[str] | None:
    """Return compact structural summary when inspecting a large JSON file."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[":
        return None
    try:
        obj = json.loads(stripped)
    except json.JSONDecodeError:
        return None
    entries: list[str] = []
    if isinstance(obj, dict):
        entries.append(f"[JSON object: {len(obj)} top-level key(s) across {total_lines} lines]")
        for k, v in list(obj.items())[:40]:
            if isinstance(v, list):
                desc = f"list[{len(v)}]"
            elif isinstance(v, dict):
                desc = f"dict({len(v)} keys: {', '.join(list(v.keys())[:5])})"
            else:
                desc = type(v).__name__
            entries.append(f"  .{k}: {desc}")
    elif isinstance(obj, list):
        entries.append(f"[JSON array: {len(obj)} item(s) across {total_lines} lines]")
        if obj and isinstance(obj[0], dict):
            entries.append(f"  item[0] keys: {', '.join(list(obj[0].keys())[:12])}")
    return entries or None


def compress_skeleton(text: str, max_lines: int = 120) -> str:
    """Extract [Header/Imports] range plus symbols, routes, security configs, JSON keys, and Markdown headings."""
    lines = text.splitlines()
    if not lines:
        return ""

    json_entries = _json_skeleton_entries(text, len(lines))
    if json_entries is not None:
        out = [f"# Skeleton ({len(lines)} total lines)"]
        out.extend(json_entries[: max(1, max_lines - 1)])
        return "\n".join(out)

    has_code_markers = False
    chk_fence = False
    for ln in lines[:80]:
        if ln.strip().startswith("```"):
            chk_fence = not chk_fence
            continue
        if not chk_fence and RE_CODE_INDICATOR.match(ln):
            has_code_markers = True
            break

    import_lines: list[int] = []
    entries: list[str] = []
    in_fence = False

    for idx, raw in enumerate(lines):
        lineno = idx + 1
        s = raw.strip()
        if s.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or not s:
            continue

        if not has_code_markers and RE_MD_HEADING.match(raw):
            entries.append(f"[L{lineno}] {raw.rstrip()[:120]}")
            continue

        if s.startswith(("#", "//", "/*", "*")):
            continue

        if RE_IMPORT.match(raw) and lineno <= 120:
            import_lines.append(lineno)
            end_imp = _extend_multiline_import(lines, idx)
            if end_imp > lineno:
                import_lines.append(end_imp)
            continue

        is_route = bool(RE_ROUTE_DECORATOR.match(raw))
        is_sec_cfg = bool(RE_SEC_CONFIG_LINE.match(raw))
        is_symbol = bool(
            RE_SYMBOL_LINE.match(raw)
            or RE_C_FN.match(raw)
            or RE_JS_CONST_FN.match(raw)
            or RE_PHP_FN.match(raw)
            or RE_YAML_TOP.match(raw)
            or RE_YAML_CHILD.match(raw)
        )

        if is_route or is_sec_cfg or is_symbol:
            end_ln = _estimate_block_end(lines, idx) if is_symbol else None
            loc = f"L{lineno}-L{end_ln}" if end_ln and end_ln > lineno else f"L{lineno}"
            tag = "[route] " if is_route else ("[sec-cfg] " if is_sec_cfg else "")
            entries.append(f"[{loc}] {tag}{raw.rstrip()[:120]}")

    out = [f"# Skeleton ({len(lines)} total lines)"]
    if import_lines:
        out.append(f"[Header/Imports: L{min(import_lines)}-L{max(import_lines)}]")
    if entries:
        avail = max(1, max_lines - len(out))
        if len(entries) > avail:
            show = max(1, avail - 1)
            out.extend(entries[:show])
            out.append(f"[... {len(entries) - show} more symbols omitted ...]")
        else:
            out.extend(entries)
    else:
        out.append("[No structured symbols detected; use grep/rg or bounded line reads]")
    return "\n".join(out)


def compress_dedupe(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Remove duplicate lines while preserving first occurrence order."""
    seen: OrderedDict[str, int] = OrderedDict()
    for line in text.splitlines():
        key = _clip_line(line.rstrip(), max_line_chars)
        if not key:
            continue
        seen[key] = seen.get(key, 0) + 1

    items = list(seen.items())
    out: list[str] = []
    if len(items) > max_lines:
        keep = max(1, max_lines - 1)
        for line, cnt in items[:keep]:
            out.append(f"{line}  [×{cnt}]" if cnt > 1 else line)
        out.append(f"[... {len(items) - keep} unique lines omitted ...]")
    else:
        for line, cnt in items:
            out.append(f"{line}  [×{cnt}]" if cnt > 1 else line)
    return "\n".join(out)


def compress_severity(text: str, max_lines: int = 120, max_line_chars: int = 320) -> str:
    """Sort lines by recognized severity while keeping original order within each level."""
    buckets: dict[int, list[str]] = defaultdict(list)
    for line in text.splitlines():
        if not line.strip():
            continue
        m = RE_SEVERITY.search(line)
        rank = _sev_rank(m.group(1)) if m else 99
        buckets[rank].append(_clip_line(line, max_line_chars))

    ordered: list[str] = []
    for rank in sorted(buckets.keys()):
        ordered.extend(buckets[rank])

    if len(ordered) > max_lines:
        keep = max(1, max_lines - 1)
        return "\n".join([*ordered[:keep], f"[... {len(ordered) - keep} lower-severity lines omitted ...]"])
    return "\n".join(ordered)


def compress_truncate(
    text: str,
    max_lines: int = 120,
    keep_fenced: bool = False,
    max_line_chars: int = 320,
) -> str:
    """Keep balanced head + tail lines; optionally preserve markdown fenced code blocks."""
    lines = text.splitlines()
    if len(lines) <= max_lines:
        return "\n".join(_clip_line(ln, max_line_chars) for ln in lines)

    head_n = max(1, max_lines // 2)
    tail_n = max(1, max_lines - head_n - 1)
    head_indices = set(range(head_n))
    tail_indices = set(range(len(lines) - tail_n, len(lines)))

    protected: set[int] = set()
    if keep_fenced:
        in_fence = False
        for i, line in enumerate(lines):
            if line.strip().startswith("```"):
                in_fence = not in_fence
                protected.add(i)
            elif in_fence:
                protected.add(i)

    keep = sorted(head_indices | tail_indices | protected)
    out: list[str] = []
    prev = -1
    for i in keep:
        if prev != -1 and i > prev + 1:
            out.append(f"[... {i - prev - 1} lines omitted ...]")
        out.append(_clip_line(lines[i], max_line_chars))
        prev = i
    return "\n".join(out)


def detect_mode(text: str) -> str:
    """Heuristically select the safest compression mode."""
    stripped = text.strip()
    if not stripped:
        return "truncate"

    sample = stripped[:8000]
    low_sample = sample.lower()
    if stripped.startswith("<?xml") and "<nmaprun" in sample:
        return "nmap"
    if "# Nmap " in sample or "Nmap scan report for " in sample or ("Status: Up" in sample and "Ports:" in sample):
        return "nmap"
    if (
        ("sqlmap" in low_sample and ("back-end dbms" in low_sample or "[info] testing" in low_sample or "payload:" in low_sample))
        or ("back-end dbms:" in low_sample and ("[info] testing" in low_sample or "payload:" in low_sample))
    ):
        return "sqlmap"

    if stripped[0] in "{[":
        if any(
            k in sample
            for k in (
                '"check_id"',
                '"runs"',
                '"VulnerabilityID"',
                '"Results"',
                '"Vulnerabilities"',
                '"Misconfigurations"',
                '"template-id"',
                '"issue_severity"',
                '"test_id"',
            )
        ):
            return "sast"
        if any(k in sample for k in ('"status"', '"status_code"', '"status-code"', '"content_length"', '"content-length"', '"results"')):
            return "anomaly"

    first_lines = stripped.splitlines()[:25]
    if any(RE_HTTP_STATUS.match(ln) for ln in first_lines) or re.match(r"^(?:<!DOCTYPE\s+html|<html\b)", stripped, re.IGNORECASE):
        return "http"

    lines = stripped.splitlines()[:80]
    anomaly_hits = sum(1 for ln in lines if _extract_anomaly_signature(ln) is not None)
    if anomaly_hits >= 3:
        return "anomaly"

    test_hits = sum(1 for ln in lines if RE_TEST_FAIL_ANCHOR.search(ln) or RE_TEST_PASS.match(ln))
    if test_hits >= 3:
        return "testlog"

    grep_hits = sum(1 for ln in lines if RE_GREP_MATCH.match(ln))
    if grep_hits >= 4:
        return "grep"

    return "dedupe"


def run_compress(
    text: str,
    mode: str = "auto",
    max_lines: int = 120,
    min_cluster: int = 3,
    max_failures: int = 3,
    keep_fenced: bool = False,
    max_line_chars: int = 320,
) -> str:
    """Clean ANSI sequences and dispatch compression mode."""
    cleaned = strip_ansi(text)
    if not cleaned.strip():
        return ""

    chosen = detect_mode(cleaned) if mode == "auto" else mode
    if chosen == "anomaly":
        return compress_anomaly(cleaned, min_cluster=min_cluster, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "sast":
        return compress_sast(cleaned, max_lines=max_lines)
    if chosen == "nmap":
        return compress_nmap(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "sqlmap":
        return compress_sqlmap(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "http":
        return compress_http(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "grep":
        return compress_grep(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "testlog":
        return compress_testlog(cleaned, max_failures=max_failures, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "skeleton":
        return compress_skeleton(cleaned, max_lines=max_lines)
    if chosen == "dedupe":
        return compress_dedupe(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    if chosen == "severity":
        return compress_severity(cleaned, max_lines=max_lines, max_line_chars=max_line_chars)
    return compress_truncate(cleaned, max_lines=max_lines, keep_fenced=keep_fenced, max_line_chars=max_line_chars)


def main(argv: list[str] | None = None) -> int:
    cfg = load_config().get("compress", {})
    parser = argparse.ArgumentParser(description="Deterministic output compressor for AI coding agents.")
    parser.add_argument("input_pos", nargs="?", default=None, help="Optional positional input file path")
    parser.add_argument("--input", default="-", help="Input file path or '-' for stdin")
    parser.add_argument(
        "--mode",
        choices=["auto", "anomaly", "sast", "nmap", "sqlmap", "http", "grep", "testlog", "skeleton", "dedupe", "severity", "truncate"],
        default="auto",
        help="Compression strategy (default: auto)",
    )
    parser.add_argument("--max-lines", type=int, default=cfg.get("default_max_lines", 120))
    parser.add_argument(
        "--max-line-chars",
        type=int,
        default=cfg.get("default_max_line_chars", 320),
        help="Truncate individual long lines (0 to disable)",
    )
    parser.add_argument("--min-cluster", type=int, default=cfg.get("anomaly_min_cluster", 3))
    parser.add_argument("--max-failures", type=int, default=cfg.get("testlog_max_failures", 3))
    parser.add_argument("--keep-fenced", action="store_true", help="Protect fenced ``` blocks in truncate mode")
    args = parser.parse_args(argv)

    target_input = args.input_pos if args.input_pos is not None else args.input
    try:
        raw = read_input_text(target_input)
    except OSError as exc:
        print(f"Error reading `{target_input}`: {exc}", file=sys.stderr)
        return 2
    result = run_compress(
        raw,
        mode=args.mode,
        max_lines=args.max_lines,
        min_cluster=args.min_cluster,
        max_failures=args.max_failures,
        keep_fenced=args.keep_fenced,
        max_line_chars=args.max_line_chars,
    )
    if result:
        print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
