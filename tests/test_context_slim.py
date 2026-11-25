"""End-to-end tests for context-slim scripts, CLI, hooks, installer, and agentskills.io compliance."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT / "scripts"
HOOKS_DIR = ROOT / "adapters" / "claude-code" / "hooks"
sys.path.insert(0, str(SCRIPTS_DIR))

import _common  # noqa: E402
import compress_output  # noqa: E402
import diff_budget  # noqa: E402
import ledger_tool  # noqa: E402
import slice_file  # noqa: E402


class SkillSpecTests(unittest.TestCase):
    def test_skill_frontmatter_and_portability(self) -> None:
        skill_md = (ROOT / "SKILL.md").read_text(encoding="utf-8")
        lines = skill_md.splitlines()
        self.assertLess(len(lines), 150)
        self.assertTrue(skill_md.startswith("---\n"))
        fm_end = skill_md.index("\n---\n", 4)
        fm = skill_md[4:fm_end]
        name_m = re.search(r"^name:\s*(\S+)", fm, re.MULTILINE)
        self.assertIsNotNone(name_m)
        name = name_m.group(1)
        self.assertRegex(name, r"^[a-z0-9]+(-[a-z0-9]+)*$")
        self.assertEqual(name, "context-slim")
        if ROOT.parent.name == "skills":
            self.assertEqual(name, ROOT.name)
        install_sh = (ROOT / "install.sh").read_text(encoding="utf-8")
        self.assertIn(f"/skills/{name}", install_sh)
        self.assertLessEqual(len(name), 64)
        self.assertNotIn("CLAUDE_SKILL_DIR", skill_md)

    def test_config_template_matches_default_config(self) -> None:
        tmpl = json.loads((ROOT / "assets" / "config-template.json").read_text(encoding="utf-8"))
        self.assertEqual(_common.DEFAULT_CONFIG, tmpl)


class CompressTests(unittest.TestCase):
    def test_anomaly_preserves_middle_outliers_cli(self) -> None:
        lines = [f"/path{i} (Status: 403) [Size: 1245] [Words: 40]" for i in range(50)]
        lines.insert(25, "/admin/debug (Status: 200) [Size: 812] [Words: 99]")
        lines.insert(30, "/api/internal (Status: 500) [Size: 450] [Words: 12]")
        out = compress_output.run_compress("\n".join(lines), mode="anomaly")
        self.assertIn("/admin/debug", out)
        self.assertIn("/api/internal", out)
        self.assertIn("similar suppressed", out)

    def test_anomaly_ffuf_json_and_zero_length(self) -> None:
        results = [
            {"input": {"FUZZ": f"dir{i}"}, "status": 403, "length": 0, "words": 0, "url": f"https://x/dir{i}"}
            for i in range(12)
        ]
        results.insert(6, {"input": "backup.zip", "status": 200, "length": 9999, "words": 500, "url": "https://x/backup.zip"})
        payload = json.dumps({"results": results})
        out = compress_output.run_compress(payload, mode="auto")
        self.assertIn("https://x/backup.zip", out)
        self.assertIn("11 similar suppressed", out)
        self.assertIn("size=0", out)

        empty_out = compress_output.run_compress(json.dumps({"results": []}), mode="anomaly")
        self.assertIn("0 total entries", empty_out)

    def test_anomaly_feroxbuster_dirsearch_httpx(self) -> None:
        ferox = "\n".join(
            [f"403      GET        1l        2w       34c https://t/p{i}" for i in range(10)]
            + ["200      GET       20l      120w     2048c https://t/admin"]
        )
        out_f = compress_output.run_compress(ferox, mode="auto")
        self.assertIn("https://t/admin", out_f)
        self.assertIn("9 similar suppressed", out_f)

        dirsearch = "\n".join(
            [f"[10:22:01] 403 -  289B  - /item{i}" for i in range(8)]
            + ["[10:22:05] 200 -    2KB - /config.bak"]
        )
        out_d = compress_output.run_compress(dirsearch, mode="auto")
        self.assertIn("/config.bak", out_d)
        self.assertIn("7 similar suppressed", out_d)

        httpx = "\n".join(
            [f"https://sub{i}.t [200] [200]" for i in range(6)]
            + ["https://admin.t [200] [8450] [Admin Panel]"]
        )
        out_h = compress_output.run_compress(httpx, mode="auto")
        self.assertIn("https://admin.t", out_h)
        self.assertIn("size~192", out_h)  # 200 // 16 * 16 == 192

    def test_sast_semgrep_nuclei_trivy_and_empty(self) -> None:
        data = {
            "results": [
                {
                    "check_id": "python.sqli",
                    "path": "app/db.py",
                    "start": {"line": 12},
                    "extra": {"severity": "ERROR", "lines": "cur.execute(q)", "message": "Very long essay " * 20},
                },
                {
                    "check_id": "python.sqli",
                    "path": "app/db.py",
                    "start": {"line": 34},
                    "extra": {"severity": "ERROR", "lines": "cur.execute(q2)", "message": "Very long essay " * 20},
                },
            ]
        }
        out = compress_output.run_compress(json.dumps(data), mode="auto")
        self.assertIn("[ERROR] python.sqli | app/db.py:12,34 (×2)", out)
        self.assertNotIn("Very long essay", out)

        nuclei_arr = json.dumps(
            [{"template-id": "exposed-env", "matched-at": "https://t/.env", "info": {"severity": "high", "name": ".env file"}}]
        )
        out_n = compress_output.run_compress(nuclei_arr, mode="auto")
        self.assertIn("[HIGH] exposed-env | https://t/.env", out_n)

        trivy_mis = json.dumps(
            {
                "Results": [
                    {
                        "Target": "Dockerfile",
                        "Misconfigurations": [
                            {"Severity": "HIGH", "ID": "DS002", "Title": "Root user", "CauseMetadata": {"StartLine": 4}}
                        ],
                    }
                ]
            }
        )
        out_t = compress_output.run_compress(trivy_mis, mode="auto")
        self.assertIn("[HIGH] DS002 | Dockerfile:4 | Root user", out_t)

        empty_sast = compress_output.run_compress(json.dumps({"results": [], "errors": []}), mode="sast")
        self.assertEqual(empty_sast, "# SAST Summary: 0 findings")

    def test_testlog_pytest_go_cargo_and_no_overlap(self) -> None:
        log = "\n".join([f"tests/test_a.py::test_case_{i} PASSED" for i in range(40)]) + (
            "\n=== FAILURES ===\n"
            "___ test_auth ___\n"
            "    def test_auth():\n"
            ">       assert 1 == 2\n"
            "E       assert 1 == 2\n"
            "1 failed, 40 passed in 0.4s\n"
        )
        out = compress_output.run_compress(log, mode="auto")
        self.assertIn("E       assert 1 == 2", out)
        self.assertIn("1 failed, 40 passed", out)
        self.assertNotIn("test_case_15 PASSED", out)

        go_log = "=== RUN   TestA\n--- PASS: TestA (0.00s)\n=== RUN   TestB\n--- FAIL: TestB (0.01s)\n    b_test.go:12: boom\nFAIL\n"
        out_go = compress_output.run_compress(go_log, mode="auto")
        self.assertIn("--- FAIL: TestB", out_go)
        self.assertNotIn("--- PASS: TestA", out_go)

        # Ensure close failure lines don't duplicate
        multi = "ERROR: first\nline2\nERROR: second\nline4\n"
        out_m = compress_output.run_compress(multi, mode="testlog")
        self.assertEqual(out_m.count("ERROR: second"), 1)

    def test_skeleton_multiline_markdown_and_linear_perf(self) -> None:
        src = (
            "from typing import (\n"
            "    Any,\n"
            "    Optional,\n"
            ")\n\n"
            "@app.route('/admin')\n"
            "def admin_panel(\n"
            "    user_id: int,\n"
            ") -> Optional[Any]:\n"
            "    if user_id:\n"
            "        return 1\n"
            "    else:\n"
            "        return None\n"
        )
        out = compress_output.run_compress(src, mode="skeleton")
        self.assertIn("[Header/Imports: L1-L4]", out)
        self.assertIn("[route] @app.route('/admin')", out)
        self.assertIn("[L7-L13] def admin_panel(", out)
        self.assertNotIn("else:", out)

        md = "# Title\nIntro text\n```python\n# not a heading\ndef f(): pass\n```\n## Section Two\n"
        out_md = compress_output.run_compress(md, mode="skeleton")
        self.assertIn("[L1] # Title", out_md)
        self.assertIn("[L7] ## Section Two", out_md)
        self.assertNotIn("# not a heading", out_md)

        # ReDoS check: pathological long line must finish in milliseconds
        t0 = time.monotonic()
        compress_output.run_compress("public " + "tok " * 1500 + ";\n", mode="skeleton")
        self.assertLess(time.monotonic() - t0, 0.5)

    def test_dedupe_exact_max_lines_no_zero_omitted(self) -> None:
        text = "\n".join(f"line_{i}" for i in range(10))
        out = compress_output.run_compress(text, mode="dedupe", max_lines=10)
        self.assertNotIn("0 unique lines omitted", out)
        self.assertEqual(len(out.splitlines()), 10)

    def test_positional_file_arg(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "sample.py"
            p.write_text("import os\ndef hello():\n    return 1\n", encoding="utf-8")
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS_DIR / "compress_output.py"), "--mode", "skeleton", str(p)],
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0)
            self.assertIn("def hello():", proc.stdout)

    def test_max_line_chars_prevents_minified_line_bomb(self) -> None:
        huge = "ERROR: crash on payload=" + ("A" * 5000)
        out = compress_output.run_compress(huge, mode="dedupe", max_line_chars=100)
        self.assertLess(len(out), 200)
        self.assertIn("[+4924 chars]", out)

    def test_http_mode_strips_css_svg_and_keeps_surface(self) -> None:
        raw_http = (
            "*   Trying 127.0.0.1:8080...\n"
            "* SSL connection using TLSv1.3\n"
            "< HTTP/1.1 200 OK\n"
            "< Set-Cookie: session=abc; HttpOnly\n"
            "< X-Request-Id: ignore-noise\n"
            "<\n"
            "<!DOCTYPE html><html><head><title>Admin Login</title>"
            "<style>body{color:red}" + (" .cls{}" * 50) + "</style></head>"
            "<body><svg><path d='M0 0'/></svg>"
            "<!-- TODO: remove debug /internal/reset -->"
            "<form action='/login' method='POST'><input name='user'/></form>"
            "<script src='/static/app.js'></script>"
            "<script>fetch('/api/v1/users'); const x = '" + ("z" * 1000) + "';</script>"
            "</body></html>\n"
        )
        out = compress_output.run_compress(raw_http, mode="auto")
        self.assertIn("Set-Cookie: session=abc", out)
        self.assertNotIn("X-Request-Id", out)
        self.assertNotIn("TLSv1.3", out)
        self.assertNotIn(".cls{}", out)
        self.assertIn("<title>Admin Login</title>", out)
        self.assertIn("<form action='/login'", out)
        self.assertIn("/api/v1/users", out)
        self.assertIn("TODO: remove debug", out)

    def test_docker_pip_build_noise_stripped_and_cr_collapsed(self) -> None:
        build_log = (
            "#1 [1/4] FROM python:3.11\n"
            "Step 2/4 : RUN pip install x\n"
            "Collecting flask\n"
            "Downloading 10%\rDownloading 100%\n"
            "ERROR: Failed building wheel for crypt\n"
            "1 error generated\n"
        )
        out = compress_output.run_compress(build_log, mode="testlog")
        self.assertNotIn("Collecting flask", out)
        self.assertNotIn("Downloading 10%", out)
        self.assertIn("ERROR: Failed building wheel for crypt", out)

    def test_anomaly_path_reflected_403_and_long_viewstate_http(self) -> None:
        reflected = []
        for i, p in enumerate(["/a", "/ab", "/admin_long_test_1", "/backup_very_long_endpoint_name_2026", "/cfg_1234567890123456"]):
            reflected.append(f"{p} (Status: 403) [Size: {500 + len(p)}] [Words: 12]")
        reflected.insert(2, "/secret_admin (Status: 200) [Size: 912] [Words: 88]")
        out = compress_output.run_compress("\n".join(reflected), mode="auto")
        self.assertIn("/secret_admin", out)
        self.assertIn("path-reflected similar suppressed", out)

        html_doc = "<html><body><form action='/auth'><input value='" + ("A" * 500) + "' name='__VIEWSTATE'/></form></body></html>"
        out_h = compress_output.run_compress(html_doc, mode="http")
        self.assertIn("name='__VIEWSTATE'", out_h)
        self.assertIn("<len=500>", out_h)

    def test_nmap_sqlmap_grep_and_pytest_warnings(self) -> None:
        nmap_gnmap = (
            "# Nmap 7.94 scan initiated\n"
            "Host: 10.0.0.1 ()\tStatus: Down\n"
            "Host: 10.0.0.2 ()\tStatus: Up\n"
            "Host: 10.0.0.2 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9/, 80/closed/tcp//http///\n"
        )
        out_nm = compress_output.run_compress(nmap_gnmap, mode="auto")
        self.assertNotIn("10.0.0.1", out_nm)
        self.assertEqual(out_nm.count("10.0.0.2"), 1)
        self.assertIn("22/tcp ssh OpenSSH 8.9", out_nm)

        nmap_xml = (
            '<?xml version="1.0"?><nmaprun><host><status state="up"/><address addr="10.0.0.9"/>'
            '<ports><port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port></ports>'
            "</host></nmaprun>"
        )
        out_xml = compress_output.run_compress(nmap_xml, mode="auto")
        self.assertIn("10.0.0.9 -> 443/tcp https nginx", out_xml)

        sqlmap_log = (
            "[11:00:01] [INFO] testing 'AND boolean-based blind'\n"
            "[11:00:02] [INFO] testing 'MySQL >= 5.0 time-based'\n"
            "Parameter: id (GET)\n"
            "    Type: boolean-based blind\n"
            "    Payload: id=1 AND 1=1\n"
            "back-end DBMS: MySQL >= 5.0\n"
        )
        out_sql = compress_output.run_compress(sqlmap_log, mode="auto")
        self.assertNotIn("boolean-based blind'\n", out_sql)
        self.assertIn("Payload: id=1 AND 1=1", out_sql)
        self.assertIn("back-end DBMS: MySQL >= 5.0", out_sql)

        grep_out = "\n".join(
            [
                "src/db.py:12:cur.execute(q)",
                "src/db.py:45:cur.execute(q2)",
                "src/db.py:50:# cur.execute(commented)",
                "tests/test_db.py:8:cur.execute('test')",
                "src/api.py:9:cur.execute(q3)",
            ]
        )
        out_gr = compress_output.run_compress(grep_out, mode="auto")
        self.assertIn("src/db.py:12,45 | cur.execute(q)", out_gr)
        self.assertNotIn("# cur.execute", out_gr)
        self.assertIn("test/mock files folded: 1 match(es)", out_gr)

        pytest_warn = (
            "=== FAILURES ===\nAssertionError: bad\n"
            "=== warnings summary ===\n"
            "/site-packages/urllib3/__init__.py:12: DeprecationWarning: noise\n"
            "-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n"
            "1 failed, 10 passed, 1 warning in 0.2s\n"
        )
        out_pw = compress_output.run_compress(pytest_warn, mode="testlog")
        self.assertNotIn("urllib3", out_pw)
        self.assertIn("warning lines collapsed", out_pw)

    def test_skeleton_security_annotations_and_json_preview(self) -> None:
        py_sec = "@csrf_exempt\n@login_required\ndef webhook():\n    return 'ok'\n"
        sk = compress_output.run_compress(py_sec, mode="skeleton")
        self.assertIn("[route] @csrf_exempt", sk)

        big_json = json.dumps({"dependencies": {"a": "1", "b": "2"}, "scripts": {"test": "pytest"}}, indent=2)
        sk_j = compress_output.run_compress(big_json, mode="skeleton")
        self.assertIn("[JSON object: 2 top-level key(s)", sk_j)
        self.assertIn(".dependencies: dict(2 keys:", sk_j)


class SliceAndRunTests(unittest.TestCase):
    def test_slice_symbols_ranges_and_auto_imports(self) -> None:
        src = (
            "import os\n"
            "import json\n\n"
            "def filler():\n"
            "    return 0\n\n"
            "@app.route('/secret')\n"
            "def target_fn(x):\n"
            "    if x:\n"
            "        return 42\n"
            "    return 1\n"
        )
        out = slice_file.slice_text(src, file_label="app.py", symbols=["target_fn", "missing_sym"])
        self.assertIn("import os", out)
        self.assertIn("@app.route('/secret')", out)
        self.assertIn("L8: def target_fn(x):", out)
        self.assertIn("# Missing symbols: missing_sym", out)
        self.assertNotIn("def filler()", out)

    def test_cslim_run_preserves_exit_code_and_saves_large_log(self) -> None:
        # Small passing output -> passthrough verbatim
        p_ok = subprocess.run(
            [str(ROOT / "bin" / "cslim"), "run", "--", sys.executable, "-c", "print('small ok')"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p_ok.returncode, 0)
        self.assertEqual(p_ok.stdout.strip(), "small ok")

        # Large failing output -> compressed + raw log saved + exit code 3 preserved
        script = "import sys; print('\\n'.join(f'ok t_{i}' for i in range(60))); print('AssertionError: boom'); sys.exit(3)"
        p_fail = subprocess.run(
            [str(ROOT / "bin" / "cslim"), "run", "--mode", "testlog", "--", sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p_fail.returncode, 3)
        self.assertIn("AssertionError: boom", p_fail.stdout)
        self.assertNotIn("ok t_10", p_fail.stdout)
        m_log = re.search(r"raw log saved:\s+(\S+)", p_fail.stdout)
        self.assertIsNotNone(m_log)
        log_path = Path(m_log.group(1))
        self.assertTrue(log_path.is_file())
        log_path.unlink(missing_ok=True)


class DiffBudgetTests(unittest.TestCase):
    def test_audit_profile_protects_single_line_auth_removal_and_npm_v2_lockfile(self) -> None:
        big_refactor = "\n".join([f"-    old_var_{i} = {i}\n+    new_var_{i} = {i}" for i in range(120)])
        diff = (
            "diff --git a/package-lock.json b/package-lock.json\n"
            "--- a/package-lock.json\n+++ b/package-lock.json\n"
            "@@ -10,5 +10,5 @@\n"
            '     "node_modules/lodash": {\n'
            '-      "version": "4.17.20",\n'
            '+      "version": "4.17.21",\n'
            "diff --git a/src/ui.py b/src/ui.py\n"
            "--- a/src/ui.py\n+++ b/src/ui.py\n"
            "@@ -1,120 +1,120 @@\n"
            f"{big_refactor}\n"
            "diff --git a/src/my auth.py b/src/my auth.py\n"
            "--- a/src/my auth.py\n+++ b/src/my auth.py\n"
            "@@ -40,4 +40,3 @@\n"
            " def handle():\n"
            "-    if not user.is_admin: return 403\n"
            "     return serve()\n"
        )
        out = diff_budget.budget_diff(diff, budget_tokens=220, profile="audit")
        self.assertIn("lodash: 4.17.20 -> 4.17.21", out)
        self.assertIn("-    if not user.is_admin: return 403", out)
        self.assertIn("src/my auth.py", out)
        self.assertNotIn("old_var_10", out)

    def test_dev_profile_excludes_lockfiles_and_small_budget_note(self) -> None:
        diff = (
            "diff --git a/package-lock.json b/package-lock.json\n"
            "@@ -1,2 +1,2 @@\n-a\n+b\n"
            "diff --git a/src/main.py b/src/main.py\n"
            "@@ -1,2 +1,2 @@\n-print(1)\n+print(2)\n"
        )
        out = diff_budget.budget_diff(diff, budget_tokens=2000, profile="dev")
        self.assertIn("Excluded files (1): package-lock.json", out)
        self.assertIn("+print(2)", out)

        tiny = diff_budget.budget_diff(diff, budget_tokens=1, profile="dev")
        self.assertIn("smallest hunk", tiny)

    def test_audit_diff_xss_ssrf_and_sec_paths(self) -> None:
        big_refactor = "\n".join([f"-    x_{i} = {i}\n+    y_{i} = {i}" for i in range(100)])
        diff = (
            "diff --git a/src/ui.py b/src/ui.py\n"
            "@@ -1,100 +1,100 @@\n"
            f"{big_refactor}\n"
            "diff --git a/nginx/default.conf b/nginx/default.conf\n"
            "@@ -10,2 +10,2 @@\n"
            "-    return 302 https://safe.example$request_uri;\n"
            "+    dangerouslySetInnerHTML = userInput;\n"
        )
        out = diff_budget.budget_diff(diff, budget_tokens=160, profile="audit")
        self.assertIn("dangerouslySetInnerHTML", out)
        self.assertNotIn("x_10", out)


class LedgerAndCLITests(unittest.TestCase):
    def test_ledger_lifecycle_remove_and_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "app.py").write_text("@app.route('/v1/users')\ndef users():\n    return []\n", encoding="utf-8")
            ledger_tool.init_ledger(tmp_path)
            ledger_tool.upsert_entry("findings", "IDOR /api/v1/user", "confirmed id=2", root=tmp_path)
            ledger_tool.upsert_entry("findings", "IDOR /api/v1/user", "confirmed id=2\n-> PII leak", root=tmp_path)
            ledger_tool.scan_repo_map(tmp_path, include_entrypoints=True)
            txt = ledger_tool.show_ledger(root=tmp_path)
            self.assertEqual(txt.count("IDOR /api/v1/user"), 1)
            self.assertIn("PII leak", txt)
            self.assertIn("app.py", txt)
            self.assertIn("**entrypoints**:", txt)
            self.assertIn("@app.route('/v1/users')", txt)

            _, removed = ledger_tool.remove_entry("findings", "IDOR /api/v1/user", root=tmp_path)
            self.assertTrue(removed)
            self.assertNotIn("IDOR /api/v1/user", ledger_tool.show_ledger(root=tmp_path))

            proc = subprocess.run([str(ROOT / "bin" / "cslim"), "--version"], capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0)
            self.assertIn("cslim 1.0.0", proc.stdout)


class ClaudeHookTests(unittest.TestCase):
    def _run_hook(self, script_name: str, payload: dict) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(HOOKS_DIR / script_name)],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            check=False,
        )

    def test_bash_guard(self) -> None:
        # Unredirected scanners blocked (including 2>&1, bare -jsonl, and compound && commands)
        for cmd in (
            "ffuf -u https://t/FUZZ -w w.txt",
            "ffuf -u https://t/FUZZ -w w.txt 2>&1",
            "nuclei -u https://t -jsonl",
            "cd /tmp && ffuf -u https://t/FUZZ -w w.txt",
            "ffuf -u https://t/FUZZ -of json",
            "ffuf -u https://t/FUZZ -of json -o -",
        ):
            res = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(res.returncode, 2, f"Expected block for: {cmd}")

        # Properly redirected/saved scanners allowed
        for cmd in (
            "ffuf -u https://t/FUZZ -of json -o /tmp/f.json",
            "nmap -sV -oA /tmp/scan 10.0.0.1",
            "nuclei -u https://t -jsonl -o /tmp/n.jsonl",
            "ffuf -u https://t/FUZZ -w w.txt > /tmp/f.out 2>&1",
        ):
            res = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": cmd}})
            self.assertEqual(res.returncode, 0, f"Expected allow for: {cmd}")

        # Bare git log, rg, and recursive grep rewrites preserve metadata
        p3 = self._run_hook(
            "bash_guard.py",
            {"tool_name": "Bash", "tool_input": {"command": "git log", "description": "history"}},
        )
        self.assertEqual(p3.returncode, 0)
        parsed = json.loads(p3.stdout)
        self.assertEqual(parsed["hookSpecificOutput"]["updatedInput"]["command"], "git log --oneline -n 30")
        self.assertEqual(parsed["hookSpecificOutput"]["updatedInput"]["description"], "history")

        p_rg = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": "rg secret src/"}})
        self.assertEqual(p_rg.returncode, 0)
        self.assertIn("--max-columns 240", json.loads(p_rg.stdout)["hookSpecificOutput"]["updatedInput"]["command"])

        p_grep = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": "grep -rn token ."}})
        self.assertEqual(p_grep.returncode, 0)
        self.assertIn("--exclude-dir=node_modules", json.loads(p_grep.stdout)["hookSpecificOutput"]["updatedInput"]["command"])

        p_find = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": "find . -name '*.py'"}})
        self.assertEqual(p_find.returncode, 2)

        p_dlogs = self._run_hook("bash_guard.py", {"tool_name": "Bash", "tool_input": {"command": "docker logs api_srv"}})
        self.assertEqual(p_dlogs.returncode, 0)
        self.assertEqual(json.loads(p_dlogs.stdout)["hookSpecificOutput"]["updatedInput"]["command"], "docker logs --tail 100 api_srv")

        # cat on dist/* or large file blocked with skeleton
        with tempfile.TemporaryDirectory() as tmp:
            dist_dir = Path(tmp) / "dist"
            dist_dir.mkdir()
            (dist_dir / "bundle.js").write_text("console.log(1)\n", encoding="utf-8")
            p4 = self._run_hook(
                "bash_guard.py",
                {"tool_name": "Bash", "cwd": tmp, "tool_input": {"command": "cat dist/bundle.js"}},
            )
            self.assertEqual(p4.returncode, 2)

    def test_read_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            big_file = Path(tmp) / "big.py"
            big_file.write_text("import sys\n" + "\n".join([f"def fn_{i}():\n    pass" for i in range(130)]), encoding="utf-8")
            blocked = self._run_hook("read_guard.py", {"tool_name": "Read", "cwd": tmp, "tool_input": {"file_path": str(big_file)}})
            self.assertEqual(blocked.returncode, 2)
            self.assertIn("def fn_0()", blocked.stderr)

            # Boolean True must not bypass as int 1
            bool_bypass = self._run_hook(
                "read_guard.py",
                {"tool_name": "Read", "cwd": tmp, "tool_input": {"file_path": str(big_file), "limit": True}},
            )
            self.assertEqual(bool_bypass.returncode, 2)

            allowed = self._run_hook(
                "read_guard.py",
                {"tool_name": "Read", "cwd": tmp, "tool_input": {"file_path": str(big_file), "offset": 1, "limit": 40}},
            )
            self.assertEqual(allowed.returncode, 0)

            # Absolute path inside dist/ must match blocked_globs `dist/*`
            dist_dir = Path(tmp) / "dist"
            dist_dir.mkdir()
            bundle = dist_dir / "app.js"
            bundle.write_text("var x=1;\n", encoding="utf-8")
            blocked_dist = self._run_hook(
                "read_guard.py",
                {"tool_name": "Read", "cwd": tmp, "tool_input": {"file_path": str(bundle)}},
            )
            self.assertEqual(blocked_dist.returncode, 2)

    def test_dispatch_guard(self) -> None:
        nested = self._run_hook(
            "dispatch_guard.py",
            {"tool_name": "Agent", "agent_id": "agent_123", "tool_input": {"subagent_type": "Explore", "model": "haiku"}},
        )
        self.assertEqual(nested.returncode, 2)
        missing_model = self._run_hook(
            "dispatch_guard.py",
            {"tool_name": "Agent", "tool_input": {"subagent_type": "Explore"}},
        )
        self.assertEqual(missing_model.returncode, 2)
        fork_ok = self._run_hook(
            "dispatch_guard.py",
            {"tool_name": "Agent", "tool_input": {"subagent_type": "fork"}},
        )
        self.assertEqual(fork_ok.returncode, 0)

    def test_context_monitor(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tp = Path(tmp) / "transcript.jsonl"
            sid = f"test-session-{os.getpid()}"
            uid = os.getuid() if hasattr(os, "getuid") else "user"
            marker = Path(tempfile.gettempdir()) / f"context-slim-mark-{uid}-{sid}.txt"
            marker.unlink(missing_ok=True)
            try:
                lines = [
                    json.dumps({"message": {"usage": {"input_tokens": 5000, "cache_read_input_tokens": 130000, "cache_creation_input_tokens": 0}}}),
                    # Sidechain entry must be ignored so it doesn't mask main context usage
                    json.dumps({"isSidechain": True, "message": {"usage": {"input_tokens": 500, "cache_read_input_tokens": 2000}}}),
                ]
                tp.write_text("\n".join(lines) + "\n", encoding="utf-8")
                warn = self._run_hook("context_monitor.py", {"session_id": sid, "transcript_path": str(tp), "cwd": tmp})
                self.assertEqual(warn.returncode, 0)
                self.assertIn("135,000 tokens", warn.stdout)

                # PostToolUse escalation to hard threshold (175k) emits JSON additionalContext
                lines.append(
                    json.dumps({"message": {"usage": {"input_tokens": 5000, "cache_read_input_tokens": 170000, "cache_creation_input_tokens": 0}}})
                )
                tp.write_text("\n".join(lines) + "\n", encoding="utf-8")
                post = self._run_hook(
                    "context_monitor.py",
                    {"hook_event_name": "PostToolUse", "session_id": sid, "transcript_path": str(tp), "cwd": tmp},
                )
                self.assertEqual(post.returncode, 0)
                post_json = json.loads(post.stdout)
                self.assertEqual(post_json["hookSpecificOutput"]["hookEventName"], "PostToolUse")
                self.assertIn("175,000 tokens", post_json["hookSpecificOutput"]["additionalContext"])

                # PreCompact emits ledger preservation reminder
                pre_c = self._run_hook("context_monitor.py", {"hook_event_name": "PreCompact", "session_id": sid, "cwd": tmp})
                self.assertEqual(pre_c.returncode, 0)
                self.assertIn("PreCompact", pre_c.stdout)
            finally:
                marker.unlink(missing_ok=True)


class InstallerTests(unittest.TestCase):
    def test_install_and_uninstall_claude_hooks_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as fake_home:
            env = dict(os.environ, HOME=fake_home)
            settings_path = Path(fake_home) / ".claude" / "settings.json"
            settings_path.parent.mkdir(parents=True)
            settings_path.write_text(
                json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user_hook"}]}]}}),
                encoding="utf-8",
            )

            # Install twice -> must not duplicate context-slim hooks and must keep user_hook
            for _ in range(2):
                p = subprocess.run(
                    [str(ROOT / "install.sh"), "--target", "claude", "--with-claude-hooks", "--no-cli"],
                    env=env,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(p.returncode, 0, p.stderr)

            data = json.loads(settings_path.read_text(encoding="utf-8"))
            pre = data["hooks"]["PreToolUse"]
            self.assertEqual(len(pre), 4)  # 1 user hook + 3 context-slim hooks
            self.assertEqual(len(data["hooks"]["UserPromptSubmit"]), 1)
            self.assertEqual(len(data["hooks"]["PostToolUse"]), 1)
            self.assertEqual(len(data["hooks"]["PreCompact"]), 1)

            # Uninstall -> removes only context-slim hooks and preserves user_hook
            p_un = subprocess.run(
                [str(ROOT / "install.sh"), "--uninstall-claude-hooks"],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p_un.returncode, 0, p_un.stderr)
            data_after = json.loads(settings_path.read_text(encoding="utf-8"))
            self.assertEqual(len(data_after["hooks"]["PreToolUse"]), 1)
            self.assertEqual(data_after["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "echo user_hook")
            for ev in ("UserPromptSubmit", "PostToolUse", "PreCompact"):
                self.assertNotIn(ev, data_after["hooks"])


if __name__ == "__main__":
    unittest.main()
