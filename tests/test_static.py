import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from cvefuzz.adapters.semgrep import scan_static
from cvefuzz.cli import main
from cvefuzz.inventory import discover


def response():
    return {"results": [{"check_id": "cvefuzz.python.dynamic-eval", "path": "app.py",
                         "start": {"line": 1, "col": 1}, "end": {"line": 1, "col": 12},
                         "extra": {"message": "<script>warning</script>"}}],
            "errors": [], "paths": {"scanned": ["app.py"]}}


def tool(data=None, failure=None):
    def run(command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "1.100.0\n", "")
        if failure:
            raise failure
        return subprocess.CompletedProcess(command, 0, json.dumps(data if data is not None else response()), "fixture log")
    return run


class StaticTests(unittest.TestCase):
    def setup_root(self, temp):
        root = Path(temp)
        (root / "app.py").write_text("eval(value)\n", encoding="utf-8")
        return root

    def test_snapshot_local_config_and_normalized_warning(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.setup_root(temp)
            (root / ".semgrepignore").write_text("app.py")
            with patch("cvefuzz.adapters.semgrep.subprocess.run", side_effect=tool()) as runner:
                result = scan_static(root, discover(root), "semgrep", root / ".cvefuzz/artifacts", "now")
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.findings[0].evidence_kind, "static-warning")
            self.assertEqual(result.findings[0].evidence[0]["rule_license"], "CC0-1.0")
            self.assertEqual(result.findings[0].location, "app.py")
            command = runner.call_args.args[0]
            self.assertIn("--oss-only", command)
            self.assertIn("--disable-nosem", command)
            self.assertEqual(runner.call_args.kwargs["timeout"], 120)
            snapshot = Path(runner.call_args.kwargs["cwd"])
            self.assertFalse((snapshot / ".semgrepignore").exists())
            self.assertEqual((snapshot / "app.py").read_text(), "eval(value)\n")

    def test_missing_timeout_malformed_errors_and_unscanned_are_incomplete(self):
        bad = response()
        bad["paths"]["scanned"] = []
        errors = response()
        errors["errors"] = [{"type": "Parse error"}]
        escaped = response()
        escaped["results"][0]["path"] = "../outside.py"
        for data, failure in ((None, FileNotFoundError("missing")), (None, subprocess.TimeoutExpired("semgrep", 1)),
                              ({}, None), (bad, None), (errors, None), (escaped, None)):
            with self.subTest(data=data, failure=failure), tempfile.TemporaryDirectory() as temp:
                root = self.setup_root(temp)
                with patch("cvefuzz.adapters.semgrep.subprocess.run", side_effect=tool(data, failure)):
                    result = scan_static(root, discover(root), "semgrep", root / ".cvefuzz/artifacts", "now")
                self.assertNotEqual(result.status, "completed")
                self.assertTrue(result.issues)

    def test_changed_large_and_unsupported_sources(self):
        for mode in ("changed", "large", "unsupported"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                root = self.setup_root(temp)
                if mode == "large":
                    (root / "app.py").write_bytes(b"x" * 1_000_001)
                if mode == "unsupported":
                    (root / "main.rs").write_text("fn main() {}")
                inventory = discover(root)
                if mode == "changed":
                    (root / "app.py").write_text("changed")
                with patch("cvefuzz.adapters.semgrep.subprocess.run", side_effect=tool()):
                    result = scan_static(root, inventory, "semgrep", root / ".cvefuzz/artifacts", "now")
                self.assertNotEqual(result.status, "completed")

    def test_exclusions_and_repeat_fingerprints(self):
        with tempfile.TemporaryDirectory() as temp:
            root = self.setup_root(temp)
            (root / "excluded").mkdir()
            (root / "excluded/other.py").write_text("eval(value)")
            inventory = discover(root, ["excluded"])
            fingerprints = []
            for number in range(2):
                with patch("cvefuzz.adapters.semgrep.subprocess.run", side_effect=tool()):
                    result = scan_static(root, inventory, "semgrep", root / f".cvefuzz/artifacts{number}", str(number))
                self.assertEqual(result.status, "completed")
                self.assertFalse((root / f".cvefuzz/artifacts{number}/sources/excluded").exists())
                fingerprints.append(result.findings[0].fingerprint)
            self.assertEqual(fingerprints[0], fingerprints[1])

    def test_cli_policy_persistence_and_html(self):
        for data, policy, expected in ((response(), "findings", 1), (response(), "never", 0),
                                        ({"results": [], "errors": [], "paths": {"scanned": ["app.py"]}}, "findings", 0),
                                        ({}, "never", 2)):
            with self.subTest(policy=policy, expected=expected), tempfile.TemporaryDirectory() as temp:
                root = self.setup_root(temp)
                with patch("cvefuzz.adapters.semgrep.subprocess.run", side_effect=tool(data)), contextlib.redirect_stderr(io.StringIO()):
                    code = main(["static", str(root), "--database", str(root / ".cvefuzz/scans.db"),
                                 "--output", str(root / ".cvefuzz/report.json"), "--html", str(root / ".cvefuzz/report.html"), "--fail-on", policy])
                self.assertEqual(code, expected)
                report = json.loads((root / ".cvefuzz/report.json").read_text())
                self.assertEqual(report["checks"][1]["status"], "skipped")
                self.assertEqual(report["checks"][3]["status"], "skipped")
                self.assertNotIn("<script>", (root / ".cvefuzz/report.html").read_text())

    @unittest.skipUnless(os.environ.get("CVEFUZZ_SEMGREP"), "Set CVEFUZZ_SEMGREP to a trusted executable for live rule validation")
    def test_live_positive_and_negative_python_javascript_typescript(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for suffix in ("py", "js", "ts"):
                (root / f"positive.{suffix}").write_text("eval(value)\n")
                (root / f"negative.{suffix}").write_text('print("safe")\n' if suffix == "py" else 'console.log("safe");\n')
            result = scan_static(root, discover(root), os.environ["CVEFUZZ_SEMGREP"], root / ".cvefuzz/artifacts", "now")
            self.assertEqual(result.status, "completed", result.issues)
            self.assertEqual({finding.location for finding in result.findings}, {"positive.py", "positive.js", "positive.ts"})
