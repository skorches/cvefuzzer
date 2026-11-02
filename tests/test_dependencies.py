import contextlib
import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cvefuzz.adapters.osv import normalize, scan_dependencies
from cvefuzz.cli import main
from cvefuzz.inventory import discover

FIXTURE = Path(__file__).parent / "fixtures" / "dependencies" / "vulnerable"


def payload(vulnerable=True):
    advisories = [{"id": "GHSA-fixture", "aliases": ["CVE-2099-0001"],
                   "summary": "<script>alert('fixture')</script>",
                   "affected": [{"package": {"name": "fixture-package", "ecosystem": "PyPI"},
                                 "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}]}]},
                  {"id": "PYSEC-fixture", "aliases": ["CVE-2099-0001"]}] if vulnerable else []
    return {"results": [{"source": {"path": "requirements.txt", "type": "lockfile"},
                         "packages": [{"package": {"name": "fixture-package", "version": "1.0.0" if vulnerable else "2.0.0", "ecosystem": "PyPI"},
                                       "vulnerabilities": advisories}]}]}


def fake_tool(vulnerable=True):
    def run(command, **kwargs):
        if command[-1] == "--version":
            return subprocess.CompletedProcess(command, 0, "osv-scanner version: 2.7.0\n", "")
        return subprocess.CompletedProcess(command, 1 if vulnerable else 0, json.dumps(payload(vulnerable)), "fixture log")
    return run


class DependencyTests(unittest.TestCase):
    def test_aliases_ranges_and_stable_fingerprints(self):
        components, findings = normalize(payload(), "requirements.txt", "2.7.0", "now")
        self.assertEqual(len(findings), 1)
        self.assertEqual(len(findings[0].advisory_ids), 3)
        self.assertEqual(findings[0].evidence[0]["affected"][0]["ranges"][0]["events"][1]["fixed"], "2.0.0")
        self.assertEqual(components[0].version, "1.0.0")
        reordered = copy.deepcopy(payload())
        reordered["results"][0]["packages"][0]["vulnerabilities"].reverse()
        self.assertEqual(findings[0].fingerprint, normalize(reordered, "requirements.txt", "2.7.0", "later")[1][0].fingerprint)
        self.assertEqual(normalize(payload(False), "requirements.txt", "2.7.0", "now")[1], [])

    def test_adapter_uses_explicit_input_and_preserves_evidence(self):
        with tempfile.TemporaryDirectory() as temporary, patch("cvefuzz.adapters.osv.subprocess.run", side_effect=fake_tool()) as runner:
            result = scan_dependencies(FIXTURE, discover(FIXTURE), "scanner", temporary, "now")
            self.assertEqual(result.status, "completed")
            self.assertEqual(len(result.findings), 1)
            command = runner.call_args.args[0]
            self.assertIn("--lockfile", command)
            self.assertIn("--no-resolve", command)
            self.assertIn("--all-packages", command)
            self.assertFalse(runner.call_args.kwargs["shell"])
            self.assertTrue(all(Path(p).exists() for p in result.artifacts))

    def test_unavailable_tool_is_not_clean(self):
        with tempfile.TemporaryDirectory() as temporary, patch("cvefuzz.adapters.osv.subprocess.run", side_effect=FileNotFoundError("missing")):
            result = scan_dependencies(FIXTURE, discover(FIXTURE), "missing", temporary, "now")
            self.assertEqual(result.status, "failed")
            self.assertIn("Scanner unavailable", result.issues[-1])

    def test_timeout_invalid_json_and_provider_error_are_incomplete(self):
        for response in [subprocess.TimeoutExpired("scanner", 1),
                         subprocess.CompletedProcess([], 0, "not-json", ""),
                         subprocess.CompletedProcess([], 127, "{}", "provider unavailable")]:
            def run(command, **kwargs):
                if command[-1] == "--version":
                    return subprocess.CompletedProcess(command, 0, "2.7.0", "")
                if isinstance(response, Exception):
                    raise response
                return response
            with self.subTest(response=response), tempfile.TemporaryDirectory() as temporary, patch("cvefuzz.adapters.osv.subprocess.run", side_effect=run):
                result = scan_dependencies(FIXTURE, discover(FIXTURE), "scanner", temporary, "now")
                self.assertEqual(result.status, "incomplete")

    def test_cli_exit_policy_html_escaping_and_persistence(self):
        for vulnerable, policy, expected in [(True, "findings", 1), (True, "never", 0), (False, "findings", 0)]:
            with self.subTest(vulnerable=vulnerable, policy=policy), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                with patch("cvefuzz.adapters.osv.subprocess.run", side_effect=fake_tool(vulnerable)), contextlib.redirect_stderr(io.StringIO()):
                    code = main(["scan", str(FIXTURE), "--database", str(root / "scans.db"),
                                 "--output", str(root / "report.json"), "--html", str(root / "report.html"), "--fail-on", policy])
                self.assertEqual(code, expected)
                report = json.loads((root / "report.json").read_text())
                self.assertEqual(report["status"], "dependency-scan-completed")
                self.assertEqual(report["checks"][2]["status"], "skipped")
                rendered = (root / "report.html").read_text()
                self.assertNotIn("<script>", rendered)
                if vulnerable:
                    self.assertIn("&lt;script&gt;", rendered)

    def test_unsupported_manifest_remains_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text("fixture")
            result = scan_dependencies(root, discover(root), "scanner", root / "artifacts", "now")
            self.assertNotEqual(result.status, "completed")
            self.assertTrue(any("Unsupported" in issue for issue in result.issues))

    def test_unresolved_version_and_invalid_structure_are_incomplete(self):
        for value in (None, {"bad": "shape"}):
            data = payload()
            if value is None:
                data["results"][0]["packages"][0]["package"]["version"] = None
            else:
                data["results"][0]["packages"] = value
            def run(command, **kwargs):
                return subprocess.CompletedProcess(command, 0, "2.7.0" if command[-1] == "--version" else json.dumps(data), "")
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary, patch("cvefuzz.adapters.osv.subprocess.run", side_effect=run):
                result = scan_dependencies(FIXTURE, discover(FIXTURE), "scanner", temporary, "now")
                self.assertEqual(result.status, "incomplete")

    def test_missing_tool_still_writes_failure_report_and_exits_two(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("cvefuzz.adapters.osv.subprocess.run", side_effect=FileNotFoundError("missing")), contextlib.redirect_stderr(io.StringIO()):
                code = main(["scan", str(FIXTURE), "--output", str(root / "failed.json"),
                             "--database", str(root / "scans.db"), "--fail-on", "never"])
            self.assertEqual(code, 2)
            self.assertEqual(json.loads((root / "failed.json").read_text())["status"], "scan-incomplete")

    def test_local_npm_source_is_a_coverage_gap(self):
        data = payload(False)
        data["results"][0]["packages"][0]["package"]["purl"] = "pkg:npm/example@1.0.0?source=LOCAL"
        def run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, "2.7.0" if command[-1] == "--version" else json.dumps(data), "")
        with tempfile.TemporaryDirectory() as temporary, patch("cvefuzz.adapters.osv.subprocess.run", side_effect=run):
            result = scan_dependencies(FIXTURE, discover(FIXTURE), "scanner", temporary, "now")
            self.assertEqual(result.status, "incomplete")
            self.assertIn("Local-source", result.issues[0])


if __name__ == "__main__":
    unittest.main()
