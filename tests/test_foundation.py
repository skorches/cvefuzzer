import contextlib
import io
import json
import sqlite3
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from cvefuzz.cli import main
from cvefuzz.findings import Component, Finding, RunnerResult
from cvefuzz.inventory import discover
from cvefuzz.storage import Store

FIXTURE = Path(__file__).parent / "fixtures" / "mixed"


class FoundationTests(unittest.TestCase):
    def test_mixed_inventory_and_content_identity(self):
        data = discover(FIXTURE)
        self.assertEqual(set(data["languages"]), {"python", "typescript", "javascript", "rust"})
        self.assertIn("readme.txt", data["unclassified_files"])
        self.assertTrue(all(not item["parsed"] for item in data["manifests"]))
        self.assertEqual(data["content_identity"], discover(FIXTURE)["content_identity"])
        self.assertFalse(data["capabilities"]["python"]["fuzzing"])

    def test_exclusions_and_changed_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "node_modules").mkdir()
            (root / "node_modules" / "ignored.js").write_text("ignored")
            source = root / "app.py"
            source.write_text("first")
            first = discover(root)
            source.write_text("other")
            self.assertNotEqual(first["content_identity"], discover(root)["content_identity"])
            self.assertEqual(len(first["files"]), 1)

    def test_cli_persists_honest_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output, database = root / "result.json", root / "scans.sqlite3"
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                code = main(["inventory", str(FIXTURE), "--output", str(output), "--database", str(database)])
            self.assertEqual(code, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["schema_version"], 1)
            self.assertEqual(report["status"], "inventory-only")
            self.assertIn("analysis has not run", stderr.getvalue())
            self.assertEqual(report["checks"][1]["status"], "skipped")
            self.assertEqual(report["advisory_freshness"]["status"], "not-fetched")
            store = Store(database)
            try:
                self.assertEqual(store.get(report["scan_id"]), report)
            finally:
                store.close()

    def test_missing_repository_is_operational_error(self):
        with tempfile.TemporaryDirectory() as temporary, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["inventory", str(Path(temporary) / "absent")]), 2)

    def test_newer_database_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "future.sqlite3"
            connection = sqlite3.connect(database)
            connection.execute("PRAGMA user_version = 99")
            connection.close()
            with self.assertRaises(ValueError):
                Store(database)

    def test_contract_serialization(self):
        finding = Finding("id", "dependency", "fixture", "1", "high", "2026-01-01T00:00:00Z",
                          "affected-version", component=Component("example", "PyPI", "1.0"))
        self.assertEqual(json.loads(json.dumps(asdict(finding)))["component"]["version"], "1.0")
        self.assertEqual(asdict(RunnerResult("docker", "skipped", reason="Not installed"))["status"], "skipped")


if __name__ == "__main__":
    unittest.main()
