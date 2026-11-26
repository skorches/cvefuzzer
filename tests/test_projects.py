import contextlib
import copy
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import Mock, patch

from cvefuzz.advisories.osv import ProviderError
from cvefuzz.advisories.projects import list_projects, refresh_projects
from cvefuzz.advisories.refresh import refresh_saved
from cvefuzz.cli import main
from cvefuzz.findings import Component, Scan
from cvefuzz.storage import Store

CURRENT = datetime(2026, 11, 23, 12, tzinfo=timezone.utc)


def advisory():
    return {"id": "OSV-new", "aliases": ["CVE-2099-0001"], "summary": "<script>fixture</script>", "affected": []}


class Provider:
    def __init__(self, records=()):
        self.records = list(records)
        self.queries = []

    def query(self, component):
        self.queries.append(copy.deepcopy(component))
        return copy.deepcopy(self.records)

    def advisory(self, identifier):
        return None


class ProjectTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.database = self.directory / "scans.db"
        self.store = Store(self.database)
        self.addCleanup(self.store.close)

    def seed(self, identifier="scan", root="/missing/project", *, complete=True, components=True, dependency=True):
        status = ("dependency-scan-completed" if complete else "scan-incomplete") if dependency else "inventory-only"
        scan = Scan(identifier, root, "before", "before", "identity-" + identifier, status, {}, {},
                    [{"name": "dependency_scan", "requested": dependency, "status": "completed" if complete else "failed"}], {},
                    components=[Component(identifier, "PyPI", "1.0", "requirements.txt")] if components else [])
        self.store.save(scan)
        return scan

    def refresh(self, scan_id="scan", *, records=(), when=CURRENT, client=None):
        with patch("cvefuzz.advisories.refresh.now", return_value=when.isoformat()):
            return refresh_saved(self.store, scan_id, client=client or Provider(records))

    def cli(self, *arguments, client=None):
        with patch("cvefuzz.cli.OSVClient", return_value=client or Provider()), patch("cvefuzz.cli.discover", side_effect=AssertionError("repository read")), contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()):
            code = main(list(arguments) + ["--database", str(self.database)])
        return code, json.loads(output.getvalue()) if output.getvalue() else None

    def test_latest_dependency_attempt_supersedes_old_success_and_inventory_only_is_ignored(self):
        self.seed("old", "/missing/blocked")
        latest = self.seed("latest-failed", "/missing/blocked", complete=False, components=False)
        self.seed("inventory", "/missing/blocked", components=False, dependency=False)
        good = self.seed("good", "/missing/good")
        self.seed("inventory-only", "/missing/only-inventory", components=False, dependency=False)
        provider = Provider()
        result = refresh_projects(self.store, client=provider)
        self.assertEqual([query["name"] for query in provider.queries], ["good"])
        self.assertEqual([project["outcome"] for project in result["projects"]], ["blocked", "completed"])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(self.store.get(latest.scan_id), latest.to_dict())
        self.assertEqual(self.store.get(good.scan_id), good.to_dict())
        self.assertEqual(self.store.refresh_history("old"), [])
        catalog = list_projects(self.store)
        self.assertEqual(len(catalog["projects"]), 2)
        self.assertFalse(catalog["projects"][0]["refreshable"])

    def test_new_events_survive_unchanged_refresh_and_failed_attempt_until_resolved(self):
        self.seed()
        first = self.refresh(records=[advisory()], when=CURRENT - timedelta(hours=2))
        self.refresh(records=[advisory()], when=CURRENT - timedelta(hours=1))
        catalog = list_projects(self.store, current_time=CURRENT, newly_affected=True)
        project = catalog["projects"][0]
        self.assertEqual(project["new_findings"][0]["refresh_id"], first["refresh_id"])
        self.assertEqual(project["advisory_freshness"]["status"], "fresh")
        provider = Mock()
        provider.query.side_effect = ProviderError("offline")
        self.refresh(client=provider)
        project = list_projects(self.store, current_time=CURRENT, newly_affected=True)["projects"][0]
        self.assertEqual(project["advisory_freshness"]["status"], "stale")
        self.assertEqual(len(project["new_findings"]), 1)
        self.refresh(records=[])
        self.assertEqual(list_projects(self.store, newly_affected=True)["projects"], [])

    def test_since_filter_is_inclusive_timezone_aware_and_events_do_not_cross_inventories(self):
        self.seed()
        first = self.refresh(records=[advisory()])
        since = "2026-11-23T14:00:00+02:00"
        result = list_projects(self.store, since=since, newly_affected=True, current_time=CURRENT)
        self.assertEqual(result["projects"][0]["new_findings"][0]["detected_at"], first["finished_at"])
        self.assertEqual(list_projects(self.store, since=(CURRENT + timedelta(seconds=1)).isoformat(), newly_affected=True)["projects"], [])
        self.seed("new-inventory")
        self.assertEqual(list_projects(self.store, newly_affected=True)["projects"], [])
        self.assertEqual(len(self.store.refresh_history("scan")), 1)

    def test_successful_recent_refresh_skips_without_network_or_history_growth(self):
        self.seed()
        previous = self.refresh(records=[advisory()], when=CURRENT - timedelta(hours=1))
        provider = Mock()
        result = refresh_projects(self.store, client=provider, min_age_hours=24, current_time=CURRENT)
        self.assertEqual(result["status"], "completed")
        self.assertEqual((result["refreshed"], result["skipped"], result["findings_count"]), (0, 1, 1))
        self.assertIsNone(result["projects"][0]["changes"])
        provider.query.assert_not_called()
        self.assertEqual(self.store.cached_refresh("scan"), previous)
        self.assertEqual(len(self.store.refresh_history("scan")), 1)

    def test_refresh_is_due_at_interval_boundary_or_after_failed_attempt(self):
        self.seed()
        self.refresh(when=CURRENT - timedelta(hours=24))
        provider = Provider()
        refresh_projects(self.store, client=provider, min_age_hours=24, current_time=CURRENT)
        self.assertEqual(len(provider.queries), 1)
        self.refresh(when=CURRENT - timedelta(hours=1))
        bad = Mock()
        bad.query.side_effect = ProviderError("unavailable")
        self.refresh(client=bad)
        provider = Provider()
        result = refresh_projects(self.store, client=provider, min_age_hours=24, current_time=CURRENT)
        self.assertEqual(result["refreshed"], 1)
        self.assertEqual(len(provider.queries), 1)

    def test_failed_project_does_not_stop_later_project_or_replace_its_cache(self):
        self.seed("bad", "/missing/a-bad")
        self.seed("good", "/missing/b-good")
        original = self.refresh("bad", records=[advisory()])
        provider = Mock()
        provider.query.side_effect = [ProviderError("unavailable"), [advisory()]]
        result = refresh_projects(self.store, client=provider)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual([project["outcome"] for project in result["projects"]], ["incomplete", "completed"])
        self.assertEqual(result["findings_count"], 2)
        self.assertEqual(self.store.cached_refresh("bad"), original)
        self.assertIsNotNone(self.store.cached_refresh("good"))

    def test_storage_conflict_is_reported_without_aborting_other_projects(self):
        self.seed("a", "/missing/a")
        self.seed("b", "/missing/b")
        original = self.store.save_refresh
        def save(result, previous_refresh_id=None):
            if result["scan_id"] == "a":
                raise ValueError("Another refresh completed meanwhile")
            return original(result, previous_refresh_id)
        with patch.object(self.store, "save_refresh", side_effect=save):
            result = refresh_projects(self.store, client=Provider())
        self.assertEqual([project["outcome"] for project in result["projects"]], ["failed", "completed"])
        self.assertIn("Another refresh", result["projects"][0]["issues"][0])
        self.assertEqual(result["status"], "incomplete")

    def test_future_or_invalid_cache_time_is_stale_and_does_not_suppress_refresh(self):
        self.seed()
        for when in (CURRENT + timedelta(days=1),):
            self.refresh(when=when)
            project = list_projects(self.store, current_time=CURRENT)["projects"][0]
            self.assertEqual(project["advisory_freshness"]["status"], "stale")
            self.assertIsNone(project["advisory_freshness"]["age_hours"])
            provider = Provider()
            self.assertEqual(refresh_projects(self.store, client=provider, min_age_hours=24, current_time=CURRENT)["refreshed"], 1)
        cached = self.store.cached_refresh("scan")
        cached["finished_at"] = "invalid"
        with self.store.connection:
            self.store.connection.execute("UPDATE advisory_cache SET result_json = ? WHERE scan_id = 'scan'", (json.dumps(cached),))
        self.assertEqual(list_projects(self.store, current_time=CURRENT)["projects"][0]["advisory_freshness"]["status"], "stale")

    def test_offline_batches_ignore_due_gate_and_never_call_provider(self):
        self.seed()
        self.refresh(records=[advisory()], when=CURRENT - timedelta(hours=1))
        provider = Mock()
        result = refresh_projects(self.store, client=provider, offline=True, min_age_hours=24, current_time=CURRENT)
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["projects"][0]["outcome"], "offline")
        self.assertEqual(result["skipped"], 0)
        self.assertEqual(result["findings_count"], 1)
        provider.query.assert_not_called()

    def test_target_selection_is_frozen_before_network_requests(self):
        self.seed("original")
        provider = Mock()
        def query(component):
            self.seed("added-later", "/missing/later")
            return []
        provider.query.side_effect = query
        result = refresh_projects(self.store, client=provider)
        self.assertEqual(len(result["projects"]), 1)
        self.assertEqual(result["projects"][0]["scan_id"], "original")
        self.assertEqual(len(self.store.project_scans()), 2)

    def test_cli_batch_policy_and_json_html_reports(self):
        self.seed(root="/missing/<script>project</script>")
        for records, policy, expected in (([advisory()], "findings", 1), ([advisory()], "never", 0), ([], "findings", 0)):
            code, report = self.cli("refresh", "--all", "--fail-on", policy, client=Provider(records))
            self.assertEqual(code, expected)
            self.assertEqual(report["status"], "completed")
        code, _ = self.cli("projects", "--output", str(self.directory / "projects.json"), "--html", str(self.directory / "projects.html"))
        self.assertEqual(code, 0)
        report = json.loads((self.directory / "projects.json").read_text())
        self.assertEqual(report["report_kind"], "projects")
        rendered = (self.directory / "projects.html").read_text()
        self.assertNotIn("<script>", rendered)
        self.assertIn("&lt;script&gt;project", rendered)
        self.assertIn("<table>", rendered)
        code, _ = self.cli("refresh", "--all", "--html", str(self.directory / "batch.html"), "--offline", "--fail-on", "never")
        self.assertEqual(code, 2)
        self.assertNotIn("<script>", (self.directory / "batch.html").read_text())

    def test_incomplete_coverage_is_not_hidden_by_due_skips_or_exit_policy(self):
        self.seed(complete=False)
        self.refresh(when=datetime.now(timezone.utc))
        code, report = self.cli("refresh", "--all", "--min-age-hours", "24", "--fail-on", "never")
        self.assertEqual(code, 2)
        self.assertEqual(report["skipped"], 1)
        self.assertFalse(report["projects"][0]["coverage_complete"])

    def test_empty_database_and_invalid_cli_options(self):
        code, report = self.cli("projects")
        self.assertEqual((code, report["projects"]), (0, []))
        code, report = self.cli("refresh", "--all", "--fail-on", "never")
        self.assertEqual(code, 2)
        self.assertIn("No saved dependency", report["issues"][0])
        for arguments in (("refresh",), ("refresh", "scan", "--all"), ("refresh", "scan", "--min-age-hours", "1"),
                          ("refresh", "--all", "--min-age-hours", "nan"), ("refresh", "--all", "--min-age-hours", "-1"),
                          ("projects", "--max-age-hours", "inf"), ("projects", "--max-age-hours", "0"),
                          ("projects", "--since", "2026-11-23")):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as raised:
                self.cli(*arguments)
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
