import contextlib
import copy
import io
import json
import sqlite3
import tempfile
import unittest
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from cvefuzz.advisories.osv import OSVClient, ProviderError, retry_delay
from cvefuzz.advisories.refresh import reconcile, refresh_saved
from cvefuzz.cli import main
from cvefuzz.findings import Component, Scan
from cvefuzz.storage import Store


def advisory(identifier="OSV-fixture", **changes):
    return {"id": identifier, "modified": "2026-01-01T00:00:00Z", "aliases": ["CVE-2099-0001"],
            "summary": "<script>fixture</script>",
            "affected": [{"package": {"name": "example", "ecosystem": "PyPI"}, "versions": ["1.0"]}],
            **changes}


class Provider:
    def __init__(self, records=(), lookup=None):
        self.records = list(records)
        self.lookup = lookup or {}
        self.queries = []

    def query(self, component):
        self.queries.append(component)
        return copy.deepcopy(self.records)

    def advisory(self, identifier):
        return copy.deepcopy(self.lookup.get(identifier))


def saved_scan(store, *, complete=True, components=None):
    scan = Scan("saved-scan", "/repository-that-no-longer-exists", "before", "before", "unchanged-content",
                "dependency-scan-completed" if complete else "scan-incomplete", {}, {},
                [{"name": "dependency_scan", "requested": True, "status": "completed" if complete else "incomplete"}], {},
                components=components or [Component("example", "PyPI", "1.0", "requirements.txt")])
    store.save(scan)
    return scan


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = Store(Path(self.temporary.name) / "scans.db")
        self.addCleanup(self.store.close)

    def test_new_changed_withdrawn_reappeared_and_resolved_without_code_changes(self):
        scan = saved_scan(self.store)
        first = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        self.assertEqual(len(first["changes"]["new"]), 1)
        self.assertEqual(first["content_identity"], scan.content_identity)
        self.assertFalse(first["dependency_changes"])
        self.assertEqual(first["findings"][0]["tool"], "osv-api")
        second = refresh_saved(self.store, scan.scan_id, client=Provider([advisory(summary="Changed", aliases=["CVE-2099-0001", "AAA-new-alias"])]))
        self.assertEqual(len(second["changes"]["changed"]), 1)
        self.assertEqual(second["changes"]["new"], [])
        withdrawal = refresh_saved(self.store, scan.scan_id, client=Provider(lookup={"OSV-fixture": advisory(withdrawn="2026-02-01T00:00:00Z")}))
        self.assertEqual(len(withdrawal["changes"]["withdrawn"]), 1)
        self.assertEqual(withdrawal["findings"], [])
        returned = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        self.assertEqual(len(returned["changes"]["new"]), 1)
        resolved = refresh_saved(self.store, scan.scan_id, client=Provider(lookup={"OSV-fixture": advisory(affected=[])}))
        self.assertEqual(len(resolved["changes"]["resolved"]), 1)
        self.assertEqual(resolved["changes"]["withdrawn"], [])
        self.assertEqual(len(self.store.refresh_history(scan.scan_id)), 5)
        self.assertEqual(self.store.get(scan.scan_id), scan.to_dict())

    def test_identical_refresh_does_not_change_findings_because_of_time_or_tool(self):
        scan = saved_scan(self.store)
        first = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        second = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        self.assertEqual(second["changes"]["unchanged"], 1)
        self.assertEqual(second["changes"]["changed"], [])
        # A first API refresh can compare scanner evidence without treating its tool label as a feed change.
        before = copy.deepcopy(first["findings"])
        before[0].update(tool="osv-scanner", tool_version="2.7.0", scanned_at="earlier")
        self.assertEqual(reconcile(before, second["findings"], set())["unchanged"], 1)

    def test_alias_merge_and_split_are_changes_with_component_provenance(self):
        scan = saved_scan(self.store, components=[Component("example", "PyPI", "1.0", "a/requirements.txt"),
                                                  Component("example", "PyPI", "1.0", "b/requirements.txt")])
        separate = [advisory("A", aliases=["alias-A"]), advisory("B", aliases=["alias-B"])]
        provider = Provider(separate)
        initial = refresh_saved(self.store, scan.scan_id, client=provider)
        self.assertEqual(len(provider.queries), 1)
        self.assertEqual(len(initial["findings"]), 4)
        merged = [advisory("A", aliases=["alias-A", "alias-B"]), separate[1]]
        changed = refresh_saved(self.store, scan.scan_id, client=Provider(merged))
        self.assertEqual(len(changed["changes"]["changed"]), 2)
        self.assertTrue(all(len(group["before"]) == 2 and len(group["after"]) == 1 for group in changed["changes"]["changed"]))
        split = refresh_saved(self.store, scan.scan_id, client=Provider(separate))
        self.assertEqual(len(split["changes"]["changed"]), 2)
        self.assertEqual(split["changes"]["new"], [])

    def test_failure_mid_refresh_preserves_entire_previous_cache_and_finding_history(self):
        scan = saved_scan(self.store, components=[Component("example", "PyPI", "1.0", "requirements.txt"),
                                                  Component("other", "npm", "2.0", "package-lock.json", ["other@2.0"])])
        original = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        client = Mock()
        client.query.side_effect = [[], ProviderError("rate limited")]
        failed = refresh_saved(self.store, scan.scan_id, client=client)
        self.assertEqual(failed["status"], "incomplete")
        self.assertEqual(failed["findings"], original["findings"])
        self.assertIsNone(failed["changes"])
        self.assertEqual(failed["advisory_freshness"]["status"], "stale")
        self.assertEqual(failed["advisory_freshness"]["last_successful_refresh"], original["finished_at"])
        self.assertEqual(self.store.cached_refresh(scan.scan_id), original)
        self.assertEqual(len(self.store.refresh_history(scan.scan_id)), 2)
        self.assertEqual(original["findings"][1]["component"]["dependency_path"], ["other@2.0"])

    def test_interruption_and_storage_failure_do_not_replace_cache(self):
        scan = saved_scan(self.store)
        original = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        client = Mock()
        client.query.side_effect = KeyboardInterrupt
        with self.assertRaises(KeyboardInterrupt):
            refresh_saved(self.store, scan.scan_id, client=client)
        self.assertEqual(self.store.cached_refresh(scan.scan_id), original)
        # Simulate a write failure between recording history and updating the cache.
        self.store.connection.execute("CREATE TRIGGER fail_cache BEFORE UPDATE ON advisory_cache BEGIN SELECT RAISE(ABORT, 'disk failure'); END")
        with self.assertRaises(sqlite3.Error):
            refresh_saved(self.store, scan.scan_id, client=Provider([]))
        self.assertEqual(self.store.cached_refresh(scan.scan_id), original)
        self.assertEqual(len(self.store.refresh_history(scan.scan_id)), 1)

    def test_competing_refresh_cannot_overwrite_newer_cache(self):
        scan = saved_scan(self.store)
        original = refresh_saved(self.store, scan.scan_id, client=Provider())
        stale = copy.deepcopy(original)
        stale["refresh_id"] = "competing-refresh"
        with self.assertRaisesRegex(ValueError, "Another refresh"):
            self.store.save_refresh(stale, previous_refresh_id=None)
        self.assertEqual(self.store.cached_refresh(scan.scan_id), original)
        self.assertEqual(len(self.store.refresh_history(scan.scan_id)), 1)

    def test_offline_and_first_failure_retain_evidence_without_network(self):
        scan = saved_scan(self.store)
        client = Mock()
        client.query.side_effect = ProviderError("unavailable")
        failed = refresh_saved(self.store, scan.scan_id, client=client)
        self.assertEqual(failed["advisory_freshness"]["status"], "unavailable")
        self.assertIsNone(self.store.cached_refresh(scan.scan_id))
        original = refresh_saved(self.store, scan.scan_id, client=Provider([advisory()]))
        offline = refresh_saved(self.store, scan.scan_id, client=Mock(), offline=True)
        self.assertEqual(offline["status"], "offline")
        self.assertEqual(offline["findings"], original["findings"])
        self.assertEqual(self.store.cached_refresh(scan.scan_id), original)

    def test_withdrawal_lookup_failure_retains_findings_and_partial_withdrawal_is_not_confirmed(self):
        scan = saved_scan(self.store)
        records = [advisory("A"), advisory("B")]
        original = refresh_saved(self.store, scan.scan_id, client=Provider(records))
        client = Mock()
        client.query.return_value = []
        client.advisory.side_effect = ProviderError("lookup unavailable")
        failed = refresh_saved(self.store, scan.scan_id, client=client)
        self.assertEqual(failed["status"], "incomplete")
        self.assertEqual(failed["findings"], original["findings"])
        self.assertIsNone(failed["changes"])
        provider = Provider(lookup={"A": advisory("A", withdrawn="2026-02-01T00:00:00Z"), "B": advisory("B")})
        result = refresh_saved(self.store, scan.scan_id, client=provider)
        self.assertEqual(len(result["changes"]["resolved"]), 1)
        self.assertEqual(result["changes"]["withdrawn"], [])

    def test_incomplete_and_unresolved_inventories_never_become_clean(self):
        scan = saved_scan(self.store, complete=False)
        result = refresh_saved(self.store, scan.scan_id, client=Provider())
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["coverage_complete"])
        self.assertIn("incomplete", result["issues"][-1])
        with patch("cvefuzz.cli.OSVClient", return_value=Provider()), contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["refresh", scan.scan_id, "--database", str(Path(self.temporary.name) / "scans.db"), "--fail-on", "never"]), 2)
        unresolved = scan.to_dict()
        unresolved["scan_id"] = "unresolved"
        unresolved["components"][0]["version"] = None
        self.store.connection.execute("INSERT INTO scans VALUES (?, ?, ?)", ("unresolved", "before", json.dumps(unresolved)))
        self.store.connection.commit()
        client = Mock()
        result = refresh_saved(self.store, "unresolved", client=client)
        self.assertEqual(result["status"], "incomplete")
        client.query.assert_not_called()

    def test_cli_refresh_reports_history_and_exit_policies_without_repository_access(self):
        scan = saved_scan(self.store)
        root = Path(self.temporary.name)
        for records, policy, expected in [([advisory()], "findings", 1), ([advisory()], "never", 0), ([], "findings", 0)]:
            with self.subTest(policy=policy, records=bool(records)), patch("cvefuzz.cli.OSVClient", return_value=Provider(records)), patch("cvefuzz.cli.discover", side_effect=AssertionError("repository read")), contextlib.redirect_stderr(io.StringIO()):
                code = main(["refresh", scan.scan_id, "--database", str(root / "scans.db"), "--output", str(root / "report.json"), "--html", str(root / "report.html"), "--fail-on", policy])
            self.assertEqual(code, expected)
            report = json.loads((root / "report.json").read_text())
            self.assertEqual(report["content_identity"], scan.content_identity)
            rendered = (root / "report.html").read_text()
            self.assertNotIn("<script>", rendered)
            self.assertIn("Repository files were not rechecked", rendered)
        with contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["history", scan.scan_id, "--database", str(root / "scans.db")]), 0)
        self.assertEqual(len(json.loads(output.getvalue())), 3)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["refresh", scan.scan_id, "--database", str(root / "scans.db"), "--offline", "--fail-on", "never"]), 2)
            self.assertEqual(main(["refresh", "missing", "--database", str(root / "scans.db")]), 2)

    def test_v1_database_migration_preserves_saved_scan(self):
        database = Path(self.temporary.name) / "v1.db"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, result_json TEXT NOT NULL)")
            connection.execute("INSERT INTO scans VALUES ('old', 'before', '{\"scan_id\": \"old\"}')")
            connection.execute("PRAGMA user_version = 1")
        migrated = Store(database)
        try:
            self.assertEqual(migrated.get("old"), {"scan_id": "old"})
            self.assertEqual(migrated.connection.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(migrated.refresh_history("old"), [])
        finally:
            migrated.close()

    def test_migration_failure_rolls_back_schema_and_keeps_saved_scans(self):
        database = Path(self.temporary.name) / "failed-migration.db"
        with contextlib.closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, result_json TEXT NOT NULL)")
            connection.execute("CREATE TABLE advisory_cache (legacy TEXT)")
            connection.execute("INSERT INTO scans VALUES ('old', 'before', '{}')")
            connection.execute("PRAGMA user_version = 1")
        with self.assertRaises(sqlite3.Error):
            Store(database)
        with contextlib.closing(sqlite3.connect(database)) as connection:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT scan_id FROM scans").fetchall(), [("old",)])
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name = 'advisory_refreshes'").fetchone())


class OSVClientTests(unittest.TestCase):
    def response(self, payload):
        return io.BytesIO(json.dumps(payload).encode())

    def test_paginated_query_empty_page_and_withdrawal_lookup(self):
        component = asdict(Component("example", "PyPI", "1.0"))
        with patch("cvefuzz.advisories.osv.urlopen", side_effect=[self.response({"next_page_token": "next"}), self.response({"vulns": [advisory()]}), self.response(advisory())]) as opener:
            client = OSVClient()
            self.assertEqual(client.query(component), [advisory()])
            self.assertEqual(client.advisory("OSV-fixture"), advisory())
        first, second, lookup = [call.args[0] for call in opener.call_args_list]
        self.assertEqual(json.loads(first.data), {"package": {"name": "example", "ecosystem": "PyPI"}, "version": "1.0"})
        self.assertEqual(json.loads(second.data)["page_token"], "next")
        self.assertEqual(lookup.get_method(), "GET")
        self.assertTrue(lookup.full_url.endswith("/v1/vulns/OSV-fixture"))

    def test_empty_match_and_missing_advisory_are_distinct(self):
        with patch("cvefuzz.advisories.osv.urlopen", side_effect=[self.response({}), HTTPError("url", 404, "missing", {}, None)]):
            client = OSVClient()
            self.assertEqual(client.query(asdict(Component("example", "PyPI", "1.0"))), [])
            self.assertIsNone(client.advisory("missing"))

    def test_rate_limits_transient_errors_and_timeouts_are_bounded(self):
        component = asdict(Component("example", "PyPI", "1.0"))
        for failure in (HTTPError("url", 429, "limited", {"Retry-After": "2"}, None), HTTPError("url", 503, "busy", {}, None), TimeoutError("timed out")):
            with self.subTest(failure=failure), patch("cvefuzz.advisories.osv.urlopen", side_effect=[failure, self.response({})]) as opener, patch("cvefuzz.advisories.osv.time.sleep") as sleep:
                self.assertEqual(OSVClient().query(component), [])
                self.assertEqual(opener.call_count, 2)
                sleep.assert_called_once()
        for status, retry_after in ((400, "0"), (429, "999")):
            with self.subTest(status=status), patch("cvefuzz.advisories.osv.urlopen", side_effect=HTTPError("url", status, "error", {"Retry-After": retry_after}, None)) as opener, patch("cvefuzz.advisories.osv.time.sleep") as sleep:
                with self.assertRaises(ProviderError):
                    OSVClient(timeout=1).query(component)
                self.assertEqual(opener.call_count, 1)
                sleep.assert_not_called()
        with patch("cvefuzz.advisories.osv.urlopen", side_effect=TimeoutError()) as opener, patch("cvefuzz.advisories.osv.time.sleep"):
            with self.assertRaises(ProviderError):
                OSVClient(retries=1).query(component)
            self.assertEqual(opener.call_count, 2)

    def test_malformed_and_repeating_responses_cannot_be_clean(self):
        component = asdict(Component("example", "PyPI", "1.0"))
        for payload in ([], {"error": "unavailable"}, {"unexpected": True}, {"vulns": {}}, {"vulns": [None]}, {"vulns": [advisory(aliases=[{}])]}, {"vulns": [advisory(database_specific=[])]}, {"next_page_token": 42}):
            with self.subTest(payload=payload), patch("cvefuzz.advisories.osv.urlopen", return_value=self.response(payload)):
                with self.assertRaises(ProviderError):
                    OSVClient().query(component)
        pages = [{"vulns": [advisory()], "next_page_token": "same"}, {"next_page_token": "same"}]
        with patch("cvefuzz.advisories.osv.urlopen", side_effect=[self.response(p) for p in pages]):
            with self.assertRaisesRegex(ProviderError, "repeated"):
                OSVClient().query(component)
        pages[1] = {"vulns": [advisory(summary="changed during query")]}
        with patch("cvefuzz.advisories.osv.urlopen", side_effect=[self.response(p) for p in pages]):
            with self.assertRaisesRegex(ProviderError, "changed during pagination"):
                OSVClient().query(component)
        with patch("cvefuzz.advisories.osv.urlopen", return_value=io.BytesIO(b"not-json")):
            with self.assertRaises(ProviderError):
                OSVClient().query(component)
        with patch("cvefuzz.advisories.osv.MAX_RESPONSE_BYTES", 10), patch("cvefuzz.advisories.osv.urlopen", return_value=self.response({"vulns": [advisory()]})):
            with self.assertRaisesRegex(ProviderError, "exceeds"):
                OSVClient().query(component)

    def test_retry_after_http_date_and_invalid_configuration(self):
        value = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=20))
        self.assertGreater(retry_delay(value, 1), 18)
        self.assertEqual(retry_delay("invalid", 2), 2)
        self.assertEqual(retry_delay("NaN", 2), 2)
        for timeout, retries in ((0, 2), (float("inf"), 2), (30, 6), (30, -1)):
            with self.subTest(timeout=timeout, retries=retries), self.assertRaises(ValueError):
                OSVClient(timeout, retries)

    def test_response_deadline_is_checked_while_reading(self):
        component = asdict(Component("example", "PyPI", "1.0"))
        with patch("cvefuzz.advisories.osv.urlopen", return_value=self.response({"vulns": [advisory()]})), patch("cvefuzz.advisories.osv.time.monotonic", side_effect=[0, 0, 0, 31]):
            with self.assertRaisesRegex(ProviderError, "deadline exceeded"):
                OSVClient(timeout=30).query(component)


if __name__ == "__main__":
    unittest.main()
