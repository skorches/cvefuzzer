import json
import os
import sqlite3
from pathlib import Path

from ..findings import Scan

DB_VERSION = 2


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        try:
            with self.connection:
                self.connection.execute("BEGIN IMMEDIATE")
                version = self.connection.execute("PRAGMA user_version").fetchone()[0]
                if version > DB_VERSION:
                    raise ValueError(f"Database schema {version} is newer than supported {DB_VERSION}")
                if version == 0:
                    self.connection.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, result_json TEXT NOT NULL)")
                if version < 2:
                    self.connection.execute("CREATE TABLE advisory_refreshes (refresh_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, started_at TEXT NOT NULL, status TEXT NOT NULL, result_json TEXT NOT NULL)")
                    self.connection.execute("CREATE INDEX refreshes_by_scan ON advisory_refreshes(scan_id, started_at)")
                    self.connection.execute("CREATE TABLE advisory_cache (scan_id TEXT PRIMARY KEY, refresh_id TEXT NOT NULL, result_json TEXT NOT NULL)")
                    self.connection.execute("PRAGMA user_version = 2")
        except Exception:
            self.connection.close()
            raise

    def save(self, scan: Scan):
        with self.connection:
            self.connection.execute("INSERT INTO scans VALUES (?, ?, ?)",
                                    (scan.scan_id, scan.started_at, json.dumps(scan.to_dict())))

    def get(self, scan_id: str):
        row = self.connection.execute("SELECT result_json FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def cached_refresh(self, scan_id: str):
        row = self.connection.execute("SELECT result_json FROM advisory_cache WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None

    def save_refresh(self, result, previous_refresh_id=None):
        """Commit the complete cache and its history together; failures only append history."""
        serialized = json.dumps(result)
        with self.connection:
            if result["status"] == "completed":
                # Serialize writers before checking for another updater's intervening commit.
                self.connection.execute("BEGIN IMMEDIATE")
                row = self.connection.execute("SELECT refresh_id FROM advisory_cache WHERE scan_id = ?", (result["scan_id"],)).fetchone()
                if (row[0] if row else None) != previous_refresh_id:
                    raise ValueError("Another refresh completed meanwhile; retry against the latest cache")
            self.connection.execute("INSERT INTO advisory_refreshes VALUES (?, ?, ?, ?, ?)",
                                    (result["refresh_id"], result["scan_id"], result["started_at"], result["status"], serialized))
            if result["status"] == "completed":
                self.connection.execute("INSERT INTO advisory_cache VALUES (?, ?, ?) ON CONFLICT(scan_id) DO UPDATE SET refresh_id=excluded.refresh_id, result_json=excluded.result_json",
                                        (result["scan_id"], result["refresh_id"], serialized))

    def refresh_history(self, scan_id: str):
        rows = self.connection.execute("SELECT result_json FROM advisory_refreshes WHERE scan_id = ? ORDER BY rowid", (scan_id,))
        return [json.loads(row[0]) for row in rows]

    def project_scans(self):
        """Latest saved dependency attempt per root, including unsuccessful attempts.

        Inventory-only scans do not replace dependency inventories. Save order is
        authoritative; roots are compared using this host's path case rules.
        """
        projects = {}
        rows = self.connection.execute("SELECT result_json FROM scans ORDER BY rowid DESC")
        for row in rows:
            scan = json.loads(row[0])
            if not any(check.get("name") == "dependency_scan" and check.get("requested") for check in scan["checks"]):
                continue
            key = os.path.normcase(os.path.normpath(scan["root"]))
            if key not in projects:
                projects[key] = scan
        return [projects[key] for key in sorted(projects)]

    def close(self):
        self.connection.close()
