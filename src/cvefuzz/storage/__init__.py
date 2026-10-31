import json
import sqlite3
from pathlib import Path

from ..findings import Scan

DB_VERSION = 1


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(path)
        try:
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version > DB_VERSION:
                raise ValueError(f"Database schema {version} is newer than supported {DB_VERSION}")
            if version == 0:
                with self.connection:
                    self.connection.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, started_at TEXT NOT NULL, result_json TEXT NOT NULL)")
                    self.connection.execute("PRAGMA user_version = 1")
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

    def close(self):
        self.connection.close()
