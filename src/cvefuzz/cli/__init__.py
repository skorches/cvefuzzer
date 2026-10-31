import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .. import __version__
from ..adapters import capabilities
from ..findings import Scan
from ..inventory import discover
from ..storage import Store


def now():
    return datetime.now(timezone.utc).isoformat()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cvefuzz", description="Passive repository inventory; security analysis is not implemented yet.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities", help="Show implemented capabilities by language")
    inventory = commands.add_parser("inventory", help="Inventory files without executing repository code")
    inventory.add_argument("path", type=Path)
    inventory.add_argument("--output", type=Path, help="Write JSON (default: standard output)")
    inventory.add_argument("--database", type=Path, default=Path(".cvefuzz/scans.sqlite3"))
    inventory.add_argument("--exclude", action="append", default=[], help="Additional directory basename to skip; repeatable")
    args = parser.parse_args(argv)
    if args.command == "capabilities":
        print(json.dumps(capabilities(), indent=2))
        return 0
    try:
        started = now()
        data = discover(args.path, args.exclude)
        scan = Scan(str(uuid4()), str(args.path.resolve()), started, now(),
                    data.pop("content_identity"), "inventory-incomplete" if data["errors"] else "inventory-only",
                    {"exclude": args.exclude}, {"cvefuzz": __version__},
                    [{"name": "inventory", "requested": True, "status": "failed" if data["errors"] else "completed"}] +
                    [{"name": name, "requested": False, "status": "skipped", "reason": "Not implemented; analysis has not run"}
                     for name in ("dependency_scan", "static_analysis", "fuzzing")], data)
        if args.output:
            scan.artifacts.append(str(args.output.resolve()))
        rendered = json.dumps(scan.to_dict(), indent=2) + "\n"
        store = Store(args.database)
        try:
            store.save(scan)
        finally:
            store.close()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
        print("Inventory only: security analysis has not run. No safety conclusion can be drawn.", file=sys.stderr)
        return 2 if data["errors"] else 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"cvefuzz: {error}", file=sys.stderr)
        return 2
