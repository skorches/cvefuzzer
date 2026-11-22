import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .. import __version__
from ..adapters import capabilities
from ..adapters.osv import scan_dependencies
from ..advisories.osv import OSVClient
from ..advisories.refresh import refresh_saved
from ..findings import Scan
from ..inventory import discover
from ..reports import render_html
from ..storage import Store


def now():
    return datetime.now(timezone.utc).isoformat()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="cvefuzz", description="Repository inventory, dependency vulnerability scanning, and saved-inventory advisory refresh.")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("capabilities", help="Show implemented capabilities by language")
    inventory = commands.add_parser("inventory", help="Inventory files without executing repository code")
    inventory.add_argument("path", type=Path)
    inventory.add_argument("--output", type=Path, help="Write JSON (default: standard output)")
    inventory.add_argument("--database", type=Path, default=Path(".cvefuzz/scans.sqlite3"))
    inventory.add_argument("--exclude", action="append", default=[], help="Additional directory basename to skip; repeatable")
    dependency = commands.add_parser("scan", help="Check supported lockfiles using OSV-Scanner v2")
    dependency.add_argument("path", type=Path)
    dependency.add_argument("--output", type=Path)
    dependency.add_argument("--html", type=Path, help="Write a self-contained HTML report")
    dependency.add_argument("--database", type=Path, default=Path(".cvefuzz/scans.sqlite3"))
    dependency.add_argument("--exclude", action="append", default=[])
    dependency.add_argument("--osv-scanner", default="osv-scanner", help="Trusted OSV-Scanner v2 executable")
    dependency.add_argument("--timeout", type=int, default=120, help="Per-lockfile timeout in seconds")
    dependency.add_argument("--fail-on", choices=["findings", "never"], default="findings", help="Operational errors always exit 2")
    refresh = commands.add_parser("refresh", help="Requery OSV for a saved scan without reading repository files")
    refresh.add_argument("scan_id", help="scan_id from a saved scan report")
    refresh.add_argument("--database", type=Path, default=Path(".cvefuzz/scans.sqlite3"))
    refresh.add_argument("--output", type=Path)
    refresh.add_argument("--html", type=Path)
    refresh.add_argument("--timeout", type=int, default=30, help="Time budget per package query or withdrawal lookup, in seconds")
    refresh.add_argument("--retries", type=int, choices=range(6), default=2, help="Retries per request within its time budget (0-5)")
    refresh.add_argument("--offline", action="store_true", help="Show retained findings without network access; exits 2")
    refresh.add_argument("--fail-on", choices=["findings", "never"], default="findings")
    history = commands.add_parser("history", help="Show saved advisory refresh attempts and finding changes")
    history.add_argument("scan_id")
    history.add_argument("--database", type=Path, default=Path(".cvefuzz/scans.sqlite3"))
    args = parser.parse_args(argv)
    if args.command == "capabilities":
        print(json.dumps(capabilities(), indent=2))
        return 0
    if args.command in {"scan", "refresh"} and args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        if args.command in {"refresh", "history"}:
            store = Store(args.database)
            try:
                if args.command == "history":
                    if store.get(args.scan_id) is None:
                        raise ValueError(f"Saved scan not found: {args.scan_id}")
                    print(json.dumps(store.refresh_history(args.scan_id), indent=2))
                    return 0
                result = refresh_saved(store, args.scan_id, client=OSVClient(args.timeout, args.retries), offline=args.offline,
                                       configuration={"timeout": args.timeout, "retries": args.retries})
            finally:
                store.close()
            rendered = json.dumps(result, indent=2) + "\n"
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(rendered, encoding="utf-8")
            else:
                print(rendered, end="")
            if args.html:
                args.html.parent.mkdir(parents=True, exist_ok=True)
                args.html.write_text(render_html(result), encoding="utf-8")
            print(f"Advisory refresh {result['status']}: {len(result['findings'])} retained/current findings; "
                  f"dependency inventory unchanged. Original coverage: {result['inventory_status']}.", file=sys.stderr)
            if result["status"] != "completed" or not result["coverage_complete"]:
                return 2
            return 1 if result["findings"] and args.fail_on == "findings" else 0
        started = now()
        data = discover(args.path, args.exclude)
        scan = Scan(str(uuid4()), str(args.path.resolve()), started, now(),
                    data.pop("content_identity"), "inventory-incomplete" if data["errors"] else "inventory-only",
                    {"exclude": args.exclude}, {"cvefuzz": __version__},
                    [{"name": "inventory", "requested": True, "status": "failed" if data["errors"] else "completed"}] +
                    [{"name": name, "requested": False, "status": "skipped", "reason": "Not implemented; analysis has not run"}
                     for name in ("dependency_scan", "static_analysis", "fuzzing")], data)
        if args.command == "scan":
            artifact_dir = args.database.resolve().parent / "artifacts" / scan.scan_id
            dependencies = scan_dependencies(args.path, data, args.osv_scanner, artifact_dir, started, args.timeout)
            scan.components, scan.findings = dependencies.components, dependencies.findings
            scan.artifacts.extend(dependencies.artifacts)
            scan.tool_versions["osv-scanner"] = dependencies.version
            scan.configuration.update({"fail_on": args.fail_on, "timeout": args.timeout, "osv_scanner": args.osv_scanner})
            scan.checks[1] = {"name": "dependency_scan", "requested": True, "status": dependencies.status,
                              "issues": dependencies.issues, "scanned_files": dependencies.scanned_files}
            scan.status = "dependency-scan-completed" if dependencies.status == "completed" and not data["errors"] else "scan-incomplete"
            scan.advisory_freshness = {"status": "queried-by-scanner" if dependencies.scanned_files else "unavailable",
                                       "query_time": started, "last_successful_refresh": None,
                                       "note": "Provider freshness is not independently verified; no scheduled refresh yet."}
            scan.finished_at = now()
            if args.html:
                scan.artifacts.append(str(args.html.resolve()))
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
        if args.command == "scan":
            if args.html:
                args.html.parent.mkdir(parents=True, exist_ok=True)
                args.html.write_text(render_html(scan), encoding="utf-8")
            print(f"{scan.status}: {len(scan.findings)} dependency findings. Static analysis and fuzzing have not run.", file=sys.stderr)
            if scan.status == "scan-incomplete":
                return 2
            return 1 if scan.findings and args.fail_on == "findings" else 0
        print("Inventory only: security analysis has not run. No safety conclusion can be drawn.", file=sys.stderr)
        return 2 if data["errors"] else 0
    except (OSError, ValueError, sqlite3.Error) as error:
        print(f"cvefuzz: {error}", file=sys.stderr)
        return 2
