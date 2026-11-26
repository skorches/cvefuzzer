"""Local project summaries and due refreshes; no repository filesystem access."""

import math
import sqlite3
from datetime import datetime, timezone
from uuid import uuid4

from .refresh import component_key, refresh_saved


def timestamp(value):
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        raise ValueError("Expected an ISO 8601 timestamp with a timezone") from None
    if parsed.tzinfo is None:
        raise ValueError("Expected an ISO 8601 timestamp with a timezone")
    return parsed.astimezone(timezone.utc)


def valid_hours(value, *, positive=False):
    if not math.isfinite(value) or value < 0 or (positive and value == 0):
        raise ValueError("Hours must be finite and " + ("positive" if positive else "nonnegative"))
    return value


def freshness(cached, latest_attempt, current_time, max_age_hours):
    last_success = cached["finished_at"] if cached else None
    result = {"status": "unavailable", "last_successful_refresh": last_success,
              "age_hours": None, "last_attempt_status": latest_attempt["status"] if latest_attempt else None,
              "last_attempt_at": latest_attempt["finished_at"] if latest_attempt else None,
              "last_attempt_issues": latest_attempt.get("issues", []) if latest_attempt else []}
    if cached:
        result["status"] = "stale"
        try:
            age = (current_time - timestamp(last_success)).total_seconds() / 3600
        except ValueError:
            result["reason"] = "Invalid successful-refresh timestamp; refresh required"
        else:
            if age < 0:
                result["reason"] = "Successful refresh is in the future; check the clock and refresh"
            else:
                result["age_hours"] = age
                if age < max_age_hours and latest_attempt and latest_attempt["status"] == "completed":
                    result["status"] = "fresh"
    return result


def new_findings(current, history, since):
    """Most recent 'new' event for each still-matched finding on this saved scan."""
    events = []
    successful = [attempt for attempt in reversed(history) if attempt["status"] == "completed"]
    for finding in current:
        found = None
        for attempt in successful:
            if since is not None and timestamp(attempt["finished_at"]) < since:
                continue
            for group in (attempt.get("changes") or {}).get("new", []):
                if any(component_key(candidate["component"]) == component_key(finding["component"]) and
                       set(candidate["advisory_ids"]).intersection(finding["advisory_ids"]) for candidate in group["after"]):
                    found = {"detected_at": attempt["finished_at"], "refresh_id": attempt["refresh_id"],
                             "advisory_ids": finding["advisory_ids"], "component": finding["component"]}
                    break
            if found:
                break
        if found:
            events.append(found)
    return events


def project_summary(store, scan, *, current_time, max_age_hours=24, since=None):
    cached = store.cached_refresh(scan["scan_id"])
    history = store.refresh_history(scan["scan_id"])
    findings = (cached if cached else scan)["findings"]
    summary = {
        "scan_id": scan["scan_id"], "root": scan["root"], "content_identity": scan["content_identity"],
        "inventory_status": scan["status"], "coverage_complete": scan["status"] == "dependency-scan-completed",
        "inventory_checks": scan["checks"],
        "refreshable": bool(scan.get("components")), "findings_count": len(findings),
        "advisory_freshness": freshness(cached, history[-1] if history else None, current_time, max_age_hours),
        "new_findings": new_findings(findings, history, since),
    }
    if not summary["refreshable"]:
        summary["reason"] = "Latest dependency scan saved no components; run scan again"
    return summary


def list_projects(store, *, max_age_hours=24, since=None, newly_affected=False, current_time=None):
    valid_hours(max_age_hours, positive=True)
    since = timestamp(since) if since is not None else None
    current_time = current_time or datetime.now(timezone.utc)
    projects = [project_summary(store, scan, current_time=current_time, max_age_hours=max_age_hours, since=since)
                for scan in store.project_scans()]
    if newly_affected:
        projects = [project for project in projects if project["new_findings"]]
    return {"schema_version": 1, "report_kind": "projects", "generated_at": current_time.isoformat(),
            "status": "catalog", "configuration": {"max_age_hours": max_age_hours, "since": since.isoformat() if since else None,
                                                       "newly_affected": newly_affected},
            "projects": projects,
            "note": "Saved dependency inventories only. Listing success does not mean projects are safe; repository files were not rechecked."}


def refresh_projects(store, *, client=None, offline=False, min_age_hours=0, configuration=None, current_time=None):
    valid_hours(min_age_hours)
    started = current_time or datetime.now(timezone.utc)
    scans = store.project_scans()  # Freeze target selection before the first provider request.
    result = {"schema_version": 1, "report_kind": "refresh-batch", "batch_id": str(uuid4()),
              "started_at": started.isoformat(), "finished_at": None, "status": "completed",
              "configuration": {**(configuration or {}), "offline": offline, "min_age_hours": min_age_hours},
              "projects": [], "issues": [], "findings_count": 0, "refreshed": 0, "skipped": 0}
    if not scans:
        result["status"] = "incomplete"
        result["issues"].append("No saved dependency scans found; run scan first")
    for scan in scans:
        cached = store.cached_refresh(scan["scan_id"])
        history = store.refresh_history(scan["scan_id"])
        age = freshness(cached, history[-1] if history else None, started, min_age_hours)
        outcome, issues, changes, refresh_id = "blocked", [], None, None
        findings = (cached if cached else scan)["findings"]
        coverage_complete = scan["status"] == "dependency-scan-completed"
        if not scan.get("components"):
            issues.append("Latest dependency scan saved no components; run scan again")
        elif not offline and min_age_hours > 0 and age["status"] == "fresh":
            outcome = "skipped"
            result["skipped"] += 1
            if not coverage_complete:
                issues.append("Original dependency scan was incomplete; refreshing saved components cannot complete its coverage")
        else:
            try:
                refreshed = refresh_saved(store, scan["scan_id"], client=client, offline=offline,
                                          configuration={**(configuration or {}), "batch_id": result["batch_id"], "min_age_hours": min_age_hours})
                outcome, issues = refreshed["status"], refreshed["issues"]
                findings, refresh_id = refreshed["findings"], refreshed["refresh_id"]
                if refreshed["changes"] is not None:
                    changes = {key: value if key == "unchanged" else len(value) for key, value in refreshed["changes"].items()}
                if outcome == "completed":
                    result["refreshed"] += 1
            except (OSError, ValueError, sqlite3.Error) as error:
                outcome, issues = "failed", [str(error)]
        if outcome not in {"completed", "skipped"} or not coverage_complete:
            result["status"] = "incomplete"
        result["findings_count"] += len(findings)
        result["projects"].append({"scan_id": scan["scan_id"], "root": scan["root"], "outcome": outcome,
                                   "inventory_status": scan["status"], "coverage_complete": coverage_complete,
                                   "refresh_id": refresh_id, "findings_count": len(findings), "changes": changes, "issues": issues})
    result["finished_at"] = datetime.now(timezone.utc).isoformat()
    return result
