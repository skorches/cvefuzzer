"""Recheck saved components; publish only complete provider snapshots."""

import copy
import json
from dataclasses import asdict
from datetime import datetime, timezone
from uuid import uuid4

from .. import __version__
from .normalize import normalize
from .osv import ENDPOINT, OSVClient, ProviderError


def now():
    return datetime.now(timezone.utc).isoformat()


def component_key(component):
    return tuple(component.get(key) for key in ("ecosystem", "name", "version", "manifest"))


def semantic(finding):
    # Execution time, provider tool label, and fingerprints do not describe feed changes.
    return {key: finding.get(key) for key in ("advisory_ids", "evidence", "severity", "severity_source")}


def reconcile(previous, current, withdrawn):
    """Compare alias-connected groups, including merges/splits, within one component."""
    changes = {key: [] for key in ("new", "changed", "withdrawn", "resolved")}
    changes["unchanged"] = 0
    pending = [("before", finding) for finding in previous] + [("after", finding) for finding in current]
    while pending:
        side, first = pending.pop(0)
        group = {"before": [], "after": []}
        group[side].append(first)
        key, identifiers = component_key(first["component"]), set(first["advisory_ids"])
        while True:
            remaining, matched = [], False
            for side, finding in pending:
                if component_key(finding["component"]) == key and identifiers.intersection(finding["advisory_ids"]):
                    group[side].append(finding)
                    identifiers.update(finding["advisory_ids"])
                    matched = True
                else:
                    remaining.append((side, finding))
            pending = remaining
            if not matched:
                break
        before, after = group["before"], group["after"]
        if not before:
            changes["new"].append(group)
        elif not after:
            # Only call a whole alias group withdrawn if every formerly active record is withdrawn.
            records = {e["id"] for finding in before for e in finding["evidence"]}
            state = "withdrawn" if records and records <= withdrawn else "resolved"
            changes[state].append(group)
        else:
            old = sorted(json.dumps(semantic(f), sort_keys=True) for f in before)
            new = sorted(json.dumps(semantic(f), sort_keys=True) for f in after)
            if old != new:
                changes["changed"].append(group)
            else:
                changes["unchanged"] += 1
    return changes


def refresh_saved(store, scan_id, *, client=None, offline=False, configuration=None):
    scan = store.get(scan_id)
    if scan is None:
        raise ValueError(f"Saved scan not found: {scan_id}")
    checks = [check for check in scan["checks"] if check["name"] == "dependency_scan"]
    if not checks or not checks[0].get("requested") or not scan.get("components"):
        raise ValueError("Saved scan has no dependency component inventory to refresh; run scan first")
    cached = store.cached_refresh(scan_id)
    baseline = cached if cached else scan
    started = now()
    result = {
        "schema_version": 1, "refresh_id": str(uuid4()), "scan_id": scan_id,
        "root": scan["root"], "content_identity": scan["content_identity"],
        "started_at": started, "finished_at": None, "status": "incomplete",
        "configuration": {**(configuration or {}), "offline": offline},
        "tool_versions": {"cvefuzz": __version__, "osv-api": "v1"},
        "cause": "advisory-refresh", "dependency_changes": False,
        "inventory_status": scan["status"], "inventory_checks": copy.deepcopy(scan["checks"]),
        "coverage_complete": scan["status"] == "dependency-scan-completed",
        "components": copy.deepcopy(scan["components"]), "findings": copy.deepcopy(baseline["findings"]),
        "changes": None, "issues": [], "responses": [], "withdrawal_checks": {},
        "advisory_freshness": {"provider": "OSV", "endpoint": ENDPOINT, "status": "stale" if cached else "unavailable",
                               "fetched_at": cached["advisory_freshness"]["fetched_at"] if cached else None,
                               "last_successful_refresh": cached["finished_at"] if cached else None,
                               "attempted_at": started, "outcome": "offline" if offline else "failed"},
    }
    if offline:
        result["status"] = "offline"
        result["issues"].append("Offline: retained saved findings; advisory changes have not been checked")
    else:
        client = client if client is not None else OSVClient()
        try:
            unique = {}
            for component in scan["components"]:
                if not all(isinstance(component.get(key), str) and component[key].strip() for key in ("name", "ecosystem", "version")):
                    raise ProviderError("Saved inventory contains an unresolved package identity or version; rescan first")
                if component["ecosystem"] not in {"PyPI", "npm"}:
                    raise ProviderError(f"Refresh ecosystem not supported: {component['ecosystem']}")
                identity = tuple(component[key] for key in ("ecosystem", "name", "version"))
                if identity not in unique:
                    records = client.query(component)
                    unique[identity] = records
                    result["responses"].append({"package": {key: component[key] for key in ("name", "ecosystem", "version")}, "vulns": records})
            returned = {record["id"]: record for records in unique.values() for record in records}
            previous_ids = {e["id"] for finding in baseline["findings"] for e in finding["evidence"]}
            # Query missing record IDs to distinguish withdrawal from changed matching results.
            for identifier in sorted(previous_ids - returned.keys()):
                result["withdrawal_checks"][identifier] = client.advisory(identifier)
            withdrawn = {identifier for identifier, record in {**returned, **result["withdrawal_checks"]}.items()
                         if record and record.get("withdrawn")}
            findings = []
            for component in scan["components"]:
                identity = tuple(component[key] for key in ("ecosystem", "name", "version"))
                payload = {"results": [{"packages": [{"package": component, "vulnerabilities": unique[identity]}]}]}
                _, normalized = normalize(payload, component.get("manifest"), "v1", started, tool="osv-api")
                for finding in normalized:
                    finding.component.dependency_path = list(component.get("dependency_path", []))
                    findings.append(asdict(finding))
            result["changes"] = reconcile(baseline["findings"], findings, withdrawn)
            result["findings"] = findings
            result["status"] = "completed"
            result["advisory_freshness"].update(status="queried", fetched_at=now(), outcome="completed")
        except (ProviderError, OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            result["issues"].append(f"Refresh failed; retained previous findings: {error}")
    result["finished_at"] = now()
    if result["status"] == "completed":
        result["advisory_freshness"]["last_successful_refresh"] = result["finished_at"]
    if not result["coverage_complete"]:
        result["issues"].append("Original dependency scan was incomplete; refresh only covers its saved components")
    store.save_refresh(result, cached["refresh_id"] if cached else None)
    return result
