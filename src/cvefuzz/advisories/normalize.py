import hashlib
import json

from ..findings import Component, Finding


def normalize(payload, manifest, version, scanned_at, *, tool="osv-scanner"):
    """Merge transitively overlapping advisory aliases within one component."""
    if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
        raise ValueError("Invalid OSV JSON: expected a results array")
    components, findings = [], []
    for source in payload["results"]:
        if not isinstance(source, dict) or not isinstance(source.get("packages"), list):
            raise ValueError("Invalid OSV JSON: expected a packages array")
        for entry in source["packages"]:
            package = entry["package"]
            component = Component(package["name"], package["ecosystem"], package.get("version"), manifest)
            if not isinstance(component.name, str) or not isinstance(component.ecosystem, str):
                raise ValueError("Invalid OSV package identity")
            components.append(component)
            advisories = [v for v in entry.get("vulnerabilities", []) if not v.get("withdrawn")]
            groups = []
            for advisory in advisories:
                identifiers = {advisory["id"], *advisory.get("aliases", [])}
                merged, remaining = [advisory], []
                # Repeat because a newly merged group can bridge earlier groups.
                pending = groups[:]
                while True:
                    changed = False
                    remaining = []
                    for ids, members in pending:
                        if ids & identifiers:
                            identifiers |= ids
                            merged += members
                            changed = True
                        else:
                            remaining.append((ids, members))
                    if not changed:
                        break
                    pending = remaining
                groups = remaining + [(identifiers, merged)]
            for identifiers, members in groups:
                canonical = min(identifiers)
                identity = [component.ecosystem, component.name, component.version, manifest, canonical]
                fingerprint = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
                evidence = [{"id": v["id"], "summary": v.get("summary"),
                             "affected": v.get("affected", []), "severity": v.get("severity", []),
                             **{key: v[key] for key in ("modified", "published", "details", "references", "database_specific") if key in v}}
                            for v in sorted(members, key=lambda v: v["id"])]
                # Keep fix ranges as advisory evidence; do not guess which branch upgrade is appropriate.
                ratings = sorted({str(v.get("database_specific", {}).get("severity")) for v in members
                                  if v.get("database_specific", {}).get("severity")})
                findings.append(Finding(fingerprint, "dependency", tool, version,
                                        "affected-version-match" if component.version else "unresolved-version",
                                        scanned_at, "affected-version", evidence=evidence,
                                        location=manifest, component=component,
                                        advisory_ids=sorted(identifiers),
                                        severity=", ".join(ratings) or None,
                                        severity_source="OSV database_specific.severity" if ratings else None,
                                        remediation="Review affected ranges and fixed events in advisory evidence before choosing an upgrade."))
    return components, findings
