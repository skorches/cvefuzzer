"""OSV-Scanner v2 boundary. Only explicit lockfiles are sent to the scanner."""

import hashlib
import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from ..findings import Component, Finding
from .npm import dependency_paths
from .requirements import requirements_issues

SUPPORTED = {"requirements.txt", "package-lock.json"}


@dataclass
class DependencyResult:
    status: str = "failed"
    version: str = "unknown"
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)


def normalize(payload, manifest, version, scanned_at):
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
                             "affected": v.get("affected", []), "severity": v.get("severity", [])}
                            for v in sorted(members, key=lambda v: v["id"])]
                # Keep fix ranges as advisory evidence; do not guess which branch upgrade is appropriate.
                ratings = sorted({str(v.get("database_specific", {}).get("severity")) for v in members
                                  if v.get("database_specific", {}).get("severity")})
                findings.append(Finding(fingerprint, "dependency", "osv-scanner", version,
                                        "affected-version-match" if component.version else "unresolved-version",
                                        scanned_at, "affected-version", evidence=evidence,
                                        location=manifest, component=component,
                                        advisory_ids=sorted(identifiers),
                                        severity=", ".join(ratings) or None,
                                        severity_source="OSV database_specific.severity" if ratings else None,
                                        remediation="Review affected ranges and fixed events in advisory evidence before choosing an upgrade."))
    return components, findings


def scan_dependencies(root, inventory, executable, artifact_dir, scanned_at, timeout=120):
    result = DependencyResult()
    if "/" in str(executable) or "\\" in str(executable):
        executable = str(Path(executable).resolve())
    root, artifact_dir = Path(root).resolve(), Path(artifact_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    selected = [item["path"] for item in inventory["manifests"] if Path(item["path"]).name in SUPPORTED]
    unsupported = [item["path"] for item in inventory["manifests"]
                   if Path(item["path"]).name not in SUPPORTED and
                   Path(item["path"]).name not in {"package.json", "pyproject.toml", "tsconfig.json"}]
    result.issues.extend(f"Unsupported manifest for dependency scanning: {path}" for path in unsupported)
    for item in inventory["manifests"]:
        path = Path(item["path"])
        if path.name in {"package.json", "pyproject.toml"} and not any(Path(p).parent == path.parent for p in selected):
            result.issues.append(f"No supported lockfile beside {path.as_posix()}; dependency versions unresolved")
    if not selected:
        result.issues.append("No supported dependency inputs found")
        return result
    try:
        process = subprocess.run([str(executable), "--version"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=min(timeout, 15), shell=False)
        result.version = process.stdout.strip()
        if process.returncode != 0 or not re.search(r"\b2\.\d+\.\d+", result.version):
            raise ValueError("OSV-Scanner v2 is required; unexpected version response")
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        result.issues.append(f"Scanner unavailable: {error}")
        return result
    # Override repository suppressions/configuration with an empty tool-owned config.
    config = artifact_dir / "osv-scanner.toml"
    config.write_text("# CVEFuzz: no repository suppressions\n", encoding="utf-8")
    result.artifacts.append(str(config))
    for number, relative in enumerate(selected):
        if Path(relative).name == "requirements.txt":
            try:
                gaps = requirements_issues(root / relative)
            except (OSError, ValueError) as error:
                gaps = [f"Requirements input unavailable: {error}"]
            if gaps:
                result.issues.extend(f"{relative}: {gap}; input skipped" for gap in gaps)
                continue
        prefix = artifact_dir / f"osv-{number}"
        raw_path, log_path = prefix.with_suffix(".json"), prefix.with_suffix(".log")
        command = [str(executable), "scan", "source", "--format", "json", "--all-packages", "--all-vulns",
                   "--no-resolve", "--no-call-analysis=go", "--no-call-analysis=rust", "--config", str(config),
                   "--lockfile", str(root / relative)]
        try:
            process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                     errors="replace", timeout=timeout, shell=False)
            raw_path.write_text(process.stdout, encoding="utf-8")
            log_path.write_text(process.stderr, encoding="utf-8")
            result.artifacts.extend([str(raw_path), str(log_path)])
            if process.returncode not in (0, 1):
                raise ValueError(f"scanner exited {process.returncode}; see {log_path}")
            components, findings = normalize(json.loads(process.stdout), relative, result.version, scanned_at)
            if Path(relative).name == "package-lock.json":
                try:
                    paths, gaps = dependency_paths(root / relative)
                    result.issues.extend(f"{relative}: {gap}" for gap in gaps)
                    for component in components:
                        if component.ecosystem == "npm":
                            component.dependency_path = paths.get((component.name, component.version), [])
                            if not component.dependency_path:
                                result.issues.append(f"Unresolved npm provenance: {component.name}@{component.version} in {relative}")
                except (OSError, ValueError, TypeError, AttributeError) as error:
                    result.issues.append(f"{relative}: npm provenance unavailable: {error}")
            raw = json.loads(process.stdout)
            for source in raw["results"]:
                for entry in source["packages"]:
                    if "source=LOCAL" in entry["package"].get("purl", ""):
                        result.issues.append(f"Local-source package may not have registry advisory coverage: {entry['package']['name']} in {relative}")
            result.components.extend(components)
            result.findings.extend(findings)
            if not components:
                raise ValueError("Scanner returned no packages for this input")
            if any(not c.version for c in components):
                result.issues.append(f"Unresolved package versions in {relative}")
            if process.returncode == 1 and not findings:
                result.issues.append(f"Scanner reported findings not represented by vulnerability records in {relative}")
            result.scanned_files.append(relative)
        except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
            result.issues.append(f"{relative}: {error}")
    result.status = "completed" if not result.issues else "incomplete"
    return result
