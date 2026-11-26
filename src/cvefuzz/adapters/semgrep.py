"""Local Semgrep CE boundary; only immutable, inventoried source copies are scanned."""

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from dataclasses import dataclass, field

from . import REGISTRY
from ..findings import Finding

EXTENSIONS = {".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"}
RULES = [{"id": f"cvefuzz.{language}.dynamic-eval", "languages": languages,
          "message": "Dynamic evaluation can execute code; review the origin of this value.",
          "severity": "WARNING", "pattern": "eval($VALUE)",
          "metadata": {"license": "CC0-1.0", "confidence": "LOW", "ruleset_version": "1"}}
         for language, languages in (("python", ["python"]), ("javascript", ["javascript", "typescript"]))]


@dataclass
class StaticResult:
    status: str = "failed"
    version: str = "unknown"
    findings: list[Finding] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    scanned_files: list[str] = field(default_factory=list)


def scan_static(root, inventory, executable, artifact_dir, scanned_at, timeout=120):
    result = StaticResult()
    root, artifact_dir = Path(root).resolve(), Path(artifact_dir).resolve()
    if "/" in str(executable) or "\\" in str(executable):
        executable = str(Path(executable).resolve())
    artifact_dir.mkdir(parents=True, exist_ok=True)
    snapshot = artifact_dir / "sources"
    snapshot.mkdir()
    expected = set()
    total = 0
    for item in inventory["files"]:
        relative = item["path"]
        if Path(relative).suffix.lower() not in EXTENSIONS:
            if any(Path(relative).suffix.lower() in spec["extensions"] for spec in REGISTRY.values()):
                result.issues.append(f"Unsupported source language for static analysis: {relative}")
            continue
        try:
            source = root / relative
            if source.is_symlink() or not source.resolve().is_relative_to(root):
                raise ValueError("Source escaped repository or became a symlink")
            with source.open("rb") as stream:
                content = stream.read(1_000_001)
            total += len(content)
            if len(content) > 1_000_000 or total > 20_000_000 or len(expected) >= 1000:
                raise ValueError("Static source limit exceeded (1 MB/file, 20 MB total, 1000 files)")
            if hashlib.sha256(content).hexdigest() != item["sha256"]:
                raise ValueError("Source changed since inventory")
            target = snapshot / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            expected.add(relative)
        except (OSError, ValueError) as error:
            result.issues.append(f"{relative}: {error}")
    if not expected:
        result.issues.append("No supported source files available for static analysis")
        return result
    # Tool-owned config and cwd exclude repository ignore/config files and inline suppressions.
    config = artifact_dir / "rules.json"
    config.write_text(json.dumps({"rules": RULES}, indent=2), encoding="utf-8")
    result.artifacts.append(str(config))
    environment = dict(os.environ, SEMGREP_SEND_METRICS="off", SEMGREP_ENABLE_VERSION_CHECK="0")
    environment.pop("SEMGREP_APP_TOKEN", None)
    try:
        version = subprocess.run([str(executable), "--version"], capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=min(timeout, 15),
                                 env=environment, cwd=snapshot, shell=False)
        result.version = version.stdout.strip()
        if version.returncode or not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+].*)?", result.version):
            raise ValueError("Unexpected Semgrep version response")
        command = [str(executable), "scan", "--config", str(config), "--json", "--oss-only",
                   "--metrics=off", "--disable-version-check", "--disable-nosem", "--no-git-ignore", "--no-rewrite-rule-ids",
                   "--jobs", "1", "--timeout", "10", "--max-memory", "512",
                   "--max-target-bytes", "1000000", "."]
        process = subprocess.run(command, capture_output=True, text=True, encoding="utf-8",
                                 errors="replace", timeout=timeout, env=environment, cwd=snapshot, shell=False)
        raw, log = artifact_dir / "semgrep.json", artifact_dir / "semgrep.log"
        raw.write_text(process.stdout, encoding="utf-8")
        log.write_text(process.stderr, encoding="utf-8")
        result.artifacts.extend([str(raw), str(log)])
        if process.returncode != 0:
            raise ValueError(f"Semgrep exited {process.returncode}; see {log}")
        payload = json.loads(process.stdout)
        if not isinstance(payload.get("results"), list) or not isinstance(payload.get("errors"), list):
            raise ValueError("Invalid Semgrep result structure")
        if payload["errors"]:
            result.issues.append("Semgrep reported errors; inspect raw output")
        scanned = set()
        for name in payload.get("paths", {}).get("scanned", []):
            path = Path(name)
            relative = path.relative_to(snapshot).as_posix() if path.is_absolute() else path.as_posix().removeprefix("./")
            if relative in expected:
                scanned.add(relative)
        result.scanned_files = sorted(scanned)
        if expected - scanned:
            result.issues.append("Semgrep did not confirm scanning every selected source file")
        for entry in payload["results"]:
            path = Path(entry["path"])
            relative = path.relative_to(snapshot).as_posix() if path.is_absolute() else path.as_posix().removeprefix("./")
            if relative not in expected:
                raise ValueError("Semgrep returned a location outside selected source files")
            rule = next((rule for rule in RULES if entry["check_id"] == rule["id"] or entry["check_id"].endswith("." + rule["id"])), None)
            if rule is None:
                raise ValueError("Semgrep returned an unknown rule")
            start, end = entry["start"], entry["end"]
            if any(type(position.get(key)) is not int or position[key] < 1 for position in (start, end) for key in ("line", "col")):
                raise ValueError("Invalid Semgrep source position")
            identity = [rule["id"], relative, start["line"], start["col"], end["line"], end["col"]]
            fingerprint = hashlib.sha256(json.dumps(identity, separators=(",", ":")).encode()).hexdigest()
            result.findings.append(Finding(fingerprint, "static", "semgrep", result.version, "low",
                scanned_at, "static-warning", location=relative, severity=rule["severity"],
                severity_source="CVEFuzz rule", evidence=[{"rule_id": rule["id"], "rule_license": "CC0-1.0",
                "ruleset_version": "1", "engine_license": "LGPL-2.1", "start": start, "end": end,
                "message": rule["message"], "dataflow": entry.get("extra", {}).get("dataflow_trace")}],
                remediation="Review the evaluated value and replace dynamic evaluation when possible."))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, subprocess.TimeoutExpired) as error:
        result.issues.append(f"Static analyzer unavailable or incomplete: {error}")
    result.status = "incomplete" if result.issues else "completed"
    return result
