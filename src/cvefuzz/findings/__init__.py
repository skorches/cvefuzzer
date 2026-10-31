"""Versioned serialized contracts. Severity and confidence are independent."""

from dataclasses import asdict, dataclass, field
from typing import Literal

SCHEMA_VERSION = 1


@dataclass
class Component:
    name: str
    ecosystem: str
    version: str | None = None
    manifest: str | None = None
    dependency_path: list[str] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION


@dataclass
class Finding:
    fingerprint: str
    category: str
    tool: str
    tool_version: str
    confidence: str
    scanned_at: str
    evidence_kind: Literal["affected-version", "static-warning", "reachability", "reproduced-failure"]
    evidence: list[dict] = field(default_factory=list)
    location: str | None = None
    component: Component | None = None
    advisory_ids: list[str] = field(default_factory=list)
    severity: str | None = None
    severity_source: str | None = None
    remediation: str | None = None
    schema_version: int = SCHEMA_VERSION


@dataclass
class RunnerResult:
    runner: str
    status: Literal["completed", "skipped", "failed", "cancelled", "timed-out"]
    exit_code: int | None = None
    artifacts: list[str] = field(default_factory=list)
    reason: str | None = None
    schema_version: int = SCHEMA_VERSION


@dataclass
class Scan:
    scan_id: str
    root: str
    started_at: str
    finished_at: str
    content_identity: str
    status: str
    configuration: dict
    tool_versions: dict
    checks: list[dict]
    inventory: dict
    advisory_freshness: dict = field(default_factory=lambda: {"status": "not-fetched", "last_successful_refresh": None})
    artifacts: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self):
        return asdict(self)
