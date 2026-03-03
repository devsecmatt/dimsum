from __future__ import annotations

import enum
from dataclasses import dataclass, field


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, enum.Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass
class ScanFinding:
    """Intermediate finding produced by a scan plugin before DB persistence."""

    plugin_id: str
    title: str
    description: str
    severity: Severity
    confidence: Confidence
    url: str
    method: str | None = None
    parameter: str | None = None
    payload: str | None = None
    evidence: str | None = None
    request_dump: str | None = None
    response_dump: str | None = None
    cwe_id: int | None = None
    cvss_score: float | None = None
    remediation: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    asvs_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "plugin_id": self.plugin_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "url": self.url,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.payload,
            "evidence": self.evidence,
            "request_dump": self.request_dump,
            "response_dump": self.response_dump,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "remediation": self.remediation,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "asvs_ids": self.asvs_ids,
        }
