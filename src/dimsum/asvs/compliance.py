"""ASVS compliance analysis engine.

Analyzes scan findings against ASVS requirements to produce
compliance reports and gap analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ComplianceCheckResult:
    """Result of evaluating a single ASVS check."""

    asvs_id: str
    chapter: int
    section: str
    requirement: str
    level: int
    status: str  # pass, fail, partial, not_tested
    cwe_id: int | None = None
    tested_by: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "asvs_id": self.asvs_id,
            "chapter": self.chapter,
            "section": self.section,
            "requirement": self.requirement,
            "level": self.level,
            "status": self.status,
            "cwe_id": self.cwe_id,
            "tested_by": self.tested_by,
            "findings_count": len(self.findings),
        }


@dataclass
class ComplianceReport:
    """Aggregated compliance report."""

    asvs_level: int
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    not_tested: int = 0
    checks: list[ComplianceCheckResult] = field(default_factory=list)
    score_percent: float = 0.0

    def to_dict(self) -> dict:
        return {
            "asvs_level": self.asvs_level,
            "total_checks": self.total_checks,
            "passed": self.passed,
            "failed": self.failed,
            "partial": self.partial,
            "not_tested": self.not_tested,
            "score_percent": round(self.score_percent, 1),
            "chapter_summary": self._chapter_summary(),
            "checks": [c.to_dict() for c in self.checks],
        }

    def _chapter_summary(self) -> list[dict]:
        chapters: dict[int, dict] = {}
        for c in self.checks:
            if c.chapter not in chapters:
                chapters[c.chapter] = {"chapter": c.chapter, "total": 0, "passed": 0, "failed": 0, "not_tested": 0}
            chapters[c.chapter]["total"] += 1
            if c.status == "pass":
                chapters[c.chapter]["passed"] += 1
            elif c.status in ("fail", "partial"):
                chapters[c.chapter]["failed"] += 1
            else:
                chapters[c.chapter]["not_tested"] += 1
        return sorted(chapters.values(), key=lambda x: x["chapter"])


def analyze_compliance(
    asvs_checks: list[dict],
    scan_findings: list[dict],
    asvs_level: int = 1,
) -> ComplianceReport:
    """Analyze scan findings against ASVS checks.

    Args:
        asvs_checks: List of ASVS check dicts from the DB.
        scan_findings: List of finding dicts from the scan.
        asvs_level: ASVS level (1, 2, or 3). Only checks at or below this level are included.

    Returns:
        ComplianceReport with pass/fail/not_tested status for each check.
    """
    report = ComplianceReport(asvs_level=asvs_level)

    # Index findings by plugin_id and CWE
    findings_by_plugin: dict[str, list[dict]] = {}
    findings_by_cwe: dict[int, list[dict]] = {}

    for f in scan_findings:
        pid = f.get("plugin_id", "")
        findings_by_plugin.setdefault(pid, []).append(f)
        cwe = f.get("cwe_id")
        if cwe:
            findings_by_cwe.setdefault(cwe, []).append(f)

    for check in asvs_checks:
        check_level = check.get("level", 1)
        if check_level > asvs_level:
            continue

        asvs_id = check["asvs_id"]
        plugin_ids = check.get("plugin_ids", [])
        can_be_automated = check.get("can_be_automated", False)
        cwe_id = check.get("cwe_id")

        # Determine which plugins tested this check
        tested_by = [pid for pid in plugin_ids if pid in findings_by_plugin or pid in _all_plugin_ids(scan_findings)]

        # Collect relevant findings
        related_findings = []
        for pid in plugin_ids:
            related_findings.extend(findings_by_plugin.get(pid, []))
        # Also match by CWE ID
        if cwe_id and cwe_id in findings_by_cwe:
            for f in findings_by_cwe[cwe_id]:
                if f not in related_findings:
                    related_findings.append(f)

        # Determine status
        if not can_be_automated and not plugin_ids:
            status = "not_tested"
        elif not tested_by and not related_findings:
            if can_be_automated and plugin_ids:
                # Plugins exist but weren't run or found nothing → assume pass
                status = "pass"
            else:
                status = "not_tested"
        elif related_findings:
            # Findings exist with matching severity
            high_sev = any(
                f.get("severity") in ("critical", "high") for f in related_findings
            )
            if high_sev:
                status = "fail"
            else:
                status = "partial"
        else:
            # Plugins ran but found no issues → pass
            status = "pass"

        result = ComplianceCheckResult(
            asvs_id=asvs_id,
            chapter=check.get("chapter", 0),
            section=check.get("section", ""),
            requirement=check.get("requirement", ""),
            level=check_level,
            status=status,
            cwe_id=cwe_id,
            tested_by=tested_by,
            findings=related_findings,
        )
        report.checks.append(result)

    report.total_checks = len(report.checks)
    report.passed = sum(1 for c in report.checks if c.status == "pass")
    report.failed = sum(1 for c in report.checks if c.status == "fail")
    report.partial = sum(1 for c in report.checks if c.status == "partial")
    report.not_tested = sum(1 for c in report.checks if c.status == "not_tested")

    testable = report.total_checks - report.not_tested
    if testable > 0:
        report.score_percent = (report.passed / testable) * 100
    else:
        report.score_percent = 0.0

    return report


def _all_plugin_ids(findings: list[dict]) -> set[str]:
    """Get the set of all plugin IDs that produced findings."""
    return {f.get("plugin_id", "") for f in findings}
