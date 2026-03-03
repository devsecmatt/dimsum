"""Tests for ASVS compliance engine and seeder (Phase 9)."""

from __future__ import annotations

import pytest

from dimsum.asvs.compliance import analyze_compliance, ComplianceReport
from dimsum.asvs.seeder import ASVS_CHECKS, seed_asvs_checks
from dimsum.models.asvs_check import ASVSCheck


SAMPLE_CHECKS = [
    {
        "asvs_id": "V5.3.7",
        "chapter": 5,
        "section": "5.3",
        "requirement": "Verify that the application is not vulnerable to SQL Injection.",
        "level": 1,
        "cwe_id": 89,
        "can_be_automated": True,
        "plugin_ids": ["sqli_error"],
    },
    {
        "asvs_id": "V14.4.3",
        "chapter": 14,
        "section": "14.4",
        "requirement": "Verify that a Content-Security-Policy response header is in place.",
        "level": 1,
        "cwe_id": 693,
        "can_be_automated": True,
        "plugin_ids": ["security_headers"],
    },
    {
        "asvs_id": "V2.1.1",
        "chapter": 2,
        "section": "2.1",
        "requirement": "Verify that user set passwords are at least 12 characters in length.",
        "level": 1,
        "cwe_id": 521,
        "can_be_automated": False,
        "plugin_ids": [],
    },
    {
        "asvs_id": "V9.1.2",
        "chapter": 9,
        "section": "9.1",
        "requirement": "Verify using up to date TLS testing tools that only strong cipher suites are enabled.",
        "level": 2,
        "cwe_id": 326,
        "can_be_automated": True,
        "plugin_ids": ["tls_crypto"],
    },
]


class TestComplianceAnalysis:
    def test_no_findings_all_pass(self):
        report = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=1)
        # Non-automatable checks with no plugins → not_tested
        # Automatable checks with plugins that found nothing → pass
        assert report.total_checks == 3  # V9.1.2 is level 2, excluded
        assert report.passed >= 1
        assert isinstance(report, ComplianceReport)

    def test_findings_cause_failures(self):
        findings = [
            {
                "plugin_id": "sqli_error",
                "severity": "critical",
                "cwe_id": 89,
                "title": "SQL Injection found",
                "url": "http://example.com",
            },
        ]
        report = analyze_compliance(SAMPLE_CHECKS, findings, asvs_level=1)
        sqli_check = next(c for c in report.checks if c.asvs_id == "V5.3.7")
        assert sqli_check.status == "fail"

    def test_low_severity_causes_partial(self):
        findings = [
            {
                "plugin_id": "security_headers",
                "severity": "low",
                "cwe_id": 693,
                "title": "Missing CSP header",
                "url": "http://example.com",
            },
        ]
        report = analyze_compliance(SAMPLE_CHECKS, findings, asvs_level=1)
        csp_check = next(c for c in report.checks if c.asvs_id == "V14.4.3")
        assert csp_check.status == "partial"

    def test_non_automatable_is_not_tested(self):
        report = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=1)
        password_check = next(c for c in report.checks if c.asvs_id == "V2.1.1")
        assert password_check.status == "not_tested"

    def test_level_filtering(self):
        report_l1 = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=1)
        report_l2 = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=2)
        assert report_l2.total_checks > report_l1.total_checks

    def test_score_calculation(self):
        findings = [
            {
                "plugin_id": "sqli_error",
                "severity": "high",
                "cwe_id": 89,
                "title": "SQLi",
                "url": "http://example.com",
            },
        ]
        report = analyze_compliance(SAMPLE_CHECKS, findings, asvs_level=1)
        # Some checks pass, one fails, one not tested
        assert 0 <= report.score_percent <= 100

    def test_cwe_matching(self):
        findings = [
            {
                "plugin_id": "unknown_plugin",
                "severity": "high",
                "cwe_id": 89,
                "title": "SQL Injection via CWE match",
                "url": "http://example.com",
            },
        ]
        report = analyze_compliance(SAMPLE_CHECKS, findings, asvs_level=1)
        sqli_check = next(c for c in report.checks if c.asvs_id == "V5.3.7")
        assert sqli_check.status == "fail"  # Matched by CWE ID

    def test_to_dict(self):
        report = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=1)
        d = report.to_dict()
        assert "asvs_level" in d
        assert "total_checks" in d
        assert "passed" in d
        assert "failed" in d
        assert "not_tested" in d
        assert "score_percent" in d
        assert "chapter_summary" in d
        assert "checks" in d

    def test_chapter_summary(self):
        report = analyze_compliance(SAMPLE_CHECKS, [], asvs_level=1)
        d = report.to_dict()
        chapters = d["chapter_summary"]
        assert isinstance(chapters, list)
        assert all("chapter" in ch and "total" in ch for ch in chapters)


class TestASVSSeeder:
    def test_seed_data_valid(self):
        for check in ASVS_CHECKS:
            assert len(check) == 8
            asvs_id, chapter, section, req, level, cwe, automated, plugins = check
            assert asvs_id.startswith("V")
            assert isinstance(chapter, int) and chapter > 0
            assert isinstance(level, int) and 1 <= level <= 3
            assert isinstance(automated, bool)
            assert isinstance(plugins, list)

    def test_seed_creates_records(self, app, db):
        with app.app_context():
            count = seed_asvs_checks()
            assert count > 0

            checks = db.session.execute(
                db.select(ASVSCheck)
            ).scalars().all()
            assert len(checks) == count

    def test_seed_idempotent(self, app, db):
        with app.app_context():
            count1 = seed_asvs_checks()
            count2 = seed_asvs_checks()
            assert count1 > 0
            assert count2 == 0

    def test_plugin_id_mappings(self):
        """Verify plugin IDs in ASVS checks refer to known plugins."""
        known_plugins = {
            "reflected_xss", "sqli_error", "command_injection",
            "security_headers", "cors_misconfig", "broken_auth",
            "tls_crypto", "ssrf", "web_crawler", "dir_bruteforce",
            "tech_fingerprint",
        }
        for check in ASVS_CHECKS:
            for pid in check[7]:
                assert pid in known_plugins, f"Unknown plugin '{pid}' in {check[0]}"
