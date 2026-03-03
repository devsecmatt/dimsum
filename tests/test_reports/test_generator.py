"""Tests for the report generation engine (Phase 8)."""

from __future__ import annotations

import csv
import io
import json

import pytest

from dimsum.reports.generator import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)

SAMPLE_SCAN = {
    "scan_id": "12345678-1234-1234-1234-123456789abc",
    "project_id": "abcdefab-abcd-abcd-abcd-abcdefabcdef",
    "status": "completed",
    "scan_type": "full",
    "started_at": "2026-03-01T10:00:00+00:00",
    "completed_at": "2026-03-01T10:05:00+00:00",
    "duration_seconds": 300,
    "total_requests": 150,
    "summary_stats": {},
}

SAMPLE_FINDINGS = [
    {
        "id": "f1",
        "plugin_id": "reflected_xss",
        "title": "Reflected XSS in 'q' parameter",
        "description": "The parameter 'q' reflects user input without sanitization.",
        "severity": "high",
        "confidence": "confirmed",
        "url": "https://example.com/search?q=test",
        "method": "GET",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "...<script>alert(1)</script>...",
        "cwe_id": 79,
        "cvss_score": 6.1,
        "remediation": "Encode user input before output.",
    },
    {
        "id": "f2",
        "plugin_id": "security_headers",
        "title": "Missing Content-Security-Policy header",
        "description": "CSP header is missing.",
        "severity": "medium",
        "confidence": "confirmed",
        "url": "https://example.com/",
        "method": "GET",
        "parameter": None,
        "payload": None,
        "evidence": None,
        "cwe_id": 693,
        "cvss_score": None,
        "remediation": "Implement a Content-Security-Policy header.",
    },
    {
        "id": "f3",
        "plugin_id": "dir_bruteforce",
        "title": "Environment file exposed",
        "description": ".env file is accessible.",
        "severity": "critical",
        "confidence": "confirmed",
        "url": "https://example.com/.env",
        "method": "GET",
        "parameter": None,
        "payload": None,
        "evidence": "DB_PASSWORD=secret",
        "cwe_id": 538,
        "cvss_score": 7.5,
        "remediation": "Restrict access to .env files.",
    },
]


class TestJSONReport:
    def test_valid_json(self):
        output = generate_json_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        assert "report_metadata" in data
        assert "scan" in data
        assert "summary" in data
        assert "findings" in data

    def test_metadata(self):
        output = generate_json_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        meta = data["report_metadata"]
        assert meta["generator"] == "dimsum"
        assert meta["format"] == "json"
        assert "generated_at" in meta

    def test_summary_counts(self):
        output = generate_json_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        summary = data["summary"]
        assert summary["total"] == 3
        assert summary["severity_counts"]["high"] == 1
        assert summary["severity_counts"]["medium"] == 1
        assert summary["severity_counts"]["critical"] == 1

    def test_findings_included(self):
        output = generate_json_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        assert len(data["findings"]) == 3

    def test_empty_findings(self):
        output = generate_json_report(SAMPLE_SCAN, [])
        data = json.loads(output)
        assert data["summary"]["total"] == 0
        assert data["findings"] == []


class TestCSVReport:
    def test_valid_csv(self):
        output = generate_csv_report(SAMPLE_FINDINGS)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 3

    def test_headers(self):
        output = generate_csv_report(SAMPLE_FINDINGS)
        reader = csv.DictReader(io.StringIO(output))
        fields = reader.fieldnames
        assert "title" in fields
        assert "severity" in fields
        assert "url" in fields
        assert "cwe_id" in fields

    def test_data_content(self):
        output = generate_csv_report(SAMPLE_FINDINGS)
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert rows[0]["title"] == "Reflected XSS in 'q' parameter"
        assert rows[0]["severity"] == "high"

    def test_empty_findings(self):
        output = generate_csv_report([])
        reader = csv.DictReader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 0


class TestSARIFReport:
    def test_valid_sarif_structure(self):
        output = generate_sarif_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_tool_info(self):
        output = generate_sarif_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        tool = data["runs"][0]["tool"]["driver"]
        assert tool["name"] == "dimsum"
        assert len(tool["rules"]) >= 1

    def test_results(self):
        output = generate_sarif_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        assert len(results) == 3

    def test_severity_mapping(self):
        output = generate_sarif_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        results = data["runs"][0]["results"]
        levels = {r["ruleId"]: r["level"] for r in results}
        assert levels["reflected_xss"] == "error"  # high -> error
        assert levels["security_headers"] == "warning"  # medium -> warning
        assert levels["dir_bruteforce"] == "error"  # critical -> error

    def test_cwe_tags(self):
        output = generate_sarif_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        data = json.loads(output)
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        xss_rule = [r for r in rules if r["id"] == "reflected_xss"][0]
        assert "CWE-79" in xss_rule["properties"]["tags"]

    def test_empty_findings(self):
        output = generate_sarif_report(SAMPLE_SCAN, [])
        data = json.loads(output)
        assert len(data["runs"][0]["results"]) == 0


class TestHTMLReport:
    def test_valid_html(self):
        output = generate_html_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        assert "<!DOCTYPE html>" in output
        assert "<html" in output
        assert "</html>" in output

    def test_contains_findings(self):
        output = generate_html_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        assert "Reflected XSS" in output
        assert "Content-Security-Policy" in output
        assert "Environment file exposed" in output

    def test_contains_summary(self):
        output = generate_html_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        assert "Executive Summary" in output
        assert "Total Findings" in output

    def test_html_escaping(self):
        findings = [{
            "id": "x1",
            "plugin_id": "test",
            "title": "<script>alert('xss')</script>",
            "description": "Test & verify < escaping >",
            "severity": "high",
            "confidence": "confirmed",
            "url": "http://example.com",
            "method": "GET",
        }]
        output = generate_html_report(SAMPLE_SCAN, findings)
        assert "<script>alert" not in output
        assert "&lt;script&gt;" in output
        assert "&amp;" in output

    def test_empty_findings(self):
        output = generate_html_report(SAMPLE_SCAN, [])
        assert "No findings" in output

    def test_severity_colors(self):
        output = generate_html_report(SAMPLE_SCAN, SAMPLE_FINDINGS)
        assert "#dc2626" in output  # critical color
        assert "#ea580c" in output  # high color
