"""End-to-end integration tests tying all phases together (Phase 10)."""

from __future__ import annotations

import json

import pytest

from dimsum.asvs.compliance import analyze_compliance
from dimsum.asvs.seeder import ASVS_CHECKS
from dimsum.reports.generator import (
    generate_csv_report,
    generate_html_report,
    generate_json_report,
    generate_sarif_report,
)
from dimsum.scanner.registry import PluginRegistry
from dimsum.source_analysis.analyzer import analyze_source


@pytest.fixture(autouse=True)
def discover_plugins():
    PluginRegistry.discover_plugins()


class TestEndToEndFlow:
    """Tests that simulate a complete dimsum workflow."""

    def test_source_analysis_feeds_compliance(self):
        """Source analysis risk indicators → mock findings → compliance report."""
        code = """
app.get('/api/users', (req, res) => {
    const name = req.query.name;
    const query = "SELECT * FROM users WHERE name = " + req.body.name;
    res.send(eval(userInput));
});
"""
        analysis = analyze_source(code, "server.js")

        # Verify source analysis extracted useful data
        assert len(analysis.routes) >= 1
        assert len(analysis.parameters) >= 1
        assert len(analysis.risk_indicators) >= 2  # SQL concat + eval

        # Convert risk indicators to "mock findings" for compliance check
        mock_findings = []
        for ri in analysis.risk_indicators:
            mock_findings.append({
                "plugin_id": "source_analysis",
                "severity": ri.severity,
                "cwe_id": ri.cwe_id,
                "title": ri.description,
                "url": f"file://{ri.file}",
            })

        # Run compliance check with those findings
        checks = [
            {
                "asvs_id": c[0], "chapter": c[1], "section": c[2],
                "requirement": c[3], "level": c[4], "cwe_id": c[5],
                "can_be_automated": c[6], "plugin_ids": c[7],
            }
            for c in ASVS_CHECKS
        ]
        report = analyze_compliance(checks, mock_findings, asvs_level=1)

        # SQL injection check (CWE-89) should fail due to sql_string_concat finding
        sqli_check = next((c for c in report.checks if c.asvs_id == "V5.3.7"), None)
        assert sqli_check is not None
        assert sqli_check.status == "fail"

    def test_findings_to_all_report_formats(self):
        """Verify all report formats work with the same finding data."""
        scan_data = {
            "scan_id": "test-scan-123",
            "status": "completed",
            "scan_type": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "completed_at": "2026-03-01T10:05:00Z",
            "duration_seconds": 300,
        }
        findings = [
            {
                "plugin_id": "reflected_xss",
                "title": "XSS in search",
                "description": "Reflected XSS found.",
                "severity": "high",
                "confidence": "confirmed",
                "url": "http://example.com/search?q=test",
                "method": "GET",
                "parameter": "q",
                "cwe_id": 79,
                "remediation": "Encode output.",
            },
        ]

        # JSON
        json_report = generate_json_report(scan_data, findings)
        data = json.loads(json_report)
        assert data["summary"]["total"] == 1

        # CSV
        csv_report = generate_csv_report(findings)
        assert "reflected_xss" in csv_report
        assert "XSS in search" in csv_report

        # SARIF
        sarif_report = generate_sarif_report(scan_data, findings)
        sarif = json.loads(sarif_report)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"][0]["results"]) == 1

        # HTML
        html_report = generate_html_report(scan_data, findings)
        assert "XSS in search" in html_report
        assert "<!DOCTYPE html>" in html_report

    def test_plugin_registry_completeness(self):
        """All registered plugins have required metadata."""
        all_plugins = PluginRegistry.get_all()
        assert len(all_plugins) >= 11

        for pid, pcls in all_plugins.items():
            meta = pcls.meta
            assert meta.plugin_id == pid
            assert meta.name, f"Plugin {pid} missing name"
            assert meta.category, f"Plugin {pid} missing category"
            assert meta.description, f"Plugin {pid} missing description"

    def test_asvs_coverage_of_plugins(self):
        """Every plugin_id referenced in ASVS checks exists in the registry."""
        all_plugins = PluginRegistry.get_all()
        for check in ASVS_CHECKS:
            for pid in check[7]:  # plugin_ids
                assert pid in all_plugins, f"ASVS check {check[0]} references unknown plugin '{pid}'"

    def test_source_analysis_multiple_frameworks(self):
        """Analyze code using multiple frameworks at once."""
        js_code = """
const express = require('express');
const app = express();
app.get('/api/data', (req, res) => {
    const id = req.query.id;
    fetch('/api/backend');
});
"""
        py_code = """
from flask import Flask, request
app = Flask(__name__)

@app.route('/users', methods=['GET', 'POST'])
def users():
    name = request.args.get('name')
    return 'ok'
"""
        js_result = analyze_source(js_code, "server.js")
        py_result = analyze_source(py_code, "app.py")

        assert len(js_result.routes) >= 2  # app.get + fetch
        assert len(js_result.parameters) >= 1  # req.query.id
        assert len(py_result.routes) >= 2  # GET + POST
        assert len(py_result.parameters) >= 1  # request.args.get('name')

    def test_compliance_score_improves_without_findings(self):
        """Score should be higher when there are no findings (everything passes)."""
        checks = [
            {
                "asvs_id": c[0], "chapter": c[1], "section": c[2],
                "requirement": c[3], "level": c[4], "cwe_id": c[5],
                "can_be_automated": c[6], "plugin_ids": c[7],
            }
            for c in ASVS_CHECKS
        ]

        # With findings (failures)
        bad_findings = [
            {"plugin_id": "sqli_error", "severity": "critical", "cwe_id": 89, "title": "SQLi", "url": "http://ex.com"},
            {"plugin_id": "reflected_xss", "severity": "high", "cwe_id": 79, "title": "XSS", "url": "http://ex.com"},
            {"plugin_id": "security_headers", "severity": "medium", "cwe_id": 693, "title": "Headers", "url": "http://ex.com"},
        ]
        bad_report = analyze_compliance(checks, bad_findings, asvs_level=1)

        # Without findings (all pass)
        good_report = analyze_compliance(checks, [], asvs_level=1)

        assert good_report.score_percent >= bad_report.score_percent

    def test_source_analysis_generates_fuzz_targets(self):
        """Source analysis extracts params that can be used as fuzz targets."""
        code = """
const express = require('express');
const app = express();
app.post('/api/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const token = req.query.token;
    res.json({ok: true});
});
app.get('/api/search', (req, res) => {
    const q = req.query.q;
    const page = req.query.page;
});
"""
        analysis = analyze_source(code, "server.js")

        # Source analysis should extract parameters
        param_names = {p.name for p in analysis.parameters}
        assert "username" in param_names or "q" in param_names

        # Convert to the format ScanContext expects
        extracted_params = [
            {"name": p.name, "source": p.source, "file": p.file, "line": p.line}
            for p in analysis.parameters
        ]

        # These should be usable by injection plugins via context
        from dimsum.scanner.context import ScanContext
        ctx = ScanContext(
            scan_id=__import__("uuid").uuid4(),
            target_urls=["http://example.com"],
            extracted_parameters=extracted_params,
        )

        assert len(ctx.extracted_parameters) >= 2

        # Extracted routes become discovered endpoints
        extracted_routes = [
            {"path": r.path, "method": r.method, "framework": r.framework}
            for r in analysis.routes
        ]
        base = ctx.target_urls[0].rstrip("/")
        for route in extracted_routes:
            path = route.get("path", "")
            if path.startswith("/"):
                ctx.add_discovered_endpoint(f"{base}{path}")

        assert "http://example.com/api/login" in ctx.discovered_endpoints
        assert "http://example.com/api/search" in ctx.discovered_endpoints
