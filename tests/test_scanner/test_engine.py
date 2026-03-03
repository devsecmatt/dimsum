"""Tests for the scan engine orchestration (Phase 10 - integration tests)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from dimsum.scanner.context import ScanContext
from dimsum.scanner.engine import ScanEngine
from dimsum.scanner.http_client import HTTPResponse
from dimsum.scanner.registry import PluginRegistry


def _make_response(url="http://example.com", status_code=200, text="", headers=None):
    return HTTPResponse(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
        url=url,
        elapsed_ms=10.0,
        request_method="GET",
        request_url=url,
        request_headers={},
    )


@pytest.fixture(autouse=True)
def discover_plugins():
    PluginRegistry.discover_plugins()


class TestScanEngine:
    @pytest.mark.asyncio
    async def test_select_plugins_full_scan(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), scan_type="full")
        engine = ScanEngine(ctx)
        enum_plugins, security_plugins = engine._select_plugins()
        assert len(enum_plugins) >= 3  # crawler, dir_bruteforce, tech_fingerprint
        assert len(security_plugins) >= 8  # 8 OWASP plugins

    @pytest.mark.asyncio
    async def test_select_plugins_quick_scan(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), scan_type="quick")
        engine = ScanEngine(ctx)
        enum_plugins, security_plugins = engine._select_plugins()
        assert len(enum_plugins) == 0  # No enumeration in quick scan
        assert len(security_plugins) >= 8

    @pytest.mark.asyncio
    async def test_select_plugins_source_only(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), scan_type="source_only")
        engine = ScanEngine(ctx)
        enum_plugins, security_plugins = engine._select_plugins()
        assert len(enum_plugins) == 0
        assert len(security_plugins) == 0

    @pytest.mark.asyncio
    async def test_select_specific_plugins(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            scan_type="full",
            enabled_plugin_ids=["reflected_xss", "sqli_error"],
        )
        engine = ScanEngine(ctx)
        enum_plugins, security_plugins = engine._select_plugins()
        assert len(security_plugins) == 2
        plugin_ids = {p.meta.plugin_id for p in security_plugins}
        assert "reflected_xss" in plugin_ids
        assert "sqli_error" in plugin_ids

    @pytest.mark.asyncio
    async def test_deduplication(self):
        from dimsum.scanner.result import Confidence, ScanFinding, Severity

        findings = [
            ScanFinding(plugin_id="xss", title="XSS", description="desc", severity=Severity.HIGH, confidence=Confidence.CONFIRMED, url="http://example.com", parameter="q", payload="<script>"),
            ScanFinding(plugin_id="xss", title="XSS", description="desc", severity=Severity.HIGH, confidence=Confidence.CONFIRMED, url="http://example.com", parameter="q", payload="<script>"),
            ScanFinding(plugin_id="xss", title="XSS", description="desc", severity=Severity.HIGH, confidence=Confidence.CONFIRMED, url="http://example.com", parameter="q", payload="<img>"),
        ]
        unique = ScanEngine._deduplicate(findings)
        assert len(unique) == 2  # Two unique payloads

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), scan_type="full", target_urls=["http://example.com"])
        progress_calls = []

        def callback(pct, msg):
            progress_calls.append((pct, msg))

        engine = ScanEngine(ctx, progress_callback=callback)
        engine._report_progress(50, "halfway")
        assert len(progress_calls) == 1
        assert progress_calls[0] == (50, "halfway")


class TestPluginRegistry:
    def test_all_plugins_registered(self):
        PluginRegistry.discover_plugins()
        all_plugins = PluginRegistry.get_all()
        expected = {
            "web_crawler", "dir_bruteforce", "tech_fingerprint",
            "reflected_xss", "sqli_error", "command_injection",
            "security_headers", "cors_misconfig", "broken_auth",
            "tls_crypto", "ssrf",
        }
        assert expected.issubset(set(all_plugins.keys())), f"Missing: {expected - set(all_plugins.keys())}"

    def test_enumeration_plugins(self):
        PluginRegistry.discover_plugins()
        enum = PluginRegistry.get_enumeration_plugins()
        ids = {p.meta.plugin_id for p in enum}
        assert "web_crawler" in ids
        assert "dir_bruteforce" in ids
        assert "tech_fingerprint" in ids

    def test_security_plugins(self):
        PluginRegistry.discover_plugins()
        sec = PluginRegistry.get_security_plugins()
        ids = {p.meta.plugin_id for p in sec}
        assert "reflected_xss" in ids
        assert "sqli_error" in ids

    def test_list_info(self):
        PluginRegistry.discover_plugins()
        info = PluginRegistry.list_info()
        assert len(info) >= 11
        for item in info:
            assert "plugin_id" in item
            assert "name" in item
            assert "category" in item

    def test_get_by_category(self):
        PluginRegistry.discover_plugins()
        injection = PluginRegistry.get_by_category("injection")
        assert len(injection) >= 3  # XSS, SQLi, CMDi


class TestScanContext:
    def test_all_urls(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://a.com", "http://b.com"],
            discovered_endpoints=["http://a.com/page1", "http://c.com"],
        )
        all_urls = ctx.all_urls
        assert len(all_urls) == 4
        assert "http://a.com" in all_urls
        assert "http://c.com" in all_urls

    def test_add_discovered_endpoint_dedup(self):
        ctx = ScanContext(scan_id=uuid.uuid4())
        ctx.add_discovered_endpoint("http://a.com")
        ctx.add_discovered_endpoint("http://a.com")
        assert len(ctx.discovered_endpoints) == 1

    def test_progress_percent(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), total_checks=10, completed_checks=5)
        assert ctx.progress_percent == 50

    def test_progress_zero_total(self):
        ctx = ScanContext(scan_id=uuid.uuid4(), total_checks=0, completed_checks=0)
        assert ctx.progress_percent == 0
