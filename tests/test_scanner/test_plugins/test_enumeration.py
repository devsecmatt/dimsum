"""Tests for enumeration plugins (Phase 5)."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest

from dimsum.scanner.context import ScanContext
from dimsum.scanner.http_client import HTTPResponse
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Severity


def _make_response(
    url: str = "http://example.com",
    status_code: int = 200,
    text: str = "",
    headers: dict | None = None,
) -> HTTPResponse:
    return HTTPResponse(
        status_code=status_code,
        headers=headers or {"content-type": "text/html"},
        text=text,
        url=url,
        elapsed_ms=50.0,
        request_method="GET",
        request_url=url,
        request_headers={},
    )


@pytest.fixture(autouse=True)
def discover_plugins():
    PluginRegistry.discover_plugins()


class TestWebCrawler:
    def _get_plugin_cls(self):
        return PluginRegistry.get("web_crawler")

    @pytest.mark.asyncio
    async def test_discovers_links(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
            max_depth=1,
        )
        http = AsyncMock()
        html = '''
        <html>
        <body>
            <a href="/about">About</a>
            <a href="/contact">Contact</a>
            <a href="https://external.com/page">External</a>
        </body>
        </html>
        '''
        http.get = AsyncMock(side_effect=[
            _make_response("http://example.com", text=html),
            _make_response("http://example.com/about", text="<html><body>About</body></html>"),
            _make_response("http://example.com/contact", text="<html><body>Contact</body></html>"),
        ])

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        assert len(ctx.discovered_endpoints) >= 2
        assert "http://example.com/about" in ctx.discovered_endpoints
        assert "http://example.com/contact" in ctx.discovered_endpoints
        # External links should be excluded
        assert "https://external.com/page" not in ctx.discovered_endpoints

    @pytest.mark.asyncio
    async def test_extracts_forms(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
            max_depth=0,
        )
        http = AsyncMock()
        html = '''
        <html><body>
        <form action="/search" method="GET">
            <input name="q" type="text" />
            <input name="category" type="hidden" value="all" />
        </form>
        </body></html>
        '''
        http.get = AsyncMock(return_value=_make_response("http://example.com", text=html))

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        await plugin.run()

        assert "http://example.com/search" in ctx.discovered_endpoints
        forms = ctx.shared_data.get("discovered_forms", [])
        assert len(forms) == 1
        assert "q" in forms[0]["params"]

    @pytest.mark.asyncio
    async def test_respects_max_depth(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
            max_depth=0,
        )
        http = AsyncMock()
        html = '<html><body><a href="/page2">Link</a></body></html>'
        http.get = AsyncMock(return_value=_make_response("http://example.com", text=html))

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        await plugin.run()

        # /page2 should be discovered but not crawled (depth 1 > max 0)
        assert "http://example.com/page2" in ctx.discovered_endpoints


class TestDirBruteForce:
    def _get_plugin_cls(self):
        return PluginRegistry.get("dir_bruteforce")

    @pytest.mark.asyncio
    async def test_finds_exposed_files(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com/app"],
        )
        http = AsyncMock()

        not_found_body = "Not found"

        async def mock_get(url, **kwargs):
            if ".env" in url:
                env_content = (
                    "DB_HOST=localhost\nDB_PORT=5432\nDB_USER=admin\n"
                    "DB_PASSWORD=super_secret_password_123\n"
                    "SECRET_KEY=abc123def456ghi789\nREDIS_URL=redis://localhost:6379\n"
                    "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\nAWS_SECRET_KEY=wJalrXUtnFEMI\n"
                )
                return _make_response(url, status_code=200, text=env_content)
            if "robots.txt" in url:
                robots_content = (
                    "User-agent: *\nDisallow: /admin\nDisallow: /private\n"
                    "Disallow: /api/internal\nSitemap: http://example.com/sitemap.xml\n"
                    "Sitemap: http://example.com/sitemap-pages.xml\n"
                )
                return _make_response(url, status_code=200, text=robots_content)
            if "nonexistent" in url:
                return _make_response(url, status_code=404, text=not_found_body)
            return _make_response(url, status_code=404, text=not_found_body)

        http.get = AsyncMock(side_effect=mock_get)

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        env_findings = [f for f in findings if ".env" in f.url]
        assert len(env_findings) >= 1
        assert env_findings[0].severity == Severity.HIGH

    @pytest.mark.asyncio
    async def test_filters_soft_404s(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
        )
        soft_404_body = "Sorry, page not found. " * 10
        http = AsyncMock()

        async def mock_get(url, **kwargs):
            return _make_response(url, status_code=200, text=soft_404_body)

        http.get = AsyncMock(side_effect=mock_get)

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        # All should be filtered as soft-404s
        assert len(findings) == 0


class TestTechFingerprint:
    def _get_plugin_cls(self):
        return PluginRegistry.get("tech_fingerprint")

    @pytest.mark.asyncio
    async def test_detects_from_headers(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
        )
        http = AsyncMock()
        http.get = AsyncMock(return_value=_make_response(
            "http://example.com",
            text="<html><body>Hello</body></html>",
            headers={
                "content-type": "text/html",
                "server": "nginx/1.24.0",
                "x-powered-by": "Express",
            },
        ))

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        assert len(findings) == 1
        assert "Nginx" in findings[0].title
        assert "Express" in findings[0].title

    @pytest.mark.asyncio
    async def test_detects_from_body(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
        )
        http = AsyncMock()
        html = '''
        <html>
        <head><meta name="generator" content="WordPress 6.4" /></head>
        <body><link href="/wp-content/themes/default/style.css" /></body>
        </html>
        '''
        http.get = AsyncMock(return_value=_make_response(
            "http://example.com",
            text=html,
            headers={"content-type": "text/html"},
        ))

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        assert len(findings) == 1
        assert "WordPress" in findings[0].title

    @pytest.mark.asyncio
    async def test_detects_from_cookies(self):
        ctx = ScanContext(
            scan_id=uuid.uuid4(),
            target_urls=["http://example.com"],
        )
        http = AsyncMock()
        http.get = AsyncMock(return_value=_make_response(
            "http://example.com",
            text="<html></html>",
            headers={
                "content-type": "text/html",
                "set-cookie": "PHPSESSID=abc123; path=/",
            },
        ))

        pcls = self._get_plugin_cls()
        plugin = pcls(ctx, http)
        findings = await plugin.run()

        assert len(findings) == 1
        assert "PHP" in findings[0].title
