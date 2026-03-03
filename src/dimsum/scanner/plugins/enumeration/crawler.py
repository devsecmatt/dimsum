"""Web Crawler / Spider Plugin.

Discovers links, forms, and endpoints by crawling web pages starting
from the target URLs.  Discovered endpoints are added to the scan context
so that subsequent security plugins can test them.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


_LINK_ATTRS = re.compile(
    r'''(?:href|src|action|data-url)\s*=\s*["']([^"'#]+)["']''',
    re.IGNORECASE,
)
_FORM_ACTION = re.compile(
    r'''<form[^>]*\saction\s*=\s*["']([^"'#]+)["']''',
    re.IGNORECASE,
)
_FORM_METHOD = re.compile(
    r'''<form[^>]*\smethod\s*=\s*["'](\w+)["']''',
    re.IGNORECASE,
)
_INPUT_NAME = re.compile(
    r'''<input[^>]*\sname\s*=\s*["']([^"']+)["']''',
    re.IGNORECASE,
)


@PluginRegistry.register(
    "web_crawler",
    name="Web Crawler / Spider",
    category="enumeration",
    owasp_category=None,
    description=(
        "Crawls target web pages to discover links, forms, and additional "
        "endpoints for security testing."
    ),
    is_enumeration=True,
)
class WebCrawlerPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        visited: set[str] = set()
        queue: list[str] = list(self.context.target_urls)
        max_depth = self.context.max_depth
        allowed_domains = self._get_allowed_domains()

        depth_map: dict[str, int] = {url: 0 for url in queue}

        while queue:
            url = queue.pop(0)
            normalized = self._normalize_url(url)
            if normalized in visited:
                continue
            visited.add(normalized)

            current_depth = depth_map.get(url, 0)
            if current_depth > max_depth:
                continue

            resp = await self.http.get(url)
            if resp is None:
                continue

            content_type = resp.header("content-type", "")
            if "text/html" not in content_type and "application/xhtml" not in content_type:
                continue

            # Extract links
            discovered = self._extract_links(resp.text, url)
            for link in discovered:
                link_norm = self._normalize_url(link)
                if link_norm in visited:
                    continue
                parsed = urlparse(link)
                if parsed.hostname and parsed.hostname not in allowed_domains:
                    continue
                if link not in depth_map:
                    depth_map[link] = current_depth + 1
                if depth_map[link] <= max_depth:
                    queue.append(link)
                self.context.add_discovered_endpoint(link)

            # Extract forms and their parameters
            forms = self._extract_forms(resp.text, url)
            for form in forms:
                form_url = form["action"]
                self.context.add_discovered_endpoint(form_url)
                if form["params"]:
                    self.context.shared_data.setdefault("discovered_forms", []).append(form)

        total = len(self.context.discovered_endpoints)
        if total > 0:
            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title=f"Web Crawler discovered {total} endpoints",
                description=(
                    f"The web crawler discovered {total} additional endpoints "
                    f"by following links and parsing forms across {len(visited)} pages."
                ),
                severity=Severity.INFO,
                confidence=Confidence.CONFIRMED,
                url=self.context.target_urls[0] if self.context.target_urls else "",
                method="GET",
                evidence="\n".join(sorted(self.context.discovered_endpoints)[:50]),
            ))

        return findings

    def _get_allowed_domains(self) -> set[str]:
        domains = set(self.context.target_domains)
        for url in self.context.target_urls:
            parsed = urlparse(url)
            if parsed.hostname:
                domains.add(parsed.hostname)
        return domains

    @staticmethod
    def _normalize_url(url: str) -> str:
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}".rstrip("/").lower()

    @staticmethod
    def _extract_links(html: str, base_url: str) -> list[str]:
        links = []
        for match in _LINK_ATTRS.finditer(html):
            href = match.group(1).strip()
            if href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme in ("http", "https"):
                links.append(absolute)
        return links

    @staticmethod
    def _extract_forms(html: str, base_url: str) -> list[dict]:
        forms = []
        for action_match in _FORM_ACTION.finditer(html):
            action = urljoin(base_url, action_match.group(1).strip())
            # Find the method for this form (look nearby in the match context)
            form_start = action_match.start()
            form_html = html[form_start:form_start + 5000]
            method_match = _FORM_METHOD.search(form_html)
            method = method_match.group(1).upper() if method_match else "GET"
            params = _INPUT_NAME.findall(form_html)
            forms.append({
                "action": action,
                "method": method,
                "params": params,
            })
        return forms
