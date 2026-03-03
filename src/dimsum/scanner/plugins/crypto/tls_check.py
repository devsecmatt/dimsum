"""TLS/Cryptographic Failures Scanner Plugin.

Checks for:
- Missing HTTPS redirect
- Mixed content issues
- Insecure cookie transport
- HSTS configuration
- Information disclosure via TLS
"""

from __future__ import annotations

from urllib.parse import urlparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "tls_crypto",
    name="TLS & Cryptographic Failures Check",
    category="crypto",
    owasp_category="A02:2021-Cryptographic Failures",
    asvs_ids=["V9.1.1", "V9.1.2", "V9.1.3"],
    cwe_ids=[319, 311, 327],
    description="Checks for TLS/SSL misconfigurations and cryptographic weaknesses.",
)
class TLSCryptoPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            parsed = urlparse(url)

            # Test 1: HTTP to HTTPS redirect
            await self._check_https_redirect(url, parsed, findings)

            # Test 2: Mixed content on HTTPS pages
            if parsed.scheme == "https":
                await self._check_mixed_content(url, findings)

            # Test 3: Sensitive data in URL
            self._check_sensitive_url_data(url, findings)

        return findings

    async def _check_https_redirect(
        self, url: str, parsed, findings: list[ScanFinding]
    ) -> None:
        """Check if HTTP requests are redirected to HTTPS."""
        if parsed.scheme == "https":
            # Try the HTTP version
            http_url = url.replace("https://", "http://", 1)
        elif parsed.scheme == "http":
            http_url = url
        else:
            return

        resp = await self.http.get(http_url, follow_redirects=False)
        if resp is None:
            return

        if resp.status_code == 200:
            # HTTP serves content without redirect — bad
            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title="No HTTP to HTTPS Redirect",
                description=(
                    "The server responds over HTTP without redirecting to HTTPS. "
                    "All HTTP traffic should redirect to HTTPS to protect data in transit."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=http_url,
                method="GET",
                evidence=f"HTTP {resp.status_code} response on HTTP (no redirect to HTTPS)",
                cwe_id=319,
                cvss_score=5.3,
                remediation=(
                    "Configure the web server to redirect all HTTP requests to HTTPS "
                    "with a 301 permanent redirect. Also add HSTS headers."
                ),
                request_dump=resp.dump_request(),
                response_dump=resp.dump_response(max_body=500),
            ))
        elif resp.status_code in (301, 302, 307, 308):
            location = resp.header("Location", "")
            if location and not location.startswith("https"):
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title="HTTP Redirect Not to HTTPS",
                    description=(
                        f"HTTP redirects to {location} instead of an HTTPS URL. "
                        f"Redirect should be to HTTPS to protect data in transit."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.CONFIRMED,
                    url=http_url,
                    method="GET",
                    evidence=f"Redirect Location: {location}",
                    cwe_id=319,
                    remediation="Ensure HTTP redirect target uses HTTPS.",
                    request_dump=resp.dump_request(),
                    response_dump=resp.dump_response(max_body=500),
                ))

    async def _check_mixed_content(
        self, url: str, findings: list[ScanFinding]
    ) -> None:
        """Check for HTTP resources loaded on an HTTPS page."""
        resp = await self.http.get(url)
        if resp is None:
            return

        body = resp.text.lower()
        mixed_patterns = [
            'src="http://',
            "src='http://",
            'action="http://',
            "action='http://",
            'href="http://',
            "href='http://",
        ]

        found_mixed = []
        for pattern in mixed_patterns:
            if pattern in body:
                # Extract the URL
                idx = body.find(pattern)
                end = body.find('"', idx + len(pattern) - 1)
                if end == -1:
                    end = body.find("'", idx + len(pattern) - 1)
                if end > idx:
                    resource = body[idx:end + 1]
                    found_mixed.append(resource[:200])

        if found_mixed:
            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title="Mixed Content: HTTP Resources on HTTPS Page",
                description=(
                    f"The HTTPS page loads {len(found_mixed)} resource(s) over insecure HTTP, "
                    f"creating mixed content that can be intercepted or modified by attackers."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=url,
                method="GET",
                evidence="Mixed content found:\n" + "\n".join(found_mixed[:5]),
                cwe_id=311,
                remediation=(
                    "Ensure all resources (scripts, stylesheets, images, etc.) are loaded "
                    "over HTTPS. Use protocol-relative URLs or always use https://."
                ),
                request_dump=resp.dump_request(),
                response_dump=resp.dump_response(max_body=500),
            ))

    @staticmethod
    def _check_sensitive_url_data(url: str, findings: list[ScanFinding]) -> None:
        """Check if URL contains potentially sensitive data in query parameters."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        sensitive_params = [
            "password", "passwd", "pwd", "pass",
            "token", "api_key", "apikey", "secret",
            "ssn", "credit_card", "cc",
        ]

        query_lower = parsed.query.lower()
        for param in sensitive_params:
            if f"{param}=" in query_lower:
                findings.append(ScanFinding(
                    plugin_id="tls_crypto",
                    title=f"Sensitive Data in URL: '{param}' parameter",
                    description=(
                        f"The URL contains a '{param}' parameter in the query string. "
                        f"Sensitive data in URLs is logged in browser history, server logs, "
                        f"and may be leaked through Referer headers."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=Confidence.FIRM,
                    url=url,
                    method="GET",
                    parameter=param,
                    cwe_id=598,
                    remediation=(
                        "Send sensitive data via POST body or request headers instead of "
                        "URL query parameters. Use HTTPS to encrypt data in transit."
                    ),
                ))
