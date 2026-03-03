"""CORS Misconfiguration Scanner Plugin.

Tests for insecure Cross-Origin Resource Sharing (CORS) configurations
that could allow unauthorized cross-origin access.
"""

from __future__ import annotations

from urllib.parse import urlparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity


@PluginRegistry.register(
    "cors_misconfig",
    name="CORS Misconfiguration Check",
    category="misconfig",
    owasp_category="A05:2021-Security Misconfiguration",
    asvs_ids=["V14.5.2", "V14.5.3"],
    cwe_ids=[942, 346],
    description="Tests for insecure CORS configurations including wildcard and null origins.",
)
class CORSMisconfigPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            parsed = urlparse(url)
            origin = f"{parsed.scheme}://{parsed.netloc}"

            # Test 1: Wildcard origin
            await self._test_wildcard_cors(url, findings)

            # Test 2: Arbitrary origin reflection
            await self._test_origin_reflection(url, origin, findings)

            # Test 3: Null origin
            await self._test_null_origin(url, findings)

            # Test 4: Subdomain trust
            await self._test_subdomain_trust(url, origin, findings)

        return findings

    async def _test_wildcard_cors(
        self, url: str, findings: list[ScanFinding]
    ) -> None:
        """Check if the server returns Access-Control-Allow-Origin: *."""
        resp = await self.http.get(url)
        if resp is None:
            return

        acao = resp.header("Access-Control-Allow-Origin")
        if acao == "*":
            # Check if credentials are also allowed (very dangerous)
            acac = resp.header("Access-Control-Allow-Credentials")
            if acac and acac.lower() == "true":
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title="CORS Wildcard with Credentials",
                    description=(
                        "The server allows CORS from any origin (*) AND allows credentials. "
                        "This is extremely dangerous and allows any website to make authenticated "
                        "requests on behalf of the user."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=Confidence.CONFIRMED,
                    url=url,
                    method="GET",
                    evidence=f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}",
                    cwe_id=942,
                    cvss_score=9.1,
                    remediation=(
                        "Never combine Access-Control-Allow-Origin: * with "
                        "Access-Control-Allow-Credentials: true. Use a specific origin allowlist."
                    ),
                    request_dump=resp.dump_request(),
                    response_dump=resp.dump_response(max_body=500),
                ))
            else:
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title="CORS Wildcard Origin Allowed",
                    description=(
                        "The server allows CORS requests from any origin (*). "
                        "While less severe without credentials, this may expose data to "
                        "unauthorized origins."
                    ),
                    severity=Severity.LOW,
                    confidence=Confidence.CONFIRMED,
                    url=url,
                    method="GET",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    cwe_id=942,
                    remediation="Restrict CORS to specific trusted origins instead of using *.",
                    request_dump=resp.dump_request(),
                    response_dump=resp.dump_response(max_body=500),
                ))

    async def _test_origin_reflection(
        self, url: str, legitimate_origin: str, findings: list[ScanFinding]
    ) -> None:
        """Test if the server reflects arbitrary origin values."""
        evil_origin = "https://evil.attacker.com"
        resp = await self.http.get(url, headers={"Origin": evil_origin})
        if resp is None:
            return

        acao = resp.header("Access-Control-Allow-Origin")
        if acao == evil_origin:
            acac = resp.header("Access-Control-Allow-Credentials")
            creds_allowed = acac and acac.lower() == "true"

            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title="CORS Origin Reflection (Arbitrary Origin Accepted)",
                description=(
                    f"The server reflects arbitrary Origin headers in Access-Control-Allow-Origin. "
                    f"Any website can make cross-origin requests to this endpoint"
                    f"{' with credentials' if creds_allowed else ''}."
                ),
                severity=Severity.HIGH if creds_allowed else Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=url,
                method="GET",
                evidence=(
                    f"Sent Origin: {evil_origin}, "
                    f"Received Access-Control-Allow-Origin: {acao}"
                    f"{', Access-Control-Allow-Credentials: true' if creds_allowed else ''}"
                ),
                cwe_id=346,
                cvss_score=7.5 if creds_allowed else 5.3,
                remediation=(
                    "Do not reflect the Origin header directly. Validate against an "
                    "allowlist of trusted origins before setting Access-Control-Allow-Origin."
                ),
                request_dump=resp.dump_request(),
                response_dump=resp.dump_response(max_body=500),
            ))

    async def _test_null_origin(
        self, url: str, findings: list[ScanFinding]
    ) -> None:
        """Test if the server accepts 'null' as an origin."""
        resp = await self.http.get(url, headers={"Origin": "null"})
        if resp is None:
            return

        acao = resp.header("Access-Control-Allow-Origin")
        if acao == "null":
            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title="CORS Allows Null Origin",
                description=(
                    "The server accepts 'null' as a valid origin. Sandboxed iframes and "
                    "redirected requests send Origin: null, enabling potential bypass of "
                    "origin-based access controls."
                ),
                severity=Severity.MEDIUM,
                confidence=Confidence.CONFIRMED,
                url=url,
                method="GET",
                evidence=f"Sent Origin: null, Received Access-Control-Allow-Origin: null",
                cwe_id=346,
                remediation="Do not allow 'null' as a trusted origin in CORS configuration.",
                request_dump=resp.dump_request(),
                response_dump=resp.dump_response(max_body=500),
            ))

    async def _test_subdomain_trust(
        self, url: str, origin: str, findings: list[ScanFinding]
    ) -> None:
        """Test if the server trusts all subdomains of the target."""
        parsed = urlparse(origin)
        domain = parsed.netloc.split(":")[0]

        # Try a malicious subdomain
        evil_subdomain = f"{parsed.scheme}://evil.{domain}"
        resp = await self.http.get(url, headers={"Origin": evil_subdomain})
        if resp is None:
            return

        acao = resp.header("Access-Control-Allow-Origin")
        if acao == evil_subdomain:
            findings.append(ScanFinding(
                plugin_id=self.meta.plugin_id,
                title="CORS Trusts All Subdomains",
                description=(
                    f"The server accepts CORS requests from any subdomain of {domain}. "
                    f"If any subdomain is compromised, it could be used to bypass CORS."
                ),
                severity=Severity.LOW,
                confidence=Confidence.FIRM,
                url=url,
                method="GET",
                evidence=f"Sent Origin: {evil_subdomain}, Received Access-Control-Allow-Origin: {acao}",
                cwe_id=346,
                remediation="Use an explicit allowlist of trusted subdomains rather than matching all subdomains.",
                request_dump=resp.dump_request(),
                response_dump=resp.dump_response(max_body=500),
            ))
