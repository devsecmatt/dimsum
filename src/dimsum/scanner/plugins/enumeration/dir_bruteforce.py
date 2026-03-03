"""Directory / Path Brute-Force Plugin.

Discovers hidden paths and directories by testing common path names
against each target.  Uses a built-in compact wordlist; larger lists
can be supplied through the wordlist management feature.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity

# Compact default wordlist — common discovery paths
_DEFAULT_PATHS = [
    ".env",
    ".git/config",
    ".git/HEAD",
    ".svn/entries",
    ".DS_Store",
    ".htaccess",
    "robots.txt",
    "sitemap.xml",
    "crossdomain.xml",
    "security.txt",
    ".well-known/security.txt",
    "wp-login.php",
    "wp-admin/",
    "administrator/",
    "admin/",
    "login",
    "api/",
    "api/v1/",
    "api/v2/",
    "swagger.json",
    "openapi.json",
    "api-docs",
    "graphql",
    "graphiql",
    "console",
    "debug",
    "server-status",
    "server-info",
    "phpinfo.php",
    "info.php",
    "test",
    "backup/",
    "backups/",
    "config/",
    "config.json",
    "config.yml",
    "config.yaml",
    "config.xml",
    "database.yml",
    "docker-compose.yml",
    "Dockerfile",
    ".dockerenv",
    "actuator",
    "actuator/health",
    "actuator/env",
    "health",
    "healthcheck",
    "status",
    "metrics",
    "trace",
    "dumps",
    "heapdump",
    "threaddump",
    "env",
    "elmah.axd",
    "web.config",
    "WEB-INF/web.xml",
    "package.json",
    "composer.json",
    "Gemfile",
    "requirements.txt",
]

# Status codes that indicate an interesting resource
_INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403}

# Sensitive file patterns that warrant higher severity
_SENSITIVE_PATTERNS = {
    ".env": ("Environment file exposed", Severity.HIGH),
    ".git/config": ("Git repository exposed", Severity.HIGH),
    ".git/HEAD": ("Git repository exposed", Severity.HIGH),
    ".svn/entries": ("SVN repository exposed", Severity.HIGH),
    ".htaccess": ("htaccess file exposed", Severity.MEDIUM),
    "config.json": ("Configuration file exposed", Severity.MEDIUM),
    "config.yml": ("Configuration file exposed", Severity.MEDIUM),
    "config.yaml": ("Configuration file exposed", Severity.MEDIUM),
    "database.yml": ("Database configuration exposed", Severity.HIGH),
    "docker-compose.yml": ("Docker Compose file exposed", Severity.MEDIUM),
    "phpinfo.php": ("PHP info page exposed", Severity.MEDIUM),
    "actuator/env": ("Spring Actuator env exposed", Severity.HIGH),
    "heapdump": ("Heap dump exposed", Severity.CRITICAL),
    "threaddump": ("Thread dump exposed", Severity.HIGH),
    "swagger.json": ("API documentation exposed", Severity.LOW),
    "openapi.json": ("API documentation exposed", Severity.LOW),
    "web.config": ("Web config exposed", Severity.MEDIUM),
    "WEB-INF/web.xml": ("Java web descriptor exposed", Severity.MEDIUM),
    "package.json": ("Package manifest exposed", Severity.LOW),
    "requirements.txt": ("Python requirements exposed", Severity.LOW),
}


@PluginRegistry.register(
    "dir_bruteforce",
    name="Directory / Path Discovery",
    category="enumeration",
    owasp_category="A05:2021-Security Misconfiguration",
    cwe_ids=[538, 548],
    description=(
        "Discovers hidden files, directories, and endpoints by probing "
        "common paths against targets."
    ),
    is_enumeration=True,
)
class DirBruteForcePlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        paths = self._get_wordlist()

        base_urls = self._get_base_urls()

        for base_url in base_urls:
            # First request the base to get a reference 404 response length
            not_found_resp = await self.http.get(urljoin(base_url, "dimsum-nonexistent-path-404-check"))
            not_found_len = len(not_found_resp.text) if not_found_resp else 0

            for path in paths:
                test_url = urljoin(base_url.rstrip("/") + "/", path)
                resp = await self.http.get(test_url, follow_redirects=False)
                if resp is None:
                    continue

                if resp.status_code not in _INTERESTING_CODES:
                    continue

                # Filter out soft-404s (same body length as known 404)
                if resp.status_code == 200 and not_found_len and abs(len(resp.text) - not_found_len) < 50:
                    continue

                self.context.add_discovered_endpoint(test_url)

                severity, title = self._classify_finding(path, resp.status_code)
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=title,
                    description=(
                        f"The path '{path}' returned HTTP {resp.status_code} on {base_url}. "
                        f"This may expose sensitive information or functionality."
                    ),
                    severity=severity,
                    confidence=Confidence.CONFIRMED if resp.status_code == 200 else Confidence.FIRM,
                    url=test_url,
                    method="GET",
                    evidence=f"HTTP {resp.status_code} — {len(resp.text)} bytes",
                    cwe_id=538,
                    remediation=(
                        "Restrict access to sensitive files and directories. "
                        "Ensure development files (.git, .env, config) are not "
                        "deployed to production. Use proper access controls."
                    ),
                    request_dump=resp.dump_request(),
                    response_dump=resp.dump_response(max_body=500),
                ))

        return findings

    def _get_base_urls(self) -> list[str]:
        base_urls = set()
        for url in self.context.target_urls:
            parsed = urlparse(url)
            base_urls.add(f"{parsed.scheme}://{parsed.netloc}")
        return list(base_urls)

    def _get_wordlist(self) -> list[str]:
        custom = self.context.shared_data.get("bruteforce_paths")
        if custom:
            return custom
        return list(_DEFAULT_PATHS)

    @staticmethod
    def _classify_finding(path: str, status_code: int) -> tuple[Severity, str]:
        if path in _SENSITIVE_PATTERNS:
            title, severity = _SENSITIVE_PATTERNS[path]
            return severity, title

        if status_code in (401, 403):
            return Severity.INFO, f"Protected resource found: {path}"

        if status_code in (301, 302, 307, 308):
            return Severity.INFO, f"Redirect found: {path}"

        return Severity.LOW, f"Accessible path discovered: {path}"
