"""Broken Authentication Scanner Plugin.

Tests for common authentication misconfigurations including:
- Default credentials
- Missing authentication on sensitive endpoints
- Session management issues
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.payloads import DEFAULT_CREDENTIALS
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity

# Common admin/sensitive paths to check
SENSITIVE_PATHS = [
    "/admin", "/admin/", "/administrator",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/pma",
    "/console", "/debug",
    "/api/admin", "/api/users",
    "/graphql",
    "/.env", "/config.json",
    "/server-status", "/server-info",
    "/actuator", "/actuator/health",
    "/swagger-ui.html", "/api-docs",
]

# Common login form paths
LOGIN_PATHS = [
    "/login", "/signin", "/auth/login",
    "/admin/login", "/api/auth/login",
    "/api/login", "/user/login",
]


@PluginRegistry.register(
    "broken_auth",
    name="Broken Authentication Check",
    category="auth",
    owasp_category="A07:2021-Identification and Authentication Failures",
    asvs_ids=["V2.1.1", "V2.1.4", "V3.1.1"],
    cwe_ids=[287, 798, 306],
    description="Tests for broken authentication including default credentials and unprotected endpoints.",
)
class BrokenAuthPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []

        for url in self.get_target_urls():
            # Test 1: Check for unprotected sensitive paths
            await self._check_sensitive_paths(url, findings)

            # Test 2: Try default credentials on login endpoints
            await self._check_default_credentials(url, findings)

        return findings

    async def _check_sensitive_paths(
        self, base_url: str, findings: list[ScanFinding]
    ) -> None:
        """Check if sensitive paths are accessible without authentication."""
        for path in SENSITIVE_PATHS:
            url = urljoin(base_url, path)
            resp = await self.http.get(url)
            if resp is None:
                continue

            # A 200 response on a sensitive path may indicate missing auth
            if resp.status_code == 200 and len(resp.text) > 100:
                # Skip if it's just a redirect to login or a generic page
                if self._looks_like_login_redirect(resp.text):
                    continue

                severity = Severity.MEDIUM
                if any(p in path for p in (".env", "config", "actuator", "debug", "console")):
                    severity = Severity.HIGH

                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=f"Unprotected Sensitive Endpoint: {path}",
                    description=(
                        f"The endpoint '{path}' returned HTTP 200 and appears accessible "
                        f"without authentication. Sensitive endpoints should require authentication."
                    ),
                    severity=severity,
                    confidence=Confidence.TENTATIVE,
                    url=url,
                    method="GET",
                    evidence=f"HTTP {resp.status_code} response ({len(resp.text)} bytes)",
                    cwe_id=306,
                    remediation=(
                        "Require authentication for all sensitive endpoints. "
                        "Implement proper access control and return 401/403 for "
                        "unauthorized access attempts."
                    ),
                    request_dump=resp.dump_request(),
                    response_dump=resp.dump_response(max_body=500),
                ))

    async def _check_default_credentials(
        self, base_url: str, findings: list[ScanFinding]
    ) -> None:
        """Try default credentials on discovered login endpoints."""
        for path in LOGIN_PATHS:
            url = urljoin(base_url, path)

            # First check if the login endpoint exists
            resp = await self.http.get(url)
            if resp is None or resp.status_code >= 404:
                continue

            # Try default credentials
            for username, password in DEFAULT_CREDENTIALS[:5]:  # Limit attempts
                login_resp = await self.http.post(
                    url,
                    json={"username": username, "password": password},
                    headers={"Content-Type": "application/json"},
                )
                if login_resp is None:
                    continue

                # Also try form-encoded
                if login_resp.status_code >= 400:
                    login_resp = await self.http.post(
                        url,
                        data=f"username={username}&password={password}",
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                    if login_resp is None:
                        continue

                if self._login_appears_successful(login_resp):
                    findings.append(ScanFinding(
                        plugin_id=self.meta.plugin_id,
                        title=f"Default Credentials: {username}:{password}",
                        description=(
                            f"The login endpoint '{path}' accepts default credentials "
                            f"({username}:{password}). Default credentials must be changed "
                            f"before deployment."
                        ),
                        severity=Severity.CRITICAL,
                        confidence=Confidence.CONFIRMED,
                        url=url,
                        method="POST",
                        payload=f"username={username}&password={password}",
                        evidence=f"Login returned HTTP {login_resp.status_code} with success indicators",
                        cwe_id=798,
                        cvss_score=9.8,
                        remediation=(
                            "Change all default credentials immediately. Implement strong "
                            "password policies. Use multi-factor authentication for admin accounts."
                        ),
                        request_dump=login_resp.dump_request(),
                        response_dump=login_resp.dump_response(max_body=500),
                    ))
                    return  # One finding is enough

    @staticmethod
    def _looks_like_login_redirect(body: str) -> bool:
        body_lower = body.lower()
        indicators = ["login", "sign in", "log in", "authenticate"]
        form_count = body_lower.count("<form")
        password_field = "type=\"password\"" in body_lower or "type='password'" in body_lower
        return (form_count > 0 and password_field) or sum(1 for i in indicators if i in body_lower) >= 2

    @staticmethod
    def _login_appears_successful(resp) -> bool:
        """Heuristic to determine if a login attempt succeeded."""
        if resp.status_code in (200, 302, 303):
            body_lower = resp.text.lower()
            # Negative indicators (login failed)
            fail_indicators = [
                "invalid", "incorrect", "failed", "wrong",
                "error", "denied", "unauthorized",
            ]
            if any(ind in body_lower for ind in fail_indicators):
                return False

            # Positive indicators (login succeeded)
            success_indicators = [
                "dashboard", "welcome", "logout", "token",
                "session", "success", "authenticated",
            ]
            if any(ind in body_lower for ind in success_indicators):
                return True

            # 302 redirect usually means success
            if resp.status_code in (302, 303):
                location = resp.header("Location", "")
                if location and "login" not in location.lower():
                    return True

        return False
