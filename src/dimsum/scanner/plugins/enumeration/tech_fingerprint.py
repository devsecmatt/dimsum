"""Technology Fingerprinting Plugin.

Identifies the technology stack (web server, framework, language, CMS)
of each target by inspecting HTTP headers, HTML meta tags, cookies,
and response body patterns.
"""

from __future__ import annotations

import re

from dimsum.scanner.base_plugin import BaseScanPlugin
from dimsum.scanner.registry import PluginRegistry
from dimsum.scanner.result import Confidence, ScanFinding, Severity

# Header-based signatures: header_name -> [(value_pattern, tech_name, category)]
_HEADER_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (header_name, regex_pattern, tech_name, category)
    ("server", r"nginx", "Nginx", "web-server"),
    ("server", r"apache", "Apache", "web-server"),
    ("server", r"microsoft-iis", "Microsoft IIS", "web-server"),
    ("server", r"cloudflare", "Cloudflare", "cdn"),
    ("server", r"gunicorn", "Gunicorn", "web-server"),
    ("server", r"uvicorn", "Uvicorn", "web-server"),
    ("server", r"openresty", "OpenResty", "web-server"),
    ("server", r"lighttpd", "Lighttpd", "web-server"),
    ("server", r"caddy", "Caddy", "web-server"),
    ("x-powered-by", r"php", "PHP", "language"),
    ("x-powered-by", r"asp\.net", "ASP.NET", "framework"),
    ("x-powered-by", r"express", "Express.js", "framework"),
    ("x-powered-by", r"next\.js", "Next.js", "framework"),
    ("x-powered-by", r"flask", "Flask", "framework"),
    ("x-powered-by", r"django", "Django", "framework"),
    ("x-powered-by", r"rails", "Ruby on Rails", "framework"),
    ("x-generator", r"wordpress", "WordPress", "cms"),
    ("x-generator", r"drupal", "Drupal", "cms"),
    ("x-drupal-cache", r".", "Drupal", "cms"),
    ("x-aspnet-version", r".", "ASP.NET", "framework"),
    ("x-aspnetmvc-version", r".", "ASP.NET MVC", "framework"),
    ("x-amz-request-id", r".", "Amazon S3 / AWS", "cloud"),
    ("x-goog-", r".", "Google Cloud", "cloud"),
    ("x-azure-ref", r".", "Microsoft Azure", "cloud"),
]

# Cookie-based signatures: (cookie_name_pattern, tech_name, category)
_COOKIE_SIGNATURES: list[tuple[str, str, str]] = [
    (r"PHPSESSID", "PHP", "language"),
    (r"JSESSIONID", "Java", "language"),
    (r"ASP\.NET_SessionId", "ASP.NET", "framework"),
    (r"csrftoken", "Django", "framework"),
    (r"_rails_session", "Ruby on Rails", "framework"),
    (r"laravel_session", "Laravel", "framework"),
    (r"ci_session", "CodeIgniter", "framework"),
    (r"connect\.sid", "Express.js", "framework"),
    (r"wp-settings", "WordPress", "cms"),
]

# Body-based signatures: (regex_pattern, tech_name, category)
_BODY_SIGNATURES: list[tuple[str, str, str]] = [
    (r'<meta\s+name=["\']generator["\']\s+content=["\']WordPress', "WordPress", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Drupal', "Drupal", "cms"),
    (r'<meta\s+name=["\']generator["\']\s+content=["\']Joomla', "Joomla", "cms"),
    (r"wp-content/", "WordPress", "cms"),
    (r"wp-includes/", "WordPress", "cms"),
    (r"/sites/default/files/", "Drupal", "cms"),
    (r"__next", "Next.js", "framework"),
    (r"__nuxt", "Nuxt.js", "framework"),
    (r"ng-version=", "Angular", "framework"),
    (r'data-reactroot', "React", "framework"),
    (r"__VUE__", "Vue.js", "framework"),
    (r"__svelte", "Svelte", "framework"),
    (r"ember-view", "Ember.js", "framework"),
    (r"Powered by.*Django", "Django", "framework"),
]


@PluginRegistry.register(
    "tech_fingerprint",
    name="Technology Fingerprinting",
    category="enumeration",
    owasp_category="A05:2021-Security Misconfiguration",
    cwe_ids=[200],
    description=(
        "Identifies the technology stack of targets by inspecting HTTP headers, "
        "cookies, HTML content, and response patterns."
    ),
    is_enumeration=True,
)
class TechFingerprintPlugin(BaseScanPlugin):

    async def run(self) -> list[ScanFinding]:
        findings: list[ScanFinding] = []
        all_techs: dict[str, set[str]] = {}  # url -> set of techs

        for url in self.context.target_urls:
            resp = await self.http.get(url)
            if resp is None:
                continue

            techs: dict[str, dict] = {}

            # Check headers
            for header_name, pattern, tech_name, category in _HEADER_SIGNATURES:
                header_val = resp.header(header_name)
                if header_val and re.search(pattern, header_val, re.IGNORECASE):
                    techs[tech_name] = {"category": category, "source": f"header:{header_name}", "value": header_val}

            # Check cookies
            set_cookie = resp.header("set-cookie")
            if set_cookie:
                for cookie_pattern, tech_name, category in _COOKIE_SIGNATURES:
                    if re.search(cookie_pattern, set_cookie, re.IGNORECASE):
                        techs[tech_name] = {"category": category, "source": "cookie"}

            # Check body
            for body_pattern, tech_name, category in _BODY_SIGNATURES:
                if re.search(body_pattern, resp.text, re.IGNORECASE):
                    techs[tech_name] = {"category": category, "source": "body"}

            if techs:
                all_techs[url] = set(techs.keys())
                tech_list = ", ".join(sorted(techs.keys()))
                details = "\n".join(
                    f"  - {name}: {info['category']} (detected via {info['source']})"
                    for name, info in sorted(techs.items())
                )
                findings.append(ScanFinding(
                    plugin_id=self.meta.plugin_id,
                    title=f"Technology stack identified: {tech_list}",
                    description=(
                        f"The following technologies were detected on {url}:\n{details}"
                    ),
                    severity=Severity.INFO,
                    confidence=Confidence.FIRM,
                    url=url,
                    method="GET",
                    evidence=details,
                    cwe_id=200,
                    remediation=(
                        "Remove or obfuscate technology identifiers where possible. "
                        "Remove version information from Server, X-Powered-By, and "
                        "X-Generator headers. Ensure technology-specific default files "
                        "are removed from production."
                    ),
                ))

                # Store in shared data for other plugins
                self.context.shared_data.setdefault("technologies", {}).update(
                    {url: list(techs.keys())}
                )

        return findings
