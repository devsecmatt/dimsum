from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str:
    """Normalize a URL: add scheme if missing, lowercase host, strip trailing slash."""
    url = url.strip()
    if not url:
        return url

    # Add scheme if missing
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "https://" + url

    parsed = urlparse(url)
    # Lowercase the hostname
    netloc = parsed.hostname or ""
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{netloc}:{parsed.port}"

    # Strip trailing slash from path (unless it's just "/")
    path = parsed.path.rstrip("/") or "/"

    return urlunparse((
        parsed.scheme.lower(),
        netloc.lower(),
        path,
        parsed.params,
        parsed.query,
        "",  # drop fragment
    ))


def is_valid_url(url: str) -> bool:
    """Check if a string is a valid HTTP/HTTPS URL."""
    try:
        parsed = urlparse(url)
        return parsed.scheme in ("http", "https") and bool(parsed.hostname)
    except Exception:
        return False


def is_valid_domain(domain: str) -> bool:
    """Check if a string is a valid domain name."""
    domain = domain.strip().lower()
    if not domain:
        return False
    # Basic domain pattern
    pattern = re.compile(
        r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$"
    )
    return bool(pattern.match(domain))


def is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def extract_base_url(url: str) -> str:
    """Extract scheme + host + port from a URL."""
    parsed = urlparse(normalize_url(url))
    return f"{parsed.scheme}://{parsed.netloc}"


def parse_url_list(text: str) -> list[str]:
    """Parse a newline/comma separated list of URLs, normalizing each."""
    urls = []
    for line in re.split(r"[\n,]+", text):
        line = line.strip()
        if line:
            normalized = normalize_url(line)
            if is_valid_url(normalized):
                urls.append(normalized)
    return urls
