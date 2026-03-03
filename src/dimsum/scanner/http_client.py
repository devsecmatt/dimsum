from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class HTTPResponse:
    """Simplified response wrapper for scan plugins."""

    status_code: int
    headers: dict[str, str]
    text: str
    url: str
    elapsed_ms: float
    request_method: str
    request_url: str
    request_headers: dict[str, str]
    request_body: str | None = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 400

    def header(self, name: str, default: str = "") -> str:
        """Case-insensitive header lookup."""
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return default

    def dump_request(self) -> str:
        lines = [f"{self.request_method} {self.request_url}"]
        for k, v in self.request_headers.items():
            lines.append(f"{k}: {v}")
        if self.request_body:
            lines.append("")
            lines.append(self.request_body[:2000])
        return "\n".join(lines)

    def dump_response(self, max_body: int = 2000) -> str:
        lines = [f"HTTP {self.status_code}"]
        for k, v in self.headers.items():
            lines.append(f"{k}: {v}")
        lines.append("")
        lines.append(self.text[:max_body])
        return "\n".join(lines)


@dataclass
class ClientConfig:
    timeout_seconds: int = 30
    max_concurrency: int = 10
    request_delay_ms: int = 100
    custom_headers: dict[str, str] = field(default_factory=dict)
    auth_config: dict[str, Any] | None = None
    verify_ssl: bool = False
    max_redirects: int = 5


class AsyncHTTPClient:
    """Async HTTP client with rate limiting and concurrency control."""

    def __init__(self, config: ClientConfig | None = None):
        self.config = config or ClientConfig()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._last_request_time: float = 0
        self._request_count: int = 0
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self) -> AsyncHTTPClient:
        headers = {
            "User-Agent": "dimsum-scanner/1.0",
            "Accept": "*/*",
        }
        headers.update(self.config.custom_headers)

        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(self.config.timeout_seconds),
            follow_redirects=True,
            max_redirects=self.config.max_redirects,
            verify=self.config.verify_ssl,
            headers=headers,
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    async def _rate_limit(self) -> None:
        if self.config.request_delay_ms <= 0:
            return
        delay = self.config.request_delay_ms / 1000.0
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < delay:
            await asyncio.sleep(delay - elapsed)

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        data: str | None = None,
        json: Any = None,
        params: dict[str, str] | None = None,
        follow_redirects: bool = True,
    ) -> HTTPResponse | None:
        """Send an HTTP request with rate limiting and concurrency control.

        Returns None if the request fails (timeout, connection error, etc.).
        """
        async with self._semaphore:
            await self._rate_limit()
            self._last_request_time = time.monotonic()
            self._request_count += 1

            try:
                req_headers = dict(headers or {})
                resp = await self._client.request(
                    method,
                    url,
                    headers=req_headers,
                    content=data,
                    json=json,
                    params=params,
                    follow_redirects=follow_redirects,
                )
                return HTTPResponse(
                    status_code=resp.status_code,
                    headers=dict(resp.headers),
                    text=resp.text,
                    url=str(resp.url),
                    elapsed_ms=resp.elapsed.total_seconds() * 1000,
                    request_method=method,
                    request_url=url,
                    request_headers=req_headers,
                    request_body=data,
                )
            except httpx.TimeoutException:
                logger.debug("Timeout requesting %s %s", method, url)
                return None
            except httpx.HTTPError as exc:
                logger.debug("HTTP error requesting %s %s: %s", method, url, exc)
                return None

    async def get(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("PUT", url, **kwargs)

    async def head(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("HEAD", url, **kwargs)

    async def options(self, url: str, **kwargs) -> HTTPResponse | None:
        return await self.request("OPTIONS", url, **kwargs)

    @property
    def request_count(self) -> int:
        return self._request_count
