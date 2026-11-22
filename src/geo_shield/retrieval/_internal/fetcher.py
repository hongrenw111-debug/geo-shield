"""SSRF-guarded, per-hop validated, size-capped HTTP page fetcher."""

from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import subprocess
from urllib.parse import urljoin, urlparse

import httpx

from .models import FetchedPage

MAX_BODY_BYTES = 2 * 1024 * 1024  # 2 MiB
_HTML_SNIFF_BYTES = 8192
_MAX_REDIRECTS = 5
_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 GeoShield/0.1"
)


def make_http_client(
    target_url: str, *, timeout: float = 15.0, follow_redirects: bool = False, max_redirects: int = 5
) -> httpx.Client:
    """Create httpx.Client safely even when Windows NO_PROXY contains IPv6 entries like [::1]."""
    host = (urlparse(target_url).hostname or "").lower()
    if host in {"127.0.0.1", "localhost", "::1"}:
        return httpx.Client(
            timeout=timeout,
            follow_redirects=follow_redirects,
            max_redirects=max_redirects,
            trust_env=False,
        )
    proxy = (
        os.getenv("HTTPS_PROXY")
        or os.getenv("https_proxy")
        or os.getenv("HTTP_PROXY")
        or os.getenv("http_proxy")
    )
    return httpx.Client(
        timeout=timeout,
        follow_redirects=follow_redirects,
        max_redirects=max_redirects,
        trust_env=False,
        proxy=proxy or None,
    )


def _is_blocked_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        return not addr.ipv4_mapped.is_global
    return not addr.is_global


def validate_public_url(url: str) -> str | None:
    """Return error message if URL scheme or resolved address violates SSRF policy."""
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        return f"Unsupported URL scheme '{parsed.scheme}'; only http/https allowed."
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return "URL missing hostname."
    if host in {"localhost", "localhost.localdomain"} or host.endswith(".local"):
        return f"Blocked private/local hostname '{host}'."

    try:
        ipaddress.ip_address(host)
        if _is_blocked_ip(host):
            return f"Blocked non-global IP address '{host}'."
        return None
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80))
    except socket.gaierror as exc:
        return f"DNS resolution failed for '{host}': {exc}"

    for info in infos:
        sockaddr = info[4]
        if sockaddr and _is_blocked_ip(str(sockaddr[0])):
            return f"Blocked non-global resolved IP for '{host}'."
    return None


def _looks_like_html(ctype: str, body: str) -> bool:
    if "html" in ctype or "xml" in ctype:
        return True
    head = body[:_HTML_SNIFF_BYTES].lower()
    return any(
        marker in head
        for marker in ("<!doctype html", "<html", "<head", "<body", "<div", "<p>")
    )


def _try_agent_reach_read(url: str, timeout: float = 12.0) -> str | None:
    if os.getenv("GEOSHIELD_DISABLE_AGENT_REACH", "").strip() == "1":
        return None
    exe = shutil.which("agent-reach")
    if not exe:
        return None
    try:
        proc = subprocess.run(
            [exe, "read", url, "--backend", "public-web"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        payload = json.loads(proc.stdout)
        if not payload.get("ok"):
            return None
        items = payload.get("items") or []
        if not items:
            return None
        text = str(items[0].get("text") or "").strip()
        return text or None
    except Exception:  # noqa: BLE001
        return None


def fetch_remote_page(url: str, timeout: float = 15.0) -> FetchedPage:
    current_url = url.strip()
    err = validate_public_url(current_url)
    if err:
        return FetchedPage(url=url, ok=False, error=err)

    headers = {"User-Agent": _USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    try:
        for _ in range(_MAX_REDIRECTS + 1):
            with make_http_client(
                current_url, timeout=timeout, follow_redirects=False, max_redirects=0
            ) as client:
                with client.stream("GET", current_url, headers=headers) as resp:
                    if resp.status_code in _REDIRECT_CODES:
                        location = resp.headers.get("location") or resp.headers.get("Location")
                        if not location:
                            return FetchedPage(
                                url=url,
                                final_url=current_url,
                                status_code=resp.status_code,
                                ok=False,
                                error=f"Redirect HTTP {resp.status_code} missing Location header.",
                            )
                        next_url = urljoin(current_url, location.strip())
                        hop_err = validate_public_url(next_url)
                        if hop_err:
                            return FetchedPage(
                                url=url,
                                final_url=next_url,
                                status_code=resp.status_code,
                                ok=False,
                                error=f"Redirect target blocked: {hop_err}",
                            )
                        current_url = next_url
                        continue

                    chunks: list[bytes] = []
                    total = 0
                    for chunk in resp.iter_bytes():
                        total += len(chunk)
                        if total > MAX_BODY_BYTES:
                            chunks.append(chunk[: MAX_BODY_BYTES - (total - len(chunk))])
                            break
                        chunks.append(chunk)
                    raw = b"".join(chunks)
                    encoding = resp.encoding or "utf-8"
                    body = raw.decode(encoding, errors="replace")
                    ctype = (resp.headers.get("content-type") or "").lower()

                    if resp.status_code == 403:
                        fallback_text = _try_agent_reach_read(current_url)
                        if fallback_text:
                            return FetchedPage(
                                url=url,
                                final_url=current_url,
                                status_code=200,
                                content_type="text/plain",
                                body=fallback_text,
                                is_html=False,
                                ok=True,
                            )

                    return FetchedPage(
                        url=url,
                        final_url=current_url,
                        status_code=resp.status_code,
                        content_type=ctype,
                        body=body,
                        is_html=_looks_like_html(ctype, body),
                        ok=resp.status_code < 400,
                        error="" if resp.status_code < 400 else f"HTTP {resp.status_code}",
                    )
        return FetchedPage(
            url=url,
            final_url=current_url,
            ok=False,
            error=f"Exceeded maximum redirects ({_MAX_REDIRECTS}).",
        )
    except Exception as exc:  # noqa: BLE001
        return FetchedPage(url=url, ok=False, error=f"{type(exc).__name__}: {exc}")
