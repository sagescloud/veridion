"""
app/utils/ssrf_guard.py
Server-side request forgery (SSRF) protection. PRD section 7.2.

Defence in depth, four layers:
  1. Syntax      : scheme/port allowlist, no userinfo tricks (url_tools + here).
  2. Hostname    : block obviously internal names before any DNS traffic.
  3. Resolution  : resolve DNS OURSELVES; EVERY returned IP must be public
                   (one private answer among public ones blocks the request).
  4. Connect time: a custom network backend re-resolves, re-validates and then
                   connects to the validated IP literal. This defeats DNS
                   rebinding (attacker DNS answering "public" for our check
                   and "127.0.0.1" for the real connection) because there is
                   no second, unchecked lookup. TLS SNI / cert verification
                   still use the original hostname.

ALL outbound requests for scanning MUST use `build_guarded_client` +
`safe_fetch`. Redirects are followed manually so every hop is re-validated.

For raw-socket checks (e.g. the certificate module), call
`assert_destination_allowed` and connect to the returned IP, passing the
hostname as `server_hostname`.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpcore
import httpx

from app.config import Settings
from app.utils.url_tools import ParsedUrl, UrlError, parse_url

log = logging.getLogger("veridion.ssrf")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class SSRFBlocked(Exception):
    """Destination is not allowed. The message is for LOGS ONLY, never for users."""


class HostUnresolvable(Exception):
    """DNS gave no usable answer (NXDOMAIN, timeout...). Not a security block."""


_BLOCKED_HOSTNAMES = {"localhost", "metadata", "metadata.google.internal"}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".intranet", ".lan", ".home", ".corp", ".home.arpa")

# Belt-and-braces on top of `ip.is_global`: ranges that embed or tunnel IPv4,
# or that stdlib versions classify inconsistently.
_EXTRA_BLOCKED = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16", "192.0.0.0/24", "198.18.0.0/15",
        "224.0.0.0/4", "240.0.0.0/4",
        "::/128", "::1/128", "64:ff9b::/96", "64:ff9b:1::/48", "2001::/32", "2002::/16",
        "fc00::/7", "fe80::/10", "ff00::/8",
    )
)


def is_public_ip(ip: IPAddress) -> bool:
    """True only for globally routable unicast addresses."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 must be judged as 127.0.0.1
    if not ip.is_global or ip.is_multicast:
        return False
    return not any(ip in net for net in _EXTRA_BLOCKED)


async def resolve_public_addresses(host: str, port: int, *, timeout: float = 3.0) -> list[str]:
    """Resolve `host` and return its IPs, or raise.

    Raises SSRFBlocked if ANY address is non-public, HostUnresolvable if DNS fails.
    """
    try:
        addrs: list[IPAddress] = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        loop = asyncio.get_running_loop()
        try:
            infos = await asyncio.wait_for(
                loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP),
                timeout,
            )
        except (socket.gaierror, TimeoutError, UnicodeError) as exc:
            raise HostUnresolvable(f"cannot resolve {host}") from exc
        addrs = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0].split("%")[0])  # strip IPv6 scope id
            if ip not in addrs:
                addrs.append(ip)

    if not addrs:
        raise HostUnresolvable(f"no addresses for {host}")
    for ip in addrs:
        if not is_public_ip(ip):
            log.warning("SSRF block: host=%s resolved to non-public ip=%s", host, ip)
            raise SSRFBlocked(f"{host} resolves to a non-public address")
    return [str(ip) for ip in addrs]


async def assert_destination_allowed(parsed: ParsedUrl, settings: Settings) -> list[str]:
    """Layers 1-3. Returns the validated IPs (callers may pin to them)."""
    host = parsed.hostname
    if not parsed.is_ip_literal:
        if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES) or "." not in host:
            log.warning("SSRF block: internal-looking hostname %s", host)
            raise SSRFBlocked("internal-looking hostname")
    if parsed.port not in settings.allowed_port_set:
        log.warning("SSRF block: port %s not allowed (host=%s)", parsed.port, host)
        raise SSRFBlocked("port not allowed")
    return await resolve_public_addresses(host, parsed.port, timeout=settings.dns_timeout_s)


# --------------------------------------------------------------------------
# Layer 4: connect-time validation (DNS-rebinding proof)
# --------------------------------------------------------------------------
class GuardedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Resolves + validates the host, then connects to the validated IP literal."""

    def __init__(self, dns_timeout: float = 3.0) -> None:
        self._inner = httpcore.AnyIOBackend()
        self._dns_timeout = dns_timeout

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        try:
            addrs = await resolve_public_addresses(host, port, timeout=self._dns_timeout)
        except (SSRFBlocked, HostUnresolvable) as exc:
            # Surface as an ordinary connection failure; details stay in the logs.
            raise httpcore.ConnectError("destination not reachable") from exc

        last_exc: Exception | None = None
        for ip in addrs:
            try:
                return await self._inner.connect_tcp(
                    ip, port, timeout=timeout, local_address=local_address, socket_options=socket_options
                )
            except (httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_exc = exc
        raise last_exc or httpcore.ConnectError("connection failed")

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise httpcore.ConnectError("unix sockets are not permitted")

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport whose connection pool uses GuardedNetworkBackend.

    NOTE: swaps the private `_pool` attribute (httpx exposes no public hook for
    a custom network backend). requirements.txt pins httpx; the startup check
    below fails loudly if a future version changes this. Re-run tests/test_ssrf_guard.py
    after any httpx upgrade.
    """

    def __init__(self, *, dns_timeout: float = 3.0, verify_tls: bool = True, max_connections: int = 50) -> None:
        super().__init__(verify=verify_tls, trust_env=False, http2=False, retries=0)
        if not isinstance(getattr(self, "_pool", None), httpcore.AsyncConnectionPool):
            raise RuntimeError("httpx internals changed: re-verify the SSRF transport before upgrading")
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=verify_tls, trust_env=False),
            max_connections=max_connections,
            max_keepalive_connections=max_connections // 2,
            keepalive_expiry=10.0,
            http1=True,
            http2=False,
            retries=0,
            network_backend=GuardedNetworkBackend(dns_timeout),
        )


def build_guarded_client(settings: Settings, *, verify_tls: bool = True) -> httpx.AsyncClient:
    """The ONLY HTTP client scanning code may use.

    verify_tls=False lets header/redirect inspection still work on sites with
    broken certificates (the certificate module reports those separately).
    Never follows redirects itself, never reads proxy env vars, no cookies kept.
    """
    return httpx.AsyncClient(
        transport=GuardedTransport(dns_timeout=settings.dns_timeout_s, verify_tls=verify_tls),
        follow_redirects=False,
        trust_env=False,
        timeout=httpx.Timeout(settings.http_timeout_s, connect=min(5.0, settings.http_timeout_s)),
        headers={
            "User-Agent": "VeridionScanner/0.1 (+website security analysis)",
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        },
    )


# --------------------------------------------------------------------------
# Safe fetch: manual redirects, per-hop validation, size + time caps
# --------------------------------------------------------------------------
@dataclass
class RedirectHop:
    url: str
    status_code: int


@dataclass
class FetchResult:
    final_url: str
    status_code: int
    headers: dict[str, str]                 # lower-case names
    body: bytes                             # capped at settings.max_response_bytes
    truncated: bool
    redirect_chain: list[RedirectHop] = field(default_factory=list)
    blocked_redirect: str | None = None     # a redirect target we refused to follow (itself a finding!)
    redirect_limit_hit: bool = False


_REDIRECT_CODES = {301, 302, 303, 307, 308}


async def safe_fetch(client: httpx.AsyncClient, url: str, settings: Settings) -> FetchResult:
    """GET `url` safely. The FIRST hop raises (UrlError / SSRFBlocked / HostUnresolvable /
    httpx.HTTPError); later hops that are refused are reported via `blocked_redirect`
    instead, because "redirects to an internal address" is useful evidence.
    """
    chain: list[RedirectHop] = []
    current = url

    async with asyncio.timeout(settings.http_total_timeout_s):
        for hop in range(settings.max_redirects + 1):
            try:
                parsed = parse_url(current)
                await assert_destination_allowed(parsed, settings)
            except (UrlError, SSRFBlocked, HostUnresolvable):
                if hop == 0:
                    raise
                return FetchResult(
                    final_url=chain[-1].url, status_code=chain[-1].status_code, headers={},
                    body=b"", truncated=False, redirect_chain=chain, blocked_redirect=current,
                )

            async with client.stream("GET", parsed.normalized) as resp:
                headers = {k.lower(): v for k, v in resp.headers.items()}
                chain.append(RedirectHop(url=parsed.normalized, status_code=resp.status_code))
                location = headers.get("location")
                if resp.status_code in _REDIRECT_CODES and location:
                    next_url = urljoin(parsed.normalized, location)
                else:
                    body, truncated = await _read_capped(resp, settings.max_response_bytes)
                    return FetchResult(
                        final_url=parsed.normalized, status_code=resp.status_code, headers=headers,
                        body=body, truncated=truncated, redirect_chain=chain,
                    )
            current = next_url  # stream closed without downloading the redirect body

    last = chain[-1]
    return FetchResult(
        final_url=last.url, status_code=last.status_code, headers={}, body=b"",
        truncated=False, redirect_chain=chain, redirect_limit_hit=True,
    )


async def _read_capped(resp: httpx.Response, limit: int) -> tuple[bytes, bool]:
    """Read at most `limit` DECODED bytes (also bounds gzip bombs)."""
    buf = bytearray()
    async for chunk in resp.aiter_bytes():
        room = limit - len(buf)
        if len(chunk) > room:
            buf += chunk[:room]
            return bytes(buf), True
        buf += chunk
    return bytes(buf), False
