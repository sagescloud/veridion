"""
app/utils/url_tools.py
Strict URL parsing + normalization. Pure functions, no network access.

`parse_url` is the single entry point every other component uses, so the
whole backend agrees on what "the URL" is. The normalized form is used for
duplicate detection (community reports) and as the scan's `normalized_url`.
"""
from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass
from urllib.parse import urlsplit

import idna

MAX_URL_LENGTH = 2048
ALLOWED_SCHEMES = {"http", "https"}
_DEFAULT_PORTS = {"http": 80, "https": 443}

_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:")
# Letters, digits, hyphen, underscore, dot-separated. (IDNs are converted to
# punycode before this check.)
_HOST_RE = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$")


class UrlError(Exception):
    """Raised for user-correctable URL problems. `code` matches the API error codes."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class ParsedUrl:
    submitted: str          # exactly what the caller sent (trimmed)
    normalized: str         # canonical form (no userinfo, no fragment)
    scheme: str
    hostname: str           # lower-case ASCII (punycode for IDNs), or IP literal
    port: int               # effective port (explicit or scheme default)
    has_userinfo: bool      # "user:pass@" present: classic phishing trick, kept as a signal
    is_ip_literal: bool


def parse_url(raw: str) -> ParsedUrl:
    """Validate and normalize a URL. Raises UrlError (never returns garbage)."""
    if not isinstance(raw, str):
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    text = raw.strip()
    if not text or len(text) > MAX_URL_LENGTH:
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    # Control chars, spaces and backslashes are never legitimate here, and
    # backslashes are parsed differently by browsers vs. libraries (a known
    # URL-confusion trick), so we refuse them outright.
    if any(ord(c) <= 0x20 or ord(c) == 0x7F or c == "\\" for c in text):
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    scheme_match = _SCHEME_RE.match(text)
    if not scheme_match:
        raise UrlError("INVALID_URL", "Please include http:// or https:// at the start of the address.")
    scheme = scheme_match.group(0)[:-1].lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlError("UNSUPPORTED_SCHEME", "Only http:// and https:// addresses can be scanned.")
    if not text[scheme_match.end():].startswith("//"):
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    try:
        parts = urlsplit(text)
        explicit_port = parts.port  # raises ValueError on bad ports
        host = parts.hostname       # lower-cased, userinfo/brackets stripped
    except ValueError:
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.") from None

    if not host:
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")
    host = host.rstrip(".")
    if not host:
        raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    # IP literal? Also canonicalise legacy IPv4 spellings ("2130706433",
    # "0x7f.1", "127.1") so they can't sneak past later checks.
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            ip = ipaddress.ip_address(socket.inet_ntoa(socket.inet_aton(host)))
        except (OSError, ValueError):
            ip = None

    if ip is not None:
        host_ascii = str(ip)
    else:
        if host.isascii():
            host_ascii = host
        else:
            try:
                host_ascii = idna.encode(host, uts46=True).decode("ascii")
            except (idna.IDNAError, UnicodeError):
                raise UrlError("INVALID_URL", "That doesn't look like a valid website address.") from None
        if len(host_ascii) > 253 or not _HOST_RE.match(host_ascii):
            raise UrlError("INVALID_URL", "That doesn't look like a valid website address.")

    default_port = _DEFAULT_PORTS[scheme]
    netloc_host = f"[{host_ascii}]" if ip is not None and ip.version == 6 else host_ascii
    netloc = netloc_host + (f":{explicit_port}" if explicit_port and explicit_port != default_port else "")
    path = parts.path or "/"
    query = f"?{parts.query}" if parts.query else ""
    normalized = f"{scheme}://{netloc}{path}{query}"  # fragment + userinfo dropped on purpose

    return ParsedUrl(
        submitted=text,
        normalized=normalized,
        scheme=scheme,
        hostname=host_ascii,
        port=explicit_port or default_port,
        has_userinfo="@" in parts.netloc,
        is_ip_literal=ip is not None,
    )
