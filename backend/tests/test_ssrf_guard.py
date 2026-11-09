import asyncio
import ipaddress
import socket

import pytest

from app.config import Settings
from app.utils import ssrf_guard
from app.utils.ssrf_guard import (GuardedTransport, SSRFBlocked, assert_destination_allowed, is_public_ip)
from app.utils.url_tools import parse_url

S = Settings(app_env="development")


@pytest.mark.parametrize("ip", [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0",
    "224.0.0.1", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "64:ff9b::7f00:1",
    "2002:7f00:1::1",
])
def test_non_public_ips_blocked(ip):
    assert not is_public_ip(ipaddress.ip_address(ip))


@pytest.mark.parametrize("ip", ["8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"])
def test_public_ips_allowed(ip):
    assert is_public_ip(ipaddress.ip_address(ip))


def _run(url):
    return asyncio.run(assert_destination_allowed(parse_url(url), S))


@pytest.mark.parametrize("url", [
    "http://127.0.0.1/", "http://localhost/", "http://foo.localhost/", "http://intranet/", "http://printer.local/",
    "http://169.254.169.254/latest/meta-data/", "http://2130706433/", "http://[::1]/",
    "http://example.com:22/", "http://example.com:6379/",
])
def test_blocked_destinations(url):
    with pytest.raises(SSRFBlocked):
        _run(url)


def test_hostname_resolving_to_private_ip_is_blocked(monkeypatch):
    async def go():
        loop = asyncio.get_running_loop()

        async def fake(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", port))]
        monkeypatch.setattr(loop, "getaddrinfo", fake)
        await assert_destination_allowed(parse_url("http://evil.example/"), S)
    with pytest.raises(SSRFBlocked):
        asyncio.run(go())


def test_one_private_answer_among_public_ones_blocks(monkeypatch):
    async def go():
        loop = asyncio.get_running_loop()
        async def fake(host, port, **kw):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port)),
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]
        monkeypatch.setattr(loop, "getaddrinfo", fake)
        await assert_destination_allowed(parse_url("http://rebind.example/"), S)
    with pytest.raises(SSRFBlocked):
        asyncio.run(go())


def test_guarded_transport_builds_with_installed_httpx():
    # Fails loudly if an httpx upgrade changed the internals we rely on.
    GuardedTransport()
