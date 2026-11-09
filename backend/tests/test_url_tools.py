import pytest
from app.utils.url_tools import UrlError, parse_url


def test_normalizes_case_default_port_fragment_and_userinfo():
    p = parse_url("HTTP://User:pw@Example.COM:80/Path?q=1#frag")
    assert p.normalized == "http://example.com/Path?q=1"
    assert p.hostname == "example.com" and p.port == 80 and p.has_userinfo


def test_bare_host_gets_root_path():
    assert parse_url("https://example.com").normalized == "https://example.com/"


def test_idn_becomes_punycode():
    assert parse_url("https://bücher.example/").hostname == "xn--bcher-kva.example"


@pytest.mark.parametrize("raw,code", [
    ("", "INVALID_URL"), ("example.com", "INVALID_URL"), ("http://", "INVALID_URL"),
    ("http://exa mple.com", "INVALID_URL"), ("http://a.com\\@b.com", "INVALID_URL"),
    ("http://example.com:99999/", "INVALID_URL"), ("http:/example.com", "INVALID_URL"),
    ("ftp://example.com", "UNSUPPORTED_SCHEME"), ("javascript:alert(1)", "UNSUPPORTED_SCHEME"),
    ("file:///etc/passwd", "UNSUPPORTED_SCHEME"), ("http://" + "a" * 3000 + ".com", "INVALID_URL"),
])
def test_rejects(raw, code):
    with pytest.raises(UrlError) as e:
        parse_url(raw)
    assert e.value.code == code


@pytest.mark.parametrize("raw,canon", [
    ("http://2130706433/", "127.0.0.1"), ("http://0x7f.1/", "127.0.0.1"),
    ("http://127.1/", "127.0.0.1"), ("http://[::1]/", "::1"),
])
def test_legacy_ip_spellings_are_canonicalised(raw, canon):
    p = parse_url(raw)
    assert p.is_ip_literal and p.hostname == canon
