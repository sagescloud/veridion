
"""Website behaviour analysis.

Inspects fetched HTML for potentially suspicious browser behaviour.
This is a lightweight static assessment, not a malware sandbox.
"""

from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from app.models.scan import Evidence, Finding, ModuleResult
from app.modules.base import ScanContext, not_run
from app.utils.ssrf_guard import safe_fetch


class BehaviourParser(HTMLParser):
    """Extract selected behaviour indicators from HTML."""

    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.external_scripts = []
        self.iframes = []
        self.meta_refreshes = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        if tag == "form":
            self.current_form = {
                "action": attrs.get("action", ""),
                "method": attrs.get("method", "get").lower(),
                "password": False,
            }

        elif tag == "input" and self.current_form is not None:
            if attrs.get("type", "").lower() == "password":
                self.current_form["password"] = True

        elif tag == "script":
            src = attrs.get("src")
            if src:
                self.external_scripts.append(src)

        elif tag == "iframe":
            self.iframes.append({
                "src": attrs.get("src", ""),
                "style": attrs.get("style", "").lower(),
                "width": attrs.get("width", ""),
                "height": attrs.get("height", ""),
            })

        elif tag == "meta":
            if attrs.get("http-equiv", "").lower() == "refresh":
                self.meta_refreshes.append(attrs.get("content", ""))

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None


def _origin(url: str):
    """Return a normalized origin for URL comparison."""
    try:
        parsed = urlsplit(url)
        port = parsed.port

        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80

        return (
            parsed.scheme.lower(),
            (parsed.hostname or "").lower(),
            port,
        )
    except ValueError:
        return None


def _is_external(target: str, base_url: str) -> bool:
    resolved = urljoin(base_url, target)
    target_origin = _origin(resolved)
    base_origin = _origin(base_url)

    return (
        target_origin is not None
        and base_origin is not None
        and target_origin != base_origin
    )


def _is_hidden_iframe(iframe: dict) -> bool:
    style = iframe["style"].replace(" ", "")

    hidden_style = (
        "display:none" in style
        or "visibility:hidden" in style
    )

    zero_size = (
        iframe["width"] == "0"
        or iframe["height"] == "0"
    )

    return hidden_style or zero_size


class WebsiteBehaviourModule:
    id = "website_behaviour"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        try:
            response = await safe_fetch(
                ctx.http,
                ctx.url.normalized,
                ctx.settings,
            )
        except Exception:
            return not_run(
                self.id,
                "failed",
                "BEHAVIOUR_FETCH_FAILED",
                "The website could not be fetched safely for behaviour analysis.",
            )

        content_type = response.headers.get("content-type", "").lower()

        if "html" not in content_type:
            return not_run(
                self.id,
                "unavailable",
                "HTML_CONTENT_UNAVAILABLE",
                "The fetched response did not contain an HTML document to analyse.",
            )

        parser = BehaviourParser()

        try:
            parser.feed(response.body.decode("utf-8", errors="replace"))
            parser.close()
        except Exception:
            return not_run(
                self.id,
                "failed",
                "HTML_PARSE_FAILED",
                "The website HTML could not be analysed.",
            )

        findings = []
        score = 0

        def add_finding(
            code: str,
            severity: str,
            title: str,
            description: str,
            evidence: list[Evidence],
            points: int,
        ):
            nonlocal score

            findings.append(
                Finding(
                    id=code.lower(),
                    code=code,
                    type="suspicious_indicator",
                    severity=severity,
                    title=title,
                    description=description,
                    evidence=evidence,
                )
            )
            score += points

        final_url = response.final_url

        # 1. Password form submitted over insecure HTTP.
        for form in parser.forms:
            if not form["password"]:
                continue

            action = urljoin(final_url, form["action"] or final_url)
            action_scheme = urlsplit(action).scheme.lower()

            if action_scheme == "http":
                add_finding(
                    code="INSECURE_PASSWORD_SUBMISSION",
                    severity="high",
                    title="Password submitted over HTTP",
                    description=(
                        "A form containing a password field submits data "
                        "to an HTTP destination. Credentials may be exposed "
                        "during transmission."
                    ),
                    evidence=[
                        Evidence(label="Form action", value=action),
                        Evidence(label="Form method", value=form["method"]),
                    ],
                    points=35,
                )

        # 2. Forms submitting data to a different origin.
        external_forms = []

        for form in parser.forms:
            action = urljoin(final_url, form["action"] or final_url)

            if _is_external(action, final_url):
                external_forms.append(action)

        if external_forms:
            add_finding(
                code="EXTERNAL_FORM_SUBMISSION",
                severity="medium",
                title="External form submission detected",
                description=(
                    "One or more forms submit data to a different origin. "
                    "This may be legitimate, but the destination should be reviewed."
                ),
                evidence=[
                    Evidence(
                        label="External form destinations",
                        value=", ".join(external_forms[:5]),
                    )
                ],
                points=15,
            )

        # 3. Hidden iframes.
        hidden_iframes = [
            iframe for iframe in parser.iframes
            if _is_hidden_iframe(iframe)
        ]

        if hidden_iframes:
            add_finding(
                code="HIDDEN_IFRAME_DETECTED",
                severity="medium",
                title="Hidden iframe detected",
                description=(
                    "The page contains one or more hidden or zero-sized "
                    "iframes. Hidden frames can be legitimate, but may "
                    "also be used to load unexpected third-party content."
                ),
                evidence=[
                    Evidence(
                        label="Hidden iframe count",
                        value=str(len(hidden_iframes)),
                    )
                ],
                points=15,
            )

        # 4. External scripts.
        external_scripts = [
            src for src in parser.external_scripts
            if _is_external(src, final_url)
        ]

        if len(external_scripts) >= 10:
            add_finding(
                code="EXCESSIVE_EXTERNAL_SCRIPTS",
                severity="low",
                title="Large number of external scripts",
                description=(
                    "The page loads scripts from many external sources. "
                    "Third-party scripts increase the website's external "
                    "dependency and supply-chain exposure."
                ),
                evidence=[
                    Evidence(
                        label="External script count",
                        value=str(len(external_scripts)),
                    )
                ],
                points=8,
            )

        # 5. Automatic browser redirects through meta refresh.
        if parser.meta_refreshes:
            add_finding(
                code="META_REFRESH_REDIRECT",
                severity="low",
                title="Automatic meta refresh detected",
                description=(
                    "The HTML contains a meta refresh directive that may "
                    "automatically redirect or reload the browser."
                ),
                evidence=[
                    Evidence(
                        label="Meta refresh directives",
                        value=str(len(parser.meta_refreshes)),
                    )
                ],
                points=7,
            )

        return ModuleResult(
            id=self.id,
            status="completed",
            risk_score=min(score, 100),
            status_reason=None,
            findings=findings,
            details={
                "final_url": final_url,
                "http_status": response.status_code,
                "forms_detected": len(parser.forms),
                "external_scripts_detected": len(external_scripts),
                "iframes_detected": len(parser.iframes),
                "hidden_iframes_detected": len(hidden_iframes),
                "meta_refreshes_detected": len(parser.meta_refreshes),
                "checks_performed": 5,
                "assessment_scope": "Static HTML and browser behaviour indicators",
            },
        )
