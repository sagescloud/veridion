"""Website security configuration checks.

Checks HTTPS usage and common HTTP security headers.
This is a header-based assessment, not a full penetration test.
"""

from app.utils.ssrf_guard import safe_fetch
from app.models.scan import Evidence, Finding, ModuleResult
from app.modules.base import ScanContext, not_run



class SecurityConfigModule:
    id = "security_config"

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
                "SECURITY_FETCH_FAILED",
                "The website could not be fetched safely for security-header analysis.",
            )

        headers = {
            key.lower(): value.strip()
            for key, value in response.headers.items()
        }

        findings = []
        score = 0

        def add_finding(
            code: str,
            severity: str,
            title: str,
            description: str,
            evidence: list[Evidence],
            points: int,
        ) -> None:
            nonlocal score
            findings.append(
                Finding(
                    id=code.lower(),
                    code=code,
                    type="misconfiguration",
                    severity=severity,
                    title=title,
                    description=description,
                    evidence=evidence,
                )
            )
            score += points

        # Assess the final URL after redirects, not just the submitted URL.
        final_url = response.final_url.lower()
        is_https = final_url.startswith("https://")

        if not is_https:
            add_finding(
                code="HTTPS_NOT_ENFORCED",
                severity="high",
                title="HTTPS is not used",
                description=(
                    "The final website URL uses HTTP rather than HTTPS. "
                    "Traffic may be exposed to interception or modification."
                ),
                evidence=[
                    Evidence(label="Final URL", value=response.final_url)
                ],
                points=35,
            )

        # HSTS is meaningful only for HTTPS responses.
        if is_https and "strict-transport-security" not in headers:
            add_finding(
                code="HSTS_MISSING",
                severity="medium",
                title="HSTS header missing",
                description=(
                    "The HTTPS response does not include a Strict-Transport-Security "
                    "header to instruct browsers to prefer secure connections."
                ),
                evidence=[
                    Evidence(
                        label="Strict-Transport-Security",
                        value="Not present",
                    )
                ],
                points=15,
            )

        if "content-security-policy" not in headers:
            add_finding(
                code="CSP_MISSING",
                severity="medium",
                title="Content Security Policy missing",
                description=(
                    "No Content-Security-Policy header was detected. "
                    "A suitable policy can help reduce certain cross-site scripting "
                    "and content-injection risks."
                ),
                evidence=[
                    Evidence(
                        label="Content-Security-Policy",
                        value="Not present",
                    )
                ],
                points=15,
            )

        if headers.get("x-content-type-options", "").lower() != "nosniff":
            add_finding(
                code="CONTENT_TYPE_OPTIONS_MISSING",
                severity="low",
                title="Content type protection missing",
                description=(
                    "The response does not set X-Content-Type-Options to nosniff."
                ),
                evidence=[
                    Evidence(
                        label="X-Content-Type-Options",
                        value=headers.get("x-content-type-options", "Not present"),
                    )
                ],
                points=8,
            )

        has_frame_protection = (
            "x-frame-options" in headers
            or "frame-ancestors" in headers.get("content-security-policy", "").lower()
        )

        if not has_frame_protection:
            add_finding(
                code="CLICKJACKING_PROTECTION_MISSING",
                severity="low",
                title="Clickjacking protection missing",
                description=(
                    "No X-Frame-Options header or CSP frame-ancestors directive "
                    "was detected."
                ),
                evidence=[
                    Evidence(
                        label="X-Frame-Options",
                        value=headers.get("x-frame-options", "Not present"),
                    )
                ],
                points=8,
            )

        if "referrer-policy" not in headers:
            add_finding(
                code="REFERRER_POLICY_MISSING",
                severity="low",
                title="Referrer Policy missing",
                description=(
                    "The response does not specify a Referrer-Policy header "
                    "to control referrer information sent by browsers."
                ),
                evidence=[
                    Evidence(
                        label="Referrer-Policy",
                        value="Not present",
                    )
                ],
                points=5,
            )

        if "permissions-policy" not in headers:
            add_finding(
                code="PERMISSIONS_POLICY_MISSING",
                severity="info",
                title="Permissions Policy missing",
                description=(
                    "No Permissions-Policy header was detected. "
                    "This header can restrict access to selected browser features."
                ),
                evidence=[
                    Evidence(
                        label="Permissions-Policy",
                        value="Not present",
                    )
                ],
                points=2,
            )

        return ModuleResult(
            id=self.id,
            status="completed",
            risk_score=min(score, 100),
            status_reason=None,
            findings=findings,
            details={
                "final_url": response.final_url,
                "http_status": response.status_code,
                "checks_performed": 7,
                "assessment_scope": "HTTP security headers and HTTPS usage",
            },
        )