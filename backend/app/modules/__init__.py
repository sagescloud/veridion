"""
Module registry for Veridion.
"""

from __future__ import annotations

from app.modules.base import AnalysisModule, ScanContext
from app.modules.stubs import NotImplementedModule
from app.modules.url_domain import run as run_url_domain
from app.modules.security_config import SecurityConfigModule
from app.modules.website_behaviour import WebsiteBehaviourModule
from app.modules.certificate import CertificateModule
from app.modules.threat_reputation import ThreatReputationModule


class UrlDomainModule:
    id = "url_domain"

    async def run(self, ctx: ScanContext):
        return await run_url_domain(ctx)


def get_modules() -> list[AnalysisModule]:
    return [
        UrlDomainModule(),
        ThreatReputationModule(),
        CertificateModule(),
        SecurityConfigModule(),
        WebsiteBehaviourModule(),
    ]