"""
Module registry for Veridion.
"""

from __future__ import annotations

from app.modules.base import AnalysisModule, ScanContext
from app.modules.stubs import NotImplementedModule
from app.modules.url_domain import run as run_url_domain
from app.modules.security_config import SecurityConfigModule


class UrlDomainModule:
    id = "url_domain"

    async def run(self, ctx: ScanContext):
        return await run_url_domain(ctx)


def get_modules() -> list[AnalysisModule]:
    return [
        UrlDomainModule(),
        NotImplementedModule("threat_reputation"),
        NotImplementedModule("certificate"),
        SecurityConfigModule(),
        NotImplementedModule("website_behaviour"),
    ]