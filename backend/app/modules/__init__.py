"""
app/modules/__init__.py
Module registry. P: replace stubs here as real modules are finished, e.g.

    from app.modules.url_domain import UrlDomainModule
    ...
    return [UrlDomainModule(), ThreatReputationModule(), ...]
"""
from __future__ import annotations

from app.modules.base import AnalysisModule
from app.modules.stubs import NotImplementedModule


def get_modules() -> list[AnalysisModule]:
    return [
        NotImplementedModule("url_domain"),
        NotImplementedModule("threat_reputation"),
        NotImplementedModule("certificate"),
        NotImplementedModule("security_config"),
        NotImplementedModule("website_behaviour"),
    ]
