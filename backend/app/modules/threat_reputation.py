"""Threat reputation analysis integration point.

The actual detection/provider implementation will be supplied by T.
This adapter guarantees that missing or unavailable intelligence is never
reported as a clean result.
"""

from __future__ import annotations

from app.models.scan import ModuleResult
from app.modules.base import ScanContext, not_run


class ThreatReputationModule:
    id = "threat_reputation"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        return not_run(
            self.id,
            "unavailable",
            "THREAT_INTELLIGENCE_UNAVAILABLE",
            (
                "Threat reputation checks are not connected yet. "
                "No conclusion about whether this URL is malicious can be made."
            ),
        )
