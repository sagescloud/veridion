"""
app/modules/stubs.py
PLACEHOLDER modules so the API runs end-to-end before P's detection logic lands.
They honestly report "unavailable". They never fabricate a score or a "safe" result.
Delete each stub as P's real module replaces it.
"""
from __future__ import annotations

from app.models.scan import ModuleId, ModuleResult
from app.modules.base import ScanContext, not_run


class NotImplementedModule:
    def __init__(self, module_id: ModuleId):
        self.id: ModuleId = module_id

    async def run(self, ctx: ScanContext) -> ModuleResult:
        return not_run(self.id, "unavailable", "MODULE_NOT_IMPLEMENTED",
                       "This analysis module is not available yet. This is not a clean result.")
