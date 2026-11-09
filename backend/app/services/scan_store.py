"""
app/services/scan_store.py
Tiny in-memory TTL cache so GET /api/scan/{id} is instant right after a scan.
The durable copy lives in Supabase (see SupabaseService.save_scan/get_scan).
Per-process only: with several workers/instances, the Supabase copy is the source of truth.
"""
from __future__ import annotations

import time
from collections import OrderedDict

from app.models.scan import ScanReport


class ScanStore:
    def __init__(self, max_items: int = 500, ttl_seconds: int = 3600) -> None:
        self._items: OrderedDict[str, tuple[float, ScanReport]] = OrderedDict()
        self._max = max_items
        self._ttl = ttl_seconds

    def put(self, report: ScanReport) -> None:
        self._items[report.scan_id] = (time.monotonic(), report)
        self._items.move_to_end(report.scan_id)
        while len(self._items) > self._max:
            self._items.popitem(last=False)

    def get(self, scan_id: str) -> ScanReport | None:
        entry = self._items.get(scan_id)
        if entry is None:
            return None
        stored_at, report = entry
        if time.monotonic() - stored_at > self._ttl:
            del self._items[scan_id]
            return None
        return report
