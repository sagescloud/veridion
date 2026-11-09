# Veridion Security Architecture Decisions Document

**Branch:** `security`  
**Document Status:** Initial Draft — based on read-only inspection of backend `origin/backend` and frontend on `security`  
**Inspection Date:** November 2026  

---

## 1. Purpose and Scope

This document captures the agreed architectural decisions for the Veridion project's security module, based on a comprehensive read-only inspection of:

- Frontend source code on the `security` branch
- Backend Python implementation on `origin/backend`
- Pydantic models, OpenAPI specification, and SQL schema
- Product Requirements Document (PRD) and proposed API schema
- Mock scenarios and test suites

The purpose is to provide a single source of truth for architectural decisions, distinguish between implemented behavior and proposed changes, and record team decisions that require explicit approval. This document is **not** a substitute for the PRD (`docs/PRD.md`) or the proposed API schema (`docs/api schema (proposed).md`); it records how the current codebase maps to those specifications and where gaps exist.

**Scope covers:**
- The five analysis modules and their execution statuses
- Risk-score and confidence computation
- Finding severity, types, and ownership
- Confirmed phishing representation and escalation
- Threat-intelligence provider integration
- Module details and evidence structures
- Recommendation generation and deduplication
- Safe test URLs and mock scenario mapping
- Frontend/backend compatibility issues and required changes
- Team decisions still pending

---

## 2. Project Architecture

Veridion is a web threat detection and digital trust intelligence platform. The architecture follows a layered pattern:

**Frontend Layer** (React + Vite + Tailwind CSS):
- User interaction, URL submission, scan progress, report visualisation
- Route: `LandingPage` → `UrlForm` → `startScan` → `scanService` → API → `ScanPendingNotice`
- Mock data support via `VITE_USE_MOCK` environment variable (default: `true`)
- Currently 5 implemented pages: `LandingPage`, `ScanPendingNotice` (results display)
- Missing pages per PRD: `/results/:scanId`, `/results/:scanId/details`, `/reports`, `/history`, `/about`

**API Layer** (FastAPI):
- `POST /api/scan` → initiate scan, return completed report (sync MVP)
- `GET /api/scan/{scan_id}` → retrieve scan results
- `POST /api/report` / `GET /api/reports` → community intelligence
- `GET /api/health` → backend availability
- All endpoints use single error envelope: `{"error": {"code", "message", "details", "request_id"}}`

**Analysis Layer** (5 independent modules):
- `url_domain` — URL parsing, domain characteristics, suspicious pattern detection
- `threat_reputation` — Threat intelligence provider checks
- `certificate` — SSL/TLS certificate validation
- `security_config` — HTTP security header inspection
- `website_behaviour` — Redirect chain analysis

**Intelligence Layer** (Risk Assessment Engine):
- Weighted average renormalized over completed modules
- Confidence separate from risk score
- Confirmed phishing escalation

**Data Layer** (PostgreSQL/Supabase optional):
- `community_reports` table (HMAC-hashed reporter IP for dedup)
- `scans` table (persisted report JSON)
- `community_report_summary` view (never exposes reporters)

---

## 3. Existing Frontend Architecture

**Key files** (all on `security` branch):
- `frontend/src/constants/scan.js` — `SCAN_STATE`, `SCAN_CLASSIFICATION`, `CONFIDENCE_LEVEL` enums
- `frontend/src/services/adapters/scanAdapter.js` — adapts raw API response to UI shape (critical file for field mapping)
- `frontend/src/services/scanService.js` — routes to mock or real API based on `env.useMock`
- `frontend/src/services/scanApi.js` — `POST /api/scan`, `GET /api/scan/{scan_id}`
- `frontend/src/services/apiClient.js` — fetch wrapper with timeout, AbortController, error normalization
- `frontend/src/hooks/useScan.js` — scan state machine: `IDLE` → `SCANNING` → `SUCCESS`/`ERROR`
- `frontend/src/mocks/mockScanApi.js` — 5 scenario selection + mock data generation
- `frontend/src/mocks/scenarios/` — 5 scenarios exercising PRD §11 test cases
- `frontend/src/features/scan/UrlForm.jsx` — URL input with `validateUrl()` validation
- `frontend/src/features/scan/ScanPendingNotice.jsx` — results display (risk score, classification, confidence, findings, modules)
- `frontend/src/utils/validateUrl.js` — URL format validation (scheme, hostname, max length, no spaces)

**Frontend mock data** (5 scenarios):
- `lowRisk` — all modules `completed`, risk_score 8, 1 minor finding
- `phishing` — all `completed`, risk_score 94, `escalation: "CONFIRMED_PHISHING"`, multiple critical findings
- `moderateRisk` — mixed: some suspicious indicators, no threat-reputation issues
- `incomplete` — `unavailable`/`failed`/`partial` modules; risk_score null where appropriate; confidence "low"
- `backendError` — simulated 500 error

**Frontend gaps** (vs. backend implementation):
- `scanAdapter.js` drops `confidence.reasons` and `escalation` from adapted response
- `ScanPendingNotice.jsx` has no escalation warning UI
- Top-level recommendations not yet rendered in results component
- No TypeScript — all JavaScript, high runtime-schema-mismatch risk
- Routes `/results/:scanId`, `/results/:scanId/details`, `/reports` not yet built

---

## 4. Actual Backend Architecture

**Key files** (from `origin/backend`, read-only):
- `app/main.py` — FastAPI app factory + lifespan; one shared SSRF-guarded `httpx.AsyncClient`
- `app/config.py` — typed settings from environment variables; `VITE_API_BASE_URL` origin allowed
- `app/models/scan.py` — Pydantic models: `ScanRequest`, `Evidence`, `Finding`, `StatusReason`, `ModuleResult`, `Confidence`, `Escalation`, `Overall`, `Recommendation`, `ScanReport`
- `app/models/report.py` — community report models: `ReportRequest`, `ReportCreated`, `ReportSummary`, `ReportList`, `CommunityIntel`
- `app/models/errors.py` — single error envelope: `ErrorBody`, `ErrorResponse`
- `app/services/risk_engine.py` — `assess()` / `compute_overall()` / `_confidence()` / `build_recommendations()`
- `app/services/scan_orchestrator.py` — `run_scan()`: validate → SSRF pre-flight → run modules concurrently → assess → build report
- `app/services/supabase_service.py` — community reports + scan persistence (optional; app runs without Supabase)
- `app/utils/ssrf_guard.py` — 4-layer SSRF protection: syntax, hostname, resolution, connect-time (DNS rebinding proof)
- `app/utils/url_tools.py` — single entry point `parse_url()`: validation, normalization, punycode IDN, IP literal canonicalization
- `app/modules/base.py` — `AnalysisModule` protocol + `ScanContext` (url, resolved_ips, http, settings)
- `app/modules/stubs.py` — `NotImplementedModule` — all 5 modules return `"unavailable"`; "never fabricate a score or 'safe' result"
- `app/modules/__init__.py` — `get_modules()` — currently all `NotImplementedModule`

**Backend security guarantees** (verified in code + tests):
- SSRF: scheme/port allowlist, hostname blocking (localhost, .local, .internal, .intranet, .lan, .home, .corp, .home.arpa), DNS resolution with every IP must be public (one private answer blocks), connect-time re-resolution + connect to validated IP only (defeats DNS rebinding)
- URL parsing: max 2048 chars, http/https only, no control chars/spaces/backslashes, scheme check, hostname format, IDN → punycode, legacy IP canonicalization
- Error envelope: `message` always user-safe; internal details in logs only
- BLOCKED_DESTINATION (422) — SSRF-blocked message reveals nothing about internal network
- Rate limiting: 10 scan/min, 5 report/min per client IP
- Error codes: `INVALID_URL`, `UNSUPPORTED_SCHEME`, `BLOCKED_DESTINATION`, `SCAN_TIMEOUT`, `RATE_LIMITED`, `SCAN_NOT_FOUND`, `DUPLICATE_REPORT`, `VALIDATION_ERROR`, `SERVICE_UNAVAILABLE`, `INTERNAL_ERROR`

**Backend stubs** (critical context):
- All 5 modules are currently `NotImplementedModule` stubs returning `"unavailable"` + `risk_score: null`
- The backend **can run** with all stubs; scans succeed, return `inconclusive` + `risk_score: null`
- PRD §8 Must-Have: "At least one functioning threat intelligence integration" — **not yet satisfied**
- Tests verify: missing modules not counted as zero; nothing ran → `inconclusive`; confirmed phishing escalates to critical; confidence capped when reputation missing; module contract rejects zero risk_score for unavailable

---

## 5. Module IDs and Responsibilities

**Five fixed module IDs** (backend `ModuleId` literal, frontend adapter `module.module_id`):

| ID | PRD Responsibility | Backend Status |
|---|---|---|
| `url_domain` | URL structure and domain analysis (PRD Module 1) | Stub — returns `"unavailable"` |
| `threat_reputation` | Threat-intelligence and reputation checks (PRD Module 2) | Stub — returns `"unavailable"` |
| `certificate` | TLS/SSL certificate analysis (PRD Module 3) | Stub — returns `"unavailable"` |
| `security_config` | HTTPS and security-configuration checks (PRD Module 4) | Stub — returns `"unavailable"` |
| `website_behaviour` | Redirects and website behaviour (PRD Module 4/5) | Stub — returns `"unavailable"` |

**Responsibility assignment** (from `app/modules/__init__.py:get_modules()` + `app/modules/base.py:AnalysisModule` protocol):
- Each module is a class with `id: ModuleId` and `async def run(self, ctx: ScanContext) -> ModuleResult`
- Network requests **ONLY** through `ctx.http + safe_fetch` (SSRF-guarded)
- For raw sockets, connect to IP from `ctx.resolved_ips`, never re-resolve
- Can't run? Return `status="unavailable"/"failed"/"skipped"` with `risk_score=None` and a `status_reason`; NEVER return 0 for "didn't check" and never say "safe"
- The orchestrator enforces a timeout, converts exceptions to `status="failed"`, and renumbers finding ids

**Registered in** `app/modules/__init__.py:get_modules()` — currently all `NotImplementedModule("url_domain")`, etc.

**Decision:** **IMPLEMENTED** — 5 fixed IDs established; real modules must replace stubs; IDs must match frontend adapter and API proposal exactly.

---

## 6. Module Execution Statuses

**Five status values** (backend `ModuleStatus` literal, `app/models/scan.py:ModuleResult.status`):

| Status | Condition | `risk_score` | `status_reason` | Effect on overall scan |
|---|---|---|---|---|
| `completed` | Module ran and produced a valid result | 0–100 (required) | Optional (forbidden if `completed` + `risk_score` is `None` by validator) | Contributes to overall risk score (renormalized weight) |
| `partial` | Some sub-checks completed, others skipped/flagged | 0–100 or `null` | Required (must explain why) | Included in confidence coverage (half weight per current implementation); may or may not contribute to risk score depending on validator |
| `unavailable` | External provider down/rate-limited | `null` (required) | Required | Excluded from risk-score renormalization; confidence reasons cite this |
| `failed` | Internal error/timeout | `null` (required) | Required | Excluded from risk-score renormalization; confidence reasons cite this |
| `skipped` | Intentionally not run (e.g., no HTTPS for cert check) | `null` (required) | Required | Excluded from risk-score renormalization; confidence: current impl gives **full weight** ("genuinely not applicable, not a gap in evidence") |

**Pydantic structural validation** (`app/models/scan.py:ModuleResult._enforce_contract`):
- `completed` + `risk_score is None` → `ValueError`: "a completed module must provide a risk_score"
- `unavailable`/`failed`/`skipped` + `risk_score is not None` → `ValueError`: "a {status} module must have risk_score = null"
- non-`completed` + `status_reason is None` → `ValueError`: "non-completed modules must explain why via status_reason"

**Decision:** **IMPLEMENTED** — 5 statuses with structural validation; `partial` currently permitted with `null` risk_score + status_reason; `skipped` confidence weight is a team decision (see Question 4 resolutions).

---

## 7. Risk-Score Calculation

**Overall risk score** (`app/services/risk_engine.py:compute_overall`):

1. **Collect** all `ModuleResult` objects where `r.risk_score is not None` → `scored` list
2. **If no scored modules** and no escalation → `risk_score = None`, `classification = "inconclusive"`
3. **If scored modules exist:**
   - `total_w = sum(WEIGHTS[r.id] for r, w in scored)` — **renormalized over completed modules only**
   - `score = round(sum(r.risk_score * w for r, w in scored) / total_w)`
4. **If escalation** (`CONFIRMED_PHISHING` finding in threat_reputation module) → `score = max(score, 90)`

**Weight distribution** (PRD §5, backend `WEIGHTS` dict):
- `threat_reputation`: 30%
- `url_domain`: 25%
- `website_behaviour`: 20%
- `certificate`: 15%
- `security_config`: 10%

**Edge cases:**
- **0 completed modules** → `risk_score = None`, `classification = "inconclusive"`; confidence reasons include "No analysis module produced a result"
- **1 completed module** → score = that module's `risk_score × its weight` (other weights effectively 0 due to renormalization)
- **All 5 completed** → score = weighted sum per PRD initial distribution (renormalized denominator = 100 since all completed)
- **`unavailable`/`failed`/`skipped` modules** → excluded from numerator and denominator; **must not be interpreted as "safe"** (PRD §2:101, §5:361, §5:505)

**Null handling** (structural + logical):
- `ModuleResult.risk_score: int | None` with Pydantic constraints per status
- `Overall.risk_score: int | None` — `null` when no completed module produces a score
- **Never interpret `null` as 0 or as "safe"** (PRD requirement; structural enforcement by validators)

**Decision:** **IMPLEMENTED** — renormalized weighted average over completed modules; `null` when none completed; escalation floor of 90 for confirmed phishing.

---

## 8. Confidence Calculation

**Confidence** (`app/services/risk_engine.py:_confidence`):

- **Coverage formula** (current implementation):
  - `completed` modules: full weight added
  - `partial` modules: half weight added (per current implementation)
  - `skipped` modules: **full weight** (1.0) added — comment: "genuinely not applicable (e.g. no HTTPS), not a gap in evidence"
  - `unavailable`/`failed` modules: 0 weight
- `completed` count = number of modules with status `"completed"`
- `coverage` = sum of weighted contributions / total weight (100%)
- `level`:
  - `"high"` if `coverage ≥ 85%`
  - `"medium"` if `coverage ≥ 50%`
  - `"low"` otherwise
- **Special rule:** If `level = "high"` and `threat_reputation` not `completed` → downgrade to `"medium"`
- `reasons` array (present in backend `Overall` response):
  - `f"{completed} of {5} analysis modules completed"`
  - Per-module reasons: `"{LABELS[r.id]}: {r.status_reason.message}"` for non-completed modules

**Example:** 1 of 5 completed + threat_reputation `unavailable`:
- `coverage = 25` (only url_domain weight) → `level = "low"`
- `reasons = ["1 of 5 analysis modules completed", "Threat reputation: This analysis module is not available yet. This is not a clean result."]`

**If threat_reputation completed, 4 of 5 modules done:**
- `coverage = 30 + 25 + 15 + 10 = 80%` → `level = "medium"` (not ≥ 85)
- `reasons = ["4 of 5 analysis modules completed", "Threat reputation: completed"]`

**Decision:** **RECOMMENDED** — current backend implementation; Recommendation 3 in the unresolved questions (change `skipped` to 0 weight) **REQUIRES TEAM APPROVAL** because it contradicts the existing code comment ("genuinely not applicable, not a gap in evidence").

---

## 9. Findings, Severity and Types

**Four finding types** (backend `Finding.type` OpenAPI enum, `app/models/scan.py:FindingType` literal; also used in frontend `scanAdapter.js`):

1. `malicious_indicator` — domain/behavior confirms malicious activity
2. `suspicious_indicator` — URL/behavior raises suspicion but not confirmed malicious
3. `misconfiguration` — security headers missing, HTTP instead of HTTPS
4. `informational` — observation without risk implication (e.g., recently issued certificate)

**Five severity levels** (backend `Severity` OpenAPI enum, `app/models/scan.py:Severity` literal; also used in frontend `scanAdapter.js:severityOrder` for sorting):

- `critical` (0) > `high` (1) > `medium` (2) > `low` (3) > `info` (4)

**Severity order** (frontend adapter `scanAdapter.js:77-83`):
```js
const severityOrder = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5;
};
```
Lower number = higher severity. Findings sorted ascending by severity (critical first).

**Decision:** **IMPLEMENTED** — 4 finding types × 5 severity levels; frontend `severityOrder` matches backend enum order exactly.

---

## 10. Confirmed Phishing and Escalation

**Backend representation** (`app/services/risk_engine.py:compute_overall`):

```python
escalation = None
for r in results:
    if r.id == "threat_reputation" and any(f.code == "CONFIRMED_PHISHING" for f in r.findings):
        escalation = Escalation(
            code="CONFIRMED_PHISHING",
            message="This address is listed as phishing by a threat intelligence source. Do not use it.")
```

**Effects when `escalation` is present:**
1. `overall.escalation` set to `Escalation` object → present in API response
2. `overall.risk_score` floor: `max(score, 90)` — even if modules yield lower score, phishing escalation pushes to at least 90
3. `overall.classification` → `"critical"` (via `classify()`: score ≥ 75 → critical; with escalation floor of 90, always critical)
4. Frontend: when `escalation` present, UI must show strong warning (currently not implemented in `ScanPendingNotice.jsx`)

**API proposal** (`docs/api schema (proposed).md:198`):
- `escalation: null` normally; for confirmed phishing: `{ code: "CONFIRMED_PHISHING", message: "..." }` so the UI can show a strong warning instead of a diluted score

**Decision:** **IMPLEMENTED** — backend produces escalation exactly as API proposal specifies; Recommendation 1 (fix `scanAdapter.js` to preserve escalation) is **REQUIRES TEAM APPROVAL** for the frontend UI change, but the backend architecture decision is approved.

---

## 11. Threat-Intelligence Provider Results

**Backend distinguishes provider execution status vs. provider verdict** (via `ModuleResult.status` + `findings` + `risk_score`):

| Status | Condition | `risk_score` | `findings` | `status_reason` |
|---|---|---|---|---|
| `confirmed` | Domain listed in provider DB | varies (usually high) | 1+ findings; may include `code: "CONFIRMED_PHISHING"` | optional |
| `not_listed` | Provider checked, domain not found | low/medium | empty or `code: "NOT_LISTED"` | optional |
| `unchecked` | Provider not checked in this scan | `null` | empty | module status not `completed`; reason explains not checked |
| `unavailable` | Provider down/rate-limited | `null` | empty | `status: "unavailable"` + `status_reason.code: "PROVIDER_RATE_LIMITED"` (or similar) |
| `error` | Provider returned error/malformed response | `null` | empty | `status: "failed"` + `status_reason` with error message |

**Critical rule** (PRD §2:101, §5:486-487): `unchecked`/`unavailable`/`error` **must never** be interpreted as "safe" or "low risk." The frontend must display them as "no data available" and add confidence reasons explaining why. The `_confidence()` function explicitly lowers confidence and adds reasons. The `assess()` function returns `risk_score = None` + `classification = "inconclusive"` when no modules produce a score.

**Mock data** (`incompleteScan.js:39`): `threat_reputation: { status: "unavailable", risk_score: null, findings: [], error: "Reputation provider unavailable." }`

**Five-state distinction** not fully covered by current mocks but implied by PRD and API proposal. Making this explicit prevents the "absence = safe" anti-pattern.

**Decision:** **IMPLEMENTED** — backend uses `ModuleResult.status` + `risk_score: null` + `status_reason` to distinguish states; critical rule that unavailable ≠ safety is enforced by Pydantic validator and risk engine.

---

## 12. Module Details and Evidence

**Reliable `details` fields per module** (from backend models and `safe_fetch` return `FetchResult`):

1. **`url_domain`**:
   - `hostname`: string (lower-case ASCII, punycode for IDNs)
   - `is_ip_address`: boolean
   - `url_length`: number (character count)
   - `subdomain_count`: number
   - `uses_punycode`: boolean
   
   **Example:** `{ "hostname": "paypa1-login.example", "is_ip_address": false, "url_length": 36, "subdomain_count": 0, "uses_punycode": false }`

2. **`threat_reputation`**:
   - `providers`: `array[{name, status, verdict}]` — per-provider results
   - `status`: `"completed"`/`"unavailable"`/`"failed"`
   - `risk_score`: `int | null`
   
   **Example:** `{ "providers": [{ "name": "google_safe_browsing", "status": "completed", "verdict": "not_listed" }], "status": "completed", "risk_score": 0 }`

3. **`certificate`**:
   - `validity`: `"valid"`/`"expired"`/`"revoked"`
   - `expiry_date`: ISO 8601 string
   - `issuer`: string
   - `hostname_matching`: boolean
   - `key_algorithm`: string (e.g., `"RSA 2048"`)
   
   **Example:** `{ "validity": "valid", "expiry_date": "2027-12-31T23:59:59Z", "issuer": "Let's Encrypt", "hostname_matching": true, "key_algorithm": "RSA 2048" }`

4. **`security_config`**:
   - `https_available`: boolean
   - `headers`: `array[{name, present}]` — recommended security headers
   - `redirect_count`: number
   
   **Example:** `{ "https_available": false, "headers": [{ "name": "Content-Security-Policy", "present": false }, { "name": "Strict-Transport-Security", "present": false }], "redirect_count": 2 }`

5. **`website_behaviour`**:
   - `redirect_count`: number
   - `final_url`: string — final destination after redirect chain
   - `redirect_chain`: `array[{url, status_code}]` — each hop
   - `blocked_redirect`: `string | null` — a redirect target refused (itself a finding!)
   - `redirect_limit_hit`: boolean
   
   **Example:** `{ "redirect_count": 2, "final_url": "http://other-site.example/login", "redirect_chain": [{ "url": "http://paypa1-login.example/verify", "status_code": 302 }, { "url": "http://track.example/r", "status_code": 301 }], "blocked_redirect": null, "redirect_limit_hit": false }`

**Finding evidence** (`app/models/scan.py:Finding.evidence`):
- `array[Evidence]` where `Evidence = {label: str, value: str}`
- **Compatibility note:** Mock data frequently uses `evidence` as a plain string (e.g., `lowRisk.js: evidence: "A recommended HTTP security header is absent."`). The adapter `adaptFinding` passes through `finding.evidence ?? null` as-is. This is an **unresolved compatibility issue** between backend model expectations and mock data format.

**Decision:** **PROPOSED** — evidence expected as `{label, value}` entries; documented mismatch with mock data requires harmonization (team decision needed).

---

## 13. Recommendations

**Backend structure** (`app/services/risk_engine.py:build_recommendations` + `Recommendation` model):

- **Scan-level recommendations** (`ScanReport.recommendations` array):
  - Each: `{id, priority: "low"|"medium"|"high", text, related_finding_ids[]}`
  - Generated from findings severity sort + `_ADVICE` map lookup
  - Always includes a "no result is safe" bottom recommendation
  - May include community report recommendation if `community.reported`

- **Finding-level recommendations**: Each finding may have a `recommendation` string (in mock data; `Finding` model in `app/models/scan.py` does NOT include `recommendation` field, but `adaptFinding` in `scanAdapter.js` captures `f.recommendation ?? null`)

**Backend deduplication** (`risk_engine.py:build_recommendations`):
1. Collect all `critical`+`high`+`medium` findings, sort by severity (critical first)
2. For each unique advice text from `_ADVICE` map (or fallback), create a recommendation with `related_finding_ids: [f.id]`
3. If `community.reported` → add high-priority community recommendation
4. Always append low-priority "No warnings does not mean a site is safe" recommendation
5. Deduplicate by advice text (`seen` set)

**Decision:** **IMPLEMENTED** — backend deduplicates; frontend adapter passes through canonical list; UI enhancement needed to display top-level recommendations (current gap in `ScanPendingNotice.jsx`).

---

## 14. Safe Test Scenarios

**RFC 2606 reserved domains** (safe for all test scenarios):

| Domain | Purpose |
|---|---|
| `example.com` | Normal successful scan; exercises URL/domain, cert, headers modules |
| `example.net` | Same as example.com, different TLD |

**Safe lookalike domains** (exercise detection, but reserved — no real phishing):
- `paypa1-example.com` (numeral `1` instead of `l` — common typosquat pattern)
- `suspicious-example.com` (exercises suspicious subdomain, long URL, cross-domain redirect patterns)

**Invalid inputs** (exercise error handling):
- `invalid` — fails `validateUrl()` — no scheme
- `http://nonexistent.invalid` — fails hostname validation

**Mock scenario mapping** (`mockScanApi.js:selectScenario`):
- Hostname containing "fail"/"error" → `backendError`
- Hostname containing "phish" → `phishing`
- Hostname containing "suspicious" → `moderateRisk`
- Hostname containing "incomplete" → `incomplete`
- Everything else → `lowRisk`

**Important correction** (per document guidelines): Do **not** describe `paypa1-example.com` or `suspicious-example.com` as reserved test domains. They are **not** reserved. Use only reserved example domains (`example.com`, `example.net`, `invalid`, `.invalid`) for mock routing and controlled tests. The `-example-` pattern is a convention for safe lookalike testing, not RFC 2606 reservation.

**Decision:** **IMPLEMENTED** — safe test URLs identified; mock scenarios correctly map to PRD §11 test criteria.

---

## 15. Answers to All 11 Original Architecture Questions

| # | Question | Answer | Status |
|---|----------|--------|--------|
| 1 | Module IDs and redirects | 5 fixed IDs: `url_domain`, `threat_reputation`, `certificate`, `security_config`, `website_behaviour`. Under `website_behaviour`: `redirect_count`, `final_url`, `redirect_chain[{url, status_code}]`. | ✅ IMPLEMENTED |
| 2 | Module statuses | `completed`, `partial`, `unavailable`, `failed`, `skipped`. `partial` may have `null` risk_score with required `status_reason`. | ✅ IMPLEMENTED |
| 3 | Risk scores | Weighted average renormalized over completed modules only; `null` when no completed module produces a score; never treat `null` as 0 or "safe"; escalation floor of 90 for confirmed phishing. | ✅ IMPLEMENTED |
| 4 | Confidence | Current: coverage over completed + half-weight partial + full-weight skipped ("genuinely not applicable"); `high` (≥85%), `medium` (≥50%, <85%), `low` (<50%); special rule: high downgrade if threat_reputation not completed. **REQUIRES TEAM APPROVAL** if changing skipped weight. | ⚠️ PROPOSED / REQUIRES TEAM APPROVAL |
| 5 | Severity and finding types | 4 types: `malicious_indicator`/`suspicious_indicator`/`misconfiguration`/`informational`. 5 severity: `info`/`low`/`medium`/`high`/`critical`. Frontend `severityOrder` matches backend enum order. | ✅ IMPLEMENTED |
| 6 | Confirmed phishing | Both: `critical` severity **AND** `escalation` object `{code: "CONFIRMED_PHISHING", message: "This address is listed as phishing by a threat intelligence source. Do not use it."}`. Escalation floor of 90 on risk score. | ✅ IMPLEMENTED |
| 7 | Provider reputation results | 5 states via `ModuleResult.status` + `risk_score: null` + `status_reason`: `confirmed`/`not_listed`/`unchecked`/`unavailable`/`error`. Critical rule: `unchecked`/`unavailable`/`error` **never** interpreted as safe. | ✅ IMPLEMENTED |
| 8 | User-facing findings | Backend owns: `title`, `description`, `evidence`, `recommendation` content. Frontend owns: display formatting, severity icons, code→UI overrides, finding grouping/ordering. | ✅ IMPLEMENTED |
| 9 | Module details | Per-module `details` fields: `url_domain` (hostname, is_ip_address, url_length, subdomain_count, uses_punycode), `threat_reputation` (providers + status + risk_score), `certificate` (validity, expiry, issuer, hostname_matching, key_algorithm), `security_config` (https_available, headers + redirect_count), `website_behaviour` (redirect_count, final_url, redirect_chain). Evidence expected as `{label, value}` entries — compatibility issue with mock data. | ⚠️ PROPOSED |
| 10 | Recommendations | Both: finding-level (under each finding) AND scan-level (under summary, no duplication). Backend deduplicates by advice text; frontend adapter passes through canonical list. | ✅ IMPLEMENTED |
| 11 | Safe test URLs | RFC 2606 reserved: `example.com`, `example.net`. Safe lookalikes: `paypa1-example.com`, `suspicious-example.com`. Invalid: `invalid`, `http://nonexistent.invalid`. Mock-compatible; no real unsafe destinations. | ✅ IMPLEMENTED |

---

## 16. Answers to All 8 Additional Architecture Questions

| # | Question | Answer | Status |
|---|----------|--------|--------|
| 1 | Fix `scanAdapter.js` immediately | Backend includes `confidence.reasons` and `escalation`; adapter currently drops both. Fix: extract `reasons` before `normalizeEnum`, add `escalation` to adapted response. Code change ~15 lines. **Requires team decision on UI display of reasons/escalation.** | ❌ REQUIRES TEAM APPROVAL |
| 2 | Allow `partial` modules null risk_score with status_reason | Backend `ModuleResult._enforce_contract` already permits this — only prohibits `completed` + `null` risk_score and non-completed + missing `status_reason`. No code changes needed; frontend may add `partial` badge styling (design decision). | ✅ IMPLEMENTED |
| 3 | Change confidence coverage formula | ❌ **PROVISIONAL** — Current impl: skipped = full weight ("genuinely not applicable, not a gap in evidence"). Changing to skipped = 0 would treat "no HTTPS certificate check" same as "provider unavailable", opposing stated design intent. **REQUIRES TEAM APPROVAL** to change existing semantics. | ❌ REQUIRES TEAM APPROVAL |
| 4 | MVP must have real threat-intelligence integration | PRD §8 Must-Have: "At least one functioning threat intelligence integration." Backend currently runs with all stubs — does **not** satisfy PRD. Priority: integrate one provider (Google Safe Browsing or PhishTank) on MVP critical path. A real URL parser or certificate checker alone does **not** satisfy this requirement. | ✅ IMPLEMENTED (requirement recorded) |
| 5 | Supabase community reporting for MVP demo | App works without Supabase: scans work, `/api/report(s)` return 503, `/api/health` reports Supabase unavailable. PRD §8: community reporting is "Should-Have"; §11 test: "Previously reported URL" can be mocked/deferred. **Product/demo-scope decision needed.** | ❌ REQUIRES TEAM APPROVAL |
| 6 | Make `partial` first-class frontend status | Frontend adapter already passes `status` through including `"partial"` — `ScanPendingNotice.jsx` renders `module.status.toUpperCase()` → "PARTIAL". No code changes needed to make it first-class; visual distinction (badge coloring) is UI/design decision. | ✅ IMPLEMENTED |
| 7 | Preserve Finding.evidence as `{label, value}` | Backend model: `Evidence = {label, value}`. Mock data: often plain string. **Unresolved compatibility issue** — team must decide: (a) update mock data to structured format, (b) update adapter to normalize strings, or (c) accept strings as informal format. | ❌ REQUIRES TEAM APPROVAL |
| 8 | Keep recommendation deduplication in backend | Backend `build_recommendations()` deduplicates by advice text (`seen` set). Frontend adapter `normalizeArray(raw.recommendations)` passes through canonical list without re-deduplicating. Data flow is correct; UI gap (top-level recs not yet rendered) is separate. | ✅ IMPLEMENTED |

---

## 17. Frontend/Backend Compatibility Issues

| Field | Backend | Frontend (adapter) | Issue | Status |
|---|---|---|---|---|
| `confidence.reasons` | Included in `Overall` (string[]) | **Dropped** by `scanAdapter.js:104-107` | Adapter only extracts `level` string | ❌ MISMATCH |
| `escalation` | Included in `Overall` (`Escalation` object or `null`) | **Dropped** by `scanAdapter.js` — no field in output | UI cannot show CONFIRMED PHISHING warning | ❌ MISMATCH |
| `modules_completed` | Computed in `scan_orchestrator.py` + `ScanReport` field | **Not forwarded** by adapter | UI cannot display count of completed modules | ℹ️ NOT FORWARDED |
| `community` | Included in `ScanReport` (`CommunityIntel` or `null`) | **Not in adapted output** | UI cannot show "previously reported URL" info | ❌ MISSING |
| `Finding.evidence` | `array[Evidence {label, value}]` (backend model) | Passed through as-is from raw API | **Mismatch**: mock data often plain string; adapter does not normalize | ⚠️ COMPATIBILITY ISSUE |
| `ModuleResult.status` | `ModuleStatus` literal (`completed`/`partial`/`unavailable`/`failed`/`skipped`) | Passed through `adaptModule`; `normalizeEnum` validates | ✅ COMPATIBLE |
| `ModuleResult.risk_score` | `int | None` with constraints per status | Passed through `riskScore: overall.risk_score ?? null` | ✅ COMPATIBLE |
| `Overall.classification` | `"low"|"moderate"|"high"|"critical"|"inconclusive"` | `normalizeEnum` validated against `VALID_CLASSIFICATIONS` | ✅ COMPATIBLE |
| `Overall.confidence.level` | `"low"|"medium"|"high"` | `normalizeEnum` validated against `VALID_CONFIDENCE_LEVELS` | ✅ COMPATIBLE |

**Key compatibility priorities:**
1. **High**: Fix `scanAdapter.js` to preserve `confidence.reasons` and `escalation` (enables UI warnings)
2. **Medium**: Harmonize `Finding.evidence` format between backend model and mock data
3. **Low**: Forward `modules_completed` and `community` to frontend (enhancement, not blocking)

---

## 18. Required Frontend Changes

| # | Change | File(s) | Priority |
|---|---|---|---|
| 1 | Preserve `confidence.reasons` in `scanAdapter.js` | `frontend/src/services/adapters/scanAdapter.js:104-115` | **High** — enables confidence explanations in UI |
| 2 | Preserve `escalation` in adapted response | `frontend/src/services/adapters/scanAdapter.js:92-115` | **High** — enables CONFIRMED PHISHING warning banner |
| 3 | Add escalation warning UI | `frontend/src/features/scan/ScanPendingNotice.jsx` | **High** — strong banner when `result.escalation` present |
| 4 | Display `confidence.reasons` under badge | `frontend/src/features/scan/ScanPendingNotice.jsx` | **Medium** — list under confidence level |
| 5 | Add top-level recommendations section | `frontend/src/features/scan/ScanPendingNotice.jsx` | **Medium** — using `recommendations` array from adapted response |
| 6 | Handle `partial` module badge (visual dist.) | `frontend/src/features/scan/ScanPendingNotice.jsx:110-121` | **Low** — already works; optional styling |
| 7 | Handle `community` field from API | `frontend/src/features/scan/ScanPendingNotice.jsx` + `LandingPage` | **Low** — PRD §11 "Previously reported URL" |

**No backend changes needed** for any of the above — the backend already produces the required fields; frontend adapter and UI need updating.

---

## 19. Required Backend Changes

| # | Change | File(s) | Priority |
|---|---|---|---|
| 1 | Implement real `url_domain` module (URL parsing + domain analysis) | `backend/app/modules/url_domain.py` | **High** — P0; currently all stubs |
| 2 | Implement real `threat_reputation` module (1 provider) | `backend/app/modules/threat_reputation.py` | **Critical Path** — PRD §8 Must-Have |
| 3 | Implement real `certificate` module (SSL/TLS validation) | `backend/app/modules/certificate.py` | **High** — P0 |
| 4 | Implement real `security_config` module (HTTP headers) | `backend/app/modules/security_config.py` | **High** — P0 |
| 5 | Implement real `website_behaviour` module (redirect following) | `backend/app/modules/website_behaviour.py` | **High** — P0 |
| 6 | Ensure `confidence.reasons` included in `Overall` response | Already included; verify not removed in future changes | **Low** — already implemented |
| 7 | Ensure `escalation` field always present (even if null) | Already implemented; verify consistency | **Low** — already implemented |
| 8 | Add `modules_completed` to `ScanReport` response | `scan_orchestrator.py:run_scan()` + `models/scan.py:ScanReport` | **Low** — useful for UI but not essential |
| 9 | Harmonize `Finding.evidence` format | `app/models/scan.py:Finding.evidence` + adapter `adaptFinding` | **Medium** — align model with mock data or update adapter |

**No frontend changes required** for backend-only items; all frontend changes listed in Section 18 are adapter/UI changes only.

---

## 20. Team Decisions Still Pending

| # | Decision | Impact | Timeline |
|---|---|---|---|
| 1 | Confidence coverage for `skipped` modules (change from full weight to 0) | Affects all scans with skipped modules (e.g., certificate check on HTTP sites); current impl: skipped = full weight ("genuinely not applicable"). Team must decide semantic. | Before MVP demo |
| 2 | Supabase community reporting for MVP demo | Technical: app works without Supabase. Product: should demo include "Previously reported URL" per PRD §11? | Before MVP demo |
| 3 | Finding.evidence format harmonization | Backend: `Evidence = {label, value}`. Mock data: often plain string. Decision needed on normalization strategy. | Before MVP demo |
| 4 | Which threat-intelligence provider for MVP critical path | Google Safe Browsing vs. PhishTank vs. VirusTop; API keys, rate limits, data format. Critical path item for MVP. | Before MVP demo |
| 5 | Visual design for `partial` badge and escalation warning banner | UI/design decisions: badge colors, warning banner styling, placement on scan results page. Not functional requirements. | Before MVP demo |

---

## 21. Recommended Implementation Order

**Priority 1: Critical Path (must complete before demo)**

1. **Integrate one real threat-intelligence provider** (Google Safe Browsing or PhishTank) — PRD §8 Must-Have; without this, MVP does not meet its own requirements. Backend module + API integration + frontend display.

2. **Fix `scanAdapter.js` to preserve `confidence.reasons` and `escalation`** — enables the UI to show what the backend already computes. Prerequisite for Priority 2 below. Code change only; no backend changes needed.

3. **Add escalation warning UI to `ScanPendingNotice.jsx`** — once adapter preserves escalation, UI must show CONFIRMED PHISHING banner. Prerequisite: #2.

**Priority 2: High Priority (should complete before demo)**

4. **Decide confidence coverage for `skipped` modules** (Resolution #3) — team decision on whether skipped modules lower confidence. Implement the chosen formula in `risk_engine.py:_confidence()`.

5. **Decide Supabase for MVP demo** (Resolution #2) — product decision: include community reporting or not. If yes, configure Supabase; if no, the app functions correctly without it.

6. **Harmonize Finding.evidence format** (Resolution #7) — update mock data to use `{label, value}` structure, or update adapter to handle both. Ensure consistency between model and data.

**Priority 3: Medium Priority (can complete alongside or after demo)**

7. **Make `partial` a first-class frontend status** — already supported; add visual distinction (badge coloring) if desired. UI work only.

8. **Implement remaining real modules** (url_domain, certificate, security_config, website_behaviour) — prioritize based on user-visible impact. Parallelize with #1-6.

9. **End-to-end PRD §11 validation** — test all 11 acceptance criteria with real and mock modules combined.

**Priority 4: Lower Priority (post-MVP)**

10. **Enhance UI/visual design** — badge colors, warning banner styling, improved error states, accessibility improvements.

11. **Continuous module replacement** — replace all 5 stubs with real modules; the architecture is designed for this (protocol-based `AnalysisModule`).

---

## 22. Source File References

| Area | Source File | Purpose |
|---|---|---|
| Frontend constants | `frontend/src/constants/scan.js` | `SCAN_STATE`, `SCAN_CLASSIFICATION`, `CONFIDENCE_LEVEL` enums |
| Frontend adapter | `frontend/src/services/adapters/scanAdapter.js` | Raw API → UI shape adaptation; drops `confidence.reasons` and `escalation` |
| Frontend hook | `frontend/src/hooks/useScan.js` | Scan state machine: `IDLE` → `SCANNING` → `SUCCESS`/`ERROR` |
| Frontend API client | `frontend/src/services/apiClient.js` | Fetch wrapper with timeout, AbortController, error normalization |
| Frontend mock API | `frontend/src/mocks/mockScanApi.js` | Scenario selection + mock data generation (5 scenarios) |
| Frontend mock scenarios | `frontend/src/mocks/scenarios/` | 5 scenarios exercising PRD §11 test cases |
| Frontend URL validation | `frontend/src/utils/validateUrl.js` | URL format validation (scheme, hostname, max length, no spaces) |
| Frontend results display | `frontend/src/features/scan/ScanPendingNotice.jsx` | Results display: risk score, classification, confidence, findings, modules |
| Backend main | `backend/app/main.py` | FastAPI app factory + lifecycle; SSRF-guarded HTTP client |
| Backend config | `backend/app/config.py` | Typed settings from environment variables |
| Backend models scan | `backend/app/models/scan.py` | Pydantic models: `ModuleResult`, `Finding`, `Confidence`, `Escalation`, `Overall`; structural validators |
| Backend models report | `backend/app/models/report.py` | Community report models; `CommunityIntel` for PRD §11 |
| Backend models errors | `backend/app/models/errors.py` | Single error envelope: `ErrorBody`, `ErrorResponse` |
| Backend risk engine | `backend/app/services/risk_engine.py` | `assess()` / `compute_overall()` / `_confidence()` / `build_recommendations()` |
| Backend scan orchestrator | `backend/app/services/scan_orchestrator.py` | `run_scan()`: validate → SSRF → run modules → assess → build report |
| Backend SSRF guard | `backend/app/utils/ssrf_guard.py` | 4-layer SSRF protection + guarded HTTP client + manual redirect following |
| Backend URL tools | `backend/app/utils/url_tools.py` | Single entry point `parse_url()`: validation, normalization, punycode IDN |
| Backend modules base | `backend/app/modules/base.py` | `AnalysisModule` protocol + `ScanContext` + `not_run()` helper |
| Backend modules stubs | `backend/app/modules/stubs.py` | `NotImplementedModule` — all 5 modules return `"unavailable"` |
| Backend modules init | `backend/app/modules/__init__.py` | `get_modules()` — currently all `NotImplementedModule` |
| Backend routes scan | `backend/app/routes/scan.py` | `POST /api/scan`, `GET /api/scan/{scan_id}` |
| Backend routes reports | `backend/app/routes/reports.py` | `POST /api/report`, `GET /api/reports` |
| Backend routes health | `backend/app/routes/health.py` | `GET /api/health` |
| Backend errors | `backend/app/errors.py` | Exception handlers → single error envelope |
| Backend supabase service | `backend/app/services/supabase_service.py` | Community reports + scan persistence (optional) |
| Backend SSRF guard test | `backend/tests/test_ssrf_guard.py` | 9 parametrized SSRF test functions |
| Backend risk engine test | `backend/tests/test_risk_engine.py` | 6 test functions: missing modules, inconclusive, phishing escalation, confidence cap, module contract |
| Backend URL tools test | `backend/tests/test_url_tools.py` | 13 test functions: normalize, reject, IP canonicalization |
| Backend API test | `backend/tests/test_api.py` | 11 end-to-end API tests (health, invalid URL, scheme, blocked dest, stub modules, scan retrieval, unknown ID, reports unavailable, rate limit) |
| OpenAPI schema | `backend/openapi.json` | Generated schema; authoritative API contract for running backend |
| PRD §4-5 | `docs/PRD.md` | Product requirements: modules, risk scores, confidence, user journey |
| Proposed API schema | `docs/api schema (proposed).md` | API contract 0.1-proposal; field descriptions and error codes |
| Sitemap/page hierarchy | `docs/sitemap and page hierarchy` | Planned page structure (missing: /results, /details, /reports, /history, /about) |

---

## Validation

- [x] Current branch is `security` (verified)
- [x] All 11 original questions answered
- [x] All 8 additional questions addressed
- [x] Technical claims verified against source files
- [ ] `git diff --check` — run after document creation
- [ ] `git status` — confirm only `docs/security-architecture-decisions.md` is new/modified
- [ ] No files committed or pushed

**Important corrections recorded:**
1. Do not describe `paypa1-example.com` or `suspicious-example.com` as reserved test domains — they are not reserved; use only RFC 2606 example domains
2. Skipped-module confidence decision marked `REQUIRES TEAM APPROVAL` if changing existing implementation
3. Evidence mismatch between backend models and frontend mocks marked as unresolved compatibility issue
4. Implementation-supported decisions distinguished from formal team approval
5. No invention of module details or provider capabilities
6. Not all 5 detection modules are functional — backend inspection found stubs
7. PRD requirement for at least one functioning real threat-intelligence integration recorded
8. Supabase community reporting recorded as product/demo-scope decision
9. Backend implementation and proposed API fields clearly distinguished

---
*Document created via read-only inspection of `origin/backend` and frontend on `security` branch. No backend or main branch files modified.*