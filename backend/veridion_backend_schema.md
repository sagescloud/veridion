# Veridion Backend API Schema

**Framework:** FastAPI\
**API version:** 0.1.0\
**Local base URL:** `http://127.0.0.1:8000`

> This document records the API contract verified during local
> frontend/backend integration. The five analysis modules are currently
> registered but return `unavailable` until implemented. For exact
> validation constraints, the Pydantic models and generated OpenAPI
> schema remain authoritative.

## 1. Endpoints

  Method   Endpoint          Purpose
  -------- ----------------- ----------------------------------------
  GET      `/api/health`     Backend health check
  POST     `/api/scan`       Submit a URL and receive a scan report
  GET      `/docs`           Swagger UI
  GET      `/openapi.json`   OpenAPI specification

Local frontend origin: `http://localhost:5173`. This origin is allowed
by the backend CORS configuration.

## 2. Health check

### `GET /api/health`

Verified successful response (HTTP 200):

``` json
{
  "status": "ok",
  "version": "0.1.0"
}
```

The running application may include additional health metadata.

## 3. Scan endpoint

### `POST /api/scan`

Accepts a URL, validates and normalizes it, runs the configured analysis
modules, and returns a scan report.

**Request content type:** `application/json`

``` json
{
  "url": "https://example.com"
}
```

  Field   Type       Required Description
  ------- -------- ---------- ----------------------------
  `url`   string          Yes URL submitted for scanning

Example:

``` bash
curl -X POST http://127.0.0.1:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

A successfully processed scan returns HTTP 200 even if some analysis
modules are unavailable. A completed scan does not necessarily mean a
risk score could be calculated.

## 4. Scan report response

The following is a representative response structure based on the
locally observed API response. Values are illustrative; the actual
`modules` array contains all registered modules.

``` json
{
  "scan_id": "4ef4e630-cc19-46d2-81a3-65511bb33c89",
  "status": "completed",
  "submitted_url": "https://example.com",
  "normalized_url": "https://example.com/",
  "scanned_at": "2026-11-09T08:36:44Z",
  "duration_ms": 68,
  "overall": {
    "risk_score": null,
    "classification": "inconclusive",
    "confidence": {
      "level": "low",
      "reasons": [
        "No analysis module produced a result, so no risk score can be given."
      ]
    }
  },
  "modules_completed": 0,
  "modules": [
    {
      "id": "url_domain",
      "status": "unavailable",
      "risk_score": null,
      "status_reason": {
        "code": "MODULE_NOT_IMPLEMENTED",
        "message": "This analysis module is not available yet. This is not a clean result."
      },
      "findings": [],
      "details": null
    }
  ],
  "recommendations": [
    {
      "id": "example-recommendation",
      "priority": "low",
      "text": "No warnings does not mean a site is safe. Be careful with links you did not expect.",
      "related_finding_ids": []
    }
  ],
  "community": null
}
```

### 4.1 Top-level fields

  ------------------------------------------------------------------------
  Field                   Type                    Description
  ----------------------- ----------------------- ------------------------
  `scan_id`               string                  Unique scan identifier

  `status`                string                  Scan processing status;
                                                  observed successful
                                                  value: `completed`

  `submitted_url`         string                  URL as submitted

  `normalized_url`        string                  Parsed and normalized
                                                  URL

  `scanned_at`            string                  Scan timestamp in ISO
                                                  8601 format

  `duration_ms`           integer                 Scan duration in
                                                  milliseconds

  `overall`               object                  Aggregate risk
                                                  assessment and
                                                  confidence

  `modules_completed`     integer                 Number of modules that
                                                  produced completed
                                                  results

  `modules`               array                   Individual analysis
                                                  module results

  `recommendations`       array                   Recommendations for the
                                                  user

  `community`             object or null          Community-intelligence
                                                  result, when available
  ------------------------------------------------------------------------

### 4.2 Overall assessment

  -----------------------------------------------------------------------
  Field                   Type                    Description
  ----------------------- ----------------------- -----------------------
  `risk_score`            integer or null         Aggregate score; null
                                                  when there is
                                                  insufficient completed
                                                  analysis

  `classification`        string                  Overall risk
                                                  classification

  `confidence`            object                  Confidence level and
                                                  explanatory reasons
  -----------------------------------------------------------------------

Risk classifications defined by the risk engine:

      Score Classification
  --------- ----------------
      0--24 Low
     25--49 Moderate
     50--74 High
    75--100 Critical

A confirmed phishing signal may escalate the score to at least 90.

Risk weights:

  Module                     Weight
  ------------------------ --------
  Threat reputation             30%
  URL and domain                25%
  Website behaviour             20%
  Certificate                   15%
  Security configuration        10%

The risk engine calculates the weighted score from eligible completed
module results. Unavailable, failed, and skipped modules must not be
treated as clean results. Confidence is reported separately from risk.

### 4.3 Module result

  -----------------------------------------------------------------------
  Field                   Type                    Description
  ----------------------- ----------------------- -----------------------
  `id`                    string                  Stable module
                                                  identifier

  `status`                string                  Module execution status

  `risk_score`            integer or null         Module score; null when
                                                  no valid score exists

  `status_reason`         object or null          Machine-readable reason
                                                  and human-readable
                                                  explanation

  `findings`              array                   Findings produced by
                                                  the module

  `details`               object or null          Additional
                                                  module-specific
                                                  information
  -----------------------------------------------------------------------

Registered module IDs:

  ID                    Responsibility
  --------------------- -------------------------------------------
  `url_domain`          URL structure and domain analysis
  `threat_reputation`   Threat-intelligence and reputation checks
  `certificate`         TLS/SSL certificate analysis
  `security_config`     HTTPS and security-configuration checks
  `website_behaviour`   Redirects and website behaviour

Module statuses:

-   `completed`: the module ran and produced a valid result.
-   `unavailable`: the module could not provide an analysis result.
-   `failed`: the module encountered an execution error.
-   `skipped`: the module was intentionally not run.

Only completed modules may carry a risk score. An unavailable, failed,
or skipped module must not be interpreted as safe.

### 4.4 Status reason

``` json
{
  "code": "MODULE_NOT_IMPLEMENTED",
  "message": "This analysis module is not available yet. This is not a clean result."
}
```

### 4.5 Recommendation

  -----------------------------------------------------------------------
  Field                   Type                    Description
  ----------------------- ----------------------- -----------------------
  `id`                    string                  Recommendation
                                                  identifier

  `priority`              string                  Recommendation priority

  `text`                  string                  User-facing
                                                  recommendation

  `related_finding_ids`   array of strings        Finding IDs associated
                                                  with the recommendation
  -----------------------------------------------------------------------

### 4.6 Findings

Findings are structured objects included in module results. The backend
contains a `Finding` model. Its complete field list should be taken from
the current `app/models/scan.py` implementation or generated OpenAPI
schema rather than inferred.

## 5. URL processing and security constraints

The backend includes URL parsing and SSRF protections:

-   URLs are parsed and normalized before analysis.
-   Hostnames are normalized to lowercase ASCII/punycode where
    applicable.
-   IP-literal URLs are identified.
-   User information embedded in URLs is tracked.
-   DNS resolution and public-IP checks are part of the SSRF guard.
-   Outbound HTTP requests must use the guarded HTTP client and
    safe-fetch flow.
-   Redirect handling must preserve SSRF protections.
-   Modules must not bypass the guarded HTTP client with unrestricted
    network requests.
-   Raw socket operations, if required, must use prevalidated resolved
    IP addresses.

These controls matter because the scan endpoint accepts user-supplied
URLs.

## 6. Frontend integration contract

The React frontend sends:

``` javascript
const response = await fetch(
  `${import.meta.env.VITE_API_BASE_URL}/api/scan`,
  {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ url }),
  }
)

const report = await response.json()
```

Frontend environment file (`frontend/.env.local`):

``` env
VITE_API_BASE_URL=http://127.0.0.1:8000
```

The frontend should:

1.  Validate the URL before sending it.
2.  Show a loading state while the request is pending.
3.  Check `response.ok` before treating the response as successful.
4.  Display the returned classification and confidence.
5.  Display `N/A` when `overall.risk_score` is null.
6.  Show module status and explanatory messages.
7.  Never label an unavailable, failed, or skipped module as safe.
8.  Handle network and API errors without crashing the page.

Do not expose backend secrets, Supabase service-role keys, or private
provider API keys in frontend environment variables. Vite variables
prefixed with `VITE_` are exposed to browser code.

## 7. Local development

Start the backend from the `backend` directory, with its virtual
environment activated:

``` bash
uvicorn app.main:app --reload --port 8000
```

Start the frontend from the `frontend` directory:

``` bash
npm run dev
```

Verify the API at:

-   `http://127.0.0.1:8000/docs`
-   `http://127.0.0.1:8000/api/health`

Then submit a test scan from `http://localhost:5173`.

## 8. Current implementation status

  Capability                         Status
  ---------------------------------- ------------------------
  FastAPI application                Implemented
  Health endpoint                    Verified locally
  Scan endpoint                      Verified locally
  URL parsing and normalization      Implemented
  SSRF protection                    Implemented
  Scan orchestration                 Implemented
  Weighted risk engine               Implemented
  Frontend-to-backend request flow   Verified locally
  URL/domain analysis module         Stub / not implemented
  Threat reputation module           Stub / not implemented
  Certificate module                 Stub / not implemented
  Security configuration module      Stub / not implemented
  Website behaviour module           Stub / not implemented

## 9. Source of truth and maintenance

This document is an integration-oriented schema reference, not a
replacement for the backend's Pydantic models.

For exact field definitions and validation constraints, consult:

-   `app/models/scan.py`
-   `app/main.py`
-   `app/routers/` (endpoint definitions)
-   `app/services/scan_orchestrator.py`
-   `app/services/risk_engine.py`
-   `app/modules/base.py`

The generated OpenAPI document at `/openapi.json` and Swagger UI at
`/docs` should be treated as the authoritative API contract for the
running backend.

Update this Markdown document whenever request models, response models,
endpoint paths, status values, or module identifiers change.
