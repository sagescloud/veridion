# Veridion: Proposed Scan API Schema

> **STATUS: PROPOSAL. NOT AN AGREED BACKEND CONTRACT.**
> Drafted by the frontend side for review by backend (T) and security/intelligence (P).
> The PRD defines the endpoints (`POST /api/scan`, `GET /api/scan/{scan_id}`) but not request or response bodies. Everything below is open to change.

- **Schema version:** `0.1-proposal`
- **Scan mode (MVP decision):** synchronous. `POST /api/scan` returns the completed report.
- **Design goal:** the same response shape should later support async scanning (`status: "pending" | "running"`) without redesigning the frontend.

---

## 1. Request

`POST /api/scan`

```json
{ "url": "http://paypa1-login.example/verify" }
```

---

## 2. Success response

The example below is deliberately messy to show the hard cases: one module `unavailable`, one `skipped`, and no "safe" verdict anywhere. `.example` is a reserved domain, so it is safe for samples.

```json
{
  "schema_version": "0.1-proposal",
  "scan_id": "b7e1c2a4-5d3f-4a8e-9c1b-2f6d8e0a1b34",
  "status": "completed",
  "submitted_url": "http://paypa1-login.example/verify",
  "normalized_url": "http://paypa1-login.example/verify",
  "scanned_at": "2026-11-08T18:12:45Z",
  "duration_ms": 8421,

  "overall": {
    "risk_score": 68,
    "classification": "high",
    "confidence": {
      "level": "medium",
      "reasons": [
        "3 of 5 analysis modules completed",
        "Threat reputation providers were unavailable",
        "Certificate check skipped: site does not use HTTPS"
      ]
    },
    "escalation": null
  },

  "modules": [
    {
      "id": "url_domain",
      "status": "completed",
      "risk_score": 72,
      "status_reason": null,
      "findings": [
        {
          "id": "f1",
          "code": "LOOKALIKE_DOMAIN",
          "type": "suspicious_indicator",
          "severity": "high",
          "title": "Domain resembles a known brand",
          "description": "The domain is very similar to a well-known brand, a common phishing technique.",
          "evidence": [
            { "label": "Closest known brand", "value": "paypal.com" },
            { "label": "Similarity", "value": "0.93" }
          ]
        }
      ],
      "details": {
        "hostname": "paypa1-login.example",
        "is_ip_address": false,
        "url_length": 36,
        "subdomain_count": 0,
        "uses_punycode": false
      }
    },
    {
      "id": "threat_reputation",
      "status": "unavailable",
      "risk_score": null,
      "status_reason": {
        "code": "PROVIDER_RATE_LIMITED",
        "message": "The reputation provider could not be reached. This is not a clean result."
      },
      "findings": [],
      "details": {
        "providers": [
          { "name": "google_safe_browsing", "status": "unavailable", "verdict": null }
        ]
      }
    },
    {
      "id": "certificate",
      "status": "skipped",
      "risk_score": null,
      "status_reason": {
        "code": "NO_HTTPS",
        "message": "Certificate analysis does not apply because the site was not reachable over HTTPS."
      },
      "findings": [],
      "details": null
    },
    {
      "id": "security_config",
      "status": "completed",
      "risk_score": 40,
      "status_reason": null,
      "findings": [
        {
          "id": "f2",
          "code": "NO_HTTPS",
          "type": "misconfiguration",
          "severity": "medium",
          "title": "Site does not use HTTPS",
          "description": "Data sent to this site is not encrypted. Do not enter passwords or payment details.",
          "evidence": [{ "label": "HTTPS available", "value": "false" }]
        }
      ],
      "details": {
        "https_available": false,
        "headers": [
          { "name": "Content-Security-Policy", "present": false },
          { "name": "Strict-Transport-Security", "present": false }
        ]
      }
    },
    {
      "id": "website_behaviour",
      "status": "completed",
      "risk_score": 55,
      "status_reason": null,
      "findings": [
        {
          "id": "f3",
          "code": "REDIRECT_TO_DIFFERENT_DOMAIN",
          "type": "suspicious_indicator",
          "severity": "medium",
          "title": "Redirects to a different domain",
          "description": "The page sends visitors through another domain before showing content.",
          "evidence": [
            { "label": "Redirect count", "value": "2" },
            { "label": "Final destination", "value": "other-site.example" }
          ]
        }
      ],
      "details": {
        "redirect_count": 2,
        "final_url": "http://other-site.example/login",
        "redirect_chain": [
          { "url": "http://paypa1-login.example/verify", "status_code": 302 },
          { "url": "http://track.example/r", "status_code": 301 },
          { "url": "http://other-site.example/login", "status_code": 200 }
        ]
      }
    }
  ],

  "recommendations": [
    {
      "id": "r1",
      "priority": "high",
      "text": "Do not enter credentials or payment information on this site.",
      "related_finding_ids": ["f1", "f2"]
    }
  ]
}
```

---

## 3. Field reference

### Top level

| Field | Type | Notes |
|---|---|---|
| `schema_version` | string | Lets the frontend detect contract changes |
| `scan_id` | string | Unique per scan |
| `status` | string | `"completed"` for the sync MVP. Async could later add `"pending"` and `"running"`. |
| `submitted_url` | string | Exactly what the user entered |
| `normalized_url` | string | After normalization (also used for duplicate detection) |
| `scanned_at` | string | ISO 8601, UTC |
| `duration_ms` | number | Total scan time |
| `overall` | object | See below |
| `modules` | array | One entry per analysis module |
| `recommendations` | array | Suggested next steps |

### `overall`

| Field | Values / notes |
|---|---|
| `risk_score` | 0–100 |
| `classification` | `"low"`, `"moderate"`, `"high"`, `"critical"` (PRD Module 5). The frontend displays this value and does **not** recompute thresholds, since the PRD calls them provisional. |
| `confidence.level` | `"low"`, `"medium"`, `"high"`. Kept separate from risk score, as the PRD requires. |
| `confidence.reasons` | Array of plain-language strings explaining the confidence level |
| `escalation` | `null` normally. For confirmed phishing: `{ "code": "CONFIRMED_PHISHING", "message": "..." }` so the UI can show a strong warning instead of a diluted score. |

### Modules

| `id` | PRD source |
|---|---|
| `url_domain` | Module 1 |
| `threat_reputation` | Module 2 |
| `certificate` | Module 3 |
| `security_config` | Module 4 |
| `website_behaviour` | Module 4 (redirects) and Module 5 (behaviour weight) |

| Field | Values / notes |
|---|---|
| `status` | `completed`, `partial` (some sub-checks failed), `unavailable` (external dependency down or rate-limited), `failed` (internal error or timeout), `skipped` (not applicable) |
| `risk_score` | 0–100, or `null` when the module did not complete. **`null` must never be treated as 0 or as "safe".** |
| `status_reason` | `null` when completed. Otherwise `{ code, message }` explaining why. |
| `findings` | Array of findings (may be empty) |
| `details` | Module-specific technical data for the Detailed Analysis page. **Illustrative only.** The security side knows what is actually available. |

### Findings

| Field | Values / notes |
|---|---|
| `id` | Unique within the scan |
| `code` | Stable machine-readable code (e.g. `LOOKALIKE_DOMAIN`) so the frontend can attach icons or copy overrides without parsing titles |
| `type` | `malicious_indicator`, `suspicious_indicator`, `misconfiguration`, `informational`. Supports the PRD rule that misconfiguration must not look like confirmed malice. |
| `severity` | `info`, `low`, `medium`, `high`, `critical` |
| `title` | Short, user-facing |
| `description` | Plain-language explanation of why it matters |
| `evidence` | Array of `{ "label": string, "value": string }` pairs |

### Recommendations

| Field | Values / notes |
|---|---|
| `id` | Unique within the scan |
| `priority` | `low`, `medium`, `high` |
| `text` | Plain-language action |
| `related_finding_ids` | Links a recommendation to the findings that triggered it |

### Conventions

- Field names are `snake_case`.
- Timestamps are ISO 8601 in UTC.
- An absence of findings or reports must never be represented as, or displayed as, "safe".

---

## 4. Error response

All errors share one envelope:

```json
{
  "error": {
    "code": "INVALID_URL",
    "message": "That doesn't look like a valid website address.",
    "details": { "field": "url" },
    "request_id": "req_8f2a1c"
  }
}
```

| Code | Suggested HTTP status | When |
|---|---|---|
| `INVALID_URL` | 422 | Malformed URL |
| `UNSUPPORTED_SCHEME` | 422 | e.g. `ftp://`, `javascript:` |
| `BLOCKED_DESTINATION` | 422 or 403 | SSRF protection (private/internal address) |
| `SCAN_TIMEOUT` | 504 | Scan exceeded its time budget |
| `RATE_LIMITED` | 429 | Too many requests (with `details.retry_after_seconds`) |
| `SCAN_NOT_FOUND` | 404 | Unknown `scan_id` |
| `DUPLICATE_REPORT` | 409 | Report already submitted |
| `VALIDATION_ERROR` | 422 | Other bad input |
| `SERVICE_UNAVAILABLE` | 503 | Backend overloaded or down |
| `INTERNAL_ERROR` | 500 | Unexpected failure |

Notes for backend:

- `message` must be safe to show to users. For `BLOCKED_DESTINATION` it must not reveal internal network details.
- FastAPI's default validation errors use a different shape (`{"detail": [...]}`), so a custom exception handler is needed to match this envelope.