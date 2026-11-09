# Veridion Backend (FastAPI)

Branch: `feature/backend-api`. Schema version `0.1-proposal`.

## Run

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
cp .env.example .env                                    # fill in Supabase values (optional for first run)
pytest                                                  # run this FIRST (see "Verify" below)
uvicorn app.main:app --reload --port 8000               # docs at http://localhost:8000/docs
```

Supabase (for community reports + stored scans): create a project, open **SQL Editor**,
paste `supabase/schema.sql`, run. Put the project URL and the **service role** key in `.env`.
Without Supabase the app still runs: scans work, `/api/report(s)` return 503.

## Endpoints

| Method | Path | Notes |
|---|---|---|
| POST | `/api/scan` | `{"url": "..."}` -> full report (sync) |
| GET | `/api/scan/{scan_id}` | memory cache, then Supabase |
| POST | `/api/report` | `{"url","category?","description?"}` -> 201; 409 `DUPLICATE_REPORT` |
| GET | `/api/reports` | `?limit&offset&url=` aggregated per URL |
| GET | `/api/health` | `?deep=true` also pings Supabase |

## Where P plugs in

Implement `AnalysisModule` (see `app/modules/base.py`), register it in
`app/modules/__init__.py`. Use `ctx.http` + `safe_fetch` for HTTP and
`ctx.resolved_ips` for raw sockets. Tune scoring in `app/services/risk_engine.py`.

## Verify

`tests/test_ssrf_guard.py::test_guarded_transport_builds_with_installed_httpx` confirms
the SSRF transport works with the installed httpx. Re-run after any httpx upgrade.
