"""
app/config.py
Central, typed configuration. Every value comes from environment variables
(or a local .env file in development). Secrets never live in code.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_DEV_SALT = "dev-only-change-me"


class Settings(BaseSettings):
    # Env var names are the upper-case field names (e.g. SUPABASE_URL).
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    # --- App -------------------------------------------------------------
    app_env: str = "development"  # "development" | "production"
    app_version: str = "0.1.0"
    # Comma-separated list of allowed browser origins (your Vercel URL in prod).
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    # --- Supabase (community reports + scan persistence) -----------------
    supabase_url: str | None = None
    # SERVICE ROLE key: backend only. Never ship to the frontend.
    supabase_service_role_key: str | None = None
    # Salt for hashing reporter IPs (we never store raw IPs).
    report_hash_salt: str = _DEV_SALT

    # --- Scan budgets ----------------------------------------------------
    scan_overall_timeout_s: float = 25.0   # hard ceiling for one scan
    module_timeout_s: float = 12.0         # ceiling for a single module
    max_concurrent_scans: int = 10         # protects the server from overload
    dns_timeout_s: float = 3.0

    # --- Outbound HTTP (all of it goes through the SSRF-guarded client) --
    http_timeout_s: float = 8.0            # connect / read timeout
    http_total_timeout_s: float = 15.0     # wall-clock cap per fetch (slowloris)
    max_redirects: int = 5
    max_response_bytes: int = 1_000_000    # 1 MB body cap
    allowed_ports: str = "80,443,8080,8443"

    # --- Abuse protection ------------------------------------------------
    rate_limit_scan_per_min: int = 10
    rate_limit_report_per_min: int = 5
    # Only enable behind a reverse proxy you control (Render, Fly, etc.).
    trust_proxy_headers: bool = False

    # --- Threat intel providers (owned by P's modules) -------------------
    google_safe_browsing_api_key: str | None = None

    @model_validator(mode="after")
    def _production_guard(self) -> "Settings":
        if self.app_env == "production" and self.report_hash_salt == _DEV_SALT:
            raise ValueError("REPORT_HASH_SALT must be set in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def allowed_port_set(self) -> set[int]:
        return {int(p) for p in self.allowed_ports.split(",") if p.strip()}

    @property
    def supabase_configured(self) -> bool:
        return bool(self.supabase_url and self.supabase_service_role_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
