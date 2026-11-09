-- supabase/schema.sql
-- Run once in the Supabase dashboard: SQL Editor -> New query -> paste -> Run.
-- Idempotent: safe to re-run.

create extension if not exists pgcrypto;

-- ---------------------------------------------------------------------------
-- Community reports (PRD Module 6)
-- One row per (URL, reporter). Reporter identity = HMAC of the client IP, never the raw IP.
-- ---------------------------------------------------------------------------
create table if not exists public.community_reports (
    id             uuid primary key default gen_random_uuid(),
    normalized_url text        not null check (char_length(normalized_url) between 1 and 2048),
    category       text        not null default 'other'
                               check (category in ('phishing','scam','malware','impersonation','other')),
    description    text        check (description is null or char_length(description) <= 500),
    reporter_hash  text        not null,
    created_at     timestamptz not null default now(),
    -- Duplicate prevention: the same reporter can't report the same URL twice,
    -- while different reporters accumulate into report_count.
    constraint community_reports_unique_reporter unique (normalized_url, reporter_hash)
);

create index if not exists community_reports_url_idx     on public.community_reports (normalized_url);
create index if not exists community_reports_created_idx on public.community_reports (created_at desc);

-- Aggregated view served by GET /api/reports (never exposes reporters or free-text descriptions).
create or replace view public.community_report_summary
with (security_invoker = true) as
select normalized_url,
       count(*)::int          as report_count,
       min(created_at)        as first_reported_at,
       max(created_at)        as last_reported_at,
       array_agg(distinct category order by category) as categories
from public.community_reports
group by normalized_url;

-- ---------------------------------------------------------------------------
-- Scan results (powers GET /api/scan/{id}; later: scan history)
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
    scan_id        uuid primary key,
    normalized_url text        not null,
    risk_score     int         check (risk_score is null or risk_score between 0 and 100),
    classification text        not null,
    report         jsonb       not null,
    created_at     timestamptz not null default now()
);
create index if not exists scans_created_idx on public.scans (created_at desc);
-- Optional retention (scan reports contain URLs users typed): enable pg_cron and run daily:
--   delete from public.scans where created_at < now() - interval '30 days';

-- ---------------------------------------------------------------------------
-- Lock everything down. Only the backend's SERVICE ROLE key (which bypasses RLS)
-- can touch these. The public anon/authenticated keys get nothing.
-- ---------------------------------------------------------------------------
alter table public.community_reports enable row level security;
alter table public.scans             enable row level security;

revoke all on public.community_reports     from anon, authenticated;
revoke all on public.community_report_summary from anon, authenticated;
revoke all on public.scans                 from anon, authenticated;
