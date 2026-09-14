-- ProfitPilot AI
-- Migration 0001: Platform connections
-- Multi-platform by design: Salla today, Zid/Shopify/etc. later.

create extension if not exists pgcrypto;

create table if not exists public.commerce_connections (
  id uuid primary key default gen_random_uuid(),

  provider text not null,
  store_id text not null,
  store_name text,

  access_token_enc text,
  refresh_token_enc text,
  token_expires_at timestamptz,
  encryption_key_id text,

  scopes text[],
  status text not null default 'active',

  metadata jsonb not null default '{}'::jsonb,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint commerce_connections_provider_store_unique
    unique (provider, store_id)
);

create table if not exists public.commerce_sync_runs (
  id uuid primary key default gen_random_uuid(),

  connection_id uuid not null
    references public.commerce_connections(id)
    on delete cascade,

  resource_type text not null,
  status text not null default 'running',

  started_at timestamptz not null default now(),
  finished_at timestamptz,

  records_processed integer not null default 0,
  error_message text,

  metadata jsonb not null default '{}'::jsonb
);

create index if not exists idx_commerce_connections_provider
  on public.commerce_connections(provider);

create index if not exists idx_commerce_connections_status
  on public.commerce_connections(status);

create index if not exists idx_commerce_sync_runs_connection
  on public.commerce_sync_runs(connection_id);

create index if not exists idx_commerce_sync_runs_status
  on public.commerce_sync_runs(status);

-- Keep updated_at current automatically.
create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists commerce_connections_set_updated_at
  on public.commerce_connections;

create trigger commerce_connections_set_updated_at
before update on public.commerce_connections
for each row
execute function public.set_updated_at();

-- Security baseline:
-- RLS is enabled, but NO permissive policies are created yet.
-- Server-side privileged access uses SUPABASE_SECRET_KEY.
alter table public.commerce_connections enable row level security;
alter table public.commerce_sync_runs enable row level security;
