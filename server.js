create table if not exists premium_items (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  subtitle text,
  tags text,
  listed boolean not null default false,
  min_rows integer not null default 1000,
  price_per_1k_cents integer not null default 500,
  spreadsheet_id text,
  gid text default '0',
  sheet_url_admin text,
  csv_url_public text not null,
  headers jsonb default '[]',
  rows_estimate integer default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz
);

create index if not exists premium_items_created_at_idx on premium_items (created_at desc);
create index if not exists premium_items_listed_idx on premium_items (listed);

-- if your project has RLS on by default, either disable it for this table
alter table premium_items disable row level security;
-- (or add a permissive policy for the service role key you use on the server)
