create table public.saved_cases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  client_name text not null check (char_length(client_name) between 1 and 120),
  carrier text not null check (char_length(carrier) between 1 and 100),
  product text not null check (char_length(product) between 1 and 160),
  commission numeric(14,2) not null check (commission >= 0),
  monthly_trail numeric(14,2) not null default 0 check (monthly_trail >= 0),
  calculation jsonb not null default '{}'::jsonb check (jsonb_typeof(calculation) = 'object'),
  created_at timestamptz not null default now()
);

create index saved_cases_user_created_idx
  on public.saved_cases (user_id, created_at desc);

alter table public.saved_cases enable row level security;
revoke all on table public.saved_cases from public, anon, authenticated;
grant select, insert, delete on table public.saved_cases to authenticated;

create policy "Agents read own saved cases"
  on public.saved_cases for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "Agents create own saved cases"
  on public.saved_cases for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "Agents delete own saved cases"
  on public.saved_cases for delete to authenticated
  using ((select auth.uid()) = user_id);
