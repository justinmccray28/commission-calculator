create table public.agent_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  settings jsonb not null default '{}'::jsonb,
  constraint settings_is_object check (jsonb_typeof(settings) = 'object')
);

alter table public.agent_settings enable row level security;
revoke all on table public.agent_settings from public, anon, authenticated;
grant select, insert, update on table public.agent_settings to authenticated;

create policy "Agents read own settings"
  on public.agent_settings for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "Agents create own settings"
  on public.agent_settings for insert to authenticated
  with check ((select auth.uid()) = user_id);

create policy "Agents update own settings"
  on public.agent_settings for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);
