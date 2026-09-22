alter table public.agent_profiles
  add column if not exists avatar_path text;

alter table public.agent_profiles
  drop constraint if exists agent_profiles_avatar_path_check;
alter table public.agent_profiles
  add constraint agent_profiles_avatar_path_check
  check (avatar_path is null or avatar_path = user_id::text || '/avatar');

grant update (avatar_path) on public.agent_profiles to authenticated;

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('agent-avatars', 'agent-avatars', false, 2097152, array['image/jpeg','image/png','image/webp'])
on conflict (id) do update set
  public = excluded.public,
  file_size_limit = excluded.file_size_limit,
  allowed_mime_types = excluded.allowed_mime_types;

create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

create or replace function private.can_view_agent_avatar(target_user uuid)
returns boolean
language sql
security definer
stable
set search_path = ''
as $$
  with recursive organization as (
    select p.user_id, array[p.user_id] as path
    from public.agent_profiles p
    where p.user_id = auth.uid()
    union all
    select child.user_id, parent.path || child.user_id
    from public.agent_profiles child
    join organization parent on child.direct_upline_id = parent.user_id
    where not child.user_id = any(parent.path)
  )
  select auth.uid() is not null and exists (
    select 1 from organization where user_id = target_user
  );
$$;

revoke all on function private.can_view_agent_avatar(uuid) from public, anon;
grant execute on function private.can_view_agent_avatar(uuid) to authenticated;

drop policy if exists "organization avatar read" on storage.objects;
create policy "organization avatar read"
on storage.objects for select to authenticated
using (
  bucket_id = 'agent-avatars'
  and (storage.foldername(name))[1] ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
  and private.can_view_agent_avatar(((storage.foldername(name))[1])::uuid)
);

drop policy if exists "agent avatar insert" on storage.objects;
create policy "agent avatar insert"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'agent-avatars'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "agent avatar update" on storage.objects;
create policy "agent avatar update"
on storage.objects for update to authenticated
using (
  bucket_id = 'agent-avatars'
  and (storage.foldername(name))[1] = (select auth.uid())::text
)
with check (
  bucket_id = 'agent-avatars'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

drop policy if exists "agent avatar delete" on storage.objects;
create policy "agent avatar delete"
on storage.objects for delete to authenticated
using (
  bucket_id = 'agent-avatars'
  and (storage.foldername(name))[1] = (select auth.uid())::text
);

create or replace function public.get_organization_dashboard()
returns jsonb
language plpgsql
security definer
stable
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_result jsonb;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  with recursive organization as (
    select p.user_id, p.display_name, p.contract_level, p.direct_upline_id, p.avatar_path, 0 as depth, array[p.user_id] as path
    from public.agent_profiles p
    where p.user_id = v_user
    union all
    select child.user_id, child.display_name, child.contract_level, child.direct_upline_id, child.avatar_path, parent.depth + 1, parent.path || child.user_id
    from public.agent_profiles child
    join organization parent on child.direct_upline_id = parent.user_id
    where not child.user_id = any(parent.path)
  ), organization_metrics as (
    select o.*,
      coalesce((select sum(sc.agent_points) from public.saved_cases sc where sc.user_id = o.user_id and coalesce(sc.calculation->>'caseType','personal') <> 'downline'), 0) as personal_points,
      (select count(*) from public.saved_cases sc where sc.user_id = o.user_id) as saved_case_count,
      (select count(*) from organization d where o.user_id = any(d.path) and d.user_id <> o.user_id) as descendant_count
    from organization o
  )
  select jsonb_build_object(
    'profile', (
      select jsonb_build_object(
        'user_id', p.user_id,
        'display_name', p.display_name,
        'contract_level', p.contract_level,
        'direct_upline_id', p.direct_upline_id,
        'direct_upline_name', up.display_name,
        'avatar_path', p.avatar_path
      )
      from public.agent_profiles p
      left join public.agent_profiles up on up.user_id = p.direct_upline_id
      where p.user_id = v_user
    ),
    'tree', coalesce((
      select jsonb_agg(jsonb_build_object(
        'user_id', m.user_id,
        'display_name', m.display_name,
        'contract_level', m.contract_level,
        'direct_upline_id', m.direct_upline_id,
        'avatar_path', m.avatar_path,
        'depth', m.depth,
        'personal_points', m.personal_points,
        'saved_case_count', m.saved_case_count,
        'descendant_count', m.descendant_count
      ) order by m.depth, m.display_name)
      from organization_metrics m
    ), '[]'::jsonb),
    'incoming_requests', coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', r.id,
        'agent_id', r.agent_id,
        'agent_name', p.display_name,
        'contract_level', p.contract_level,
        'created_at', r.created_at
      ) order by r.created_at)
      from public.upline_requests r
      join public.agent_profiles p on p.user_id = r.agent_id
      where r.requested_upline_id = v_user and r.status = 'pending'
    ), '[]'::jsonb),
    'outgoing_request', (
      select jsonb_build_object(
        'id', r.id,
        'upline_id', r.requested_upline_id,
        'upline_name', p.display_name,
        'status', r.status,
        'created_at', r.created_at
      )
      from public.upline_requests r
      join public.agent_profiles p on p.user_id = r.requested_upline_id
      where r.agent_id = v_user and r.status = 'pending'
      order by r.created_at desc
      limit 1
    ),
    'active_invite', (
      select jsonb_build_object('id', i.id, 'code', i.code, 'expires_at', i.expires_at)
      from public.organization_invites i
      where i.created_by = v_user and i.used_at is null and i.claimed_by is null and i.expires_at > now()
      order by i.created_at desc
      limit 1
    )
  ) into v_result;

  return v_result;
end;
$$;


