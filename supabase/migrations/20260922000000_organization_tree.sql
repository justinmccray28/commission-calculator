create table public.agent_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 2 and 100),
  contract_level text not null check (contract_level in ('ta','associate','sa','md','smd')),
  direct_upline_id uuid references public.agent_profiles(user_id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (direct_upline_id is null or direct_upline_id <> user_id)
);

create index agent_profiles_direct_upline_idx
  on public.agent_profiles (direct_upline_id)
  where direct_upline_id is not null;

create table public.organization_invites (
  id uuid primary key default gen_random_uuid(),
  created_by uuid not null references public.agent_profiles(user_id) on delete cascade,
  code text not null unique check (code ~ '^[A-Z2-9]{4}-[A-Z2-9]{4}$'),
  expires_at timestamptz not null,
  claimed_by uuid references public.agent_profiles(user_id) on delete set null,
  claimed_at timestamptz,
  used_at timestamptz,
  created_at timestamptz not null default now(),
  check (expires_at > created_at and expires_at <= created_at + interval '8 days')
);

create index organization_invites_creator_idx
  on public.organization_invites (created_by, created_at desc);

create table public.upline_requests (
  id uuid primary key default gen_random_uuid(),
  agent_id uuid not null references public.agent_profiles(user_id) on delete cascade,
  requested_upline_id uuid not null references public.agent_profiles(user_id) on delete cascade,
  invite_id uuid not null references public.organization_invites(id) on delete restrict,
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  created_at timestamptz not null default now(),
  responded_at timestamptz,
  check (agent_id <> requested_upline_id)
);

create unique index upline_requests_one_pending_agent_idx
  on public.upline_requests (agent_id)
  where status = 'pending';

create index upline_requests_upline_status_idx
  on public.upline_requests (requested_upline_id, status, created_at desc);

alter table public.agent_profiles enable row level security;
alter table public.organization_invites enable row level security;
alter table public.upline_requests enable row level security;

revoke all on table public.agent_profiles from public, anon, authenticated;
revoke all on table public.organization_invites from public, anon, authenticated;
revoke all on table public.upline_requests from public, anon, authenticated;

grant select on table public.agent_profiles to authenticated;
grant insert (user_id, display_name, contract_level) on table public.agent_profiles to authenticated;
grant update (display_name, contract_level, updated_at) on table public.agent_profiles to authenticated;
grant select, insert on table public.organization_invites to authenticated;

create policy "Agents read their own profile"
  on public.agent_profiles for select to authenticated
  using ((select auth.uid()) = user_id);

create policy "Agents create their own profile"
  on public.agent_profiles for insert to authenticated
  with check ((select auth.uid()) = user_id and direct_upline_id is null);

create policy "Agents update their own profile"
  on public.agent_profiles for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

create policy "Agents read their own invites"
  on public.organization_invites for select to authenticated
  using ((select auth.uid()) = created_by);

create policy "Agents create their own invites"
  on public.organization_invites for insert to authenticated
  with check (
    (select auth.uid()) = created_by
    and claimed_by is null
    and claimed_at is null
    and used_at is null
  );

create or replace function public.request_upline_link(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_invite public.organization_invites%rowtype;
  v_request public.upline_requests%rowtype;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;
  if not exists (select 1 from public.agent_profiles where user_id = v_user) then
    raise exception 'Create your agent profile first' using errcode = '22023';
  end if;
  if exists (select 1 from public.agent_profiles where user_id = v_user and direct_upline_id is not null) then
    raise exception 'This account already has a direct upline' using errcode = '22023';
  end if;
  if exists (select 1 from public.upline_requests where agent_id = v_user and status = 'pending') then
    raise exception 'An upline request is already pending' using errcode = '22023';
  end if;

  select * into v_invite
  from public.organization_invites
  where code = upper(trim(p_code))
    and expires_at > now()
    and used_at is null
    and claimed_by is null
  for update;

  if not found then
    raise exception 'Invitation code is invalid, expired, or already claimed' using errcode = '22023';
  end if;
  if v_invite.created_by = v_user then
    raise exception 'You cannot join your own organization' using errcode = '22023';
  end if;

  update public.organization_invites
  set claimed_by = v_user, claimed_at = now()
  where id = v_invite.id;

  insert into public.upline_requests (agent_id, requested_upline_id, invite_id)
  values (v_user, v_invite.created_by, v_invite.id)
  returning * into v_request;

  return jsonb_build_object('request_id', v_request.id, 'status', v_request.status);
end;
$$;

create or replace function public.respond_upline_request(p_request_id uuid, p_approve boolean)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_request public.upline_requests%rowtype;
  v_cycle boolean;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select * into v_request
  from public.upline_requests
  where id = p_request_id
    and requested_upline_id = v_user
    and status = 'pending'
  for update;

  if not found then
    raise exception 'Pending request not found' using errcode = '22023';
  end if;

  if p_approve then
    if exists (select 1 from public.agent_profiles where user_id = v_request.agent_id and direct_upline_id is not null) then
      raise exception 'Agent already has a direct upline' using errcode = '22023';
    end if;

    with recursive descendants as (
      select user_id from public.agent_profiles where direct_upline_id = v_request.agent_id
      union all
      select child.user_id
      from public.agent_profiles child
      join descendants parent on child.direct_upline_id = parent.user_id
    )
    select exists (select 1 from descendants where user_id = v_user) into v_cycle;

    if v_cycle then
      raise exception 'This approval would create a circular hierarchy' using errcode = '22023';
    end if;

    update public.agent_profiles
    set direct_upline_id = v_user, updated_at = now()
    where user_id = v_request.agent_id;

    update public.organization_invites
    set used_at = now()
    where id = v_request.invite_id;

    update public.upline_requests
    set status = 'approved', responded_at = now()
    where id = v_request.id;
  else
    update public.organization_invites
    set claimed_by = null, claimed_at = null
    where id = v_request.invite_id and used_at is null;

    update public.upline_requests
    set status = 'rejected', responded_at = now()
    where id = v_request.id;
  end if;

  return jsonb_build_object('request_id', v_request.id, 'status', case when p_approve then 'approved' else 'rejected' end);
end;
$$;

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
    select p.user_id, p.display_name, p.contract_level, p.direct_upline_id, 0 as depth, array[p.user_id] as path
    from public.agent_profiles p
    where p.user_id = v_user
    union all
    select child.user_id, child.display_name, child.contract_level, child.direct_upline_id, parent.depth + 1, parent.path || child.user_id
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
        'direct_upline_name', up.display_name
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

revoke all on function public.request_upline_link(text) from public, anon;
revoke all on function public.respond_upline_request(uuid, boolean) from public, anon;
revoke all on function public.get_organization_dashboard() from public, anon;
grant execute on function public.request_upline_link(text) to authenticated;
grant execute on function public.respond_upline_request(uuid, boolean) to authenticated;
grant execute on function public.get_organization_dashboard() to authenticated;
