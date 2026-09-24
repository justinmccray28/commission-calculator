create table public.admin_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'data_admin')),
  active boolean not null default true,
  granted_by uuid references auth.users(id) on delete set null,
  granted_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.admin_audit_log (
  id bigint generated always as identity primary key,
  actor_user_id uuid references auth.users(id) on delete set null,
  action text not null,
  target_user_id uuid references auth.users(id) on delete set null,
  previous_value jsonb,
  new_value jsonb,
  created_at timestamptz not null default now()
);

create index admin_audit_log_created_at_idx on public.admin_audit_log (created_at desc);
create index admin_audit_log_actor_idx on public.admin_audit_log (actor_user_id, created_at desc);

alter table public.admin_roles enable row level security;
alter table public.admin_audit_log enable row level security;

revoke all on table public.admin_roles from public, anon, authenticated;
revoke all on table public.admin_audit_log from public, anon, authenticated;

create or replace function public.get_my_admin_role()
returns text
language plpgsql
security definer
stable
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_role text;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select role into v_role
  from public.admin_roles
  where user_id = v_user and active;

  return coalesce(v_role, 'agent');
end;
$$;

create or replace function public.get_admin_dashboard()
returns jsonb
language plpgsql
security definer
stable
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_role text;
  v_result jsonb;
begin
  if v_user is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select role into v_role
  from public.admin_roles
  where user_id = v_user and active;

  if v_role not in ('owner', 'data_admin') then
    raise exception 'Administrator access required' using errcode = '42501';
  end if;

  select jsonb_build_object(
    'role', v_role,
    'users', case when v_role = 'owner' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'user_id', u.id,
        'email', u.email,
        'display_name', p.display_name,
        'contract_level', p.contract_level,
        'admin_role', coalesce(r.role, 'agent'),
        'admin_active', coalesce(r.active, false),
        'created_at', u.created_at,
        'last_sign_in_at', u.last_sign_in_at
      ) order by coalesce(p.display_name, u.email), u.created_at)
      from auth.users u
      left join public.agent_profiles p on p.user_id = u.id
      left join public.admin_roles r on r.user_id = u.id
    ), '[]'::jsonb) else '[]'::jsonb end,
    'audit', case when v_role = 'owner' then coalesce((
      select jsonb_agg(jsonb_build_object(
        'id', a.id,
        'actor_user_id', a.actor_user_id,
        'actor_name', coalesce(actor_profile.display_name, actor.email),
        'action', a.action,
        'target_user_id', a.target_user_id,
        'target_name', coalesce(target_profile.display_name, target.email),
        'previous_value', a.previous_value,
        'new_value', a.new_value,
        'created_at', a.created_at
      ) order by a.created_at desc)
      from (
        select * from public.admin_audit_log order by created_at desc limit 50
      ) a
      left join auth.users actor on actor.id = a.actor_user_id
      left join public.agent_profiles actor_profile on actor_profile.user_id = a.actor_user_id
      left join auth.users target on target.id = a.target_user_id
      left join public.agent_profiles target_profile on target_profile.user_id = a.target_user_id
    ), '[]'::jsonb) else '[]'::jsonb end
  ) into v_result;

  return v_result;
end;
$$;

create or replace function public.set_admin_user_role(p_user_id uuid, p_role text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_actor uuid := auth.uid();
  v_actor_role text;
  v_previous public.admin_roles%rowtype;
begin
  if v_actor is null then
    raise exception 'Authentication required' using errcode = '42501';
  end if;

  select role into v_actor_role
  from public.admin_roles
  where user_id = v_actor and active;

  if v_actor_role <> 'owner' then
    raise exception 'Owner access required' using errcode = '42501';
  end if;
  if p_role not in ('agent', 'data_admin', 'owner') then
    raise exception 'Invalid administrator role' using errcode = '22023';
  end if;
  if not exists (select 1 from auth.users where id = p_user_id) then
    raise exception 'User not found' using errcode = '22023';
  end if;

  perform 1 from public.admin_roles where role = 'owner' and active for update;
  select * into v_previous from public.admin_roles where user_id = p_user_id;

  if v_previous.role = 'owner' and v_previous.active and p_role <> 'owner'
     and (select count(*) from public.admin_roles where role = 'owner' and active) <= 1 then
    raise exception 'The final owner cannot be removed' using errcode = '22023';
  end if;

  if p_role = 'agent' then
    delete from public.admin_roles where user_id = p_user_id;
  else
    insert into public.admin_roles (user_id, role, active, granted_by)
    values (p_user_id, p_role, true, v_actor)
    on conflict (user_id) do update
      set role = excluded.role,
          active = true,
          granted_by = v_actor,
          granted_at = now(),
          updated_at = now();
  end if;

  insert into public.admin_audit_log (actor_user_id, action, target_user_id, previous_value, new_value)
  values (
    v_actor,
    'admin_role_changed',
    p_user_id,
    case when v_previous.user_id is null then null else jsonb_build_object('role', v_previous.role, 'active', v_previous.active) end,
    jsonb_build_object('role', p_role, 'active', p_role <> 'agent')
  );

  return jsonb_build_object('user_id', p_user_id, 'role', p_role);
end;
$$;

revoke all on function public.get_my_admin_role() from public, anon;
revoke all on function public.get_admin_dashboard() from public, anon;
revoke all on function public.set_admin_user_role(uuid, text) from public, anon;
grant execute on function public.get_my_admin_role() to authenticated;
grant execute on function public.get_admin_dashboard() to authenticated;
grant execute on function public.set_admin_user_role(uuid, text) to authenticated;

-- Seed the existing project owner. Further administrators must be granted by an owner.
insert into public.admin_roles (user_id, role, active, granted_by)
select id, 'owner', true, id
from auth.users
where id = 'b82db036-f992-4ef1-8975-4d510c2841a7'
on conflict (user_id) do update set role = 'owner', active = true, updated_at = now();

insert into public.admin_audit_log (actor_user_id, action, target_user_id, new_value)
select id, 'initial_owner_seeded', id, jsonb_build_object('role', 'owner', 'active', true)
from auth.users
where id = 'b82db036-f992-4ef1-8975-4d510c2841a7';
