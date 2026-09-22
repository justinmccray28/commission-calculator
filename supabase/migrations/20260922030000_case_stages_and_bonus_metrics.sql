alter table public.saved_cases
  add column if not exists stage text not null default 'prospect'
  constraint saved_cases_stage_check check (stage in ('prospect','submitted','issued','paid','lost'));

create index if not exists saved_cases_user_stage_idx
  on public.saved_cases (user_id, stage);

grant update (stage) on public.saved_cases to authenticated;

create policy "Agents update their own case stage"
  on public.saved_cases for update to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

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
    from public.agent_profiles p where p.user_id = v_user
    union all
    select child.user_id, child.display_name, child.contract_level, child.direct_upline_id, child.avatar_path, parent.depth + 1, parent.path || child.user_id
    from public.agent_profiles child join organization parent on child.direct_upline_id = parent.user_id
    where not child.user_id = any(parent.path)
  ), organization_metrics as (
    select o.*,
      coalesce((select sum(sc.agent_points) from public.saved_cases sc where sc.user_id=o.user_id and sc.stage in ('issued','paid') and coalesce(sc.calculation->>'caseType','personal') <> 'downline'),0) current_points,
      coalesce((select sum(sc.agent_points) from public.saved_cases sc where sc.user_id=o.user_id and sc.stage in ('prospect','submitted') and coalesce(sc.calculation->>'caseType','personal') <> 'downline'),0) pipeline_points,
      coalesce((select sum(sc.agent_points) from public.saved_cases sc where sc.user_id=o.user_id and sc.stage='lost' and coalesce(sc.calculation->>'caseType','personal') <> 'downline'),0) lost_points,
      coalesce((select sum(sc.commission) from public.saved_cases sc where sc.user_id=o.user_id and sc.stage in ('issued','paid') and coalesce(sc.calculation->>'caseType','personal') <> 'downline'),0) current_commission,
      coalesce((select sum(sc.commission) from public.saved_cases sc where sc.user_id=o.user_id and sc.stage in ('prospect','submitted') and coalesce(sc.calculation->>'caseType','personal') <> 'downline'),0) pipeline_commission,
      (select count(*) from public.saved_cases sc where sc.user_id=o.user_id) saved_case_count,
      (select count(*) from organization d where o.user_id=any(d.path) and d.user_id<>o.user_id) descendant_count
    from organization o
  )
  select jsonb_build_object(
    'profile',(select jsonb_build_object('user_id',p.user_id,'display_name',p.display_name,'contract_level',p.contract_level,'direct_upline_id',p.direct_upline_id,'direct_upline_name',up.display_name,'avatar_path',p.avatar_path) from public.agent_profiles p left join public.agent_profiles up on up.user_id=p.direct_upline_id where p.user_id=v_user),
    'tree',coalesce((select jsonb_agg(jsonb_build_object('user_id',m.user_id,'display_name',m.display_name,'contract_level',m.contract_level,'direct_upline_id',m.direct_upline_id,'avatar_path',m.avatar_path,'depth',m.depth,'personal_points',m.current_points+m.pipeline_points,'current_points',m.current_points,'pipeline_points',m.pipeline_points,'lost_points',m.lost_points,'current_commission',m.current_commission,'pipeline_commission',m.pipeline_commission,'saved_case_count',m.saved_case_count,'descendant_count',m.descendant_count) order by m.depth,m.display_name) from organization_metrics m),'[]'::jsonb),
    'incoming_requests',coalesce((select jsonb_agg(jsonb_build_object('id',r.id,'agent_id',r.agent_id,'agent_name',p.display_name,'contract_level',p.contract_level,'created_at',r.created_at) order by r.created_at) from public.upline_requests r join public.agent_profiles p on p.user_id=r.agent_id where r.requested_upline_id=v_user and r.status='pending'),'[]'::jsonb),
    'outgoing_request',(select jsonb_build_object('id',r.id,'upline_name',p.display_name,'status',r.status) from public.upline_requests r join public.agent_profiles p on p.user_id=r.requested_upline_id where r.agent_id=v_user and r.status='pending' order by r.created_at desc limit 1),
    'active_invite',(select jsonb_build_object('code',i.code,'expires_at',i.expires_at) from public.organization_invites i where i.created_by=v_user and i.claimed_by is null and i.used_at is null and i.expires_at>now() order by i.created_at desc limit 1)
  ) into v_result;
  return v_result;
end;
$$;

revoke all on function public.get_organization_dashboard() from public, anon;
grant execute on function public.get_organization_dashboard() to authenticated;
