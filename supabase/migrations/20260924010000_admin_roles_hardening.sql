create index admin_roles_granted_by_idx on public.admin_roles (granted_by) where granted_by is not null;
create index admin_audit_log_target_idx on public.admin_audit_log (target_user_id, created_at desc) where target_user_id is not null;

create policy "Admin roles have no direct table access"
  on public.admin_roles for select to authenticated
  using (false);

create policy "Admin audit has no direct table access"
  on public.admin_audit_log for select to authenticated
  using (false);
