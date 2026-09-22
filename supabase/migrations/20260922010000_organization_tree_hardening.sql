create index organization_invites_claimed_by_idx
  on public.organization_invites (claimed_by)
  where claimed_by is not null;

create index upline_requests_invite_id_idx
  on public.upline_requests (invite_id);

create policy "Requests have no direct table access"
  on public.upline_requests for select to authenticated
  using (false);
