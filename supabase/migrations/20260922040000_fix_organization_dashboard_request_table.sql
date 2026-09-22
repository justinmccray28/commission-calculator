do $$
declare
  function_definition text;
begin
  select pg_get_functiondef('public.get_organization_dashboard()'::regprocedure)
    into function_definition;
  function_definition := replace(
    function_definition,
    'public.upline_link_requests',
    'public.upline_requests'
  );
  execute function_definition;
end;
$$;
