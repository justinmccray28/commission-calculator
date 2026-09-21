alter table public.saved_cases
  add column agent_points numeric(14,2) not null default 0
  check (agent_points >= 0);

update public.saved_cases
set agent_points = round(
  (replace(calculation->>'basis', ',', '')::numeric)
  * case when coalesce(calculation->>'termLength', '') <> '' then 12 else 1 end
  * ((calculation->>'rate')::numeric / 100)
  * case
      when calculation->>'isSplit' = 'true'
        then ((calculation->>'mySplit')::numeric / 100)
      else 1
    end,
  2
)
where replace(coalesce(calculation->>'basis', ''), ',', '') ~ '^[0-9]+([.][0-9]+)?$'
  and coalesce(calculation->>'rate', '') ~ '^[0-9]+([.][0-9]+)?$'
  and (
    calculation->>'isSplit' <> 'true'
    or coalesce(calculation->>'mySplit', '') ~ '^[0-9]+([.][0-9]+)?$'
  );
