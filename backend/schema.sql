-- Rode este script no Supabase: Project > SQL Editor > New query > Run
-- Se você já criou a tabela antiga chamada "waitlist" por engano, apague-a primeiro:
-- drop table if exists waitlist;

create table if not exists gatekeeper_waitlist (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  created_at timestamp with time zone default now()
);

-- Segurança: bloqueia leitura/escrita pública direta pelo navegador.
-- Só a "service_role key" (usada pelo backend no Render) pode gravar aqui.
alter table gatekeeper_waitlist enable row level security;
