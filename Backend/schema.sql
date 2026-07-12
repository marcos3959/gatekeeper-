-- Rode este script no Supabase: Project > SQL Editor > New query > Run

create table if not exists waitlist (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  created_at timestamp with time zone default now()
);

-- Segurança: bloqueia leitura/escrita pública direta pelo navegador.
-- Só a "service_role key" (usada pelo backend no Render) pode gravar aqui.
alter table waitlist enable row level security;
