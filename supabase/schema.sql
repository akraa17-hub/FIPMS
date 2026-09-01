-- ============================================================
-- FIPMS — نظام متابعة الأراضي | سكربت قاعدة البيانات (Supabase)
-- انسخه كاملاً في: SQL Editor → New query → Run
-- ============================================================

-- ---------- 1) الجداول ----------
create table if not exists public.lands (
  id bigint primary key,
  block text default '',
  land_no text default '',
  old_land_no text default '',
  land_type text default '',
  client_name text default '',
  client_type text default '',
  via text default '',
  contract_no text default '',
  contract_type text default '',
  contract_signed text default '',
  addendum text default '',
  addendum_signed text default '',
  first_payment text default '',
  transfer_payment text default '',
  deed_no text default '',
  deed_date text default '',
  deed_in_kind_no text default '',
  deed_in_kind_date text default '',
  area double precision,
  price_per_meter double precision,
  value double precision,
  transfer_date text default '',
  status text default '',
  deleted_at timestamptz,
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.archive (
  id bigint primary key,
  entry jsonb not null default '{}'::jsonb,
  deleted_at timestamptz,
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.tax_log (
  id bigint primary key,
  entry jsonb not null default '{}'::jsonb,
  deleted_at timestamptz,
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.reg_log (
  id bigint primary key,
  entry jsonb not null default '{}'::jsonb,
  deleted_at timestamptz,
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.app_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb,
  updated_at timestamptz default now(),
  updated_by text default ''
);

create table if not exists public.roles (
  name text primary key,
  permissions text[] not null default '{}',
  is_system boolean not null default false,
  updated_at timestamptz default now()
);

create table if not exists public.user_roles (
  email text primary key,
  role text not null references public.roles(name),
  updated_at timestamptz default now()
);

-- ---------- 2) الأدوار الافتراضية ----------
insert into public.roles (name, permissions, is_system) values
('مالك',  array['view','export','edit_records','delete_records','archive_records','recycle','issue_tax','issue_reg','follow_tax','follow_reg','manage_statuses','manage_templates','manage_settings','manage_users','reset_data','manage_connection'], true),
('مشرف',  array['view','export','edit_records','delete_records','archive_records','recycle','issue_tax','issue_reg','follow_tax','follow_reg','manage_statuses','manage_templates','manage_settings','manage_users'], true),
('محرر',  array['view','export','edit_records','issue_tax','issue_reg','follow_tax','follow_reg'], true),
('مطالع', array['view','export'], true)
on conflict (name) do nothing;

-- ---------- 3) دوال الصلاحيات ----------
create or replace function public.current_role()
returns text language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.user_roles where email = auth.email() limit 1), 'مطالع')
$$;

create or replace function public.has_perm(p text)
returns boolean language sql stable security definer set search_path = public as $$
  select exists(
    select 1 from public.roles r
    where r.name = public.current_role() and p = any(r.permissions)
  )
$$;

-- ---------- 4) سياسات RLS (قابلة لإعادة التشغيل بأمان) ----------
alter table public.lands        enable row level security;
alter table public.archive      enable row level security;
alter table public.tax_log      enable row level security;
alter table public.reg_log      enable row level security;
alter table public.app_settings enable row level security;
alter table public.roles        enable row level security;
alter table public.user_roles   enable row level security;

-- lands
drop policy if exists lands_select on public.lands;
create policy lands_select on public.lands for select
  using (public.has_perm('view') and (deleted_at is null or public.has_perm('recycle')));
drop policy if exists lands_insert on public.lands;
create policy lands_insert on public.lands for insert
  with check (public.has_perm('edit_records'));
drop policy if exists lands_update on public.lands;
create policy lands_update on public.lands for update
  using (public.has_perm('edit_records') or public.has_perm('recycle') or public.has_perm('manage_settings'));
drop policy if exists lands_delete on public.lands;
create policy lands_delete on public.lands for delete
  using (public.has_perm('recycle') or public.has_perm('reset_data'));

-- archive
drop policy if exists archive_select on public.archive;
create policy archive_select on public.archive for select
  using (public.has_perm('view') and (deleted_at is null or public.has_perm('recycle')));
drop policy if exists archive_insert on public.archive;
create policy archive_insert on public.archive for insert
  with check (public.has_perm('archive_records'));
drop policy if exists archive_update on public.archive;
create policy archive_update on public.archive for update
  using (public.has_perm('archive_records') or public.has_perm('recycle'));
drop policy if exists archive_delete on public.archive;
create policy archive_delete on public.archive for delete
  using (public.has_perm('recycle') or public.has_perm('reset_data'));

-- tax_log
drop policy if exists tax_select on public.tax_log;
create policy tax_select on public.tax_log for select
  using (public.has_perm('view') and (deleted_at is null or public.has_perm('recycle')));
drop policy if exists tax_insert on public.tax_log;
create policy tax_insert on public.tax_log for insert
  with check (public.has_perm('issue_tax'));
drop policy if exists tax_update on public.tax_log;
create policy tax_update on public.tax_log for update
  using (public.has_perm('issue_tax') or public.has_perm('follow_tax') or public.has_perm('recycle'));
drop policy if exists tax_delete on public.tax_log;
create policy tax_delete on public.tax_log for delete
  using (public.has_perm('recycle') or public.has_perm('reset_data'));

-- reg_log
drop policy if exists reg_select on public.reg_log;
create policy reg_select on public.reg_log for select
  using (public.has_perm('view') and (deleted_at is null or public.has_perm('recycle')));
drop policy if exists reg_insert on public.reg_log;
create policy reg_insert on public.reg_log for insert
  with check (public.has_perm('issue_reg'));
drop policy if exists reg_update on public.reg_log;
create policy reg_update on public.reg_log for update
  using (public.has_perm('issue_reg') or public.has_perm('follow_reg') or public.has_perm('recycle'));
drop policy if exists reg_delete on public.reg_log;
create policy reg_delete on public.reg_log for delete
  using (public.has_perm('recycle') or public.has_perm('reset_data'));

-- app_settings
drop policy if exists settings_select on public.app_settings;
create policy settings_select on public.app_settings for select
  using (public.has_perm('view'));
drop policy if exists settings_insert on public.app_settings;
create policy settings_insert on public.app_settings for insert
  with check (public.has_perm('manage_templates') or public.has_perm('manage_statuses') or public.has_perm('manage_settings'));
drop policy if exists settings_update on public.app_settings;
create policy settings_update on public.app_settings for update
  using (public.has_perm('manage_templates') or public.has_perm('manage_statuses') or public.has_perm('manage_settings'));
drop policy if exists settings_delete on public.app_settings;
create policy settings_delete on public.app_settings for delete
  using (public.has_perm('manage_settings') or public.has_perm('reset_data'));

-- roles (تعديل تعريفات الأدوار: المالك فقط)
drop policy if exists roles_select on public.roles;
create policy roles_select on public.roles for select using (public.has_perm('view'));
drop policy if exists roles_insert on public.roles;
create policy roles_insert on public.roles for insert with check (public.has_perm('manage_connection'));
drop policy if exists roles_update on public.roles;
create policy roles_update on public.roles for update using (public.has_perm('manage_connection'));
drop policy if exists roles_delete on public.roles;
create policy roles_delete on public.roles for delete using (public.has_perm('manage_connection'));

-- user_roles (القراءة لأي مستخدم مسجّل — الإدارة للمالك والمشرف)
drop policy if exists user_roles_select on public.user_roles;
create policy user_roles_select on public.user_roles for select
  using (auth.role() = 'authenticated');
drop policy if exists user_roles_insert on public.user_roles;
create policy user_roles_insert on public.user_roles for insert
  with check (public.has_perm('manage_users') and (role <> 'مالك' or public.has_perm('manage_connection')));
drop policy if exists user_roles_update on public.user_roles;
create policy user_roles_update on public.user_roles for update
  using (public.has_perm('manage_users'));
drop policy if exists user_roles_delete on public.user_roles;
create policy user_roles_delete on public.user_roles for delete
  using (public.has_perm('manage_users'));

-- ---------- 5) Realtime ----------
do $$
begin
  alter publication supabase_realtime add table public.lands;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.archive;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.tax_log;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.reg_log;
exception when duplicate_object then null;
end $$;
do $$
begin
  alter publication supabase_realtime add table public.app_settings;
exception when duplicate_object then null;
end $$;

-- ---------- 6) تعيين المالك ----------
-- شغّل هذا السطر منفرداً بعد استبدال البريد ببريد المالك:
insert into public.user_roles (email, role) values ('akr.aa17@gmail.com', 'مالك')
on conflict (email) do update set role = 'مالك';
