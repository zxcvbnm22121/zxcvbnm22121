-- Seven.AM SOL - Supabase full backend setup
-- Safe to re-run. Run in Supabase SQL Editor as postgres.

create extension if not exists pgcrypto;

-- =========================================================
-- Helper: Leader role
-- =========================================================
create or replace function public.is_leader()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where id = auth.uid() and role = 'leader' and active = true
  );
$$;

grant execute on function public.is_leader() to authenticated;

-- =========================================================
-- Existing core tables: Data API grants
-- =========================================================
grant usage on schema public to authenticated;
grant select, update on public.profiles to authenticated;
grant select, insert, update, delete on public.tasks to authenticated;
grant select, insert on public.task_history to authenticated;
grant usage, select on sequence public.task_history_id_seq to authenticated;

-- Leader delete task
drop policy if exists "Leader deletes tasks" on public.tasks;
create policy "Leader deletes tasks"
on public.tasks for delete to authenticated
using (public.is_leader());

-- =========================================================
-- Announcements / programs
-- =========================================================
create table if not exists public.announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  content text not null,
  start_date date,
  end_date date,
  priority text not null default 'Bình thường',
  active boolean not null default true,
  created_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.announcements enable row level security;
grant select, insert, update, delete on public.announcements to authenticated;

drop policy if exists "Authenticated view announcements" on public.announcements;
create policy "Authenticated view announcements"
on public.announcements for select to authenticated using (true);

drop policy if exists "Leader creates announcements" on public.announcements;
create policy "Leader creates announcements"
on public.announcements for insert to authenticated
with check (public.is_leader() and created_by = auth.uid());

drop policy if exists "Leader updates announcements" on public.announcements;
create policy "Leader updates announcements"
on public.announcements for update to authenticated
using (public.is_leader()) with check (public.is_leader());

drop policy if exists "Leader deletes announcements" on public.announcements;
create policy "Leader deletes announcements"
on public.announcements for delete to authenticated using (public.is_leader());

-- =========================================================
-- Work schedules
-- =========================================================
create table if not exists public.work_schedules (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  work_date date not null,
  shift text not null,
  start_time time,
  end_time time,
  note text,
  status text not null default 'Chờ duyệt',
  reviewed_at timestamptz,
  reviewed_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index if not exists work_schedules_user_date_uidx
on public.work_schedules(user_id, work_date);
alter table public.work_schedules enable row level security;
grant select, insert, update, delete on public.work_schedules to authenticated;

drop policy if exists "Users view schedules" on public.work_schedules;
create policy "Users view schedules"
on public.work_schedules for select to authenticated
using (user_id = auth.uid() or public.is_leader());

drop policy if exists "Users register own schedules" on public.work_schedules;
create policy "Users register own schedules"
on public.work_schedules for insert to authenticated
with check (user_id = auth.uid() or public.is_leader());

drop policy if exists "Users update own schedules or leader" on public.work_schedules;
create policy "Users update own schedules or leader"
on public.work_schedules for update to authenticated
using (user_id = auth.uid() or public.is_leader())
with check (user_id = auth.uid() or public.is_leader());

drop policy if exists "Leader deletes schedules" on public.work_schedules;
create policy "Leader deletes schedules"
on public.work_schedules for delete to authenticated
using (public.is_leader());

-- =========================================================
-- Leave / late requests
-- =========================================================
create table if not exists public.leave_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  type text not null,
  date_from date not null,
  date_to date,
  session text,
  arrival_time time,
  reason text not null,
  status text not null default 'Chờ duyệt',
  leader_note text,
  reviewed_at timestamptz,
  reviewed_by uuid references public.profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.leave_requests enable row level security;
grant select, insert, update, delete on public.leave_requests to authenticated;

drop policy if exists "Users view leave requests" on public.leave_requests;
create policy "Users view leave requests"
on public.leave_requests for select to authenticated
using (user_id = auth.uid() or public.is_leader());

drop policy if exists "Users create own leave requests" on public.leave_requests;
create policy "Users create own leave requests"
on public.leave_requests for insert to authenticated
with check (user_id = auth.uid());

drop policy if exists "Users update own pending leave or leader" on public.leave_requests;
create policy "Users update own pending leave or leader"
on public.leave_requests for update to authenticated
using (user_id = auth.uid() or public.is_leader())
with check (user_id = auth.uid() or public.is_leader());

drop policy if exists "Leader deletes leave requests" on public.leave_requests;
create policy "Leader deletes leave requests"
on public.leave_requests for delete to authenticated
using (public.is_leader());

-- =========================================================
-- Reports: Ads / Live / Zalo / Web in one table
-- =========================================================
create table if not exists public.report_entries (
  id uuid primary key default gen_random_uuid(),
  channel text not null check (channel in ('ads','live','zalo','web')),
  report_date date not null,
  employee_id uuid references public.profiles(id) on delete set null,
  employee_name text,
  entered_by uuid not null references public.profiles(id),
  data_count numeric not null default 0,
  orders numeric not null default 0,
  sales numeric not null default 0,
  products numeric not null default 0,
  posts numeric not null default 0,
  interested numeric not null default 0,
  note text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.report_entries enable row level security;
grant select, insert, update, delete on public.report_entries to authenticated;

drop policy if exists "Users view reports" on public.report_entries;
create policy "Users view reports"
on public.report_entries for select to authenticated
using (
  public.is_leader()
  or employee_id = auth.uid()
  or entered_by = auth.uid()
);

drop policy if exists "Users insert reports" on public.report_entries;
create policy "Users insert reports"
on public.report_entries for insert to authenticated
with check (
  public.is_leader()
  or entered_by = auth.uid()
);

drop policy if exists "Users update reports" on public.report_entries;
create policy "Users update reports"
on public.report_entries for update to authenticated
using (
  public.is_leader()
  or entered_by = auth.uid()
)
with check (
  public.is_leader()
  or entered_by = auth.uid()
);

drop policy if exists "Leader deletes reports" on public.report_entries;
create policy "Leader deletes reports"
on public.report_entries for delete to authenticated
using (public.is_leader());

-- =========================================================
-- Chat messages
-- =========================================================
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  content text,
  image_path text,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
alter table public.messages enable row level security;
grant select, insert, update on public.messages to authenticated;
grant usage, select on sequence public.messages_id_seq to authenticated;

drop policy if exists "Users view own conversations" on public.messages;
create policy "Users view own conversations"
on public.messages for select to authenticated
using (sender_id = auth.uid() or receiver_id = auth.uid());

drop policy if exists "Users send messages" on public.messages;
create policy "Users send messages"
on public.messages for insert to authenticated
with check (sender_id = auth.uid() and receiver_id <> auth.uid());

drop policy if exists "Receiver marks messages read" on public.messages;
create policy "Receiver marks messages read"
on public.messages for update to authenticated
using (receiver_id = auth.uid())
with check (receiver_id = auth.uid());

-- =========================================================
-- Private chat image storage
-- =========================================================
insert into storage.buckets (id, name, public)
values ('chat-images','chat-images',false)
on conflict (id) do update set public = false;

drop policy if exists "Authenticated users view chat images" on storage.objects;
create policy "Authenticated users view chat images"
on storage.objects for select to authenticated
using (bucket_id = 'chat-images');

drop policy if exists "Users upload chat images" on storage.objects;
create policy "Users upload chat images"
on storage.objects for insert to authenticated
with check (
  bucket_id = 'chat-images'
  and (storage.foldername(name))[1] = auth.uid()::text
);

drop policy if exists "Users delete own chat images" on storage.objects;
create policy "Users delete own chat images"
on storage.objects for delete to authenticated
using (
  bucket_id = 'chat-images'
  and (storage.foldername(name))[1] = auth.uid()::text
);

-- =========================================================
-- Realtime publication (ignore if already added)
-- =========================================================
do $$
begin
  begin alter publication supabase_realtime add table public.tasks; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.task_history; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.messages; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.announcements; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.work_schedules; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.leave_requests; exception when duplicate_object then null; end;
  begin alter publication supabase_realtime add table public.report_entries; exception when duplicate_object then null; end;
end $$;

select 'Seven.AM Supabase backend setup complete' as result;
