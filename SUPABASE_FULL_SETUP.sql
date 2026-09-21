-- ============================================================
-- SEVEN.AM SOL — COMPLETE SUPABASE BACKEND SETUP
-- Version: production hardening
-- Safe to re-run on the Seven.AM project.
-- Run in Supabase SQL Editor as the project owner/postgres role.
-- ============================================================

create extension if not exists pgcrypto;

-- ============================================================
-- 1. CORE PROFILES
-- ============================================================
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null default '',
  role text not null default 'sale' check (role in ('leader','sale')),
  title text,
  phone text,
  zalo text,
  email text,
  avatar_url text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles enable row level security;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, email, role, active)
  values (
    new.id,
    coalesce(new.raw_user_meta_data ->> 'full_name', ''),
    new.email,
    'sale',
    true
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- Backfill profiles for Auth users created before the trigger existed.
insert into public.profiles (id, full_name, email, role, active)
select
  u.id,
  coalesce(u.raw_user_meta_data ->> 'full_name', ''),
  u.email,
  'sale',
  true
from auth.users u
on conflict (id) do nothing;

-- Helper used by RLS and guard triggers.
create or replace function public.is_leader()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and role = 'leader'
      and active = true
  );
$$;

revoke all on function public.is_leader() from public;
grant execute on function public.is_leader() to authenticated;

grant usage on schema public to authenticated;
grant select on public.profiles to authenticated;

-- Do not allow browser clients to change their role/active/id.
revoke update on public.profiles from authenticated;
grant update (full_name, title, phone, zalo, email, avatar_url, updated_at)
on public.profiles to authenticated;

drop policy if exists "Authenticated users can view profiles" on public.profiles;
create policy "Authenticated users can view profiles"
on public.profiles for select to authenticated
using (true);

drop policy if exists "Users update own profile" on public.profiles;
create policy "Users update own profile"
on public.profiles for update to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- ============================================================
-- 2. TASKS
-- ============================================================
create table if not exists public.tasks (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text,
  task_group text,
  assigned_to uuid not null references public.profiles(id),
  created_by uuid not null references public.profiles(id),
  priority text not null default 'medium' check (priority in ('high','medium','low')),
  status text not null default 'todo' check (status in ('todo','doing','done')),
  deadline timestamptz,
  is_read boolean not null default false,
  read_at timestamptz,
  checklist jsonb not null default '{"items":[],"checked":[]}'::jsonb,
  result text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.tasks add column if not exists task_group text;
alter table public.tasks enable row level security;
grant select, insert, update, delete on public.tasks to authenticated;

drop policy if exists "Users view allowed tasks" on public.tasks;
create policy "Users view allowed tasks"
on public.tasks for select to authenticated
using (
  assigned_to = auth.uid()
  or public.is_leader()
);

drop policy if exists "Leader creates tasks" on public.tasks;
create policy "Leader creates tasks"
on public.tasks for insert to authenticated
with check (
  public.is_leader()
  and created_by = auth.uid()
  and exists (
    select 1 from public.profiles p
    where p.id = assigned_to and p.role = 'sale' and p.active = true
  )
);

drop policy if exists "Sale updates assigned tasks" on public.tasks;
create policy "Sale updates assigned tasks"
on public.tasks for update to authenticated
using (assigned_to = auth.uid())
with check (assigned_to = auth.uid());

drop policy if exists "Leader updates all tasks" on public.tasks;
create policy "Leader updates all tasks"
on public.tasks for update to authenticated
using (public.is_leader())
with check (public.is_leader());

drop policy if exists "Leader deletes tasks" on public.tasks;
create policy "Leader deletes tasks"
on public.tasks for delete to authenticated
using (public.is_leader());

-- A Sale may update progress fields only. Protected task-definition fields
-- cannot be modified even by calling the REST API manually.
create or replace function public.guard_task_update()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  item_count integer;
  checked_count integer;
begin
  new.updated_at := now();

  if auth.uid() is null or public.is_leader() then
    return new;
  end if;

  if old.assigned_to <> auth.uid() then
    raise exception 'Not allowed to update this task';
  end if;

  if new.title is distinct from old.title
     or new.description is distinct from old.description
     or new.task_group is distinct from old.task_group
     or new.assigned_to is distinct from old.assigned_to
     or new.created_by is distinct from old.created_by
     or new.priority is distinct from old.priority
     or new.deadline is distinct from old.deadline
     or new.created_at is distinct from old.created_at then
    raise exception 'Sale can only update task progress';
  end if;

  if new.status = 'done' then
    if coalesce(btrim(new.result), '') = '' then
      raise exception 'A completed task requires a result';
    end if;

    item_count := jsonb_array_length(coalesce(new.checklist -> 'items', '[]'::jsonb));
    checked_count := jsonb_array_length(coalesce(new.checklist -> 'checked', '[]'::jsonb));

    if checked_count < item_count then
      raise exception 'All checklist items must be completed';
    end if;

    if new.completed_at is null then
      new.completed_at := now();
    end if;
  end if;

  if new.is_read = true and old.is_read = false and new.read_at is null then
    new.read_at := now();
  end if;

  return new;
end;
$$;

drop trigger if exists guard_task_update_trigger on public.tasks;
create trigger guard_task_update_trigger
before update on public.tasks
for each row execute function public.guard_task_update();

-- ============================================================
-- 3. TASK HISTORY
-- ============================================================
create table if not exists public.task_history (
  id bigint generated always as identity primary key,
  task_id uuid not null references public.tasks(id) on delete cascade,
  user_id uuid references public.profiles(id),
  action text not null,
  detail text,
  created_at timestamptz not null default now()
);

alter table public.task_history enable row level security;
grant select, insert on public.task_history to authenticated;
grant usage, select on sequence public.task_history_id_seq to authenticated;

drop policy if exists "Users view task history" on public.task_history;
create policy "Users view task history"
on public.task_history for select to authenticated
using (
  exists (
    select 1 from public.tasks t
    where t.id = task_id
      and (t.assigned_to = auth.uid() or public.is_leader())
  )
);

drop policy if exists "Users create task history" on public.task_history;
create policy "Users create task history"
on public.task_history for insert to authenticated
with check (
  user_id = auth.uid()
  and exists (
    select 1 from public.tasks t
    where t.id = task_id
      and (t.assigned_to = auth.uid() or public.is_leader())
  )
);

-- ============================================================
-- 4. ANNOUNCEMENTS / PROGRAMS
-- ============================================================
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
  updated_at timestamptz not null default now(),
  constraint announcement_date_order check (
    end_date is null or start_date is null or end_date >= start_date
  )
);

alter table public.announcements enable row level security;
grant select, insert, update, delete on public.announcements to authenticated;

drop policy if exists "Authenticated view announcements" on public.announcements;
create policy "Authenticated view announcements"
on public.announcements for select to authenticated
using (
  public.is_leader()
  or (
    active = true
    and (start_date is null or start_date <= current_date)
    and (end_date is null or end_date >= current_date)
  )
);

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
on public.announcements for delete to authenticated
using (public.is_leader());

-- ============================================================
-- 5. WORK SCHEDULES
-- ============================================================
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

create or replace function public.guard_work_schedule()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  new.updated_at := now();

  if auth.uid() is not null and not public.is_leader() then
    if new.user_id <> auth.uid() then
      raise exception 'Cannot register a schedule for another user';
    end if;
    new.status := 'Chờ duyệt';
    new.reviewed_at := null;
    new.reviewed_by := null;
  end if;

  return new;
end;
$$;

drop trigger if exists guard_work_schedule_trigger on public.work_schedules;
create trigger guard_work_schedule_trigger
before insert or update on public.work_schedules
for each row execute function public.guard_work_schedule();

-- ============================================================
-- 6. LEAVE / LATE REQUESTS
-- ============================================================
create table if not exists public.leave_requests (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  type text not null check (type in ('Nghỉ phép','Đến muộn')),
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
with check (
  user_id = auth.uid()
  and status = 'Chờ duyệt'
  and reviewed_at is null
  and reviewed_by is null
);

drop policy if exists "Users update own pending leave or leader" on public.leave_requests;
create policy "Users update own pending leave or leader"
on public.leave_requests for update to authenticated
using (
  public.is_leader()
  or (user_id = auth.uid() and status = 'Chờ duyệt')
)
with check (
  public.is_leader()
  or (
    user_id = auth.uid()
    and status = 'Chờ duyệt'
    and reviewed_at is null
    and reviewed_by is null
  )
);

drop policy if exists "Leader deletes leave requests" on public.leave_requests;
create policy "Leader deletes leave requests"
on public.leave_requests for delete to authenticated
using (public.is_leader());

-- ============================================================
-- 7. REPORTS — ADS / LIVE / ZALO / WEB
-- ============================================================
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

-- Prevent negative operational numbers.
do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'report_nonnegative_values') then
    alter table public.report_entries
    add constraint report_nonnegative_values check (
      data_count >= 0 and orders >= 0 and sales >= 0
      and products >= 0 and posts >= 0 and interested >= 0
    );
  end if;
end $$;

-- One Live row per date; other channels one row per employee/date.
create unique index if not exists report_live_date_uidx
on public.report_entries(report_date)
where channel = 'live';

create unique index if not exists report_employee_date_uidx
on public.report_entries(
  channel,
  report_date,
  coalesce(employee_id, '00000000-0000-0000-0000-000000000000'::uuid)
)
where channel in ('ads','zalo','web');

create or replace function public.normalize_report_entry()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  new.updated_at := now();

  if new.employee_id is not null then
    select full_name into new.employee_name
    from public.profiles
    where id = new.employee_id;
  end if;

  if auth.uid() is not null and not public.is_leader() then
    new.entered_by := auth.uid();
    new.employee_id := auth.uid();

    select full_name into new.employee_name
    from public.profiles
    where id = auth.uid();
  end if;

  return new;
end;
$$;

drop trigger if exists normalize_report_entry_trigger on public.report_entries;
create trigger normalize_report_entry_trigger
before insert or update on public.report_entries
for each row execute function public.normalize_report_entry();

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
  or (entered_by = auth.uid() and employee_id = auth.uid())
);

drop policy if exists "Users update reports" on public.report_entries;
create policy "Users update reports"
on public.report_entries for update to authenticated
using (
  public.is_leader()
  or (entered_by = auth.uid() and employee_id = auth.uid())
)
with check (
  public.is_leader()
  or (entered_by = auth.uid() and employee_id = auth.uid())
);

drop policy if exists "Leader deletes reports" on public.report_entries;
create policy "Leader deletes reports"
on public.report_entries for delete to authenticated
using (public.is_leader());

-- ============================================================
-- 8. CHAT MESSAGES
-- ============================================================
create table if not exists public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  receiver_id uuid not null references public.profiles(id) on delete cascade,
  content text,
  image_path text,
  read_at timestamptz,
  created_at timestamptz not null default now(),
  constraint message_has_content check (
    nullif(btrim(content), '') is not null or image_path is not null
  )
);

alter table public.messages enable row level security;
grant select, insert on public.messages to authenticated;
revoke update on public.messages from authenticated;
grant update (read_at) on public.messages to authenticated;
grant usage, select on sequence public.messages_id_seq to authenticated;

drop policy if exists "Users view own conversations" on public.messages;
create policy "Users view own conversations"
on public.messages for select to authenticated
using (sender_id = auth.uid() or receiver_id = auth.uid());

drop policy if exists "Users send messages" on public.messages;
create policy "Users send messages"
on public.messages for insert to authenticated
with check (
  sender_id = auth.uid()
  and receiver_id <> auth.uid()
  and (
    image_path is null
    or (storage.foldername(image_path))[1] = auth.uid()::text
  )
);

drop policy if exists "Receiver marks messages read" on public.messages;
create policy "Receiver marks messages read"
on public.messages for update to authenticated
using (receiver_id = auth.uid())
with check (receiver_id = auth.uid());

-- ============================================================
-- 9. GROUP CHAT
-- ============================================================
create table if not exists public.chat_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null references public.profiles(id),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint chat_group_name_not_blank check (nullif(btrim(name), '') is not null)
);

create table if not exists public.chat_group_members (
  group_id uuid not null references public.chat_groups(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  added_by uuid references public.profiles(id),
  joined_at timestamptz not null default now(),
  last_read_at timestamptz not null default now(),
  primary key (group_id, user_id)
);

alter table public.chat_group_members
  add column if not exists last_read_at timestamptz not null default now();

create table if not exists public.chat_group_messages (
  id bigint generated always as identity primary key,
  group_id uuid not null references public.chat_groups(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  content text,
  image_path text,
  created_at timestamptz not null default now(),
  constraint group_message_has_content check (
    nullif(btrim(content), '') is not null or image_path is not null
  )
);

create or replace function public.is_group_member(
  target_group uuid,
  target_user uuid
)
returns boolean
language sql
stable
security definer
set search_path = public
as '
  select exists (
    select 1
    from public.chat_group_members gm
    where gm.group_id = target_group
      and gm.user_id = target_user
  );
';

revoke all on function public.is_group_member(uuid, uuid) from public;
grant execute on function public.is_group_member(uuid, uuid) to authenticated;

alter table public.chat_groups enable row level security;
alter table public.chat_group_members enable row level security;
alter table public.chat_group_messages enable row level security;

grant select, insert, update, delete on public.chat_groups to authenticated;
grant select, insert, delete on public.chat_group_members to authenticated;
revoke update on public.chat_group_members from authenticated;
grant update (last_read_at) on public.chat_group_members to authenticated;
grant select, insert on public.chat_group_messages to authenticated;
grant usage, select on sequence public.chat_group_messages_id_seq to authenticated;

drop policy if exists "Members view chat groups" on public.chat_groups;
create policy "Members view chat groups"
on public.chat_groups for select to authenticated
using (
  public.is_leader()
  or public.is_group_member(id, auth.uid())
);

drop policy if exists "Leader creates chat groups" on public.chat_groups;
create policy "Leader creates chat groups"
on public.chat_groups for insert to authenticated
with check (public.is_leader() and created_by = auth.uid());

drop policy if exists "Leader updates chat groups" on public.chat_groups;
create policy "Leader updates chat groups"
on public.chat_groups for update to authenticated
using (public.is_leader())
with check (public.is_leader());

drop policy if exists "Leader deletes chat groups" on public.chat_groups;
create policy "Leader deletes chat groups"
on public.chat_groups for delete to authenticated
using (public.is_leader());

drop policy if exists "Members view group membership" on public.chat_group_members;
create policy "Members view group membership"
on public.chat_group_members for select to authenticated
using (
  public.is_leader()
  or public.is_group_member(group_id, auth.uid())
);

drop policy if exists "Leader adds group members" on public.chat_group_members;
create policy "Leader adds group members"
on public.chat_group_members for insert to authenticated
with check (
  public.is_leader()
  and added_by = auth.uid()
);

drop policy if exists "Leader removes group members" on public.chat_group_members;
create policy "Leader removes group members"
on public.chat_group_members for delete to authenticated
using (public.is_leader());

drop policy if exists "Members update own group read state" on public.chat_group_members;
create policy "Members update own group read state"
on public.chat_group_members for update to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

drop policy if exists "Members view group messages" on public.chat_group_messages;
create policy "Members view group messages"
on public.chat_group_messages for select to authenticated
using (
  public.is_group_member(group_id, auth.uid())
);

drop policy if exists "Members send group messages" on public.chat_group_messages;
create policy "Members send group messages"
on public.chat_group_messages for insert to authenticated
with check (
  sender_id = auth.uid()
  and public.is_group_member(group_id, auth.uid())
  and (
    image_path is null
    or (storage.foldername(image_path))[1] = auth.uid()::text
  )
);

-- ============================================================
-- 10. PRIVATE CHAT IMAGE STORAGE
-- ============================================================
insert into storage.buckets (id, name, public)
values ('chat-images','chat-images',false)
on conflict (id) do update set public = false;

drop policy if exists "Authenticated users view chat images" on storage.objects;
create policy "Authenticated users view chat images"
on storage.objects for select to authenticated
using (
  bucket_id = 'chat-images'
  and (
    exists (
      select 1
      from public.messages m
      where m.image_path = name
        and (m.sender_id = auth.uid() or m.receiver_id = auth.uid())
    )
    or exists (
      select 1
      from public.chat_group_messages gm
      where gm.image_path = name
        and public.is_group_member(gm.group_id, auth.uid())
    )
  )
);

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

-- ============================================================
-- 11. REALTIME
-- ============================================================
-- Replace the publication membership with the Seven.AM tables.
-- This syntax is idempotent and avoids unsupported DROP TABLE IF EXISTS.
alter publication supabase_realtime set table
  public.profiles,
  public.tasks,
  public.task_history,
  public.messages,
  public.chat_groups,
  public.chat_group_members,
  public.chat_group_messages,
  public.announcements,
  public.work_schedules,
  public.leave_requests,
  public.report_entries;

NOTIFY pgrst, 'reload schema';

select 'Seven.AM Supabase backend setup complete — hardened' as result;
