-- Seven.AM - Group Chat patch
-- Safe to rerun after the previous schema-cache / quoting error.

create extension if not exists pgcrypto;

create table if not exists public.chat_groups (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null references public.profiles(id),
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
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
  created_at timestamptz not null default now()
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
using (public.is_group_member(group_id, auth.uid()));

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

select 'Seven.AM Group Chat patch complete' as result;
