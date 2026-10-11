create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  birth_date date,
  verified_at timestamptz,
  access_tier text not null default 'verified' check (access_tier in ('verified', 'child', 'ocr_unverified'))
);

alter table public.profiles alter column birth_date drop not null;
alter table public.profiles alter column verified_at drop not null;
alter table public.profiles add column if not exists access_tier text not null default 'verified'
  check (access_tier in ('verified', 'child', 'ocr_unverified'));
alter table public.profiles drop constraint if exists profiles_access_tier_check;
alter table public.profiles add constraint profiles_access_tier_check
  check (access_tier in ('verified', 'child', 'ocr_unverified'));

alter table public.profiles enable row level security;

-- Safe to rerun in your existing Supabase project. Private backend credentials
-- write verification results; an authenticated user's JWT cannot do so even if
-- an older permissive write policy is still present.
revoke insert, update, delete on public.profiles from public, anon, authenticated;
revoke insert (id, birth_date, verified_at, access_tier), update (id, birth_date, verified_at, access_tier)
  on public.profiles from public, anon, authenticated;
grant select on public.profiles to authenticated;
grant select, insert, update, delete on public.profiles to service_role;

-- Users can read their own row. There are no insert or update policies on purpose:
-- only a trusted verifier on the backend may write a verified birth date.
-- Never create a policy that lets users set their own birth_date or verified_at.
drop policy if exists "read own profile" on public.profiles;
create policy "read own profile" on public.profiles
  for select to authenticated using (auth.uid() = id);

-- A harmless probe lets the backend report whether these profile RPCs exist.
create or replace function public.profile_service_ready()
returns boolean
language sql
immutable
as $$ select true $$;
revoke all on function public.profile_service_ready() from public;
grant execute on function public.profile_service_ready() to anon, authenticated;

-- Unverified profile writes are scoped to the authenticated user's own row.
-- The database refuses to replace an existing provider-verified profile.
create or replace function public.set_child_profile()
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  profile_user_id uuid := auth.uid();
begin
  if profile_user_id is null then raise exception 'authentication_required'; end if;
  insert into public.profiles (id, birth_date, verified_at, access_tier)
  values (profile_user_id, null, null, 'child')
  on conflict (id) do update set birth_date = null, verified_at = null, access_tier = 'child'
    where public.profiles.verified_at is null or public.profiles.access_tier = 'child';
  if not found then raise exception 'verified_profile_immutable'; end if;
  return true;
end;
$$;
revoke all on function public.set_child_profile() from public, anon;
grant execute on function public.set_child_profile() to authenticated;

create or replace function public.save_ocr_birth_date(p_birth_date date)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  profile_user_id uuid := auth.uid();
begin
  if profile_user_id is null then raise exception 'authentication_required'; end if;
  if p_birth_date is null or p_birth_date > current_date or p_birth_date < current_date - interval '120 years' then
    raise exception 'invalid_birth_date';
  end if;
  insert into public.profiles (id, birth_date, verified_at, access_tier)
  values (profile_user_id, p_birth_date, null, 'ocr_unverified')
  on conflict (id) do update set birth_date = excluded.birth_date, verified_at = null, access_tier = 'ocr_unverified'
    where public.profiles.verified_at is null or public.profiles.access_tier = 'child';
  if not found then raise exception 'verified_profile_immutable'; end if;
  return true;
end;
$$;
revoke all on function public.save_ocr_birth_date(date) from public, anon;
grant execute on function public.save_ocr_birth_date(date) to authenticated;
