-- =====================================================================
-- SKJ बिलिंग — Supabase सेटअप (एक बार, SQL Editor में पूरा paste करके Run करें)
-- =====================================================================

-- 1) टेबल
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text,
  role text not null default 'staff' check (role in ('admin','staff'))
);

create table if not exists public.app_settings (
  key text primary key,
  value text
);

create table if not exists public.counters (
  day text primary key,
  n int not null default 0
);

create table if not exists public.bills (
  id uuid primary key default gen_random_uuid(),
  bill_no text unique not null,
  vcode text not null default substr(md5(random()::text || clock_timestamp()::text), 1, 8),
  bill_date date not null,
  customer_name text,
  customer_phone text,
  customer_gstin text,
  tax_type text not null default 'intra',
  in_gst boolean not null default false,
  items jsonb not null default '[]'::jsonb,
  taxable numeric,
  gst_amount numeric,
  total numeric,
  sealed boolean not null default false,
  sealed_at timestamptz,
  sealed_by uuid,
  created_by uuid not null default auth.uid() references auth.users(id),
  created_by_name text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists bills_date_idx on public.bills(bill_date);
create index if not exists bills_creator_idx on public.bills(created_by);

-- 2) मदद के फ़ंक्शन
create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- नया यूज़र बनते ही उसकी प्रोफ़ाइल (नाम = ID)
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles(id, name) values (new.id, split_part(new.email, '@', 1))
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- बिल बनाने वाले का नाम सर्वर खुद भरता है (नकली नाम नहीं डाल सकते)
create or replace function public.bills_before_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  new.created_by := auth.uid();
  new.created_by_name := (select name from public.profiles where id = auth.uid());
  new.sealed := false; new.sealed_at := null; new.sealed_by := null;
  return new;
end $$;
drop trigger if exists bills_bi on public.bills;
create trigger bills_bi before insert on public.bills
  for each row execute function public.bills_before_insert();

-- सील के बाद बिल बदला नहीं जा सकता (Admin सील हटाकर ही बदल सकता है)
create or replace function public.bills_before_update() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if old.sealed and new.sealed and not public.is_admin() then
    raise exception 'सील्ड बिल बदला नहीं जा सकता';
  end if;
  new.bill_no := old.bill_no; new.vcode := old.vcode;
  new.created_by := old.created_by; new.created_by_name := old.created_by_name;
  return new;
end $$;
drop trigger if exists bills_bu on public.bills;
create trigger bills_bu before update on public.bills
  for each row execute function public.bills_before_update();

-- 3) बिल नंबर (सर्वर देता है, हर दिन 001 से)
create or replace function public.next_bill_no() returns text
language plpgsql security definer set search_path = public as $$
declare d text := to_char(now() at time zone 'Asia/Kolkata', 'YYMMDD'); v_n int;
begin
  if auth.uid() is null then raise exception 'login required'; end if;
  insert into public.counters(day, n) values (d, 1)
  on conflict (day) do update set n = public.counters.n + 1
  returning n into v_n;
  return 'SKJ-' || d || '-' || lpad(v_n::text, 3, '0');
end $$;

-- सील लगाना (सिर्फ़ बिल बनाने वाला या Admin)
create or replace function public.seal_bill(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.bills set sealed = true, sealed_at = now(), sealed_by = auth.uid(), updated_at = now()
  where id = p_id and (created_by = auth.uid() or public.is_admin());
  if not found then raise exception 'अनुमति नहीं है'; end if;
end $$;

-- GST लॉग में जोड़ना/हटाना (सील्ड बिल पर भी)
create or replace function public.set_gst(p_id uuid, p_val boolean) returns void
language plpgsql security definer set search_path = public as $$
begin
  update public.bills set in_gst = p_val, updated_at = now()
  where id = p_id and (created_by = auth.uid() or public.is_admin());
  if not found then raise exception 'अनुमति नहीं है'; end if;
end $$;

-- बिल की जाँच (कोई भी, बिना लॉगिन; बिल नंबर + कोड दोनों चाहिए)
create or replace function public.verify_bill(p_no text, p_code text)
returns table(bill_no text, bill_date date, customer text, total numeric, sealed boolean)
language sql security definer set search_path = public as $$
  select b.bill_no, b.bill_date,
         case when coalesce(b.customer_name,'') = '' then null
              else left(b.customer_name,1) || repeat('*', greatest(length(b.customer_name)-1, 0)) end,
         b.total, b.sealed
  from public.bills b where b.bill_no = p_no and b.vcode = p_code limit 1;
$$;

-- 4) सुरक्षा नियम (RLS)
alter table public.profiles     enable row level security;
alter table public.app_settings enable row level security;
alter table public.counters     enable row level security;
alter table public.bills        enable row level security;

drop policy if exists profiles_select on public.profiles;
create policy profiles_select on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_admin());
drop policy if exists profiles_admin_update on public.profiles;
create policy profiles_admin_update on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists settings_select on public.app_settings;
create policy settings_select on public.app_settings for select to authenticated using (true);
drop policy if exists settings_admin_write on public.app_settings;
create policy settings_admin_write on public.app_settings for all to authenticated
  using (public.is_admin()) with check (public.is_admin());

drop policy if exists bills_select on public.bills;
create policy bills_select on public.bills for select to authenticated
  using (public.is_admin() or created_by = auth.uid());
drop policy if exists bills_insert on public.bills;
create policy bills_insert on public.bills for insert to authenticated
  with check (created_by = auth.uid());
drop policy if exists bills_update on public.bills;
create policy bills_update on public.bills for update to authenticated
  using (public.is_admin() or (created_by = auth.uid() and sealed = false))
  with check (public.is_admin() or (created_by = auth.uid() and sealed = false));
drop policy if exists bills_delete on public.bills;
create policy bills_delete on public.bills for delete to authenticated using (public.is_admin());

-- 5) फ़ंक्शन की अनुमतियाँ
revoke all on function public.next_bill_no() from public, anon;
revoke all on function public.seal_bill(uuid) from public, anon;
revoke all on function public.set_gst(uuid, boolean) from public, anon;
grant execute on function public.next_bill_no() to authenticated;
grant execute on function public.seal_bill(uuid) to authenticated;
grant execute on function public.set_gst(uuid, boolean) to authenticated;
grant execute on function public.verify_bill(text, text) to anon, authenticated;

-- 6) पहला Admin बनाने के बाद (नीचे 'ravi' की जगह अपनी ID लिखकर अलग से Run करें):
-- update public.profiles set role = 'admin' where name = 'ravi';
