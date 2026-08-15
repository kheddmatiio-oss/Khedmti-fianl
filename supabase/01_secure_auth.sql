-- ═══════════════════════════════════════════════════════════════
--  Khedmti — تأمين المصادقة والبيانات
--  الصقو كامل في SQL Editor واضغط Run مرة وحدة
-- ═══════════════════════════════════════════════════════════════
--  واش يدير:
--   1. يمنع أي قراءة/كتابة مباشرة على الجداول بالمفتاح العمومي
--   2. كلمات السر تولّي bcrypt (pgcrypto) — تتحقق في السيرفر
--   3. الدخول والحفظ يمرّوا عبر دوال RPC + توكن جلسة
--   4. الحسابات الموجودة تتعيّن لها كلمة سر جديدة في الخطوة 12
-- ═══════════════════════════════════════════════════════════════

create extension if not exists pgcrypto with schema extensions;

-- ── 1. أعمدة جديدة ────────────────────────────────────────────
alter table agencies add column if not exists pw_hash  text;
alter table agencies add column if not exists is_super boolean default false;

-- app_data: ننظّفو أي صفوف مكرّرة ثم نفرضو قيد وحدانية
-- (api_save تعتمد عليه في on conflict)
delete from app_data a using app_data b
 where a.agency_id = b.agency_id and a.ctid > b.ctid;
create unique index if not exists app_data_agency_uniq on app_data(agency_id);

-- ── 2. جدول الجلسات ───────────────────────────────────────────
create table if not exists sessions (
  token      uuid primary key default gen_random_uuid(),
  agency_id  uuid references agencies(id) on delete cascade,
  worker_id  text,
  created_at timestamptz default now(),
  expires_at timestamptz default now() + interval '60 days'
);
create index if not exists sessions_agency_idx on sessions(agency_id);

-- ── 3. قفل الجداول ────────────────────────────────────────────
-- مع تفعيل RLS وبلا أي policy، المفتاح العمومي ما يقدر يمسّ والو مباشرة.
-- الوصول الوحيد يبقى عبر الدوال تحت (security definer).
alter table agencies enable row level security;
alter table app_data enable row level security;
alter table sessions enable row level security;

drop policy if exists "allow all" on agencies;
drop policy if exists "allow all" on app_data;
drop policy if exists "allow all" on sessions;

-- ── 4. أدوات داخلية ───────────────────────────────────────────
create or replace function agency_public(a agencies)
returns jsonb language sql immutable as $$
  select to_jsonb(a) - 'pw_hash' - 'password_hash';
$$;

create or replace function session_agency(p_token uuid)
returns uuid language sql stable as $$
  select agency_id from sessions
   where token = p_token and expires_at > now();
$$;

-- ── 5. تسجيل حساب جديد ────────────────────────────────────────
create or replace function api_register(
  p_name text, p_email text, p_password text,
  p_phone text default '', p_type text default 'agency')
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a agencies; tok uuid;
begin
  p_email := lower(trim(p_email));
  if length(coalesce(p_password,'')) < 4 then raise exception 'weak_password'; end if;
  if exists (select 1 from agencies where email = p_email) then
    raise exception 'duplicate_email';
  end if;

  insert into agencies (name, email, password_hash, pw_hash, phone, account_type)
  values (trim(p_name), p_email, '', crypt(p_password, gen_salt('bf', 10)),
          trim(coalesce(p_phone,'')), coalesce(p_type,'agency'))
  returning * into a;

  insert into app_data (agency_id, data)
  values (a.id, '{"editors":[],"clients":[],"videos":[],"invoices":[],"tasks":[]}'::jsonb);

  insert into sessions (agency_id) values (a.id) returning token into tok;
  return jsonb_build_object('token', tok, 'agency', agency_public(a));
end $$;

-- ── 6. دخول الوكالة ───────────────────────────────────────────
create or replace function api_login(p_email text, p_password text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a agencies; tok uuid; ok boolean := false;
begin
  select * into a from agencies where email = lower(trim(p_email));
  if a.id is null then raise exception 'not_found'; end if;

  ok := (a.pw_hash is not null and a.pw_hash <> '' and a.pw_hash = crypt(p_password, a.pw_hash));

  if not ok then raise exception 'bad_password'; end if;

  insert into sessions (agency_id) values (a.id) returning token into tok;
  return jsonb_build_object('token', tok, 'agency', agency_public(a));
end $$;

-- ── 7. دخول عضو الفريق ────────────────────────────────────────
-- إيميل الوكالة + كلمة سر العضو. التحقق كامل في السيرفر.
create or replace function api_login_worker(p_agency_email text, p_password text)
returns jsonb
language plpgsql security definer set search_path = public, extensions as $$
declare a agencies; d jsonb; w jsonb; tok uuid; found jsonb := null;
begin
  select * into a from agencies where email = lower(trim(p_agency_email));
  if a.id is null then raise exception 'agency_not_found'; end if;

  select data into d from app_data where agency_id = a.id;

  for w in select * from jsonb_array_elements(coalesce(d->'editors','[]'::jsonb)) loop
    if (w->>'pw') is not null and w->>'pw' <> ''
       and w->>'pw' = crypt(p_password, w->>'pw') then
      found := w; exit;
    end if;
  end loop;

  if found is null then raise exception 'bad_password'; end if;

  insert into sessions (agency_id, worker_id) values (a.id, found->>'id')
  returning token into tok;

  return jsonb_build_object(
    'token', tok, 'agency', agency_public(a),
    'worker', found - 'password' - 'pw', 'data', d);
end $$;

-- ── 8. تعيين كلمة سر عضو (bcrypt) ─────────────────────────────
create or replace function api_hash_password(p_token uuid, p_password text)
returns text
language plpgsql security definer set search_path = public, extensions as $$
begin
  if session_agency(p_token) is null then raise exception 'no_session'; end if;
  if length(coalesce(p_password,'')) < 4 then raise exception 'weak_password'; end if;
  return crypt(p_password, gen_salt('bf', 10));
end $$;

-- ── 9. قراءة وحفظ البيانات ────────────────────────────────────
create or replace function api_load(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public as $$
declare ag uuid; d jsonb;
begin
  ag := session_agency(p_token);
  if ag is null then raise exception 'no_session'; end if;
  select data into d from app_data where agency_id = ag;
  return coalesce(d, '{"editors":[],"clients":[],"videos":[],"invoices":[],"tasks":[]}'::jsonb);
end $$;

create or replace function api_save(p_token uuid, p_data jsonb)
returns void
language plpgsql security definer set search_path = public as $$
declare ag uuid;
begin
  ag := session_agency(p_token);
  if ag is null then raise exception 'no_session'; end if;
  insert into app_data (agency_id, data, updated_at) values (ag, p_data, now())
  on conflict (agency_id) do update set data = excluded.data, updated_at = now();
end $$;

create or replace function api_logout(p_token uuid)
returns void language sql security definer set search_path = public as $$
  delete from sessions where token = p_token;
$$;

-- ── 10. صلاحيات التنفيذ ───────────────────────────────────────
revoke all on function session_agency(uuid)   from anon, authenticated;

grant execute on function api_register(text,text,text,text,text) to anon;
grant execute on function api_login(text,text)                    to anon;
grant execute on function api_login_worker(text,text)             to anon;
grant execute on function api_hash_password(uuid,text)            to anon;
grant execute on function api_load(uuid)                          to anon;
grant execute on function api_save(uuid,jsonb)                    to anon;
grant execute on function api_logout(uuid)                        to anon;

-- ── 11. المدير العام ──────────────────────────────────────────
-- بدّل الإيميل لإيميلك وشغّل السطر، بعدها امسح الحساب المكتوب في الكود
-- update agencies set is_super = true where email = 'kheddmati.io@gmail.com';

-- ── 12. الحسابات الموجودة ─────────────────────────────────────
-- الهاش القديم ما يتحوّلش لـ bcrypt، فلازم تعيّن كلمة سر جديدة
-- لكل حساب موجود. بدّل القيم وشغّل:
--
--   update agencies
--      set pw_hash = extensions.crypt('كلمة_السر_الجديدة', extensions.gen_salt('bf',10))
--    where email = 'bgh.agency.contact@gmail.com';
--
-- أعضاء الفريق: المسير يعاود يعيّن لهم كلمة السر من تبويب "الفريق"
-- بعد ما نحدّث الكود — تتخزن وقتها bcrypt.
