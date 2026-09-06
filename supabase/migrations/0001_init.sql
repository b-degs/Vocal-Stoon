-- Vocal STOON — real backend schema, RLS, and RPCs
-- =====================================================================
-- This replaces the Claude-artifact mock database / localStorage fallback
-- with a real, shared Postgres database on Supabase. It preserves the
-- existing app's exact behavior and UX (see SPEC.md) while fixing the
-- security shortcuts that were acceptable ONLY inside the sandboxed
-- prototype (see "SECURITY NOTES" at the bottom of this file).
--
-- ONE-TIME MANUAL SETUP after running this migration:
--   1. In the Supabase dashboard: Settings -> API -> "JWT Keys" -> copy the
--      current key's secret. If your project only shows asymmetric signing
--      keys (ES256/RS256 — no plain secret string anywhere), rotate to a
--      shared-secret key first: "Create standby key" -> choose HS256 /
--      "Legacy shared secret" -> promote it to current -> switch to the
--      "Legacy" view to reveal the actual secret string. See SPEC.md
--      "Auth caveat" for why this build needs a plain HS256 secret.
--   2. Run once, with your real values substituted in:
--        update app_config set jwt_secret = '<paste-your-secret>',
--                               council_code = '<pick-a-real-code>';
--      (Older guidance for this kind of setting says
--      `ALTER DATABASE ... SET app.foo = ...` — as of this build, Supabase
--      denies that outright on at least some projects, even to the SQL
--      Editor's own role, on both the database and any role
--      ("permission denied to set parameter"). The app_config table below
--      sidesteps that: it only needs the same ordinary table-owner
--      privilege you already have from running this migration.)
-- =====================================================================

-- Supabase installs pgcrypto (and would install pgjwt) into a schema
-- called `extensions`, not `public` — confirmed on a real project while
-- building this. Installing both explicitly into that same schema keeps
-- pgjwt's internal calls to pgcrypto's hmac()/etc. resolving correctly;
-- leaving pgjwt to default to `public` (the failure mode this comment is
-- warning about) breaks it with "function public.hmac(...) does not
-- exist" the first time sign_up()/sign_in() actually run.
create extension if not exists pgcrypto with schema extensions;   -- crypt()/gen_salt() password hashing
create extension if not exists pgjwt with schema extensions;      -- sign() for minting our own session JWTs

-- Every anon/authenticated role can, by default, CREATE TEMP TABLE in this
-- database (Postgres's default PUBLIC privilege) — and Postgres always
-- searches a session's own temp schema FIRST for relation names, before
-- anything in search_path, for every role including this one. Without this
-- revoke, any client could run `create temp table residents (...)` in
-- their own session and have every SECURITY DEFINER function below
-- (sign_in, sign_up, cast_vote, ...) silently read/write that fake table
-- instead of the real one — no `set search_path` on those functions can
-- prevent this, because search_path settings don't affect temp-schema
-- lookup for relations. This was verified to be a real, working exploit
-- (a forged council session token) against this schema before this line
-- was added; do not remove it.
do $$ begin
  execute format('revoke temporary on database %I from public', current_database());
end $$;

-- ---------------------------------------------------------------------
-- Reference data: wards/ridings. Kept as a real table (not a hardcoded
-- array in the client) so council can rename/add/retire wards later
-- without a code change — the old RIDINGS constant becomes seed data.
-- ---------------------------------------------------------------------
create table if not exists ridings (
  name text primary key
);
insert into ridings(name) values
  ('Fairhaven'),('Riverbend'),('Northgate'),('Elm Terrace'),
  ('Cedar Flats'),('Downtown Core'),('Southbridge'),('Willowdale')
on conflict do nothing;

-- ---------------------------------------------------------------------
-- residents
-- ---------------------------------------------------------------------
create table if not exists residents (
  id text primary key default ('R-' ||
    upper(substr(md5(gen_random_uuid()::text), 1, 4)) || '-' ||
    upper(substr(md5(gen_random_uuid()::text), 1, 4))),
  full_name text not null,
  address text not null,
  city text not null default 'Saskatoon',
  postal_code text default '',
  riding text references ridings(name),
  jurisdiction text not null default 'Saskatoon',
  password_hash text not null,               -- pgcrypto bcrypt hash — NEVER plaintext
  role text not null default 'resident' check (role in ('resident','council')),
  verification_status text not null default 'pending' check (verification_status in ('pending','verified','rejected')),
  verification_method text,
  submitted_at timestamptz not null default now(),
  verified_at timestamptz,
  verified_by text,
  created_at timestamptz not null default now()
);

-- Sign-in matches on normalized full name + address + riding (+ password
-- checked separately via crypt()) — index the normalized text so a real
-- resident base doesn't turn sign-in into a full table scan the way the
-- prototype's client-side scan did.
create index if not exists residents_signin_lookup_idx
  on residents (lower(regexp_replace(trim(full_name), '\s+', ' ', 'g')),
                lower(regexp_replace(trim(address), '\s+', ' ', 'g')),
                riding);

alter table residents enable row level security;
-- Intentionally NO policies here for anon/authenticated: the table is
-- fully locked down from direct PostgREST access. Every legitimate way in
-- or out goes through a SECURITY DEFINER function below (sign_up, sign_in,
-- get_my_profile, complete_self_verification, council_set_verification) or
-- the residents_public view (council roster only, no password_hash).

-- ---------------------------------------------------------------------
-- app_config — holds the JWT signing secret and the council signup code.
-- A plain locked-down table instead of the Postgres GUCs
-- (`ALTER DATABASE ... SET app.foo = ...`) earlier drafts of this
-- migration used: confirmed on a real Supabase project that newer projects
-- deny `ALTER DATABASE`/`ALTER ROLE` for custom parameters outright
-- ("permission denied to set parameter"), even to the SQL Editor's own
-- role. A table needs no special privilege beyond normal DML on something
-- you own, and RLS with zero policies keeps it exactly as unreadable over
-- the API as residents/poll_ballots are — see the one-time setup note at
-- the top of this file for the `update app_config set ...` to run after
-- this migration.
-- ---------------------------------------------------------------------
create table if not exists app_config (
  id boolean primary key default true check (id),   -- singleton-row guard
  jwt_secret text,
  council_code text
);
insert into app_config (id) values (true) on conflict (id) do nothing;
alter table app_config enable row level security;
-- No policies: fully locked from anon/authenticated. Only
-- mint_session_token()/sign_up() (both SECURITY DEFINER) ever read it.

-- =====================================================================
-- JWT / auth helper functions
-- =====================================================================
-- Reads the custom claims off whatever JWT PostgREST verified for this
-- request. Our sign_in()/sign_up() functions mint that JWT themselves
-- (see below) — this is NOT Supabase's built-in GoTrue auth, because the
-- app's login fields are full name + address + ward + password, not an
-- email/username. See SPEC.md "Auth model" for why.
-- Defined here (before polls' RLS policies) because those policies call
-- is_council()/current_resident_role() — Postgres resolves a policy's
-- expression at CREATE POLICY time, so the functions must already exist.
create or replace function current_jwt_claims() returns jsonb
language sql stable as $$
  select coalesce(current_setting('request.jwt.claims', true)::jsonb, '{}'::jsonb)
$$;

create or replace function current_resident_id() returns text
language sql stable as $$
  select current_jwt_claims()->>'resident_id'
$$;

create or replace function current_resident_role() returns text
language sql stable as $$
  select current_jwt_claims()->>'resident_role'
$$;

create or replace function is_council() returns boolean
language sql stable as $$
  select current_resident_role() = 'council'
$$;

-- ---------------------------------------------------------------------
-- polls  (options kept as JSONB, same shape the client already uses:
-- [{id, label}, ...] — avoids a bigger client rewrite for something that
-- doesn't need relational querying on its own)
-- ---------------------------------------------------------------------
create table if not exists polls (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null,
  category text not null default 'General',
  budget_amount numeric not null default 0,
  options jsonb not null,                    -- [{"id": "...", "label": "..."}]
  eligible_ridings text[],                   -- null/empty = citywide
  closes_at timestamptz not null,
  status text not null default 'open' check (status in ('open','closed')),
  created_by text references residents(id),
  created_at timestamptz not null default now(),
  closed_at timestamptz
);

alter table polls enable row level security;

create policy polls_select_authenticated on polls
  for select
  using (current_resident_role() is not null);   -- must be signed in; see helper fns below

create policy polls_insert_council on polls
  for insert
  with check (is_council());

create policy polls_update_council on polls
  for update
  using (is_council())
  with check (is_council());

-- ---------------------------------------------------------------------
-- poll_voters — "this resident voted" flag only. No option/choice here.
-- Blocks double voting and feeds turnout counts. No direct policies:
-- only cast_vote() (insert) and my_voted_polls() (select, own rows only)
-- touch this table.
-- ---------------------------------------------------------------------
create table if not exists poll_voters (
  poll_id uuid not null references polls(id) on delete cascade,
  resident_id text not null references residents(id),
  voted_at timestamptz not null default now(),
  primary key (poll_id, resident_id)
);
alter table poll_voters enable row level security;
-- No policies: fully locked to direct access, by design (secret ballot).

-- ---------------------------------------------------------------------
-- poll_ballots — the anonymous choice. NO resident reference at all,
-- on purpose — this is what keeps a ballot un-linkable to a voter, same
-- guarantee the original prototype made.
-- ---------------------------------------------------------------------
create table if not exists poll_ballots (
  id uuid primary key default gen_random_uuid(),
  poll_id uuid not null references polls(id) on delete cascade,
  option_id text not null,
  voted_at timestamptz not null default now()
);
alter table poll_ballots enable row level security;
-- No policies: fully locked. Only cast_vote() (insert) and poll_results()
-- (aggregate select) touch this table — nobody can select raw ballot rows
-- over the API, even though the rows carry no identity to begin with.

-- Council-only view of the roster, minus password_hash. Regular residents
-- never need this (they use get_my_profile() for their own row) but the
-- policy also lets a resident read their own row here as a harmless
-- fallback.
--
-- Deliberately NOT `security_invoker = true`. `residents` has RLS enabled
-- with zero policies for anon/authenticated, which means a security-invoker
-- view querying it as the caller's role would always see zero rows,
-- regardless of this view's own WHERE clause — Postgres's RLS default-deny
-- applies before the view's predicate does. Leaving this at the default
-- (security_invoker = false) makes the view run as its owner (the
-- migration role), which is exempt from residents' RLS since the table was
-- never given FORCE ROW LEVEL SECURITY — so the owner can see the rows, and
-- this view's own WHERE clause (checked against the real caller's JWT
-- claims via is_council()/current_resident_id(), which read a
-- request-scoped setting independent of which role executes the view) is
-- what actually restricts the result to council or the caller's own row.
-- password_hash is simply never in this view's column list, so it can't
-- leak through even though the owner bypasses RLS.
create or replace view residents_public as
  select id, full_name, address, city, postal_code, riding, jurisdiction,
         role, verification_status, verification_method,
         submitted_at, verified_at, verified_by, created_at
  from residents
  where is_council() or id = current_resident_id();
grant select on residents_public to authenticated;

-- Normalizes free-text the same way the old client-side normalizeText()
-- did — trims, collapses whitespace, lowercases — so sign-in stays
-- forgiving about spacing/case in name and address.
create or replace function normalize_text(s text) returns text
language sql immutable as $$
  select lower(regexp_replace(trim(coalesce(s,'')), '\s+', ' ', 'g'))
$$;

-- Mints this app's session token: a JWT signed with the project's real
-- JWT secret (see the one-time setup note at the top of this file) so
-- PostgREST accepts it exactly like a normal Supabase session token.
-- 12-hour expiry: matches the app's "re-verify identity every sign-in"
-- design intent — a resident is expected to sign back in periodically,
-- not stay silently logged in indefinitely.
create or replace function mint_session_token(p_resident_id text, p_role text) returns text
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_secret text := (select jwt_secret from app_config where id = true);
begin
  if v_secret is null or v_secret = '' then
    raise exception 'app_config.jwt_secret is not configured — see the setup note at the top of 0001_init.sql';
  end if;
  return sign(
    json_build_object(
      'role', 'authenticated',
      'resident_id', p_resident_id,
      'resident_role', p_role,
      'iat', extract(epoch from now())::int,
      'exp', extract(epoch from now() + interval '12 hours')::int
    ),
    v_secret,
    'HS256'
  );
end;
$$;

-- ---------------------------------------------------------------------
-- sign_up — mirrors doSignUp() in the current client exactly (same
-- required fields, same "no username, system-issued resident id", same
-- optional council code path), but hashes the password server-side and
-- returns a real session token instead of just handing back a plain doc.
-- ---------------------------------------------------------------------
create or replace function sign_up(
  p_full_name text, p_address text, p_city text, p_postal_code text,
  p_riding text, p_password text, p_council_code text
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_is_council boolean := (p_council_code is not null and p_council_code = (select council_code from app_config where id = true));
  v_id text;
  v_row residents;
begin
  if p_password is null or length(p_password) < 6 then
    raise exception 'Password must be at least 6 characters.' using errcode = '22023';
  end if;
  if p_full_name is null or trim(p_full_name) = '' or p_address is null or trim(p_address) = '' then
    raise exception 'Full name and address are required.' using errcode = '22023';
  end if;
  if p_riding is null or not exists (select 1 from ridings where name = p_riding) then
    raise exception 'Choose a valid ward.' using errcode = '22023';
  end if;
  if p_council_code is not null and p_council_code <> '' and not v_is_council then
    raise exception 'Council access code not recognized.' using errcode = '22023';
  end if;

  insert into residents (full_name, address, city, postal_code, riding, jurisdiction,
                          password_hash, role, verification_status, verification_method,
                          submitted_at, verified_at, verified_by)
  values (p_full_name, p_address, coalesce(nullif(p_city,''), 'Saskatoon'), coalesce(p_postal_code,''), p_riding, 'Saskatoon',
          crypt(p_password, gen_salt('bf')),
          case when v_is_council then 'council' else 'resident' end,
          case when v_is_council then 'verified' else 'pending' end,
          case when v_is_council then 'council-staff-provisioning' else null end,
          now(),
          case when v_is_council then now() else null end,
          case when v_is_council then 'council-onboarding' else null end)
  returning * into v_row;

  return jsonb_build_object(
    'token', mint_session_token(v_row.id, v_row.role),
    'resident', to_jsonb(v_row) - 'password_hash'
  );
end;
$$;
grant execute on function sign_up(text,text,text,text,text,text,text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- sign_in — same fields as the client's doSignIn(): full name + address +
-- ward + password, no username. Unlike the prototype, the match happens
-- entirely server-side so the client never receives the roster or any
-- password hash to scan through.
-- ---------------------------------------------------------------------
create or replace function sign_in(
  p_full_name text, p_address text, p_riding text, p_password text
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents;
begin
  select * into v_row
  from residents
  where normalize_text(full_name) = normalize_text(p_full_name)
    and normalize_text(address) = normalize_text(p_address)
    and riding = p_riding
    and password_hash = crypt(p_password, password_hash)
  limit 1;

  if not found then
    raise exception 'Those details don''t match an account.' using errcode = '28000';
  end if;

  return jsonb_build_object(
    'token', mint_session_token(v_row.id, v_row.role),
    'resident', to_jsonb(v_row) - 'password_hash'
  );
end;
$$;
grant execute on function sign_in(text,text,text,text) to anon, authenticated;

-- Restores a session after a page reload: called with the still-valid JWT
-- attached as the request's bearer token (see SPEC.md "Session restore").
-- Returns the caller's own row, or nothing if the token is missing/expired
-- (client falls back to the sign-in screen either way, matching current
-- behavior when a stored session doesn't resolve to a real resident).
create or replace function get_my_profile() returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents;
begin
  if current_resident_id() is null then return null; end if;
  select * into v_row from residents where id = current_resident_id();
  if not found then return null; end if;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function get_my_profile() to authenticated;

-- ---------------------------------------------------------------------
-- complete_self_verification — the resident-facing side of the
-- "simulated ID + biometric check" flow already in the UI. Deliberately
-- narrow: a caller can ONLY flip their OWN row to 'verified', with the
-- same verification_method the client already simulates. It can never
-- touch another resident's row and can never set 'rejected' — that keeps
-- today's self-service simulated flow working exactly as designed, while
-- closing the old prototype's implicit hole (a plain client-side UPDATE
-- could previously have been pointed at any resident id or any status).
-- See SPEC.md "Before this decides a real vote" for why this whole flow
-- should eventually be replaced with a real identity-verification vendor.
-- ---------------------------------------------------------------------
create or replace function complete_self_verification() returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents;
begin
  if current_resident_id() is null then
    raise exception 'Not signed in.' using errcode = '28000';
  end if;
  update residents
  set verification_status = 'verified',
      verified_at = now(),
      verified_by = 'automated-demo-check',
      verification_method = 'simulated-id-scan+biometric'
  where id = current_resident_id()
  returning * into v_row;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function complete_self_verification() to authenticated;

-- Council reviewing a pending application (or revoking one) — mirrors
-- councilSetVerification() in the client.
create or replace function council_set_verification(p_resident_id text, p_status text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents;
begin
  if not is_council() then
    raise exception 'Council access required.' using errcode = '42501';
  end if;
  if p_status not in ('verified','rejected') then
    raise exception 'Invalid status.' using errcode = '22023';
  end if;
  update residents
  set verification_status = p_status,
      verified_at = now(),
      verified_by = current_resident_id() || ' (council review)'
  where id = p_resident_id
  returning * into v_row;
  if not found then raise exception 'No such resident.' using errcode = '22023'; end if;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function council_set_verification(text,text) to authenticated;

-- ---------------------------------------------------------------------
-- cast_vote — atomic version of the client's castVote(): one round trip
-- that checks eligibility + not-already-voted, then inserts BOTH the
-- anonymous ballot and the voter flag inside a single transaction. This
-- closes a real race condition the prototype's client-side
-- check-then-write pattern had (two tabs/devices racing the same vote).
-- ---------------------------------------------------------------------
create or replace function cast_vote(p_poll_id uuid, p_option_id text) returns void
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_poll polls;
  v_resident_id text := current_resident_id();
begin
  if v_resident_id is null then
    raise exception 'Not signed in.' using errcode = '28000';
  end if;

  select * into v_poll from polls where id = p_poll_id for update;
  if not found then raise exception 'This vote is no longer available.' using errcode = '22023'; end if;
  if v_poll.status <> 'open' then
    raise exception 'This vote is closed.' using errcode = '22023';
  end if;
  if v_poll.eligible_ridings is not null and array_length(v_poll.eligible_ridings, 1) > 0 then
    if not exists (
      select 1 from residents where id = v_resident_id and riding = any(v_poll.eligible_ridings)
    ) then
      raise exception 'This vote is not open to your ward.' using errcode = '42501';
    end if;
  end if;
  if not exists (select 1 from residents where id = v_resident_id and verification_status = 'verified') then
    raise exception 'Verify your residency before voting.' using errcode = '42501';
  end if;
  if not (v_poll.options @> jsonb_build_array(jsonb_build_object('id', p_option_id))
          or exists (select 1 from jsonb_array_elements(v_poll.options) o where o->>'id' = p_option_id)) then
    raise exception 'Not a valid option for this vote.' using errcode = '22023';
  end if;

  -- poll_voters' primary key (poll_id, resident_id) is what actually
  -- blocks a double vote atomically — this insert is the real guard,
  -- not just the pre-check above.
  begin
    insert into poll_voters (poll_id, resident_id) values (p_poll_id, v_resident_id);
  exception when unique_violation then
    raise exception 'You already voted on this item.' using errcode = '23505';
  end;

  insert into poll_ballots (poll_id, option_id) values (p_poll_id, p_option_id);
end;
$$;
grant execute on function cast_vote(uuid,text) to authenticated;

-- Replaces the client's old per-poll loop of
-- votersColl(pollId).doc(residentId).get() calls with one query — returns
-- just the set of poll ids the caller has voted in. The client still
-- keeps its own note of WHICH option it chose (see SPEC.md — that stays
-- client-local, same as before, because the server never learns it).
create or replace function my_voted_polls() returns setof uuid
language sql security definer stable set search_path = pg_catalog, public, extensions as $$
  select poll_id from poll_voters where resident_id = current_resident_id()
$$;
grant execute on function my_voted_polls() to authenticated;

-- Aggregate results only — never exposes individual ballot rows, even
-- though those rows carry no resident reference to begin with. Mirrors
-- computeResults() in the client.
create or replace function poll_results(p_poll_id uuid) returns jsonb
language plpgsql security definer stable set search_path = pg_catalog, public, extensions as $$
declare
  v_poll polls;
  v_counts jsonb := '{}'::jsonb;
  v_total int;
  v_eligible int;
  r record;
begin
  select * into v_poll from polls where id = p_poll_id;
  if not found then raise exception 'No such poll.' using errcode = '22023'; end if;

  for r in
    select o->>'id' as option_id,
           count(b.id) as n
    from jsonb_array_elements(v_poll.options) o
    left join poll_ballots b on b.poll_id = p_poll_id and b.option_id = o->>'id'
    group by o->>'id'
  loop
    v_counts := v_counts || jsonb_build_object(r.option_id, r.n);
  end loop;

  select count(*) into v_total from poll_ballots where poll_id = p_poll_id;

  select count(*) into v_eligible
  from residents
  where role = 'resident' and verification_status = 'verified'
    and (v_poll.eligible_ridings is null or array_length(v_poll.eligible_ridings,1) is null
         or riding = any(v_poll.eligible_ridings));

  return jsonb_build_object('counts', v_counts, 'total', v_total, 'eligible', greatest(v_eligible, v_total));
end;
$$;
grant execute on function poll_results(uuid) to authenticated;

-- =====================================================================
-- SECURITY NOTES for whoever (Claude Code) picks this up
-- =====================================================================
-- 1. Passwords are now bcrypt-hashed (pgcrypto) and never leave the
--    database — the old prototype's client-side "fetch every resident,
--    scan for a match" pattern is gone. Sign-in/sign-up are the ONLY
--    entry points that touch residents' password_hash, and both are
--    SECURITY DEFINER functions with narrowly-scoped grants.
-- 2. `residents` has RLS enabled with NO policies for anon/authenticated
--    — direct table access is fully denied. Every legitimate read/write
--    goes through a function above, or residents_public (roster view).
-- 3. `poll_voters` / `poll_ballots` also have RLS enabled with no direct
--    policies — the secret-ballot guarantee (nothing links a resident to
--    a choice) is enforced at the schema level, not just by convention.
-- 4. complete_self_verification() intentionally can't set 'rejected' and
--    can't touch any row but the caller's own — but it's still a
--    SIMULATED check, same as the prototype. Before this app is used to
--    decide anything real, replace it with a call to a real identity-
--    verification provider; the RPC boundary here is built so that swap
--    doesn't change anything else in the schema or the client.
-- 5. cast_vote() is atomic (single transaction, `for update` row lock on
--    the poll, and the (poll_id, resident_id) primary key as the real
--    double-vote guard) — this closes a race condition the original
--    client-side check-then-write pattern had.
-- =====================================================================
