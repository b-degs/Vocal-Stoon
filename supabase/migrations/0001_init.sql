-- Vocal STOON — real backend schema, RLS, and RPCs
-- =====================================================================
-- This replaces the Claude-artifact mock database / localStorage fallback
-- with a real, shared Postgres database on Supabase. It preserves the
-- existing app's exact behavior and UX (see SPEC.md) while fixing the
-- security shortcuts that were acceptable ONLY inside the sandboxed
-- prototype (see "SECURITY NOTES" at the bottom of this file).
--
-- AUTH MODEL: this app's login is full name + address + ward + password —
-- no email, no username. An earlier draft of this migration tried to mint
-- its own PostgREST-verifiable JWTs (via the pgjwt extension) for this,
-- the way several Supabase "bring your own auth" tutorials describe. That
-- approach was built, tested against a local Postgres instance, and then
-- found to NOT work against a real project: PostgREST there verifies
-- Bearer tokens against the project's actual JWKS (its published Auth
-- signing keys), and a project can use ES256/RS256 signing keys with NO
-- HS256 entry available at all — confirmed by fetching this exact
-- project's own /auth/v1/.well-known/jwks.json. A token signed with a
-- plain HS256 secret can never verify there, no matter how the secret or
-- a "kid" is set up on our end; it's a fundamental algorithm mismatch, not
-- a config bug.
--
-- So this build uses a plain session table instead (see `sessions` below)
-- and never asks PostgREST's JWT layer to vouch for anyone. Every RPC that
-- needs to know who's calling takes an explicit `p_session_token`
-- parameter and looks it up itself via `session_resident()`. This is less
-- "clever" than minting real JWTs, but it works regardless of whatever
-- signing keys a given Supabase project happens to use, now or after any
-- future change on Supabase's end — nothing here depends on their key
-- configuration at all.
--
-- ONE-TIME MANUAL SETUP after running this migration:
--   Run once, with your own council signup code substituted in (replaces
--   the hardcoded demo "STOON-COUNCIL" constant the old client-side-only
--   version used):
--     update app_config set council_code = '<pick-a-real-code>' where id = true;
-- =====================================================================

-- Supabase installs pgcrypto into a schema called `extensions`, not
-- `public` — installing it there explicitly keeps this working the same
-- way whether or not Supabase's own provisioning already did it first
-- (CREATE EXTENSION IF NOT EXISTS is a no-op either way if it's already
-- installed anywhere).
create extension if not exists pgcrypto with schema extensions;   -- crypt()/gen_salt() password hashing

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
-- (a forged council session) against this schema before this line was
-- added; do not remove it.
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
-- get_my_profile, complete_self_verification, council_set_verification,
-- residents_roster).

-- ---------------------------------------------------------------------
-- app_config — just the council signup code now (see the auth-model note
-- at the top of this file for why there's no jwt_secret column anymore).
-- A plain locked-down table rather than a Postgres GUC
-- (`ALTER DATABASE ... SET app.foo = ...`): confirmed on a real Supabase
-- project that newer projects deny ALTER DATABASE/ALTER ROLE for custom
-- parameters outright ("permission denied to set parameter"), even to the
-- SQL Editor's own role. A table needs no special privilege beyond normal
-- DML on something you own.
-- ---------------------------------------------------------------------
create table if not exists app_config (
  id boolean primary key default true check (id),   -- singleton-row guard
  council_code text
);
insert into app_config (id) values (true) on conflict (id) do nothing;
alter table app_config enable row level security;
-- No policies: fully locked from anon/authenticated. Only sign_up() ever
-- reads it.

-- ---------------------------------------------------------------------
-- sessions — replaces "mint a JWT" entirely (see the auth-model note at
-- the top of this file). A resident's/council member's session is just a
-- random token in this table pointing at their resident row, with a
-- 12-hour expiry — matches the app's "re-verify identity every sign-in"
-- design intent, same as the JWT-based approach this replaced. No direct
-- policies: only sign_up()/sign_in() (insert), sign_out() (delete), and
-- session_resident() (select, via SECURITY DEFINER) ever touch it.
-- ---------------------------------------------------------------------
create table if not exists sessions (
  token uuid primary key default gen_random_uuid(),
  resident_id text not null references residents(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null
);
create index if not exists sessions_resident_idx on sessions (resident_id);
alter table sessions enable row level security;
-- No policies: fully locked to direct access, by design.

-- Resolves a session token to the resident row it belongs to, or a
-- null-fields row if the token is missing/unknown/expired — every
-- caller-identity check below goes through this, instead of the old
-- current_resident_id()/current_resident_role() JWT-claim readers.
create or replace function session_resident(p_session_token uuid) returns residents
language sql stable security definer set search_path = pg_catalog, public, extensions as $$
  select r.* from sessions s
  join residents r on r.id = s.resident_id
  where s.token = p_session_token and s.expires_at > now()
  limit 1
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

-- Readable by anyone, signed in or not — without a JWT-verified role to
-- gate on, there's no lightweight way to require "must be signed in" at
-- the RLS layer any more, and these are public municipal budget votes
-- anyway (a minor, disclosed behavior change from the JWT-based draft:
-- poll titles/descriptions/budgets are now visible to a logged-out
-- visitor; voting, the roster, and results still are not). Writes are
-- NOT open here — no insert/update policy means both are denied by
-- default; the only way to create or change a poll is create_poll()/
-- set_poll_status() below, which check for council themselves.
create policy polls_select_all on polls
  for select
  using (true);

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

-- ---------------------------------------------------------------------
-- council_votes — accountability tracking: how each council member
-- actually voted on an item, vs. what residents favored. Deliberately
-- attributed (unlike poll_ballots/poll_voters) — a councilperson's real
-- vote on a budget item is public record in real municipal government,
-- not a secret ballot; the whole point of this table is letting residents
-- see whether council's actual decision matched what they voted for.
-- One row per (poll, council member) — a one-shot roll-call vote, like a
-- real council record: once cast, it can't be changed (see cast_council_vote
-- below, which rejects a second attempt the same way cast_vote() rejects a
-- resident double-voting).
-- ---------------------------------------------------------------------
create table if not exists council_votes (
  poll_id uuid not null references polls(id) on delete cascade,
  resident_id text not null references residents(id),
  option_id text not null,
  voted_at timestamptz not null default now(),
  primary key (poll_id, resident_id)
);
alter table council_votes enable row level security;
-- No direct policies: only cast_council_vote() (insert) and poll_results()
-- (folded into its existing payload, see below) touch this — same "no
-- direct API access, only through a function" pattern as every other
-- table here.

-- Council casts their own vote on an item, once. Any council member can
-- vote regardless of the poll's open/closed status — this doesn't force a
-- particular process (residents vote, then council decides, in whatever
-- order actually happens) — but only a council session can call it, only
-- for one of the poll's real options, and only once: the (poll_id,
-- resident_id) primary key is the real, database-enforced guard, same
-- mechanism cast_vote() uses to block a resident double-voting.
create or replace function cast_council_vote(p_session_token uuid, p_poll_id uuid, p_option_id text) returns void
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_poll polls;
begin
  if v_caller.id is null or v_caller.role <> 'council' then
    raise exception 'Council access required.' using errcode = '42501';
  end if;
  select * into v_poll from polls where id = p_poll_id;
  if not found then raise exception 'This vote is no longer available.' using errcode = '22023'; end if;
  if not exists (select 1 from jsonb_array_elements(v_poll.options) o where o->>'id' = p_option_id) then
    raise exception 'Not a valid option for this vote.' using errcode = '22023';
  end if;

  begin
    insert into council_votes (poll_id, resident_id, option_id) values (p_poll_id, v_caller.id, p_option_id);
  exception when unique_violation then
    raise exception 'You already cast your council vote on this item.' using errcode = '23505';
  end;
end;
$$;
grant execute on function cast_council_vote(uuid,uuid,text) to anon, authenticated;

-- Normalizes free-text the same way the old client-side normalizeText()
-- did — trims, collapses whitespace, lowercases — so sign-in stays
-- forgiving about spacing/case in name and address.
create or replace function normalize_text(s text) returns text
language sql immutable as $$
  select lower(regexp_replace(trim(coalesce(s,'')), '\s+', ' ', 'g'))
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
  v_row residents;
  v_token uuid;
  v_expires_at timestamptz := now() + interval '12 hours';
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

  insert into sessions (resident_id, expires_at) values (v_row.id, v_expires_at) returning token into v_token;

  return jsonb_build_object(
    'token', v_token,
    'expires_at', v_expires_at,
    'resident', to_jsonb(v_row) - 'password_hash'
  );
end;
$$;
grant execute on function sign_up(text,text,text,text,text,text,text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- sign_in — same fields as the client's doSignIn(): full name + address +
-- ward + password, no username. The match happens entirely server-side so
-- the client never receives the roster or any password hash to scan
-- through.
-- ---------------------------------------------------------------------
create or replace function sign_in(
  p_full_name text, p_address text, p_riding text, p_password text
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents;
  v_token uuid;
  v_expires_at timestamptz := now() + interval '12 hours';
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

  insert into sessions (resident_id, expires_at) values (v_row.id, v_expires_at) returning token into v_token;

  return jsonb_build_object(
    'token', v_token,
    'expires_at', v_expires_at,
    'resident', to_jsonb(v_row) - 'password_hash'
  );
end;
$$;
grant execute on function sign_in(text,text,text,text) to anon, authenticated;

-- Ends a session server-side (so a copied/leaked token can't be replayed
-- after "sign out") — the old JWT-based draft had no equivalent, since a
-- JWT can't be revoked without extra machinery; a session table can just
-- delete the row.
create or replace function sign_out(p_session_token uuid) returns void
language sql security definer set search_path = pg_catalog, public, extensions as $$
  delete from sessions where token = p_session_token
$$;
grant execute on function sign_out(uuid) to anon, authenticated;

-- Restores a session after a page reload: called with the still-valid
-- session token saved locally (see SPEC.md "Session restore"). Returns
-- the caller's own row, or null if the token is missing/expired (client
-- falls back to the sign-in screen either way, matching current behavior
-- when a stored session doesn't resolve to a real resident).
create or replace function get_my_profile(p_session_token uuid) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_row residents := session_resident(p_session_token);
begin
  if v_row.id is null then return null; end if;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function get_my_profile(uuid) to anon, authenticated;

-- Council-only roster, minus password_hash. Replaces the old
-- residents_public VIEW, which relied on reading role/id off a verified
-- JWT — there's no such thing to read anymore, so this takes the session
-- token directly and does the same is-caller-council-or-self check
-- in-line.
create or replace function residents_roster(p_session_token uuid) returns setof jsonb
language sql stable security definer set search_path = pg_catalog, public, extensions as $$
  with caller as (select session_resident(p_session_token) as c)
  select to_jsonb(r) - 'password_hash'
  from residents r, caller
  where (caller.c).id is not null
    and ((caller.c).role = 'council' or r.id = (caller.c).id)
$$;
grant execute on function residents_roster(uuid) to anon, authenticated;

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
create or replace function complete_self_verification(p_session_token uuid) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_row residents;
begin
  if v_caller.id is null then
    raise exception 'Not signed in.' using errcode = '28000';
  end if;
  update residents
  set verification_status = 'verified',
      verified_at = now(),
      verified_by = 'automated-demo-check',
      verification_method = 'simulated-id-scan+biometric'
  where id = v_caller.id
  returning * into v_row;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function complete_self_verification(uuid) to anon, authenticated;

-- Council reviewing a pending application (or revoking one) — mirrors
-- councilSetVerification() in the client.
create or replace function council_set_verification(p_session_token uuid, p_resident_id text, p_status text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_row residents;
begin
  if v_caller.id is null or v_caller.role <> 'council' then
    raise exception 'Council access required.' using errcode = '42501';
  end if;
  if p_status not in ('verified','rejected') then
    raise exception 'Invalid status.' using errcode = '22023';
  end if;
  update residents
  set verification_status = p_status,
      verified_at = now(),
      verified_by = v_caller.id || ' (council review)'
  where id = p_resident_id
  returning * into v_row;
  if not found then raise exception 'No such resident.' using errcode = '22023'; end if;
  return to_jsonb(v_row) - 'password_hash';
end;
$$;
grant execute on function council_set_verification(uuid,text,text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- create_poll / set_poll_status — council-only poll management. These
-- replace direct `sb.from('polls').insert(...)/.update(...)` calls from
-- the old JWT-based draft (which relied on an is_council() RLS policy) —
-- with no verified role to check in RLS any more, `polls` has no
-- insert/update policy at all (see above), so these two SECURITY DEFINER
-- functions are now the only way to create or change a poll.
-- ---------------------------------------------------------------------
create or replace function create_poll(
  p_session_token uuid, p_title text, p_description text, p_category text,
  p_budget_amount numeric, p_options jsonb, p_eligible_ridings text[], p_closes_at timestamptz
) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_row polls;
begin
  if v_caller.id is null or v_caller.role <> 'council' then
    raise exception 'Council access required.' using errcode = '42501';
  end if;
  insert into polls (title, description, category, budget_amount, options, eligible_ridings, closes_at, created_by)
  values (p_title, p_description, coalesce(nullif(p_category,''),'General'), coalesce(p_budget_amount,0),
          p_options, p_eligible_ridings, p_closes_at, v_caller.id)
  returning * into v_row;
  return to_jsonb(v_row);
end;
$$;
grant execute on function create_poll(uuid,text,text,text,numeric,jsonb,text[],timestamptz) to anon, authenticated;

create or replace function set_poll_status(p_session_token uuid, p_poll_id uuid, p_status text) returns jsonb
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_row polls;
begin
  if v_caller.id is null or v_caller.role <> 'council' then
    raise exception 'Council access required.' using errcode = '42501';
  end if;
  if p_status not in ('open','closed') then
    raise exception 'Invalid status.' using errcode = '22023';
  end if;
  update polls
  set status = p_status, closed_at = case when p_status = 'closed' then now() else null end
  where id = p_poll_id
  returning * into v_row;
  if not found then raise exception 'No such vote.' using errcode = '22023'; end if;
  return to_jsonb(v_row);
end;
$$;
grant execute on function set_poll_status(uuid,uuid,text) to anon, authenticated;

-- ---------------------------------------------------------------------
-- cast_vote — atomic version of the client's castVote(): one round trip
-- that checks eligibility + not-already-voted, then inserts BOTH the
-- anonymous ballot and the voter flag inside a single transaction. This
-- closes a real race condition the prototype's client-side
-- check-then-write pattern had (two tabs/devices racing the same vote).
-- ---------------------------------------------------------------------
create or replace function cast_vote(p_session_token uuid, p_poll_id uuid, p_option_id text) returns void
language plpgsql security definer set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_poll polls;
begin
  if v_caller.id is null then
    raise exception 'Not signed in.' using errcode = '28000';
  end if;

  select * into v_poll from polls where id = p_poll_id for update;
  if not found then raise exception 'This vote is no longer available.' using errcode = '22023'; end if;
  if v_poll.status <> 'open' then
    raise exception 'This vote is closed.' using errcode = '22023';
  end if;
  if v_poll.eligible_ridings is not null and array_length(v_poll.eligible_ridings, 1) > 0 then
    if not (v_caller.riding = any(v_poll.eligible_ridings)) then
      raise exception 'This vote is not open to your ward.' using errcode = '42501';
    end if;
  end if;
  if v_caller.verification_status <> 'verified' then
    raise exception 'Verify your residency before voting.' using errcode = '42501';
  end if;
  if not exists (select 1 from jsonb_array_elements(v_poll.options) o where o->>'id' = p_option_id) then
    raise exception 'Not a valid option for this vote.' using errcode = '22023';
  end if;

  -- poll_voters' primary key (poll_id, resident_id) is what actually
  -- blocks a double vote atomically — this insert is the real guard,
  -- not just the pre-check above.
  begin
    insert into poll_voters (poll_id, resident_id) values (p_poll_id, v_caller.id);
  exception when unique_violation then
    raise exception 'You already voted on this item.' using errcode = '23505';
  end;

  insert into poll_ballots (poll_id, option_id) values (p_poll_id, p_option_id);
end;
$$;
grant execute on function cast_vote(uuid,uuid,text) to anon, authenticated;

-- Replaces the client's old per-poll loop of
-- votersColl(pollId).doc(residentId).get() calls with one query — returns
-- just the set of poll ids the caller has voted in. The client still
-- keeps its own note of WHICH option it chose (see SPEC.md — that stays
-- client-local, same as before, because the server never learns it).
create or replace function my_voted_polls(p_session_token uuid) returns setof uuid
language sql security definer stable set search_path = pg_catalog, public, extensions as $$
  select poll_id from poll_voters where resident_id = (session_resident(p_session_token)).id
$$;
grant execute on function my_voted_polls(uuid) to anon, authenticated;

-- Aggregate results only — never exposes individual ballot rows, even
-- though those rows carry no resident reference to begin with. Mirrors
-- computeResults() in the client. Requires a valid session (any
-- signed-in resident, not just council) — matches the old "must be
-- authenticated" intent from the JWT-based draft.
--
-- Also folds in council's own vote on the same item — councilCounts (an
-- aggregate tally, same shape as counts) and councilVotes (the attributed
-- list: which council member voted for what, by name) — so a resident
-- viewing results sees both what residents favored AND what council
-- actually decided, in one call. Unlike poll_ballots, council_votes rows
-- ARE attributed on purpose (see the comment on that table above).
create or replace function poll_results(p_session_token uuid, p_poll_id uuid) returns jsonb
language plpgsql security definer stable set search_path = pg_catalog, public, extensions as $$
declare
  v_caller residents := session_resident(p_session_token);
  v_poll polls;
  v_counts jsonb := '{}'::jsonb;
  v_council_counts jsonb := '{}'::jsonb;
  v_council_votes jsonb;
  v_total int;
  v_eligible int;
  r record;
begin
  if v_caller.id is null then
    raise exception 'Not signed in.' using errcode = '28000';
  end if;

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

  for r in
    select o->>'id' as option_id,
           count(cv.poll_id) as n
    from jsonb_array_elements(v_poll.options) o
    left join council_votes cv on cv.poll_id = p_poll_id and cv.option_id = o->>'id'
    group by o->>'id'
  loop
    v_council_counts := v_council_counts || jsonb_build_object(r.option_id, r.n);
  end loop;

  select coalesce(jsonb_agg(jsonb_build_object(
           'residentId', cv.resident_id, 'fullName', res.full_name, 'optionId', cv.option_id
         ) order by res.full_name), '[]'::jsonb)
  into v_council_votes
  from council_votes cv join residents res on res.id = cv.resident_id
  where cv.poll_id = p_poll_id;

  select count(*) into v_total from poll_ballots where poll_id = p_poll_id;

  select count(*) into v_eligible
  from residents
  where role = 'resident' and verification_status = 'verified'
    and (v_poll.eligible_ridings is null or array_length(v_poll.eligible_ridings,1) is null
         or riding = any(v_poll.eligible_ridings));

  return jsonb_build_object(
    'counts', v_counts, 'total', v_total, 'eligible', greatest(v_eligible, v_total),
    'councilCounts', v_council_counts, 'councilVotes', v_council_votes
  );
end;
$$;
grant execute on function poll_results(uuid,uuid) to anon, authenticated;

-- =====================================================================
-- SECURITY NOTES for whoever (Claude Code) picks this up
-- =====================================================================
-- 1. Passwords are bcrypt-hashed (pgcrypto) and never leave the database
--    — sign-in/sign-up are the ONLY entry points that touch residents'
--    password_hash, and both are SECURITY DEFINER functions with
--    narrowly-scoped grants.
-- 2. `residents` has RLS enabled with NO policies for anon/authenticated
--    — direct table access is fully denied. Every legitimate read/write
--    goes through a function above.
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
-- 6. Sessions are plain rows in `sessions`, not JWTs — see the auth-model
--    note at the top of this file for why. `sign_out()` actually deletes
--    the row, so a leaked/copied token stops working the moment the
--    owner signs out, unlike a JWT (which stays valid until it expires,
--    full stop). `sessions` itself has RLS enabled with no policies —
--    only session_resident() (SECURITY DEFINER) ever reads it.
-- 7. Every SECURITY DEFINER function above pins `search_path` and every
--    request runs as the `anon` Postgres role (there's no JWT to elevate
--    to `authenticated` any more) — this is deliberate: Postgres always
--    searches a session's own temp schema first for relation names
--    regardless of search_path, for any role, so `revoke temporary` near
--    the top of this file is what actually closes that hole, not the
--    search_path pins alone (see the comment there for the confirmed
--    exploit this fixes).
-- =====================================================================
