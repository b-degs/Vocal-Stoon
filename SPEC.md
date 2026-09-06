# Vocal STOON — real-backend build spec

## What this is

Vocal STOON is a municipal budget-voting prototype: residents sign up (name,
address, ward, password), council opens ward-scoped or citywide "votes" on
budget items, residents cast anonymous secret ballots, and council can track
turnout and results. It's been running as a single-file HTML app inside a
Claude artifact, using a Claude-specific realtime document-store capability
as its "database."

**Your job:** wire this exact app up to a real, shared Postgres database
(Supabase) so it works as a real product outside Claude — anyone can sign
up, vote, and see results, from any device, permanently, with no Claude
account involved anywhere in the loop.

This is one piece of a larger plan: the long-term product is a municipal
accountability tool that tracks whether council's actual votes align with
what residents voted for, sold to municipalities (starting with a pitch to
Saskatoon) and then replicated to other cities. Nothing here needs to build
that yet — see "Future roadmap notes" at the end for what to leave room for.

## What's already done for you

- `supabase/migrations/0001_init.sql` — complete schema, Row Level Security
  policies, and RPC functions (sign up, sign in, cast a vote, etc.). Written
  to match the app's existing behavior field-for-field.
- `frontend/vocal-stoon.html` — the original app, already rewired to call
  Supabase instead of the Claude artifact capability. Same UI, same CSS,
  same features. This is a real attempt at a finished frontend, not a
  placeholder — but see "What's unverified" below.

**Neither file has been run against a real Supabase project.** I don't have
credentials or network access to one from where I'm writing this. Treat both
as a strong, carefully-reasoned first draft: read them, stand up a real (or
local) Supabase project, and verify every RLS policy and RPC actually does
what its comment says before this goes anywhere near real residents' data.

## Setup — the concrete first steps

1. Create a Supabase project (or `supabase init && supabase start` for a
   local dev instance first — recommended, so you can iterate without
   touching production data).
2. Run `supabase/migrations/0001_init.sql` against it.
3. In the Supabase dashboard: **Settings → API**. Copy the project URL and
   anon public key into `frontend/vocal-stoon.html`'s two `window.SUPABASE_*`
   placeholders near the top of the file.
4. Copy the **JWT Secret** from that same settings page and run, once,
   against your database:
   ```sql
   ALTER DATABASE postgres SET app.jwt_secret = '<paste it>';
   ALTER DATABASE postgres SET app.council_code = '<pick a real council signup code>';
   ```
   Reconnect (or open a fresh connection) afterward so the setting takes.
5. **Auth caveat:** this only works if your project uses the classic
   shared-secret (HS256) JWT setup. Some newer Supabase projects default to
   asymmetric signing keys instead, in which case `pgjwt`'s `sign()` with a
   plain secret won't produce a token PostgREST accepts. If your dashboard
   doesn't show a plain "JWT Secret" string, check Supabase's docs for
   switching that project back to the legacy shared-secret mode, or adapt
   the signing in `mint_session_token()` to whatever your project's current
   JWT configuration requires.
6. Deploy `frontend/vocal-stoon.html` as a static file anywhere (GitHub
   Pages, Netlify, Vercel, S3+CloudFront, whatever) — it's still a single
   self-contained HTML file with one external script tag (supabase-js from
   a CDN).

## Auth model — why it's built this way

The app's sign-in has no username or email: full name + street address +
ward + password. That's a deliberate product decision (see the sign-up
screen's own copy: "there's no username to choose"), not something to
change. But it means Supabase's built-in email/password auth (GoTrue)
doesn't fit — GoTrue needs an email or phone number as the identifier.

So this build mints its **own** session tokens: `sign_in()` and `sign_up()`
(both in `0001_init.sql`) are Postgres functions that do the name+address+
ward+password matching themselves (server-side, so the client never sees
the roster or a password hash), then sign a JWT with the project's real JWT
secret via the `pgjwt` extension. That JWT is a normal, valid Supabase
session token as far as PostgREST and Row Level Security are concerned — it
carries the standard `role: authenticated` claim PostgREST needs, plus two
custom claims (`resident_id`, `resident_role`) that the RLS policies and
helper functions (`current_resident_id()`, `is_council()`) read. The client
just attaches it as a Bearer token on every request afterward (see
`makeSupabaseClient()` in the frontend).

This is a documented, legitimate pattern for "bring your own auth" on
Supabase — but it is NOT the default path, so double check it against
Supabase's current custom-JWT docs for your project's Postgres version
before relying on it.

## Data model

Four real tables replace the four "collections" the old mock store used:

| Old (Claude db capability)      | New (Postgres)                          |
|----------------------------------|------------------------------------------|
| `residents` collection           | `residents` table (locked down — see below) |
| `polls` collection                | `polls` table |
| `polls/{id}/voters` subcollection | `poll_voters` table |
| `polls/{id}/ballots` subcollection| `poll_ballots` table |

Full column definitions, indexes, and comments are in the migration file.
The frontend's `rowToResident()` / `rowToPoll()` functions translate
Postgres's `snake_case` columns back to the `camelCase` shape the rest of
the app's rendering code already expects (`p.createdAt`, `r.verificationStatus`,
etc.) — this is why almost none of the render/UI code needed to change.

## Security changes from the prototype (read this before you skip it)

The original prototype's data-access pattern was fine *only* because it ran
inside a sandboxed Claude artifact with a handful of test accounts. Ported
as-is to a real public Postgres database, several of its shortcuts become
real vulnerabilities. These are already fixed in the migration; understand
why so you don't accidentally undo them:

1. **Passwords.** The prototype stored passwords in plain text and had the
   client fetch the entire resident roster to scan for a sign-in match.
   Now: `pgcrypto` bcrypt-hashes every password, and matching happens
   inside `sign_in()`/`sign_up()` (`SECURITY DEFINER` functions) — the
   client never receives the roster or any hash.
2. **`residents` table lockdown.** RLS is enabled with **no policies at
   all** for `anon`/`authenticated` — direct reads/writes are fully denied.
   Every legitimate access path is a specific function (`sign_up`,
   `sign_in`, `get_my_profile`, `complete_self_verification`,
   `council_set_verification`) or the `residents_public` view (roster,
   council-only, no `password_hash` column).
3. **Secret ballot, enforced by schema, not convention.** `poll_voters` (did
   this resident vote — no choice attached) and `poll_ballots` (an
   anonymous choice, no resident reference at all) both have RLS enabled
   with zero direct-access policies. The only way in is `cast_vote()`
   (atomic insert of both rows) and `my_voted_polls()` / `poll_results()`
   (narrow, aggregate-only reads). Nobody — not even council, not even a
   compromised anon key — can read raw ballot rows or link a ballot to a
   resident.
4. **Atomic vote casting.** The prototype's castVote() did a client-side
   "check if I already voted, then write" — two round trips, racy if the
   same resident voted from two tabs/devices at once. `cast_vote()` is one
   transaction with a row lock on the poll and the `poll_voters` primary
   key (`poll_id, resident_id`) as the actual, database-enforced guard.
5. **Self-verification, narrowed.** The prototype's "simulated ID +
   biometric check" let a signed-in resident's client send a plain update
   that happened to target their own row — but nothing stopped a modified
   client from pointing that same call at *any* resident id, or setting
   status to something the UI never offers. `complete_self_verification()`
   can only flip the **caller's own** row to `'verified'` — never anyone
   else's, never to `'rejected'`. The feature and its UX are unchanged;
   only the blast radius of a client bug or malicious client is.

## Before this decides a real vote

`complete_self_verification()` is still a **simulation** — no real photo,
document, or biometric check happens, same as the original prototype (whose
own UI already says this out loud). That's a reasonable placeholder for a
demo or pilot. It is not something to leave in place once this is deciding
anything a city council or the public will actually act on. Before that:
replace the simulated check with a real identity-verification provider
(the kind used for KYC/age-verification elsewhere), keeping the same call
shape (`complete_self_verification()` returning the updated resident) so
nothing else in the schema or client has to change.

## Realtime

- `polls` is wired up to Supabase Realtime (`postgres_changes` on that
  table) — new/changed votes push to every signed-in client automatically,
  matching the old artifact's live-update behavior. On any change, the
  client just refetches the whole table and re-renders (`polls` is small;
  this is the simplest correct thing for a v1 — feel free to optimize to
  incremental patching later). `createPoll`/`closePoll`/`reopenPoll` also
  force an immediate refetch right after their own write, so the person who
  just made the change sees it instantly instead of waiting on the
  realtime round trip.
- `residents` is deliberately **NOT** wired up to Realtime. That table
  holds home addresses and password hashes; whether Supabase's Realtime
  layer correctly applies a table's RLS per-subscriber (vs. broadcasting
  full row payloads to anyone connected, a known historical gotcha on some
  Supabase versions) is something to verify carefully for your specific
  project before ever turning it on for a sensitive table. The council
  roster is a plain fetch instead — called once when council opens that
  tab, and re-called after every approve/reject action so it still feels
  live. If you confirm Realtime-with-RLS is safe on your project version
  and want push updates here too, `residents_public` (the roster view) is
  the thing to subscribe to, never the base `residents` table directly.

## What's been verified since, and what's still your job

The original version of this section said none of this had touched a real
Postgres instance. Since then it's been run — not against a live Supabase
project (no credentials/network path to one exists here either), but
against a local Postgres 16 with `pgcrypto` and `pgjwt` installed and
`anon`/`authenticated` roles and default grants set up to mirror a fresh
Supabase project, driving every RPC directly while manually setting
`request.jwt.claims` and `SET ROLE` the way PostgREST would per-request.
That pass found and fixed three real bugs in the migration (see git
history / SPEC.md's earlier revisions for the exact diffs):

1. **The migration didn't actually run.** `polls`'s RLS policies referenced
   `is_council()`/`current_resident_role()`, which were defined *later* in
   the file. `CREATE POLICY` resolves its expression immediately, so this
   errored out policy creation — meaning after running the migration
   top-to-bottom once, `polls` had RLS enabled with **zero** working
   policies (nobody could read or write any poll, at all). Fixed by moving
   the JWT helper functions before the `polls` section.
2. **`residents_public` always returned zero rows.** It was declared
   `security_invoker = true`, but `residents` has RLS enabled with no
   policies for anon/authenticated at all — Postgres's RLS default-deny
   applies before a view's own WHERE clause does, security-invoker or not.
   So the council roster and the "read my own row" fallback were both
   silently broken. Fixed by dropping `security_invoker` so the view runs
   as its owner (exempt from `residents`' RLS, since the table was never
   given `FORCE ROW LEVEL SECURITY`), while the view's own WHERE clause
   (checked against the real caller's JWT claims) still does the actual
   restricting.
3. **A working privilege-escalation exploit.** None of the `SECURITY
   DEFINER` functions pinned `search_path`. Postgres always searches a
   session's own temp schema first for *relation* names, for every role,
   regardless of search_path — so any signed-in-or-not client could run
   `create temp table residents (...)` in their own session and have
   `sign_in()` read that fake table instead of the real one. This was
   confirmed as a live exploit: a forged `residents` row got `sign_in()` to
   mint a real, PostgREST-valid **council** session JWT for an account that
   was never actually signed up. `SET search_path` on the functions doesn't
   stop this (search_path doesn't affect temp-schema lookup for relations)
   — the actual fix is the `REVOKE TEMPORARY ... FROM PUBLIC` now near the
   top of the migration, confirmed to close the hole.

Also exercised and confirmed correct: sign-up/sign-in (including
whitespace/case-insensitive name+address matching and bcrypt password
checks), the council-code gate, ward-scoped poll eligibility, the
verified-residents-only voting requirement, atomic double-vote rejection,
`poll_results()` aggregation without ever exposing a raw ballot row (not
even to council), and that `residents`/`poll_voters`/`poll_ballots` are
completely unreadable via direct table access for both `anon` and
`authenticated`.

**Not yet verified — still needs a real Supabase project:**

- The actual PostgREST/GoTrue wiring end-to-end through `supabase-js` from
  a browser (this was checked at the SQL/RLS layer directly, simulating
  PostgREST's per-request role and `request.jwt.claims` behavior, not
  through a live PostgREST instance).
- The JWT-secret setup (step 4 above) against your specific project's auth
  configuration — this is the part most likely to need adjustment (see the
  "Auth caveat" note); local testing used a plain HS256 secret and can't
  confirm how your project's dashboard exposes (or doesn't expose) one.
- Supabase Realtime actually applying `polls`' RLS per-subscriber the way
  the "Realtime" section above assumes.
- A true concurrent double-vote race (two simultaneous requests) — the
  primary-key-based guard was confirmed to reject a *second* vote from the
  same resident, which is the same mechanism a true race would hit, but an
  actual two-connections-at-once race wasn't run.

## Minor behavior change (disclosed, not hidden)

`refreshMyBallots()` (frontend) now reflects **every** poll a resident has
ever voted on, open or closed, via the new `my_voted_polls()` RPC. The
original client-side loop only checked currently-*open* polls, so a
returning resident's History tab could stop correctly showing "You voted:
X" for a poll that closed since their last visit (the render code already
supported showing it — the refresh function just never fetched closed-poll
ballots). This is a small correctness fix, not a feature change.

## Feature parity checklist

Everything from the original app is preserved as-is, per the explicit
instruction to keep it all except what was purely about being shared
outside the Claude artifact:

- Ward/riding-scoped vote eligibility (`pollVisibleToResident`, citywide vs
  specific-ward polls)
- The notification bell (new-vote alerts, per-resident "seen" tracking,
  baseline-seeding for brand-new signups so pre-existing polls don't spam
  them)
- Name + address + ward + password sign-in, no username, mandatory
  identity re-verification on every sign-in (auto-starts for already-
  verified residents, manual "Begin verification" for new/pending ones)
- Anonymous secret ballots (now enforced at the schema level, see above)
- Council: open ward-scoped or citywide votes, manage/close/reopen votes,
  view results and turnout, approve/reject resident applications, CSV
  export of results (now a plain browser download instead of the Claude
  artifact "downloads" capability, since that capability doesn't exist
  outside claude.ai)

**Removed** (this is the "what was needed to share it outside the app"
part, now obsolete with a real backend): the localStorage-backed
`makeLocalStore()` fallback, the "local-only copy" warning banner, and the
`window.claude` capability-detection branch in `boot()`. There's exactly
one real backend now, used the same way regardless of how someone reaches
the page.

## Future roadmap notes (not part of this build — just don't paint into a corner)

Two things from the longer-term plan are worth keeping in mind while you
work, even though neither needs building now:

- **Multi-tenancy.** The eventual plan is to sell this to more than one
  municipality. Nothing here needs a `municipality_id` column today (one
  city, one deployment, is the right scope for a first pilot) — but if you
  end up touching the schema significantly, it's worth leaving a mental
  note that `residents`/`polls`/`ridings` will likely need a tenant scope
  column eventually, so a future migration doesn't have to rewrite
  everything's primary keys and RLS policies from scratch.
- **Accountability tracking.** The bigger product idea is comparing how
  council actually voted against what a resident vote favored, and
  surfacing the divergence. This build doesn't need to touch that — but a
  `polls` table is a reasonable eventual home for a `council_vote_outcome`
  field or a related table, once that data exists somewhere to record it.

Neither of these should slow down or complicate getting the core app
working on a real backend — they're here so a schema decision made for
convenience today doesn't quietly rule out something the product needs in
six months.
