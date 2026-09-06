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
   publishable (anon) key into `frontend/vocal-stoon.html`'s two
   `window.SUPABASE_*` placeholders near the top of the file.
4. Set a real council signup code (replaces the hardcoded demo
   "STOON-COUNCIL" constant the old client-side-only version used):
   ```sql
   update app_config set council_code = '<pick a real council signup code>' where id = true;
   ```
5. Deploy `frontend/vocal-stoon.html` as a static file anywhere (GitHub
   Pages, Netlify, Vercel, S3+CloudFront, whatever) — it's still a single
   self-contained HTML file with one external script tag (supabase-js from
   a CDN).

There is deliberately no JWT-secret step here any more — see "Auth model"
below for why.

## Auth model — why it's built this way

The app's sign-in has no username or email: full name + street address +
ward + password. That's a deliberate product decision (see the sign-up
screen's own copy: "there's no username to choose"), not something to
change. But it means Supabase's built-in email/password auth (GoTrue)
doesn't fit — GoTrue needs an email or phone number as the identifier.

**An earlier draft of this build minted its own JWTs** (via the `pgjwt`
extension) for this — a real, documented "bring your own auth" pattern on
Supabase. It was built, verified against a local Postgres instance, and
then found **not to work** against an actual project: PostgREST there
verifies Bearer tokens against the project's real signing keys (its
JWKS), and a project can use ES256/RS256 keys with no HS256 entry
available at all — confirmed directly, by fetching a real project's own
`/auth/v1/.well-known/jwks.json` and seeing only an `"EC"` key. A plain
HS256-signed token can never verify there; it's an algorithm mismatch, not
a config problem, and no amount of secret-wrangling or key-ID-matching
fixes it. If your dashboard shows only asymmetric signing keys, this isn't
a "you set something up wrong" situation — it's the actual, unavoidable
shape of the problem.

**So this build uses a plain session table instead** (`sessions` in
`0001_init.sql`), and never asks PostgREST's JWT/RLS layer to vouch for
anyone:

- `sign_in()`/`sign_up()` do the name+address+ward+password matching
  themselves (server-side, so the client never sees the roster or a
  password hash), then insert a row into `sessions` — just a random
  token pointing at the resident's id, with a 12-hour expiry — and hand
  the token back to the client.
- Every RPC that needs to know who's calling (`cast_vote`,
  `complete_self_verification`, `council_set_verification`, `create_poll`,
  `set_poll_status`, `my_voted_polls`, `poll_results`, `get_my_profile`,
  `residents_roster`) takes that token as an explicit `p_session_token`
  parameter and resolves it itself via `session_resident()`, instead of
  reading a verified JWT's claims.
- The client always calls Supabase with just the plain publishable key —
  there's no Authorization-header dance, no role switching between `anon`
  and `authenticated`. Every request runs as `anon`; the actual
  authorization check happens inside each function, in plain SQL, driven
  by the session token parameter.
- `sign_out()` deletes the session row outright, which is actually a step
  *up* from the JWT approach — a JWT stays valid until it expires no
  matter what; a deleted session row stops working immediately.

This is less "clever" than minting real JWTs, but it doesn't depend on
Supabase's signing-key configuration at all — it'll keep working
regardless of what key type a given project uses, now or after any future
change on Supabase's end. `polls` had to move from RLS-gated reads/writes
to: open reads for everyone (see "Minor behavior change" below) and
writes only through `create_poll()`/`set_poll_status()`, since there's no
verified role left for an `is_council()` RLS policy to check.

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
   `council_set_verification`, `residents_roster` for the council-only
   roster, no `password_hash` column).
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

## Council voting / accountability tracking

A first cut of the "Accountability tracking" roadmap idea (below) is now
built: council members can cast their own vote on an item (`council_votes`
table, `cast_council_vote()` RPC — "Cast council vote" in Manage Votes),
and `poll_results()` folds that into the same payload residents already
fetch for results (`councilCounts` — an aggregate tally, same shape as
`counts` — and `councilVotes`, the attributed list of who voted for what).

Two things worth being explicit about, since both were corrected from an
initial pass based on direct product feedback:

1. **A council vote is final once cast — not an upsert.** `cast_council_vote()`
   rejects a second attempt from the same council member on the same item
   (`"You already cast your council vote on this item."`), the same way
   `cast_vote()` rejects a resident double-voting — a real, database-enforced
   guard (the `(poll_id, resident_id)` primary key), not just a client-side
   restriction. `renderCouncilVoteScreen()` reflects this: once a council
   member has voted, they see a locked "You voted: X" state instead of an
   editable picker — there's no "Update" path at all, by design, matching a
   real roll-call vote.
2. **Council's vote is visible to residents immediately, not gated behind
   the poll closing or a manual "Show results" click.** `renderCouncilVoteSummary()`
   (split out of `renderBars()`) shows the "How council voted" section on
   *any* poll a resident is following, open or closed — this is what
   "accountability" actually requires: a resident should be able to see how
   their council member voted without waiting. The resident tally itself
   (`renderBars()`'s bars) still stays hidden until a poll closes, unchanged
   from before — an early count of residents' own in-progress votes could
   sway still-open voting; that reasoning doesn't apply to council's vote.
   `refreshCouncilTransparency()` keeps this fed: it's called after a
   resident's poll list refreshes, right after they cast their own vote,
   and every time they open the History tab (forced, so it's never stale
   just because it was fetched once already) — there's no live push for
   this specifically (Realtime is only wired to the `polls` table itself,
   not `council_votes`), so a resident already sitting on an open History
   tab won't see a council vote the instant it's cast, only at those
   refresh points.

Council can still vote regardless of the poll's open/closed status —
nothing here enforces a particular order between "residents vote" and
"council decides."

**All-time alignment stat.** Both the resident History tab and council's
Manage Votes now show a summary card (`renderCouncilAlignmentSummary()`):
across every *closed* poll where both sides actually voted, what share of
the time did council's winning option match residents' winning option?
Computed entirely client-side from already-loaded `poll_results()` data —
no new RPC. `winningOptionId()` picks whichever option has strictly the
most votes; a tie on either side excludes that poll from the stat
entirely (there's no single "winner" to compare), rather than guessing
which way to count it. The card only appears once there's at least one
poll where both sides have a clear winner to compare.

**Per-member voting record.** Right below that, `renderCouncilRecords()`
(`computeCouncilRecords()`) lists each council member by name with their
own track record: a per-member "matched residents X% of the time" stat,
then every closed poll they've voted on with their choice and whether it
matched residents' pick. Also built entirely client-side from the same
already-loaded `poll_results()` data — `councilVotes` carries each voter's
name and choice regardless of who's asking (any signed-in resident, not
just council), so this needed no new roster-access RPC. Grouped by
resident id rather than name, in case two council members ever share one.
Shown on both the resident History tab and council's own Manage Votes.

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
- `residents` is deliberately **NOT** wired up to Realtime, and — since the
  auth-model change above dropped JWT/RLS-based authorization entirely —
  now *can't* be, safely: Realtime subscribes to a raw table's changes,
  with no way to route a session-token check through it the way the RPC
  functions do. The council roster is a plain fetch instead (via the
  `residents_roster()` RPC) — called once when council opens that tab, and
  re-called after every approve/reject action so it still feels live.

## What's been verified since, and what's still your job

This migration went through two real rounds of testing, and one full
architecture change, before landing here:

**Round 1 (local Postgres, JWT-based draft — since replaced).** Driving
every RPC directly against a local Postgres 16 instance set up to mirror a
fresh Supabase project, three real bugs surfaced and were fixed: `polls`'s
RLS policies referenced helper functions defined *later* in the file
(silently leaving `polls` with zero working policies after the migration
"succeeded"); the council-roster view always returned zero rows due to a
`security_invoker`/RLS-default-deny interaction; and a confirmed,
working privilege-escalation exploit (a client-created temp table could
shadow `residents` and trick `sign_in()` into minting a forged council
session), fixed with `REVOKE TEMPORARY ... FROM PUBLIC`.

**Then, against an actual live Supabase project**, the JWT-minting
approach itself turned out not to work at all — see "Auth model" above.
That's what drove the session-table redesign now in this file.

**Round 2 (local Postgres, current session-table design).** Re-verified
end-to-end after the redesign, calling every RPC as the `anon` role (since
that's now the only role anything runs as) with real session tokens:
sign-up/sign-in (including whitespace/case-insensitive name+address
matching and bcrypt password checks), the council-code gate, `anon`
direct-table access to `residents`/`sessions`/`poll_ballots` still fully
denied, `residents_roster()` correctly scoping to self vs. full roster for
council, ward-scoped poll eligibility, the verified-residents-only voting
requirement, atomic double-vote rejection, `create_poll()`/
`set_poll_status()` correctly requiring council and rejecting a resident
caller, `poll_results()` aggregation without ever exposing a raw ballot
row, `my_voted_polls()`, and `sign_out()` actually revoking a session (a
`get_my_profile()` call with a signed-out token correctly returns
nothing). The temp-table-shadowing exploit fix was re-confirmed against
this version too.

**Not yet verified — still needs a real Supabase project:**

- The actual round trip through `supabase-js` from a real browser talking
  to a live project (this was checked by calling the RPCs directly against
  Postgres as the `anon` role, which is what the real PostgREST layer also
  does now that there's no JWT/role-switching involved — but the literal
  HTTP path through PostgREST hasn't been exercised).
- Supabase Realtime's behavior on `polls` in practice (the subscription
  code itself didn't change in this redesign).
- A true concurrent double-vote race (two simultaneous requests) — the
  primary-key-based guard was confirmed to reject a *second* vote from the
  same resident, which is the same mechanism a true race would hit, but an
  actual two-connections-at-once race wasn't run.
- Session cleanup: expired rows in `sessions` are simply ignored (never
  matched by `session_resident()`), not deleted. Fine for a pilot; worth a
  periodic cleanup job (`delete from sessions where expires_at < now()`)
  before this scales to many users.

## Minor behavior changes (disclosed, not hidden)

- `refreshMyBallots()` (frontend) now reflects **every** poll a resident
  has ever voted on, open or closed, via the `my_voted_polls()` RPC. The
  original client-side loop only checked currently-*open* polls, so a
  returning resident's History tab could stop correctly showing "You
  voted: X" for a poll that closed since their last visit (the render code
  already supported showing it — the refresh function just never fetched
  closed-poll ballots). This is a small correctness fix, not a feature
  change.
- Poll listings (`polls`) are now readable by anyone hitting the API,
  signed in or not — see "Auth model" above for why (there's no verified
  role left for a "must be signed in" RLS policy to check). Voting, the
  resident roster, and results all still require a valid session; only
  the bare list of poll titles/descriptions/budgets is now technically
  public. Given these are public municipal budget votes, that's a
  reasonable trade-off, but flagging it since it's a real change from the
  original prototype's behavior.

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
