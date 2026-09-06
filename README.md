# Vocal STOON

Vocal STOON is a municipal budget-voting prototype: residents sign up (name,
address, ward, password), council opens ward-scoped or citywide "votes" on
budget items, residents cast anonymous secret ballots, and council tracks
turnout and results.

## What's in this repo

- **`index.html`** / **`Vocal STOON_4.html`** — the original prototype: a
  single-file HTML app that ran as a Claude artifact, using a Claude-specific
  realtime document-store capability as its "database." Kept here for
  reference; not wired to any real backend.
- **`SPEC.md`** — the real-backend build spec: what the app does, the auth
  model, the security fixes made vs. the prototype, and a feature-parity
  checklist. Read this before touching `frontend/` or `supabase/`.
- **`supabase/migrations/0001_init.sql`** — full schema, Row Level Security
  policies, and RPC functions for a real Postgres/Supabase backend. Has setup
  instructions in a comment block at the top.
- **`frontend/vocal-stoon.html`** — the app rewired to call Supabase instead
  of the old Claude-artifact database. Same UI, same features. Needs two
  config values filled in near the top of the file before it does anything
  (see `SPEC.md` step 3).

## Status

This has been through two rounds of testing and one architecture change.
An earlier draft minted its own JWTs for sessions (a real Supabase "bring
your own auth" pattern) — that was built, tested against a local Postgres
instance (catching and fixing a function-ordering bug that broke `polls`'
RLS entirely, a roster view that always returned zero rows, and a
confirmed privilege-escalation exploit via temp-table shadowing, fixed
with `REVOKE TEMPORARY`), and then found not to work at all against a
real Supabase project: that project's only signing key is asymmetric
(ES256), and a JWT signed with a plain shared secret can never verify
there — confirmed directly against the project's own JWKS endpoint, not
a guess.

So the auth model changed: sessions are now plain rows in a `sessions`
table instead of JWTs, and every RPC that needs to know who's calling
takes the session token as an explicit parameter rather than relying on
Supabase's JWT/RLS layer at all. This works regardless of what signing
keys a given Supabase project uses. Re-verified end-to-end against a local
Postgres instance after the redesign — sign-up/sign-in, the council-code
gate, ward eligibility, verified-only voting, double-vote rejection,
council-only roster access, poll create/close/reopen, results aggregation,
session sign-out actually revoking access, and the secret-ballot/temp-table
lockdowns all confirmed working. See `SPEC.md`'s "Auth model" and "What's
been verified" sections for the full detail.

Still needed before this goes live: the actual round trip through
`supabase-js` from a real browser against your live project hasn't been
exercised (everything above was verified by calling the database directly
as the `anon` role, which is what the real API layer also does now — but
the literal HTTP path hasn't been). Fill in the two config values in
`frontend/vocal-stoon.html` (Project URL + publishable key), set your
council code (`SPEC.md` step 4), and walk through `SPEC.md`'s "What's been
verified" checklist — in particular confirming Supabase Realtime behaves
as expected on `polls`.

## Where this came from

This is the same "Vocal STOON" app that ran as a Claude artifact. This
backend swaps the Claude-specific realtime-database capability for a real,
shared Postgres database on Supabase, so the app can run as an actual
product — anyone can use it from any device, permanently, no Claude account
involved anywhere. Nothing in the UI, features, or user-facing behavior was
intentionally changed — see `SPEC.md`'s feature-parity checklist.
