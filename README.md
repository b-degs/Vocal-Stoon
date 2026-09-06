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

The migration and frontend in this repo have been checked against a local
Postgres instance (schema, RLS policies, and every RPC function exercised
directly — sign-up, sign-in, casting a vote, double-vote prevention, ward
eligibility, council roster access, and the secret-ballot lockdown). Two real
bugs turned up in that pass and are already fixed in the committed migration:
a function-ordering issue that broke `polls`' Row Level Security entirely,
and a `residents_public` view that always returned zero rows. A third,
more serious issue — any client could shadow `residents` (or any other
table) with a same-named temp table and trick the sign-in/sign-up/vote
functions into operating on forged data, including minting themselves a
valid council session token — is also fixed (`REVOKE TEMPORARY` in the
migration; see the comment above it for why `search_path` alone doesn't
close this).

Still needed before this goes live, because nothing here has touched a real
Supabase project: run the migration there, do the one-time JWT-secret and
council-code setup (`SPEC.md` step 4), fill in the two config values in
`frontend/vocal-stoon.html`, and walk through the manual checklist in
`SPEC.md`'s "What's unverified" section — in particular confirming Supabase
Realtime behaves as expected and that your project's JWT configuration
matches the shared-secret (HS256) approach this migration assumes.

## Where this came from

This is the same "Vocal STOON" app that ran as a Claude artifact. This
backend swaps the Claude-specific realtime-database capability for a real,
shared Postgres database on Supabase, so the app can run as an actual
product — anyone can use it from any device, permanently, no Claude account
involved anywhere. Nothing in the UI, features, or user-facing behavior was
intentionally changed — see `SPEC.md`'s feature-parity checklist.
