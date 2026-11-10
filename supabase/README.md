# Supabase migrations

SQL migrations for Agentic_VOP. Each file in `migrations/` is applied **in
numeric order** (`0001` → `0044` → …). They build the full schema as code:
the core tables (`agent_runs`, `agent_trace_events`, `raw_findings`, `issues`,
`connection_registry`, `schema_mapping`, `prompt_db`, `monitored_packages`,
`assets`, the MITRE catalogs, `remediation_patterns`, `remediation_packages`,
`fix_runs`, `ticketing_connections`, `hardening_runs`, …) plus seed/config data.

## Environments: one Supabase PROJECT per environment

The dev/prod data boundary is the **Supabase project**, not a schema. There are
(at least) two projects:

| Environment | Supabase project | Pointed at by |
|---|---|---|
| **PROD** | the production project (`wkbymeovkopfufiaiwxm`) | the deployed EC2 app; `.env` refreshed from SSM at deploy, with `APP_ENV=prod` |
| **DEV** | a dedicated dev project (`agentic-vop-dev`) | local development; `apps/api/.env` + `apps/web/.env` with `APP_ENV=dev` |

Why a separate project (not just a separate Postgres schema): a different
project means a different URL + different keys, so local/dev work **physically
cannot** read or write PROD data regardless of any `DB_SCHEMA` setting. The
backend enforces this: with `APP_ENV=dev` (the default), the API **refuses to
start** if `AGENTIC_VOP_SUPABASE_URL` points at the PROD project. See
`APP_ENV` / `prod_supabase_url_ref` in `apps/api/app/config.py`.

> `DB_SCHEMA` is **not** the dev/prod boundary. It only switches schemas
> *within* whichever project you are already connected to. The `public` and
> `demo` schemas are both part of the normal pipeline (`public` through
> Sub-Agent 2; `demo` for Sub-Agent 3/4) and exist in every project.

## One-time setup of the DEV project

1. Create a new Supabase project (e.g. `agentic-vop-dev`).
2. Apply **every** migration in `migrations/` in numeric order (see "Apply a
   migration" below). This builds the `public` schema. **The `demo` schema
   (used by Sub-Agent 3/4) is NOT created by any migration in this repo**
   (`db.py` refers to a "migration 0046" that does not exist here), so it has
   to be reproduced from the PROD project and exposed in the Data API
   ("Exposed schemas") before the remediation/fixing flow works in dev.
3. Seed the config/reference tables so dev behaves like prod: `prompt_db`,
   `schema_mapping`, `connection_registry`, `remediation_patterns`, the MITRE
   catalogs (`mitre_cwe` / `mitre_capec` / `mitre_attack_techniques`), and
   `assets`. The seed-bearing migrations (e.g. `0002`, `0006`, `0031`, …) are
   idempotent and cover most of this; MITRE catalogs are populated via the
   `/admin/mitre/refresh*` endpoints after the app can reach the dev project.
4. In `apps/api/.env` set `APP_ENV=dev` and the **dev** project's
   `AGENTIC_VOP_SUPABASE_URL` + `AGENTIC_VOP_SUPABASE_SERVICE_KEY`.
   In `apps/web/.env` set the **dev** project's `VITE_SUPABASE_URL` +
   `VITE_SUPABASE_ANON_KEY`.

## Deploy ordering (PROD safety)

`APP_ENV` defaults to `dev` in code. For the deployed app to keep using the
PROD project, the SSM parameter **`/sisyfix/prod/app/APP_ENV = prod` must exist
before the deploy runs** — the deploy workflow writes every
`/sisyfix/prod/app/*` parameter into `/opt/app/.env`. If that parameter is
missing at deploy time, the prod container will see `APP_ENV=dev`, detect the
PROD Supabase URL, and refuse to start (fail-safe, not data corruption). Add
the SSM parameter first, then merge/deploy.

## Apply a migration

Supabase Dashboard → SQL Editor → New query → paste the migration file →
Run. Apply files in numeric order. (The project naming and manual flow match
the current process; automating this with the Supabase CLI
(`supabase db push`) is a planned follow-up so the two projects stay in sync.)

## Notes

- Realtime is enabled on `agent_trace_events`, `agent_runs`, and `issues` — the
  frontend subscribes to live updates (the Agents page trace).
- RLS is enabled on tables; authenticated users read, the backend writes via
  the service-role key (which bypasses RLS).
- `event_id` on `agent_runs` is the idempotency key for triggers.
