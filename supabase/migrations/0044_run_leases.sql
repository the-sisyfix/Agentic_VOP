-- 0044_run_leases.sql
--
-- Cross-process leases for resources shared by every pipeline (see
-- apps/api/app/leases.py).
--
--   fixer:env2              — SA-4 dispatch; env2 is one shared sandbox.
--                             Replaces the process-local threading.Lock +
--                             fix_runs polling, which didn't coordinate
--                             across uvicorn workers, hosts, or schemas.
--   sa1:<schema>:<tool>     — SA-1 fetch for one scanner; keeps two runs
--                             from reading and writing the same
--                             connection_registry.last_fetched_at watermark.
--
-- One row per held resource. Holders renew expires_at every ttl/3; a row
-- past expires_at belongs to a dead process and is taken over by the next
-- waiter.
--
-- Lives in public only, on purpose: public, dev and demo pipelines all hit
-- the same env2 instance, so they must share one lock table.
--
-- Apply: paste into Supabase Dashboard SQL Editor.

CREATE TABLE IF NOT EXISTS public.run_leases (
  resource     text        PRIMARY KEY,
  holder       text        NOT NULL,
  label        text,
  acquired_at  timestamptz NOT NULL DEFAULT now(),
  expires_at   timestamptz NOT NULL
);

COMMENT ON TABLE public.run_leases IS
  'Cross-process leases (env2 fixer dispatch, SA-1 per-scanner fetch). See apps/api/app/leases.py.';

ALTER TABLE public.run_leases ENABLE ROW LEVEL SECURITY;  -- service_role only; no policies
GRANT ALL ON public.run_leases TO service_role;
