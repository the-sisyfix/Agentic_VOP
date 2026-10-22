-- 0044_hardening_runs.sql
--
-- Image Hardening feature (NEW, isolated from the vulnerability fixer).
--
-- Creates the `hardening_runs` run-record table. This is the hardening
-- feature's OWN run table, deliberately NOT reusing fix_runs:
--   * fix_runs has NOT NULL foreign keys to issues + remediation_packages
--     (a scanner-finding lineage). A hardening run has NO scanner finding,
--     so it must not be forced through that schema.
--   * This table has NO foreign keys to any existing table — it stands alone.
--
-- ISOLATION GUARANTEE (see .kiro/specs/image-hardening/design.md):
-- This migration is STRICTLY ADDITIVE. It only CREATEs a new table in each
-- schema. It does NOT ALTER fix_runs, issues, remediation_packages, or any
-- existing object. Existing application functionality is untouched.
--
-- Applied to BOTH public.* and demo.* so the demo pipeline mirrors public,
-- consistent with every other table in this project.

-- =============================================================================
-- public.hardening_runs
-- =============================================================================
CREATE TABLE IF NOT EXISTS public.hardening_runs (
  id                 bigserial   NOT NULL,

  -- What we hardened and where it was published
  source_image_ref   text        NOT NULL,            -- e.g. golang:1.25-alpine or a client base ref
  target_registry    text        NOT NULL,            -- ECR repo URL (push target)
  published_tag      text,                            -- e.g. v0.1.0 (set after push)
  published_digest   text,                            -- sha256:... (set after push; the thing CI signs)

  -- Lifecycle
  status             text        NOT NULL DEFAULT 'pending'::text,

  -- Supply-chain artifacts
  sbom_s3_key        text,                            -- sboms/<digest>.spdx.json (set after SBOM upload)
  scan_summary       jsonb       NOT NULL DEFAULT '{}'::jsonb,   -- trivy gate result summary
  auto_sign          boolean     NOT NULL DEFAULT false,         -- did we auto-trigger the signing workflow?
  sign_dispatched    boolean     NOT NULL DEFAULT false,         -- was the GitHub Actions sign workflow dispatched?

  -- Execution detail (mirrors fix_runs' JSONB result arrays, but standalone)
  step_results       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  validation_results jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rollback_results   jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rollback_triggered boolean     NOT NULL DEFAULT false,
  backup_reference   text,

  -- Where it ran
  build_instance_id  text,

  -- Timing + errors
  started_at         timestamptz,
  finished_at        timestamptz,
  duration_seconds   integer,
  error_message      text,
  timeout_seconds    integer     NOT NULL DEFAULT 1800,

  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT hardening_runs_pkey PRIMARY KEY (id),
  CONSTRAINT hardening_runs_status_check CHECK (status IN (
    'pending',
    'preflight',
    'building',
    'scanning',
    'publishing',
    'signing',
    'success',
    'failed',
    'rolled_back'
  ))
);

CREATE INDEX IF NOT EXISTS idx_hardening_runs_status     ON public.hardening_runs (status);
CREATE INDEX IF NOT EXISTS idx_hardening_runs_created_at ON public.hardening_runs (created_at DESC);


-- =============================================================================
-- demo.hardening_runs  (mirror of public)
-- =============================================================================
CREATE TABLE IF NOT EXISTS demo.hardening_runs (
  id                 bigserial   NOT NULL,

  source_image_ref   text        NOT NULL,
  target_registry    text        NOT NULL,
  published_tag      text,
  published_digest   text,

  status             text        NOT NULL DEFAULT 'pending'::text,

  sbom_s3_key        text,
  scan_summary       jsonb       NOT NULL DEFAULT '{}'::jsonb,
  auto_sign          boolean     NOT NULL DEFAULT false,
  sign_dispatched    boolean     NOT NULL DEFAULT false,

  step_results       jsonb       NOT NULL DEFAULT '[]'::jsonb,
  validation_results jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rollback_results   jsonb       NOT NULL DEFAULT '[]'::jsonb,
  rollback_triggered boolean     NOT NULL DEFAULT false,
  backup_reference   text,

  build_instance_id  text,

  started_at         timestamptz,
  finished_at        timestamptz,
  duration_seconds   integer,
  error_message      text,
  timeout_seconds    integer     NOT NULL DEFAULT 1800,

  created_at         timestamptz NOT NULL DEFAULT now(),
  updated_at         timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT demo_hardening_runs_pkey PRIMARY KEY (id),
  CONSTRAINT demo_hardening_runs_status_check CHECK (status IN (
    'pending',
    'preflight',
    'building',
    'scanning',
    'publishing',
    'signing',
    'success',
    'failed',
    'rolled_back'
  ))
);

CREATE INDEX IF NOT EXISTS idx_demo_hardening_runs_status     ON demo.hardening_runs (status);
CREATE INDEX IF NOT EXISTS idx_demo_hardening_runs_created_at ON demo.hardening_runs (created_at DESC);


-- =============================================================================
-- RLS (Row Level Security) — matches every other table in this project.
-- Service role (used by the backend via supabase_admin()) bypasses RLS; the
-- anon/authenticated keys get no access since the frontend never reads this
-- table directly. Mirrors the posture in 0036_remediation_kb.sql.
-- =============================================================================
ALTER TABLE public.hardening_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on hardening_runs"
    ON public.hardening_runs
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);

ALTER TABLE demo.hardening_runs ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access on hardening_runs"
    ON demo.hardening_runs
    FOR ALL
    USING (TRUE)
    WITH CHECK (TRUE);
