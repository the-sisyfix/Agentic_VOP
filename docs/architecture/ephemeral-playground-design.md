# Ephemeral Remediation Playground: Design

Status: DRAFT for team review. No code has been changed.
Scope of work: dev Supabase project and the current feature branch only.

Legend used in this document:
- **[Verified]** was read in the repository.
- **[Assumption]** has not been checked and must be confirmed in the spike (section 12).

---

## 1. Problem

Sub-Agent 4 (SA-4) applies fixes on one fixed EC2 instance (env2 in PROD, env3 in DEV), set by
`FIXER_ENV2_INSTANCE_ID`. Everything is serialized around it:

| Layer | Where | Behavior |
|---|---|---|
| API guard | `main.py` `_guard_env2_free_for_trigger()`, called by `/agents/trigger` and all four `/agents/trigger_demo*` routes | Returns 409 if any `fix_runs` row is `pending/provisioning/executing/validating`, or any `agent_runs` row is `queued/running`, in either schema. [Verified] |
| Process lock | `fixer/orchestrator.py` `_ENV2_DISPATCH_LOCK` (`threading.Lock`) | One `run_fixer` at a time per Python process, whatever the target instance. [Verified] |
| DB check | `fixer/persistence.py` `any_concurrent_run()` | Any non-terminal `fix_runs` row in the caller's schema blocks the run. Not filtered by instance. [Verified] |
| Reset/force-release | `/admin/env2/*` | Operates on the single static instance. [Verified] |

Effect: while one user's pipeline runs, nobody else can start any pipeline (including the plain
ingest pipeline). Management needs parallel demo users now and more later.

## 2. Goal

Each pipeline run gets its own short-lived, isolated playground instance, built from a known
baseline, destroyed afterwards. Parallel runs do not share a target, so the global serialization
can be removed.

## 3. Direction and guiding rules

1. One playground per pipeline run (not per fix run, so earlier fixes in the run remain in place).
2. Instances are single-use and time-limited. They are destroyed, never reset.
3. Leases live in the database (not in a process lock), so they survive restarts and work with
   more than one API worker.
4. A "target provider" seam hides how instances are created, so a lighter provider
   (containers) or a different source of truth can be added later without touching strategies.
5. Every record carries an optional `tenant_id` so a multi-tenant answer from management does not
   force a redesign.
6. All new behavior is behind a flag. Default keeps today's behavior.

## 4. What is in the first delivery and what is deferred

Management wants this simple and ready for the demo. The split below keeps the first delivery to
the minimum that delivers parallelism, and keeps the seams for the rest.

| Item | Phase 1 (demo + parallelization) | Later |
|---|---|---|
| Per-run instance launched from a golden AMI | Yes | |
| DB lease table, TTL, teardown, leak sweeper | Yes | |
| Remove the global guard/lock when flag is on (per-instance scoping) | Yes | |
| Unique resource naming per run for CSPM/serverless labs | Yes | |
| SA-3 and SA-4 both use the run's instance | Yes | |
| Security hardening of the instances (no SSH, IMDSv2, tags, tag-scoped SSM) | Yes | |
| Separate AWS account | Prerequisite (user arranging) | |
| Warm pool of pre-launched instances | | Yes, if cold start is too slow |
| Client CI/CD manifest as replica source (GitHub Actions) | | Phase 2 |
| Functional tests (before/after) in the proof | | Phase 2 |
| Reproduction check on the replica before the fix | | Phase 2 |
| Replica attestation record for audits | | Phase 2 |
| IaC proof tiers (plan diff, sandbox-account apply) | | Phase 2 |
| OS-family replica from a client host definition | | Separate track |
| Container-based provider for code/dependency fixes | | Later |

## 5. Current flow (relevant parts) [Verified]

- Demo trigger: creates a real `agent_run` (public schema) and a demo `agent_run` (demo schema),
  then a background task runs `run_master(real_run_id)` and then
  `run_demo_master(demo_run_id, real_run_id=...)`.
- SA-3 builds `remediation_packages` rows (with `agent_run_id` = demo run id). It reads the live
  target file via SSM: `remediation/tools/file_fetch.py` falls back to
  `settings.fixer_env2_instance_id` when called with `target_instance_id=None`
  (`agent_v2.py` and `kb_replay.py` both pass `None`).
- SA-4: `run_fixer` resolves the target in `_run_fixer_locked`: `FIXER_ENV2_INSTANCE_ID`, overridden
  by `connection_registry.metadata.target_instance_id` for scanners that define one.
- The target is stored per run in `fix_runs.target_instance_id`.
- HITL approve (`/admin/remediation-packages/demo/{id}/approve`) dispatches `run_fixer` in the
  background later, using the package's `agent_run_id`.

Consequence: the demo run id is the one key that connects planning, fixing and approvals. The
lease is keyed on it.

## 6. Target architecture

```
 trigger_demo*  ->  PlaygroundService.acquire(run_id)     (creates lease, starts launch)
                         |
                         v
                  playground_leases (DB)  <-- reaper / sweeper
                         |
   run_master (real pipeline, minutes)   runs while the instance boots
                         |
   SA-3  -> TargetResolver.for_run(run_id) -> instance_id   (file reads)
   SA-4  -> TargetResolver.for_run(run_id) -> instance_id   (fix lifecycle)
                         |
   pipeline finished / all packages terminal / TTL  ->  PlaygroundService.release(run_id)
```

Components (all new, in one package, e.g. `app/services/playground/`):

- **PlaygroundService**: `acquire(run_id, tenant_id=None)`, `wait_ready(run_id, timeout)`,
  `release(run_id)`, `extend(run_id)`.
- **TargetProvider** (interface). Phase 1 implementation: `Ec2AmiProvider` (launch, tag,
  terminate). `StaticProvider` returns today's `FIXER_ENV2_INSTANCE_ID`, used when the flag is off.
- **TargetResolver**: given a run id (or none), returns the instance id. If the scanner has its own
  `connection_registry.metadata.target_instance_id` (the separate OS track, env5), that wins.
- **Reaper/sweeper**: extends the existing 60 s reaper in `main.py`. It expires leases past TTL and
  terminates any instance carrying our tags that has no active lease.

Feature flag: `PLAYGROUND_MODE=static|ephemeral`, default `static`.

## 7. Data model (dev Supabase only; new migration file, applied manually to dev)

`playground_leases`

| Column | Notes |
|---|---|
| id uuid PK | |
| tenant_id text null | Optional, reserved for multi-tenancy |
| owner_run_id text | Demo `agent_run` id. Partial unique index where status is not released/failed |
| status | `provisioning`, `ready`, `releasing`, `released`, `failed` |
| instance_id text null | |
| ami_id text | Baseline used (audit) |
| name_prefix text | Unique per lease, used for resource names and state key |
| created_at, ready_at, expires_at, released_at | |
| error text null | |

Capacity: a configured maximum of simultaneous non-terminal leases. Beyond it the trigger returns a
clear "capacity" error (replaces today's blanket 409).

The existing `fix_runs.target_instance_id` column is used as-is.

## 8. Lifecycle

1. **Acquire**: on a demo trigger (flag on), insert a lease (`provisioning`) and launch
   asynchronously. The real ingest pipeline (`run_master`) runs while the instance boots, which
   hides most of the boot time.
2. **Ready gate**: before SA-3 starts, wait until the lease is `ready`: instance running, SSM
   agent `Online`, a health probe passes (lab files present). On timeout the run fails with a
   clear message and the lease is released.
3. **Use**: SA-3 file reads and SA-4 use the leased instance. Fix runs on different leases do not
   block each other.
4. **Release**: automatic pipelines release after the fix stage. HITL pipelines keep the lease
   until every package is terminal (fixed, rolled back, failed, rejected) or the TTL passes.
   Release runs teardown (section 9), then terminates the instance.
5. **TTL**: every lease has `expires_at`. HITL waits on humans, so the TTL has to be long enough
   (open question 3).

## 9. Teardown and real AWS resources

The labs create real AWS resources (CSPM lab: S3 bucket, security group, KMS key, IAM policy, log
group, SNS topic, SQS queue; serverless lab: IAM role/policy, Lambda, log group). Resource names
embed `NAME_PLACEHOLDER`, replaced with the instance `name_prefix` [Verified in
`cspm-lab-template.tf` and `serverless-lab-template.tf`]. Terraform state key also embeds the
prefix (`vuln-labs/cspm-lab/<prefix>/terraform.tfstate`) [Verified in `user-data.sh.tpl`].

A golden AMI cloned as-is would carry the source instance's prefix and state config. Two instances
would then manage the same real resources and the same state. So each launch must set a unique
prefix before Terraform is touched.

- Launch applies a small first-boot script that rewrites `name_prefix` in the lab Terraform and
  `backend.hcl` (unique per lease).
- Teardown runs `terraform destroy` for both labs (the lab role already has the permissions
  [Verified in `lab-instance/main.tf`]), then terminates the instance.
- Leak sweeper: resources are tagged with lease id and expiry; a periodic sweep removes anything
  past expiry. Needed because a crashed backend cannot run teardown.
- Cost/time: the first-boot `terraform apply` of two labs may add minutes and is a risk for the
  "minutes" target. Options are in the spike (section 12).

## 10. Security model

Rules that apply from Phase 1:

- Instances launch with no SSH ingress, no public IP if the network allows it, IMDSv2 required,
  encrypted volumes, and egress limited to what the fixes need (package mirrors, registries,
  GitHub, AWS endpoints). [Assumption: egress restrictions need testing against the fix flows.]
- Today's playground security group opens SSH to `0.0.0.0/0` and the app role has
  `ssm:SendCommand` on `Resource: "*"` [Verified]. The new design replaces both:
  SSM-only access, and an IAM condition so the control-plane role can send commands only to
  instances tagged for playgrounds.
- Separate identities: a control-plane role (launch, tag, terminate, send commands, with tag
  conditions) and a small fixed set of instance profiles with permission boundaries. The current
  lab instance role has `ec2:*` and `kms:*` on `*` [Verified]; the ephemeral profile must be
  scoped to the lease's own resources.
- Playgrounds run in a separate sandbox AWS account (prerequisite).
- No client secrets or production data on replicas. Synthetic configuration only.
- Every instance is tagged: `Project`, `Component=playground`, `LeaseId`, `RunId`, `TenantId`,
  `AmiId`, `ExpiresAt`. CloudTrail provides the audit trail of launches and SSM commands.

Backend IAM additions (prod Terraform, `infra/app-hosting/iam.tf`; not applied as part of this
pilot): `ec2:RunInstances`, `ec2:TerminateInstances`, `ec2:CreateTags`, `ec2:DescribeInstances`,
and `iam:PassRole` for the instance profile only. Today the role has none of these [Verified].
For dev, the developer's own credentials are used.

## 11. Changes to existing code (all gated by the flag)

Touch points, so the impact on current behavior is reviewable:

1. `main.py`: `_guard_env2_free_for_trigger()`. When flag is on, replace the global busy check with
   the capacity check, and start the lease in the demo trigger background functions.
2. `fixer/orchestrator.py`: resolve the target via `TargetResolver`. Make `_ENV2_DISPATCH_LOCK`
   per-instance (a dict of locks keyed by instance id). Scope the wait loop.
3. `fixer/persistence.py`: `any_concurrent_run(sb, target_instance_id=None)`. With no argument,
   behavior is unchanged.
4. `remediation/tools/file_fetch.py` callers (`agent_v2.py`, `kb_replay.py`): pass the run's
   instance instead of `None`.
5. HITL approve endpoint: no change needed, since it dispatches by the package's `agent_run_id`.
6. `main.py` reaper: add lease expiry and leak sweeping.
7. New migration (dev) for `playground_leases`.

With the flag off, `StaticProvider` returns the existing instance and every other path is
identical to today. Reset and force-release endpoints stay as they are for the static instance.

## 12. Spike (do first, before committing to the plan)

Small, throwaway checks to remove the main unknowns:

1. Does an instance launched from an AMI of the current lab (env3) register with SSM and pass
   the lab health probe? [Assumption]
2. Boot-to-ready time from the AMI, with and without the first-boot Terraform apply.
3. Can the prefix and state rewrite be done reliably so two instances do not collide?
4. Do the existing strategies (iac, code_edit, dependency, image) run unchanged against a launched
   instance?
5. Account quotas for the instance type and count.

If the Terraform apply dominates boot time, the options are: (a) accept the time, (b) pre-launch a
warm pool, or (c) apply the cloud labs lazily, only when an IaC or serverless fix needs them. Real
AWS resource names cannot be baked into an AMI, because each lease needs its own names. Decide
after measuring.

## 13. Staged plan

| Stage | Content | Exit criterion |
|---|---|---|
| 0 | Spike (section 12) | Numbers and a go/no-go on the AMI approach |
| 1 | Golden AMI build (repeatable, versioned), `playground_leases` migration (dev) | AMI id recorded; table in dev |
| 2 | PlaygroundService, Ec2AmiProvider, TargetResolver, flag, ready gate | One run gets its own instance and finishes |
| 3 | Scope the guard, lock and DB check per instance; capacity limit | Two runs execute in parallel without interference |
| 4 | Teardown, TTL reaper, leak sweeper | Instances and cloud resources are gone after runs, including after a forced crash |
| 5 | Security hardening and tag-scoped IAM (in sandbox account) | Checklist in section 10 satisfied |
| 6 (Phase 2) | Client demo repo + GitHub Actions + build manifest | Replica built from manifest |
| 7 (Phase 2) | Proof engine: scanner before/after, functional before/after, attestation | Evidence record per fix |

Stages 0-4 are the "parallelization" delivery. Stage 5 should not be skipped before anyone outside
the team uses it.

## 14. Phase 2 outline (design now, build later)

**Replica source.** A client "demo" repo in a separate GitHub repo (same organization), with a
GitHub Actions workflow that builds artifacts and publishes a build manifest: commit SHA, image
digests, lockfile hashes, the test entry command, and the test hash. The replica builder consumes
the manifest instead of hardcoded `/opt/vuln-labs` paths.

**Proof record per fix:** scanner result before and after, functional result before and after,
manifest and test hashes, AMI id, lease id, timestamps. Differential testing: failures that
already existed before the fix are not counted against it. The claim is "no regression detected by
this test suite".

**Proposed functional tests** (each must pass on the replica before the fix and after it):

| Family | Lab | Test |
|---|---|---|
| SAST | appsec-lab | Start app on a temp DB; `/setup`; `POST /login` admin/admin123 returns 200; wrong password 401; `/search?q=adm`; `/user/1`; `/profile?name=Bob` and `/greet?msg=Hi` return 200 |
| SAST security | appsec-lab | After fix, `/login` with `' OR '1'='1` returns 401; `/profile?name=<script>` does not echo the raw tag |
| SCA | appsec-lab | After the bump, `pip install -r requirements.txt` resolves in a fresh venv; app imports and passes the SAST tests |
| Image infra | infra-lab | Container starts; nginx returns 200 on port 80; `nginx -t` passes |
| Image java | java-image-lab | Tomcat starts; `GET /` returns the page with 200 |
| Image python | python-image-lab | Imports `flask` and `main` without errors |
| Image php | php-image-lab | `php --version` and `php -r 'echo json_encode([1]);'` |
| IaC | cspm-lab | `terraform validate`; `terraform plan` shows only the intended changes, no unrelated destroy/replace |
| Serverless | serverless-lab | `py_compile`; unit test of `lambda_handler` with mocked AWS clients for `/query`, `/process`, `/token`; unknown path returns 404 |

Notes: none of these tests exist today [Verified]; the appsec app is never started by `user-data`;
its pinned `flask==1.0` and `jinja2==2.10` have not been run on the lab Python version
[Assumption]. Tests come from the client repo and are read-only to the fixer. They run through the
same SSM path and the same safety validator.

**IaC proof tiers:** (1) Checkov re-scan, (2) `terraform plan` diff limited to intended attributes,
(3) optional apply of a minimal copy in the sandbox account with unique names and destroy.

**Host OS** is a separate track. A pipeline describes applications, not host AMIs. The input for OS
replicas (client AMI, package manifest) is undecided.

## 15. Prerequisites

1. Separate sandbox AWS account for playgrounds (being arranged).
2. A registry for replica images in that account (for Phase 2), e.g. ECR.
3. Instance quota in the sandbox account for the expected parallel runs (under 10 users now).
4. Separate GitHub repo in the same organization for the demo client, with OIDC or a token for the
   workflow (Phase 2).
5. A repeatable AMI build (Packer or EC2 Image Builder, or a scripted snapshot for the pilot).
6. Dev Supabase project access to apply the new migration.

## 16. Risks

| Risk | Mitigation |
|---|---|
| Cold-start time misses "minutes" | Overlap boot with the real pipeline; warm pool; lazy cloud-lab apply |
| Resource-name or state collision between instances | Unique prefix per lease, rewrite before Terraform runs |
| Leaked instances or cloud resources after a crash | TTL, tag-based sweeper, expiry tags |
| HITL leases held by humans too long | TTL, extension, and explicit release |
| Cost growth with users | Capacity limit, TTL, instance type choice |
| Existing behavior regresses | Flag default off, static provider, changes limited to listed touch points |
| Package interference within a run (e.g. a dependency bump breaking later fixes) | Accepted for Phase 1; per-package checkpoint option later |
| AMI drifts from what was scanned | Version the AMI, record its id on every lease; Phase 2 replaces it with the client manifest |

## 17. Open questions

1. Tenancy: shared SaaS in our account, or deployed in the client's account? (Management.)
2. Instance type and size for each family; whether image-family fixes need larger disks (Docker
   builds on a 20 GB root volume are tight) [Assumption].
3. TTL for HITL runs.
4. Maximum simultaneous leases.
5. Whether `/agents/trigger` (plain ingest) should be unblocked in the same change. Today it is
   blocked by the same guard [Verified]. Ingest alone does not use the playground.
6. Whether more than one API worker or host is planned. Leases in the DB make it safe either way.
