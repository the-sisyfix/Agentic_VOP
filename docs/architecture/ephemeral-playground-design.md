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

## 3a. Decisions recorded (rev 2)

| Topic | Decision |
|---|---|
| Max simultaneous playground leases | 5 (configurable) |
| Plain ingest (`/agents/trigger`) | Unblocked. It never uses a playground, so it is removed from the guard |
| HITL runs | No instance is created at trigger. The lease is created on the first approval that dispatches a fix |
| SA-3 file reads | Read from a read-only baseline instance (the existing static instance, which stops receiving fixes in ephemeral mode), not from a lease |
| Playground contents | Only the labs needed by the scanners in the run (section 9a) |
| Sandbox account | A separate AWS account, not an IAM user in the current account (section 10) |
| Pilot scope | Dev Supabase project and current branch only; flag defaults to off |
| HITL idle timeout | 30 minutes after the last fix (initial value) |
| Capacity full at trigger | Reject immediately with a clear message (nothing has been spent yet) |
| Capacity full at approve | Queue: the approval is kept and the fix starts when a slot frees (section 8) |
| Account for the pilot | Current account, dev area, same tagging and quotas; sandbox account later (config only) |
| SA-3 baseline source | Behind a `BaselineReader` seam; static instance first, replaced later (section 6a) |

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
   SA-3  -> baseline reader instance (read-only file reads, no lease)
   SA-4  -> TargetResolver.for_run(run_id) -> leased instance_id   (fix lifecycle)
                         |
   fix stage done / all packages terminal / idle timeout / TTL  ->  PlaygroundService.release(run_id)

   (HITL pre-approval runs: the acquire step happens at the first approve, not at trigger.)
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

## 6a. Baseline reader seam: how the static instance goes away

Using the static instance as SA-3's baseline is a bridge, not the end state. To keep it from
spreading, SA-3's file reads go through one interface and the static instance is just the first
implementation.

`BaselineReader.read(path, run_context) -> (content, content_hash)`

| Implementation | Source | When |
|---|---|---|
| `StaticInstanceReader` | SSM `cat` on the baseline instance (today's `file_fetch` behavior) | Phase 1, flag on or off |
| `RepoAtCommitReader` | The replica source repo at a pinned commit (the demo client repo, GitHub API or a shallow clone) | When the client repo exists (Stage 6) |
| `ManifestReader` | Same, driven by the build manifest of the scanned build | With real client CI/CD |

Only `file_fetch.py` (and the two callers that pass `target_instance_id=None`) changes to use the
seam. `PLAYGROUND_MODE=static` is itself a temporary compatibility flag. The retirement plan:

1. Stage 2: introduce the seam with `StaticInstanceReader`.
2. Stage 6: the demo client repo and manifest exist; the golden AMI is built from the same commit,
   so the repo content is what the replica contains. Switch the reader to `RepoAtCommitReader`.
3. After one release cycle on the new reader: delete `StaticInstanceReader`, the static provider,
   `FIXER_ENV2_INSTANCE_ID` as a planning input, and the `static` mode of the flag. The old
   env2/env3 instances are then used only as an AMI build source, or destroyed.

Safety net that makes switching readers low-risk: SA-3 records the hash of every file it read, and
SA-4 verifies it against the file on the leased instance before the first edit. A mismatch fails
fast with a clear message instead of producing a bad edit.

Two problems to resolve in Stage 2, whichever reader is used:
- **Per-lease names inside files.** `cspm-lab-template.tf` and `serverless-lab-template.tf` embed
  the instance `name_prefix` in resource names [Verified], and SA-3 composes `#EDIT_FILE old_text`
  verbatim from the file it read [Verified in `agent_v2.py` prompts]. If a leased instance has a
  different prefix from the baseline, an edit whose `old_text` contains a name will not match, and
  a plain content hash will differ for every IaC file. Fix: derive the lease `name_prefix`
  deterministically from the run id before planning, render the baseline with that prefix, and
  compute the hash over content normalized for the prefix.
- **Files not in the repo.** The infra, java and python Dockerfiles exist only as heredocs in
  `user-data.sh.tpl` and in the `/admin/env2/reset-images` script [Verified], not as files in
  `infra/vuln-labs`. A repo-based reader needs them committed (the demo client repo covers this).

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

SA-3 does not need a lease. It reads target files from the read-only baseline instance, so planning
can run in parallel for any number of runs. A lease is needed only when SA-4 will actually fix.

**Automatic pipelines** (`trigger_demo`, `trigger_demo_hitl_review`, `trigger_demo_hitl_verified_pr`):
1. **Acquire** at trigger: insert a lease (`provisioning`) and launch asynchronously. Ingest, SA-1,
   SA-2 and SA-3 run while the instance boots, which hides most of the boot time.
2. **Ready gate**: before the fix stage, wait until the lease is `ready`: instance running, SSM
   agent `Online`, health probe passes (the selected lab files are present). On timeout the run
   fails with a clear message and the lease is released.
3. **Use**: SA-4 uses the leased instance. Runs on different leases do not block each other.
4. **Release**: after the fix stage (and, for the review and Verified-PR variants, after the
   post-fix human review is finished or the TTL passes). Release runs teardown (section 9), then
   terminates the instance.

**HITL pre-approval pipeline** (`trigger_demo_hitl`): SA-3 packages land as `awaiting_approval`
and SA-4 does not run until a human approves.
1. No lease at trigger.
2. The first approve call acquires the lease for that run and waits for it to be ready (this adds
   boot time after the click; show "preparing playground" in the UI).
3. Later approvals of packages from the same run reuse the lease.
4. Release when every package of the run is terminal, or after an idle timeout since the last
   fix (not a long absolute TTL). This avoids paying for an idle instance while people decide.

**Capacity full on approve: queue, do not ask the user to retry.** An approval is a durable human
decision; making the user click again loses it and invites duplicate clicks. The approve endpoint
already hands the fix to a background task, and `run_fixer` today already waits for the lock for
up to 30 minutes [Verified], so queuing keeps the current model: the task waits for a free lease
slot (polling the DB), the package shows "waiting for playground", and the fix starts when a slot
frees. Two costs to handle in Stage 3: a waiting task holds a worker thread, and an API restart
would drop the in-memory wait, so a recovery sweep must re-dispatch packages left in
`ready_for_execution` with no fix run. **At trigger time, capacity full is rejected** instead of
queued, because nothing has been spent yet and the user can simply try again.

**TTL**: every lease has `expires_at` as a hard ceiling to stop leaks. For the HITL case the idle
timeout is the practical limit (open question 3).

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

## 9a. Lab profiles: provision only what the run needs

A playground should contain only the system under test for the scanners in the run. Reasons:
faster and cheaper boot, no unrelated cloud resources created, and least privilege (an appsec
replica needs no AWS permissions at all).

Scanner-to-lab mapping (from the scan server paths [Verified in `scan-server.py`] and the path
logic in `planner._extract_iac_context` [Verified]):

| Scanner (source) | Lab on the instance | Cloud resources? | Instance permissions needed |
|---|---|---|---|
| semgrep, trivy-fs | appsec-lab | No | None beyond SSM |
| checkov | cspm-lab | Yes | S3, EC2 SG, KMS, IAM policy, logs, SNS, SQS (scoped to `cspm-lab-<prefix>*`) |
| serverless semgrep | serverless-lab | Yes | IAM role/policy and Lambda scoped to `serverless-lab-<prefix>*` |
| trivy-image (infra, java, python, php) | image labs, one image each | No | Docker only |
| trivy-os (env1/2 style) | the host itself | No | None beyond SSM |

A run's profile is the union of the labs for its selected scanners (`payload.targets.scanners`).

Mechanism for Phase 1: one golden AMI that already contains all lab files and the pre-built
Docker images (cheap, they are just disk). A first-boot step activates only the profile:
- Cloud labs (CSPM, serverless) are applied with Terraform only if they are in the profile. This
  also removes the biggest boot-time risk for runs that don't need them.
- The instance profile is chosen from the profile. Runs without a cloud lab get an instance role
  with SSM only.

Later, with the client-manifest source (Phase 2), each replica is built from the client's own
artifacts for that family, so per-lab AMIs or builds follow naturally.

A run with several scanners (for example appsec plus CSPM) gets one instance with both labs. Fixes
on one instance still run one at a time, as today.

Note: the OS-package scanners in the existing `-ec2` flow fix the host itself. Whether an
ephemeral instance gives a faithful host replica depends on the AMI baseline matching what was
scanned (the OS track is separate and undecided).

## 10. Security model

**Separate AWS account means a different AWS account ID, not an IAM user.** An IAM user in the
current account is only another login. It shares the account's quotas, billing, resource
namespace and blast radius, so a bad IAM policy or a leaked resource still lands next to the
product. A separate account (created under AWS Organizations, with its own root email) is a hard
boundary: the playground's mistakes and costs cannot touch product resources, and it can have its
own quotas and budget alerts.

Cross-account access model: the backend assumes a narrowly scoped role in the sandbox account
(`sts:AssumeRole`) and uses that session for EC2 and SSM calls. The sandbox account owns the
instances, the AMI (shared from a build account or copied), and the playground state buckets.
Today the backend builds plain boto3 clients with default credentials [Verified in
`remote_exec.py` and `main.py`], so the cross-account switch adds one more touch point: a client
factory that returns the assumed-role session.

For the pilot, the account is a configuration value (role ARN, region, subnet, AMI id), so the
code does not change when the account is created. Until then the pilot can run in the dev
environment of the current account with the same tagging and quotas.

Other rules that apply from Phase 1:

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

1. `main.py`: `_guard_env2_free_for_trigger()`. When flag is on: remove it from `/agents/trigger`
   (ingest never uses a playground), and in the demo triggers replace the global busy check with
   the capacity check (max 5 leases). Start the lease in the demo trigger background functions
   (automatic variants) or in the approve endpoint (HITL pre-approval variant).
2. `fixer/orchestrator.py`: resolve the target via `TargetResolver`. Make `_ENV2_DISPATCH_LOCK`
   per-instance (a dict of locks keyed by instance id). Scope the wait loop.
3. `fixer/persistence.py`: `any_concurrent_run(sb, target_instance_id=None)`. With no argument,
   behavior is unchanged.
4. `remediation/tools/file_fetch.py` callers (`agent_v2.py`, `kb_replay.py`): they currently pass
   `None` (falls back to `FIXER_ENV2_INSTANCE_ID`). In ephemeral mode that value becomes the
   read-only baseline instance, so no code change is needed there, but the static instance must
   stop receiving fixes and be kept at the pristine baseline. Retry planning after earlier fixes
   in the same run reads the baseline, not the fixed state; check that this is acceptable in
   Stage 2.
4b. A client factory for EC2 and SSM (used by `remote_exec.py`, the playground service and the
   reset endpoints) so the sandbox-account role can be assumed. Default returns today's client.
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

0. Parallel safety outside the playground (found while reviewing the pipeline, to verify in
   Stage 3):
   - Demo sampling is scoped to the triggering run when `real_run_id` is passed [Verified in
     `sample_from_real.py`], so parallel runs do not mix issues.
   - `connection_registry.last_fetched_at` is a per-scanner watermark shared by all runs
     [Verified in `sub_agent_1.py`]. For connectors that apply it (dependabot, osv, tenable
     [Verified]) two parallel runs of the same scanner can see different data. The `user_endpoint`
     connector ignores it [Verified: parameter unused]. Whether the `-ec2` scan-server scanners use
     `user_endpoint` is unconfirmed: their registry rows are not in the migrations, they live only
     in the database. Check the `connector_type` of those rows in dev.
   - The run-cancel endpoint (`main.py` around line 2780) deletes ALL `issues` and `raw_findings`
     for each scanner of the cancelled run, and resets that scanner's watermark [Verified]. With
     parallel users, cancelling one run deletes another user's findings for the same scanner.
     It needs to delete only rows with `agent_run_id` = the cancelled run.
   - The demo schema is shared; `POST /agents/demo/reset` wipes it for everyone [Verified]. Demo
     data is not scoped per user, and the UI shows demo packages cumulatively.
   - `remediation_kb` counters (`times_reused`, `times_succeeded`) are read-modify-write [Verified
     in `kb_capture.py`], so parallel fixes can lose increments. Best-effort, low impact.
   - LLM rate limits: each run uses up to `LLM_PARALLEL_WORKERS` (default 5) concurrent calls
     [Verified in config], so 5 parallel runs can reach 25 concurrent calls.
1. Tenancy: shared SaaS in our account, or deployed in the client's account? (Management.)
2. Instance type and size for each family; whether image-family fixes need larger disks (Docker
   builds on a 20 GB root volume are tight) [Assumption].
3. (Decided) Idle timeout for HITL leases after the last fix: 30 minutes to start.
4. (Decided) Maximum simultaneous leases = 5.
5. (Decided) Plain ingest is unblocked.
6. Whether more than one API worker or host is planned. Leases in the DB make it safe either way.
7. (Decided) Capacity full on approve: queue. At trigger: reject.

---

## 18. Spike results (executed)

Run from a developer machine with AWS CLI access to account 486655355038, us-east-1. Only dev
playground env3 (`i-01d2c874fe4092e2f`) was read (SSM read-only commands). Nothing was changed on
env3, env2 or any other existing instance. All spike resources were tagged
`Component=playground-spike` and removed at the end; a leftover check returned nothing, and env3
was still running.

What was done: no-reboot AMI of env3, one clone launched from it (no user-data, no SSH ingress,
IMDSv2 required, public IP only for SSM egress, env3's instance profile), probes over SSM, the real
`RemoteExecutor`, `file_ops` and `safety` modules driven against the clone, a plan-only Terraform
test with a rewritten prefix and state key, then full teardown.

| Question | Result |
|---|---|
| Does a clone register with SSM and pass the lab probe? | Yes. Running after 11 s, SSM `Online` after 58 s. Labs, Docker images and scanners (terraform 1.7.5, docker 26.1.3, trivy 0.76.2, checkov 3.2.477, semgrep 1.99.0) were all present |
| Does cloud-init re-run the original user-data on the clone? | No. A new instance directory was created and no terraform or docker build processes ran. `SETUP_COMPLETE` kept the original Nov 9 timestamp |
| Per-command SSM round trip | About 2.5 s for a trivial command |
| Do the real fixer primitives work unchanged against the clone? | Yes: `is_reachable`, `file_exists`, `backup_file`, the safety validator (allows a benign `sed`, blocks `reboot`), a Trivy FS rescan of appsec-lab (35 s, DB cached, 141 findings) and a cached `docker build` (3 s). I did not run `run_fixer` itself (needs Supabase and the LLM) |
| Prefix and state-key rewrite | Works. Replacing `vop-vuln-lab-env3` with a new prefix in a copy of `main.tf.original` and `backend.hcl` gave a clean plan of 8 resources to add with unique names (for example `cspm-lab-spike-i0240c877-bucket`). Init 40 s with the plugin cache copied, plan 6 s. env3's real state object was untouched and nothing was written under the new key |
| IMDSv2 enforced | Works. IMDSv1 returned 401 on the clone; SSM and the AWS CLI still worked. env3 itself still allows IMDSv1 (returned 200 without a token) |
| Quota | 256 standard vCPUs available. Five `t3.small` instances use 10 |
| AMI creation time | Snapshot of the 20 GB root volume took more than 16 minutes before the AMI became available. This is a build-time cost, not a per-run cost |

Not tested: a real `terraform apply` and destroy of the cloud labs (boot-time impact of the CSPM and
serverless labs is therefore still unmeasured), two clones running at the same time, an end-to-end
`run_fixer`, tag-conditioned SSM IAM, private-subnet operation (SSM needs a path out: I used a public
IP with no ingress; a private subnet would need VPC endpoints or NAT), and the serverless lab plan.

### Findings that change the plan

1. **A snapshot of a used instance is not a clean baseline.** Env3 currently has a modified
   `main.tf` (6402 bytes vs 6126 in `main.tf.original`), 7 `main.tf.bak-*` files, `.bak` files in
   the appsec, infra and serverless labs, a `vuln-lab-image:pre-fix-21` image and dangling images.
   The golden AMI must be built from clean source (the repo, or a freshly built instance), never
   by snapshotting env2 or env3. Stage 1 is updated accordingly.
2. **`main.tf.original` exists on env3, but it was created by hand** (root-owned, Nov 10), not by
   `user-data`. The `/admin/env2/reset` endpoint depends on it. The golden AMI build must create
   it.
3. **The clone inherits env3's IAM role** (`vop-vuln-lab-env3-role`), and therefore its access to
   env3's Terraform state prefix and the `ec2:*` and `kms:*` rights. Per-lease instance profiles
   with scoped permissions (section 9a and 10) are required, not optional.
4. **Disk is tight.** The root volume is 20 GB, 51 to 67 percent used on a lab that has few images.
   Docker builds and multiple lab images need a larger root volume in the golden AMI.
5. **Boot is no longer the main time risk.** Clone to SSM-ready is about a minute. The remaining
   unknown is the real Terraform apply of the cloud labs, which the lab profile design already
   makes optional.
6. **Registry data check** (from the `connection_registry` rows provided):
   - Every `-ec2` scanner uses `connector_type: user_endpoint`, which ignores the watermark
     [Verified in code], so the watermark concern does not apply to them.
   - `trivy-os-al2-ec2` has `target_instance_id: i-0e374829ec5fc880c`, which does not appear among
     the instances in this account and region (env4 is `i-0a36547952c4eff35`, env5 is
     `i-0cf480a449cff16a8`). The OS-track target is either stale or in another account or region.
     Fixes for that scanner would fail pre-flight until the value is corrected.
   - All other scanners have no `target_instance_id`, so they use `FIXER_ENV2_INSTANCE_ID`.
   - The scan-server endpoints use public IPs (`35.173.249.140` for env1,
     `18.213.193.246` for env4). The workflow notes that the public IP changes after a stop and
     start.

### 18a. CSPM apply/destroy measurement and decisions (executed)

Method: ran in a temporary directory on idle dev env3 (no processes, load 0.00 before starting),
copying `main.tf.original` with prefix `spike-apply1` and its own state key. No file under
`/opt/vuln-labs` and no env3 state object was touched. All resources were destroyed in the same
script, the spike state object and its lock entry were removed, and a verification from the CLI
afterwards found no remaining spike resources.

| Step | Time |
|---|---|
| `terraform init` (plugin cache copied) | 11 s |
| `terraform apply` (8 resources) | 34 s |
| `terraform destroy` | 9 s |

Conclusions:
- The CSPM lab is not a boot-time problem. About 45 s to create and 9 s to destroy. The decision
  "apply cloud labs lazily, only when the run needs them" is still right for cost and exposure, but
  it is no longer needed for speed.
- Unique-prefix creation and teardown work end to end with the existing lab role. The bucket had
  Block Public Access enabled by default and no bucket policy.
- One KMS key now sits in 7-day pending deletion (`deletion_window_in_days = 7` in the template).
  Five keys with the lab description are already pending from earlier resets, so every create and
  destroy cycle leaves a pending key. This is a cost and noise item, not an exposure.
- The lab role cannot call `iam:ListPolicies`, so a teardown verifier needs to look resources up by
  exact name, not by listing.
- I did not apply the serverless lab (see 18b).

### 18b. Security finding: the existing serverless lab is exploitable (DEFERRED, tracked as KG-1 in docs/known-gaps.md)

Read-only checks on the live account confirmed that env1, env2 and env3 each run the serverless lab
as written in `serverless-lab-template.tf`:

- The Lambda role trust policy is `Principal: {"AWS": "*"}` and the role has a policy attached with
  `Action: "*"` on `Resource: "*"` (admin).
- Each Lambda has a public Function URL with `AuthType: NONE`.
- The handler's `/process` route runs `pickle.loads` on the request body, and `/execute` calls
  `os.system` with a request parameter [Verified in `lambda_function.py`].
- Role names are predictable (`serverless-lab-vop-vuln-lab-env{1,2,3}-role`) and the account id
  appears in resource names in this repo.

Consequence: an unauthenticated caller who can reach those URLs can run code with admin
credentials in account 486655355038, which also hosts the PROD app. Separately, any AWS principal
that is allowed `sts:AssumeRole` in its own account can assume the role. I have not tested either
path (no exploitation attempted); the configuration above is what I verified.

This is existing infrastructure, not part of the new design, but it affects the design directly:
- The ephemeral playground must not apply this lab as written, and must never apply it in the
  PROD-hosting account. This strengthens the case for the separate sandbox account.
- For serverless findings, the Phase 1 proof should be static (plan, Checkov and Semgrep re-scan,
  unit test of the handler) and the replica should not deploy a public URL or a wildcard-trust role.
- The deployed copies in env1/env2/env3 should be restricted regardless of this project. Options
  that keep the scanners working (they scan source files, not the URL): delete the Function URL,
  set reserved concurrency to 0, or change the trust principal. Any of these is a change to
  existing resources, so none was made.

### 18c. Added to scope (decided)

1. Fix `POST /agents/runs/{run_id}/cancel`. It deletes every `issues` and `raw_findings` row for
   the run's scanners and resets the scanner watermark, so cancelling one run removes other users'
   data. It must delete only rows whose `agent_run_id` equals the cancelled run. [Verified in code]
   Pitfall to check in Stage 3: other rows reference `raw_findings`/`issues` (packages, fix runs),
   so the delete order and foreign keys need review.
2. The `trivy-os-al2-ec2` registry value `target_instance_id = i-0e374829ec5fc880c` refers to an old
   env5 instance that no longer exists (confirmed by the owner). The current env5 instance in this
   account is `i-0cf480a449cff16a8`. Correcting it is a database update. The rows are in the dev
   database (confirmed by the owner). No update has been made yet; it is part of the implementation.

