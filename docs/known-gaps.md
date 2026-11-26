# Known gaps (tracked, not yet fixed)

Items found during the ephemeral playground work. Each is real and verified unless stated. None is
being fixed as part of that work unless it says so. Revisit before the product goes live.

## KG-1: Serverless lab is exploitable as deployed (security)

Status: deferred by the product owner (application is not live yet). No change made.
Found: 2026-11 during the playground spike. Details and evidence: section 18b of
`docs/architecture/ephemeral-playground-design.md`.

What is deployed in the AWS account that also hosts the PROD app, in env1, env2 and env3:
- Lambda role `serverless-lab-vop-vuln-lab-env{1,2,3}-role` trusts `Principal: {"AWS": "*"}` and has
  an admin policy attached (`Action: *`, `Resource: *`).
- Each Lambda has a public Function URL with `AuthType: NONE`.
- The handler runs `pickle.loads` on the request body (`/process`) and `os.system` with a request
  parameter (`/execute`).

Why it matters: unauthenticated code execution with admin credentials in the account.

Where it comes from: `infra/vuln-labs/serverless-lab-template.tf` and
`infra/vuln-labs/serverless-lab/lambda_function.py`, applied by
`infra/vuln-labs/modules/lab-instance/user-data.sh.tpl` and the `/admin/env2/reset-serverless`
endpoint.

Options when revisited (the scanners read source files, not the URL, so these keep them working):
delete the Function URL; set reserved concurrency to 0; restrict the trust principal; run the lab
only in the separate sandbox account; fix the template so new deploys do not recreate it.

Constraint for the playground work: ephemeral playgrounds must not apply this lab as written, and
never in the PROD-hosting account.

## KG-2: Other infrastructure observations (security and hygiene)

- Lab security groups allow SSH from `0.0.0.0/0` (`modules/lab-instance/main.tf`).
- The app host role has `ssm:SendCommand` on `Resource: "*"` (`infra/app-hosting/iam.tf`).
- The lab instance role has `ec2:*` and `kms:*` on `*` (`modules/lab-instance/main.tf`).
- Env3 allows IMDSv1 (a token-less request returned 200).
- A private key file `infra/vuln-labs/env2/vop-vuln-lab-env2-key.pem` exists in the working tree. It
  is gitignored and untracked.

## KG-3: Baseline reset gaps

- `/admin/env2/reset` depends on `main.tf.original`, which `user-data` never creates (on env3 it was
  created by hand).
- Baseline content comes from four places that can drift: heredocs in `main.py`, GitHub `main`, the
  backend's local checkout, and files on the box.
- The infra, java and python Dockerfiles exist only as heredocs, not as files in the repo.

## KG-4: Data issues

- `connection_registry` row `trivy-os-al2-ec2` has `target_instance_id = i-0e374829ec5fc880c`, an
  old env5 instance that no longer exists. Current env5 is `i-0cf480a449cff16a8`. Dev database.
  Part of the playground work.
- `POST /agents/runs/{run_id}/cancel` deletes other users' findings for the same scanner. Part of
  the playground work (design section 18c).

## KG-5: Re-scan configuration and output handling (found during Stage 1)

- The semgrep rule files that SAST and serverless re-scans refer to
  (`/opt/vuln-labs/results/semgrep-rules.yaml`, `serverless-rules.yaml`) are written at runtime by
  `scan-server.py` on the scan source only. Env3 has no `/opt/vuln-labs/results/` directory at all
  (verified). The playground golden image now ships these two files.
- `agent_v2.py` tells the planner to re-scan SAST findings with
  `--config /opt/vuln-labs/appsec-lab/semgrep-rules.yaml`. That path exists on no instance I
  checked, and the scan source writes its rules to `/opt/vuln-labs/results/`. Semgrep also prefixes
  rule ids with the config path (the registry filters use `opt.vuln-labs.results.<rule>`), so a
  re-scan using the appsec-lab path would produce different rule ids. Not yet traced end to end.
- SSM `get_command_invocation` returns only the first 24,000 characters of stdout. Long
  `docker build`, `terraform` or `trivy` output is cut at the end, which is where the verdict
  usually is. `remote_exec.py` does not account for this. Steps that print a lot should log to a
  file and print a short summary.

## KG-6: Playground image follow-ups

- The AMI is unencrypted (matches env1 to env3). Cross-account sharing needs a customer-managed
  KMS key and re-encryption (`--kms-key-id` is supported by the build script).
- The builder and verification clones use env3's broad instance profile. Replace with a minimal
  SSM-only profile for builds and per-lease scoped profiles for playgrounds.
- The Trivy database baked into the image goes stale between rebuilds; Trivy refreshes it on use.