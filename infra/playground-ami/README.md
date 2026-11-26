# Playground golden image (Stage 1)

Builds the AMI that ephemeral remediation playgrounds are launched from. Design and background:
[`docs/architecture/ephemeral-playground-design.md`](../../docs/architecture/ephemeral-playground-design.md).

Nothing here changes env1 to env5, `user-data.sh.tpl`, or any running application code. The
script creates a temporary builder instance, turns it into an AMI, and deletes the builder.

## Profile: `ubuntu2004-labs`

Starts from the same frozen Ubuntu 20.04 base AMI as env1, env2 and env3
(`ami-0dba2cb6798deb6d8`), so the host package baseline matches the scan source.

| Included | Notes |
|---|---|
| appsec lab | `/opt/vuln-labs/appsec-lab` (SAST and SCA scanners) |
| CSPM lab template | `/opt/vuln-labs/cspm-lab/main.tf.template`, not applied. Rendered per lease by `activate.sh` |
| image labs | infra, java, python, php, built as `vuln-*-image:latest` |
| scanners | trivy, semgrep, checkov (versions pinned in `guest/bake.sh`), terraform, aws cli, docker |
| re-scan rules | `/opt/vuln-labs/results/semgrep-rules.yaml` and `serverless-rules.yaml`, extracted from `scan-server.py` at the same commit |
| `/opt/playground/` | `activate.sh`, `MANIFEST.json` (commit, tool versions, images, disk) |

Not included: the serverless lab (public admin Lambda, see `docs/known-gaps.md` KG-1), any `.bak`
file, any applied cloud resource, any Terraform state.

## Build

Prerequisites: AWS credentials for the target account, the backend venv (has boto3), and the lab
files committed and pushed (the builder downloads them from GitHub at one pinned commit).

```
cd <repo root>
apps/api/.venv/Scripts/python infra/playground-ami/build_ami.py build \
    --instance-profile <profile with SSM access> \
    --publish-param /sisyfix/dev/playground/ami/ubuntu2004-labs/latest
```

What it does: checks the commit is pushed and the tree is clean, launches a builder (no ingress,
IMDSv2 required, tagged `Project=sisyfix`, `ExpiresAt`), waits for SSM, runs `guest/bake.sh`,
creates the AMI (about 15 to 20 minutes, the instance reboots for a consistent snapshot), tags the
AMI and snapshot, optionally publishes the AMI id to an SSM parameter, and deletes the builder and
its security group.

Options worth knowing: `--volume-gb` (default 20, same as env1 to env5), `--min-free-gb` (the bake
fails if less is free afterwards), `--kms-key-id` (encrypt with a customer-managed key; needed
before sharing the AMI with another account), `--keep-builder` (skip the snapshot and leave the
baked builder for inspection; you must delete it).

## Verify

```
apps/api/.venv/Scripts/python infra/playground-ami/build_ami.py verify --ami <ami-id> \
    --instance-profile <profile> \
    --state-bucket sisyfix-terraform-state-486655355038 --lock-table sisyfix-terraform-locks
```

Launches a clone, runs `guest/verify.sh` (files, tools, services, images, rule files, free disk,
scanner smoke tests, and an activation test that only runs `terraform init` and `plan`), prints
PASS or FAIL per check, and deletes the clone.

## Activation (what a lease runs at start)

```
/opt/playground/activate.sh --prefix <unique-lease-prefix> --labs cspm \
    --state-bucket <bucket> --lock-table <table> [--apply]
```

Renders the CSPM template with the prefix (every real AWS name becomes unique to the lease), saves
`main.tf.original`, writes a `backend.hcl` with a state key unique to the lease, and runs
`terraform init`. `--apply` creates the lab resources. Re-running with the same prefix is safe;
a different prefix is refused.

## Known limits

- The builder uses an existing instance profile. Per-lease scoped profiles come in a later stage.
- Without `--kms-key-id` the image is unencrypted, matching env1 to env3 today.
- The Trivy database baked into the image goes stale; Trivy refreshes it on first use.
- The image Dockerfiles pin old base images and package versions on purpose. A rebuild can fail
  if an upstream mirror drops a pinned version; the bake fails loudly in that case.
