# vuln-python-sample — test fixture for the dependency-bump rebuild leg

**This image is deliberately vulnerable. Do not use it for anything real.**

It exists to prove the image-hardening pipeline's **dependency-bump (rebuild)
leg** — the path that remediates language/dependency CVEs that copa (the
OS-package patcher) cannot touch.

## What it demonstrates

- `requirements.txt` pins several pip packages to **old versions with known
  CRITICAL/HIGH CVEs that have fixes available** (`requests`, `urllib3`,
  `jinja2`, `PyYAML`). trivy reports these as fixable `lang-pkgs` / `pip`
  findings.
- The pipeline's `compute_pip_bumps` reads trivy's `FixedVersion` for each and
  deterministically rewrites `requirements.txt` to pin the fixed versions (no
  "latest", no guessing, no LLM).
- `docker build` from this Dockerfile then produces a rebuilt image with the
  dependency fixes applied; the final full-scope gate re-scan verifies.

## How it is used

The pipeline is triggered in `rebuild` mode against the built image, with the
build context pointing at this directory on the build box:

```
/opt/image-forge-src/image-forge/base-images/vuln-python-sample/
```

The OS layer (bookworm) is current/supported, so copa cleans any OS findings
and the DEPENDENCY findings are what the rebuild leg fixes.

## Honest scope

- **pip only** this increment. npm / gomod / gobinary findings are reported as
  residual.
- **Direct, declared** dependencies are bumped. Transitive findings (packages
  not in `requirements.txt`) are reported as residual, not blindly pinned.
