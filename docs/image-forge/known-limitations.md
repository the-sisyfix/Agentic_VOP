# Image Hardening — Known Limitations & Edge Cases

Tracked limitations discovered during development/testing, to be tackled
deliberately in later increments. Each entry states the problem, how it
surfaces, the current behavior, and the candidate fix.

---

## 1. Dependency bump may pin to an UNINSTALLABLE fixed version

**Discovered:** run #15 (vuln-python-sample, dep-bump rebuild leg live test).

**Problem.** `compute_pip_bumps` pins a vulnerable package to the exact
`FixedVersion` that trivy reports — i.e. the *minimal* version that resolves the
CVE. That minimal fixed version is not always installable on the image's Python
runtime, so the rebuild `docker build` (specifically `pip install`) fails even
though the bump was computed correctly.

**Concrete case.** `PyYAML==5.3.1` has CVE-2020-14343 (CRITICAL); trivy reports
`FixedVersion = 5.4`. Our bumper faithfully wrote `PyYAML==5.4`. But PyYAML
versions `> 5.3.1` and `<= 6.0.0` fail to build from source on Python 3.12 with
modern Cython (`AttributeError: 'build_ext' object has no attribute
'cython_sources'`) — there is no 3.12 wheel, and the sdist build is broken. The
CVE is only cleanly fixed AND installable at `PyYAML >= 6.0.1`.

So trivy's minimal fixed version (5.4) is uninstallable; the real usable fix is
6.0.1.

**Current behavior.** The rebuild leg fails at `docker build (rebuild)` with a
pip build error. The run is marked `failed` (honest — we did not produce a
clean image), but the failure is an installability problem, not a bump-logic
problem. The bump computation itself is correct.

**Why it matters.** The "pin to trivy's exact FixedVersion" rule is maximally
deterministic but can select a version that no longer installs. A production
remediation must produce a *buildable* image, not just a theoretically-patched
manifest.

**Candidate fixes (decide later).**
- (a) Pin to `>= FixedVersion` instead of `== FixedVersion`, letting pip pick
  the newest compatible installable version. Trades exact-pin determinism for
  installability. NOTE: this weakens the "fully deterministic" guarantee — needs
  a deliberate decision, since determinism was a hard requirement.
- (b) Keep `==`, but on a build failure, retry with a bounded "walk forward"
  (next known fixed version) — still deterministic (ordered), more robust.
- (c) Verify installability (dry-run `pip install`) during bump computation and
  select the lowest installable fixed version. Most correct, most expensive.

**Status:** DEFERRED. Flagged during the dep-bump live proof; to be tackled as a
dedicated increment. For the green end-to-end proof we use a test package whose
trivy FixedVersion is installable on the base.

---

## 2. Fixed-version selection from a multi-version list is ad-hoc

**Discovered:** run #15 follow-up (while choosing the replacement test package).

**Problem.** trivy's `FixedVersion` can be a comma-separated list spanning
multiple release branches, e.g. for `urllib3` CVE-2023-43804 trivy reports
`FixedVersion = "2.0.6, 1.26.17"`. `compute_pip_bumps` currently does:

```python
fixed_one = fixed.split(",")[0].strip()   # takes the FIRST token as-listed
```

So it pins whatever trivy listed first — here `2.0.6` (a major 1.x -> 2.x jump),
NOT the minimal same-line patch `1.26.17`, and NOT the "latest". The selection
is ordering-dependent and arbitrary.

**Two defects:**
- The inline comment claims "take the first (lowest fixed)", but the first token
  is NOT guaranteed to be the lowest — trivy ordered this list `2.0.6, 1.26.17`
  (higher branch first), so "first" = higher, contradicting the comment.
- Neither a principled "minimal compatible" nor "latest" strategy is actually
  implemented — it is incidentally whatever trivy printed first.

**Why it matters.** The chosen fixed version drives both the compatibility risk
(a major jump like 1.x -> 2.x can break the client's app) and installability
(ties into limitation #1). "Harden without breaking" argues for the minimal
same-line bump (`1.26.17`); "fix the most" argues for the latest. This is a
product decision, currently made implicitly and incorrectly by `split(",")[0]`.

**Candidate strategies (decide later, together with #1):**
- Minimal same-major bump: prefer the lowest fixed version on the SAME major/
  minor line as the installed version (least breaking).
- Latest fixed: newest version in the list (fixes the most, higher risk).
- Installability-aware: among fixed candidates, pick the lowest that installs
  (ties #1 and #2 together — likely the right combined answer).

At minimum, replace `split(",")[0]` with an explicit, documented ordering
(sorted by a real version comparison) so behavior is not trivy-ordering-
dependent.

**Status:** DEFERRED. To be decided together with limitation #1 — both are
"how do we choose the correct fixed version" problems. For the green proof, the
current behavior pins `urllib3==2.0.6` (first token), which we verified installs
cleanly on Python 3.12, so the demo run is unaffected.

**Update (run #16).** In the live green run the package had 7 findings and the
bumper's "highest FixedVersion across findings" aggregation (`_highest_version`)
selected `urllib3==2.8.0` — higher than any single finding's first-listed token.
So the `split(",")[0]` concern was masked by the cross-finding aggregation here,
but the underlying ad-hoc selection remains and should still be made principled.

---

## 3. Rebuild leg mutates requirements.txt in the git working tree

**Discovered:** run #15 / before run #16 (box `git pull` was blocked).

**Problem.** The dependency-bump leg rewrites `requirements.txt` IN PLACE inside
the build context — which, on the build box, is a checked-out git working tree
(`/opt/image-forge-src/...`). After a rebuild run the tree is dirty, so the next
`git pull` on the box aborts with "local changes would be overwritten".

**Current behavior / workaround.** Manually discard the pipeline's edit before
pulling:
`git checkout -- image-forge/base-images/<sample>/requirements.txt` then pull.
Acceptable for the test fixture, NOT acceptable for a production client build.

**Why it matters.** In production the build context is the client's source, not
a repo we pull — but we still should not mutate the caller's working tree as a
side effect. It is surprising and leaves dirty state.

**Candidate fixes (decide later).**
- Copy the build context to an ephemeral scratch dir and bump/build THERE,
  leaving the original untouched.
- Build from a temp requirements file passed via build-arg / `-f`, not an
  in-place rewrite.
- (Test-box only) have the pipeline `git stash`/reset the fixture before build.

**Status:** DEFERRED. Prefer the "build in an ephemeral copy" approach — it also
aligns with the future ephemeral-build-box model.

---

## 4. Rebuild leg collapses a multi-architecture image to arm64-only

**Discovered:** run #16 (confirmed in the ECR console — the published Image Index
had one real platform: `arm64/linux`, plus the buildkit attestation manifest
shown as `unknown/unknown`).

**Problem.** The build box is arm64 (Graviton). The dependency-rebuild leg runs a
plain `docker build`, which produces a SINGLE-architecture (arm64) image. If the
client's original image was multi-platform (e.g. amd64 + arm64), the rebuilt
image drops every architecture except arm64.

**Why it matters.** For a real client this is a silent regression: their amd64
workloads would have no image. The dependency-fix path specifically narrows the
platform set; the copa (OS) path can be made multi-platform-aware separately.

**Candidate fixes (decide later — part of the multi-arch milestone).**
- `docker buildx build --platform linux/amd64,linux/arm64 --push` (needs QEMU or
  native amd64 build capacity on the build box).
- A per-architecture build matrix (arm64 on Graviton, amd64 on an amd64 runner),
  then assemble a manifest list.

**Status:** DEFERRED — part of the broader multi-arch milestone (the copa path is
also arm64-only today). Known and accepted for the current single-arch MVP.

---

## 5. cosign verify-attestation hangs on GitHub-hosted runners (large payload)

**Discovered:** runs #17/#18/#19 (auto-sign signing workflow on a multi-arch
image).

**Problem.** `cosign verify-attestation` prints the verification RESULT and then
STREAMS the full verified predicate to stdout. For our hardened images the SBOM
attestation predicate is large (~2.6 MB SPDX; the `.att` artifact in ECR is
~3.6 MB). On GitHub-hosted runners, streaming that large payload through the
Actions log pipe HANGS the step indefinitely — observed hanging 19-23 min and
requiring manual cancellation, even though verification itself had already
succeeded (the "verified using trusted certificate" line prints first).

**Not cosign, not our code, not `timeout`.** The identical command exits `0` in
seconds on the build box (verified: `EXIT=0`). `timeout --kill-after` did NOT
reap it on the runner. So it is a GitHub-hosted-runner stdout/log-collector
artifact specific to large cosign payloads — not reproducible off the runner.

**Current behavior (MVP decision).** The signing workflow (`image-sign.yml`)
now verifies the SIGNATURE ONLY in-workflow (`cosign verify` — small payload,
reliable) and DOES NOT verify the SLSA/SBOM attestations there. The attestations
are still SIGNED + ATTACHED in ECR (the `.att` artifact); verifying them is the
CONSUMER's job at pull/deploy time. The workflow Summary documents the
consumer-side `cosign verify-attestation` command. (See the "Verify signature"
step comment in image-sign.yml.)

Why this is acceptable for the MVP: the signer's job is to sign + attest +
publish. Re-verifying its own attestation in-workflow is a redundant self-check;
real verification belongs downstream (deploy pipeline / admission control), and
we have no clients with a verification flow established yet.

**Candidate enhancements (later, when a consumer-side flow exists).**
- Verify attestations off the GitHub-hosted runner (e.g. on the build box, where
  the same command exits cleanly) or on a self-hosted runner.
- Suppress/bound cosign's payload output so the runner never has to drain it
  (e.g. output flags / pipe to a bounded reader), then re-enable strict
  in-workflow attestation verification.
- Move verification to a dedicated consumer-side step / admission controller —
  the architecturally correct home for it.

**Status:** DEFERRED. Signature verified in-workflow; attestation verification
deferred to consume-time. A1 (auto-sign) proven end-to-end in run #20 (workflow
completed green).
