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
