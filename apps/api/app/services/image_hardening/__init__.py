"""Image Hardening service — deterministic, non-agent pipeline.

Takes a base container image, rebuilds it into a hardened minimal image,
scans it (gate), publishes it to a registry, generates an SBOM, and (optionally)
auto-triggers keyless signing + SLSA provenance in GitHub Actions.

ISOLATION: this is a standalone feature. It REUSES the fixer's execution engine
as a library (BaseFixStrategy contract, RemoteExecutor over SSM, and the
family-agnostic result models), but it does NOT go through run_fixer, does NOT
touch issues/remediation_packages/fix_runs, has its own run table
(hardening_runs), its own concurrency lane, and its own non-agent identity.

See .kiro/specs/image-hardening/design.md for the full design + isolation
guarantees.
"""
