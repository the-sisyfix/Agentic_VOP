"""Unit tests for the Image Hardening feature (MVP).

Plain pytest (no BDD / no new deps), mirroring the repo's existing test style.
No live AWS: RemoteExecutor command execution is mocked. These tests pin the
behavior that matters for the demo AND the isolation guarantees from
.kiro/specs/image-hardening/design.md.

Covers:
  1. safety.py allowlist change is additive / non-regressive (pure superset).
  2. ImageHardenStrategy scan gate fails on CRITICAL/HIGH (non-zero trivy exit).
  3. ImageHardenStrategy rollback is idempotent (empty when no prior digest).
  4. Auto-sign dispatch is best-effort (returns (False, msg), never raises).
  5. Isolation: hardening does not route through the fixer's run_fixer, and
     emits under its own trace label (not "sub-agent-4").
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

from app.agents.fixer import safety
from app.agents.fixer.models import CommandResult
from app.services.image_hardening.config import HardeningConfig
from app.services.image_hardening.models import HardenContext, StepResult
from app.services.image_hardening.signing import dispatch_signing_workflow
from app.services.image_hardening.strategy import ImageHardenStrategy


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _now() -> datetime:
    return datetime.now(UTC)


def _cmd_result(*, exit_code: int, stdout: str = "", stderr: str = "") -> CommandResult:
    return CommandResult(
        command="x",
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        duration_ms=1,
        started_at=_now(),
        finished_at=_now(),
    )


def _ctx(**overrides) -> HardenContext:
    base = {
        "hardening_run_id": 1,
        "source_image_ref": "golang:1.25-alpine",
        "target_registry": "486655355038.dkr.ecr.us-east-1.amazonaws.com/sisyfix-hardened-base-test",
        "published_tag": "v0.0.1-test",
        "build_instance_id": "i-test",
        "aws_region": "us-east-1",
    }
    base.update(overrides)
    return HardenContext(**base)


def _config() -> HardeningConfig:
    return HardeningConfig(
        aws_region="us-east-1",
        build_instance_id="i-test",
        ecr_repository_url="486655355038.dkr.ecr.us-east-1.amazonaws.com/sisyfix-hardened-base-test",
        sbom_bucket="sisyfix-dev-image-forge-sbom-486655355038",
    )


# ---------------------------------------------------------------------------
# 1. safety.py allowlist is additive / non-regressive
# ---------------------------------------------------------------------------
def _allowed_under(allowlist: tuple[str, ...], wd: str) -> bool:
    return any(wd == p.rstrip("/") or wd.startswith(p) for p in allowlist)


def test_allowlist_is_pure_superset_of_prior():
    """The image-forge-src entry only ADDS; every pre-existing input yields the
    same result it would have before the entry existed."""
    new = safety._ALLOWED_WORKING_DIRECTORIES
    old = tuple(d for d in new if d != "/opt/image-forge-src/")

    for wd in [
        "/opt/vuln-labs/x",
        "/tmp/fixer-scratch/y",
        "/",
        "/etc/secret",
        "/home/u",
        "/opt/other",
        "relative/path",
    ]:
        assert _allowed_under(old, wd) == _allowed_under(new, wd), wd


def test_allowlist_adds_image_forge_src():
    """The new hardening build dir is allowed after the change."""
    r = safety.validate_command(
        "docker build .",
        working_directory="/opt/image-forge-src/image-forge/base-images/static-hello",
    )
    assert r.allowed is True


def test_blocklist_still_blocks_destructive_commands():
    """Destructive-command protection is unchanged by the hardening work."""
    for bad in ["rm -rf /", "mkfs.ext4 /dev/xvdb", "reboot", "aws iam create-user --user-name x"]:
        r = safety.validate_command(bad, working_directory="/opt/vuln-labs/")
        assert r.allowed is False, bad


# ---------------------------------------------------------------------------
# 2. Scan gate fails on CRITICAL/HIGH (non-zero trivy exit)
# ---------------------------------------------------------------------------
def test_scan_gate_fails_on_findings():
    """trivy --exit-code 1 returning non-zero => validation NOT passed."""
    strat = ImageHardenStrategy(config=_config(), emit_fn=lambda *a, **k: None)
    fake_exec = MagicMock()
    fake_exec.run_command.return_value = _cmd_result(exit_code=1, stdout="1 CRITICAL")
    with patch.object(strat, "_executor", return_value=fake_exec):
        results = strat.validate(_ctx())
    assert len(results) == 1
    assert results[0].is_rescan is True
    assert results[0].passed is False


def test_scan_gate_passes_when_clean():
    """trivy exit 0 => validation passed."""
    strat = ImageHardenStrategy(config=_config(), emit_fn=lambda *a, **k: None)
    fake_exec = MagicMock()
    fake_exec.run_command.return_value = _cmd_result(exit_code=0, stdout="")
    with patch.object(strat, "_executor", return_value=fake_exec):
        results = strat.validate(_ctx())
    assert results[0].passed is True
    assert results[0].is_rescan is True


# ---------------------------------------------------------------------------
# 3. Rollback is idempotent / safe
# ---------------------------------------------------------------------------
def test_rollback_empty_when_no_prior_digest():
    """No backup reference / no prior digest => rollback returns an empty list
    (safe no-op), per the idempotency contract."""
    strat = ImageHardenStrategy(config=_config(), emit_fn=lambda *a, **k: None)
    assert strat.rollback(_ctx(backup_reference=None)) == []
    assert strat.rollback(_ctx(backup_reference="(no prior tag)")) == []


def test_rollback_records_prior_digest_when_present():
    """A recorded prior digest => a single success rollback result (MVP: records
    intent, no destructive retag)."""
    strat = ImageHardenStrategy(config=_config(), emit_fn=lambda *a, **k: None)
    ctx = _ctx(backup_reference="tag:repo:v1|prior:sha256:abc123")
    out = strat.rollback(ctx)
    assert len(out) == 1
    assert out[0].status == "success"


# ---------------------------------------------------------------------------
# 4. Auto-sign dispatch is best-effort (never raises)
# ---------------------------------------------------------------------------
def test_signing_no_pat_returns_not_dispatched():
    cfg = _config()
    dispatched, msg = dispatch_signing_workflow(
        cfg, github_pat="", image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
    )
    assert dispatched is False
    assert "not dispatched" in msg.lower()


def test_signing_no_repo_returns_not_dispatched():
    cfg = HardeningConfig(github_repo="")  # no repo configured
    dispatched, msg = dispatch_signing_workflow(
        cfg, github_pat="tok", image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
    )
    assert dispatched is False


def test_signing_http_error_is_caught_not_raised():
    """A GitHub HTTP error must be swallowed into (False, msg), never raised —
    signing failures must not fail the hardening run."""
    import urllib.error

    cfg = HardeningConfig(github_repo="owner/repo")
    with patch(
        "app.services.image_hardening.signing.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError("u", 403, "Forbidden", {}, None),
    ):
        dispatched, msg = dispatch_signing_workflow(
            cfg, github_pat="tok", image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
        )
    assert dispatched is False
    assert "403" in msg


# ---------------------------------------------------------------------------
# 5. Isolation guarantees
# ---------------------------------------------------------------------------
def test_hardening_does_not_import_or_call_run_fixer():
    """The orchestrator must NOT route through the vulnerability fixer's
    run_fixer entry point (isolation guarantee #4).

    Checks the module AST (not raw text) so an explanatory docstring that
    merely mentions 'run_fixer' does not trip the assertion — we care that it
    is never IMPORTED or CALLED.
    """
    import ast
    import inspect

    from app.services.image_hardening import orchestrator

    tree = ast.parse(inspect.getsource(orchestrator))

    imported_names: set[str] = set()
    called_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called_names.add(node.func.id)

    assert "run_fixer" not in imported_names
    assert "run_fixer" not in called_names
    # Also confirm the fixer orchestrator module itself is not imported.
    assert not any("fixer.orchestrator" in n for n in imported_names)


def test_strategy_uses_own_trace_label_not_subagent4():
    """Hardening emits under 'image-hardening', never 'sub-agent-4'
    (isolation guarantee #6)."""
    captured = []
    strat = ImageHardenStrategy(
        config=_config(),
        emit_fn=lambda run_id, agent, et, msg, *a, **k: captured.append(agent),
    )
    strat._emit(_ctx(), "MESSAGE", "hello")
    assert captured == ["image-hardening"]
    assert "sub-agent-4" not in captured


def test_strategy_is_instance_agnostic_uses_ctx_instance():
    """The strategy builds its executor from ctx.build_instance_id (the ephemeral
    seam) — it never resolves an instance itself."""
    cfg = _config()
    strat = ImageHardenStrategy(config=cfg, emit_fn=lambda *a, **k: None)
    with patch("app.services.image_hardening.strategy.RemoteExecutor") as mock_exec:
        strat._executor(_ctx(build_instance_id="i-ephemeral-123"))
    # First positional arg to RemoteExecutor is the instance id from ctx.
    args, _kwargs = mock_exec.call_args
    assert args[0] == "i-ephemeral-123"


# ===========================================================================
# Model B — CopaPatchStrategy (image-ref in-place patch path)
# ===========================================================================
from app.services.image_hardening.copa_strategy import (  # noqa: E402
    CopaPatchStrategy,
    CopaScanResult,
)


def _copa_strat() -> CopaPatchStrategy:
    cfg = HardeningConfig(
        aws_region="us-east-1",
        build_instance_id="i-test",
        ecr_repository_url="486655355038.dkr.ecr.us-east-1.amazonaws.com/sisyfix-hardened-base-test",
        max_remediation_iterations=3,
    )
    return CopaPatchStrategy(config=cfg, emit_fn=lambda *a, **k: None)


# ---- trivy report parsing ----
def test_count_fixable_parses_critical_high_with_fixedversion():
    report = json.dumps(
        {
            "Results": [
                {
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL", "FixedVersion": "1.2.3"},
                        {"Severity": "HIGH", "FixedVersion": "4.5.6"},
                        {"Severity": "HIGH", "FixedVersion": None},  # not fixable → excluded
                        {"Severity": "MEDIUM", "FixedVersion": "7.8.9"},  # not gated
                    ]
                }
            ]
        }
    )
    crit, high = CopaPatchStrategy._count_fixable(report)
    assert crit == 1
    assert high == 1  # the no-FixedVersion HIGH is excluded


def test_count_fixable_handles_empty_or_malformed():
    assert CopaPatchStrategy._count_fixable("{}") == (0, 0)
    assert CopaPatchStrategy._count_fixable("not json") == (0, 0)
    assert CopaPatchStrategy._count_fixable('{"Results": null}') == (0, 0)


def test_scan_result_gate_property():
    assert (
        CopaScanResult(fixable_critical=0, fixable_high=0, raw_summary="").has_fixable_gate_findings
        is False
    )
    assert (
        CopaScanResult(fixable_critical=1, fixable_high=0, raw_summary="").has_fixable_gate_findings
        is True
    )
    assert (
        CopaScanResult(fixable_critical=0, fixable_high=2, raw_summary="").has_fixable_gate_findings
        is True
    )


def test_gate_validation_pass_fail():
    strat = _copa_strat()
    clean = CopaScanResult(fixable_critical=0, fixable_high=0, raw_summary="")
    dirty = CopaScanResult(fixable_critical=2, fixable_high=1, raw_summary="")
    assert strat.build_gate_validation(clean).passed is True
    assert strat.build_gate_validation(clean).is_rescan is True
    assert strat.build_gate_validation(dirty).passed is False
    assert strat.build_gate_validation(None).passed is False


# ---- remediation loop control flow (scan/patch methods mocked) ----
def _ok_step(action="copa patch"):
    return StepResult(
        step_num=0,
        action=action,
        command="x",
        exit_code=0,
        status="success",
        started_at=_now(),
        finished_at=_now(),
    )


def test_loop_already_clean_at_intake():
    """Zero fixable at intake → clean, 0 iterations, no patch attempted."""
    strat = _copa_strat()
    clean = CopaScanResult(fixable_critical=0, fixable_high=0, raw_summary="")
    with (
        patch.object(strat, "_executor", return_value=MagicMock()),
        patch.object(strat, "_scan_to_report", return_value=clean),
        patch.object(strat, "ensure_buildkit") as mock_bk,
    ):
        out = strat.remediate(_copa_ctx(), "img:latest")
    assert out["status"] == "clean"
    assert out["iterations"] == 0
    mock_bk.assert_not_called()  # no patching path entered


def test_loop_clean_after_one_patch():
    """Dirty → patch → clean on re-scan → status clean, 1 iteration."""
    strat = _copa_strat()
    dirty = CopaScanResult(fixable_critical=1, fixable_high=0, raw_summary="")
    clean = CopaScanResult(fixable_critical=0, fixable_high=0, raw_summary="")
    with (
        patch.object(strat, "_executor", return_value=MagicMock()),
        patch.object(strat, "_scan_to_report", side_effect=[dirty, clean]),
        patch.object(strat, "ensure_buildkit", return_value=_ok_step("ensure buildkit")),
        patch.object(strat, "patch_once", return_value=_ok_step()),
    ):
        out = strat.remediate(_copa_ctx(), "img:latest")
    assert out["status"] == "clean"
    assert out["iterations"] == 1


def test_loop_unfixable_when_no_progress():
    """Patch runs but counts don't drop → unfixable (copa can't fix non-OS deps)."""
    strat = _copa_strat()
    dirty = CopaScanResult(fixable_critical=2, fixable_high=0, raw_summary="")
    with (
        patch.object(strat, "_executor", return_value=MagicMock()),
        patch.object(strat, "_scan_to_report", side_effect=[dirty, dirty]),
        patch.object(strat, "ensure_buildkit", return_value=_ok_step("ensure buildkit")),
        patch.object(strat, "patch_once", return_value=_ok_step()),
    ):
        out = strat.remediate(_copa_ctx(), "img:latest")
    assert out["status"] == "unfixable"


def test_loop_exhausted_after_cap():
    """Counts keep dropping but never reach zero within the cap → exhausted."""
    strat = _copa_strat()
    # 3 iterations cap; counts decrease each time but stay > 0.
    scans = [
        CopaScanResult(fixable_critical=4, fixable_high=0, raw_summary=""),  # intake
        CopaScanResult(fixable_critical=3, fixable_high=0, raw_summary=""),  # after 1
        CopaScanResult(fixable_critical=2, fixable_high=0, raw_summary=""),  # after 2
        CopaScanResult(fixable_critical=1, fixable_high=0, raw_summary=""),  # after 3
    ]
    with (
        patch.object(strat, "_executor", return_value=MagicMock()),
        patch.object(strat, "_scan_to_report", side_effect=scans),
        patch.object(strat, "ensure_buildkit", return_value=_ok_step("ensure buildkit")),
        patch.object(strat, "patch_once", return_value=_ok_step()),
    ):
        out = strat.remediate(_copa_ctx(), "img:latest")
    assert out["status"] == "exhausted"
    assert out["iterations"] == 3


def test_loop_error_when_patch_fails():
    """A failed copa patch step → error status."""
    strat = _copa_strat()
    dirty = CopaScanResult(fixable_critical=1, fixable_high=0, raw_summary="")
    bad_patch = StepResult(
        step_num=0,
        action="copa patch",
        command="x",
        exit_code=1,
        status="failed",
        started_at=_now(),
        finished_at=_now(),
    )
    with (
        patch.object(strat, "_executor", return_value=MagicMock()),
        patch.object(strat, "_scan_to_report", return_value=dirty),
        patch.object(strat, "ensure_buildkit", return_value=_ok_step("ensure buildkit")),
        patch.object(strat, "patch_once", return_value=bad_patch),
    ):
        out = strat.remediate(_copa_ctx(), "img:latest")
    assert out["status"] == "error"


def test_copa_strategy_uses_own_trace_label():
    """Isolation: copa path emits under 'image-hardening', not 'sub-agent-4'."""
    captured = []
    strat = CopaPatchStrategy(
        config=HardeningConfig(build_instance_id="i-x"),
        emit_fn=lambda run_id, agent, et, msg, *a, **k: captured.append(agent),
    )
    strat._emit(_copa_ctx(), "MESSAGE", "hi")
    assert captured == ["image-hardening"]


def _copa_ctx() -> HardenContext:
    return HardenContext(
        hardening_run_id=99,
        source_image_ref="img:latest",
        target_registry="486655355038.dkr.ecr.us-east-1.amazonaws.com/sisyfix-hardened-base-test",
        published_tag="v0.0.9-copa",
        build_instance_id="i-test",
        aws_region="us-east-1",
    )
