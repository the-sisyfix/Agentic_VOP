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

import pytest

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
def test_signing_no_auth_returns_not_dispatched():
    # repo set but NEITHER github-app nor pat configured → skip gracefully.
    cfg = HardeningConfig(github_repo="owner/repo")
    dispatched, msg = dispatch_signing_workflow(
        cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
    )
    assert dispatched is False
    assert "not dispatched" in msg.lower()


def test_signing_no_repo_returns_not_dispatched():
    cfg = HardeningConfig(github_repo="", github_pat="tok")  # no repo configured
    dispatched, msg = dispatch_signing_workflow(
        cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
    )
    assert dispatched is False


def test_signing_http_error_is_caught_not_raised():
    """A GitHub HTTP error must be swallowed into (False, msg), never raised —
    signing failures must not fail the hardening run."""
    import urllib.error

    cfg = HardeningConfig(github_repo="owner/repo", github_pat="tok")
    with patch(
        "app.services.image_hardening.signing.urllib.request.urlopen",
        side_effect=urllib.error.HTTPError("u", 403, "Forbidden", {}, None),
    ):
        dispatched, msg = dispatch_signing_workflow(
            cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
        )
    assert dispatched is False
    assert "403" in msg


def test_signing_prefers_github_app_over_pat():
    """When App creds are configured, the App token is minted + used (not PAT)."""
    cfg = HardeningConfig(
        github_repo="owner/repo",
        github_app_id="5408664",
        github_app_installation_id="173694041",
        github_app_private_key_secret_arn="arn:aws:secretsmanager:...:secret:x",
        github_pat="legacy-pat",
    )
    captured = {}

    class _Resp:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=30):
        captured["auth"] = req.get_header("Authorization")
        return _Resp()

    with (
        patch(
            "app.services.image_hardening.signing.get_installation_token",
            return_value=("app-inst-token", None),
        ),
        patch(
            "app.services.image_hardening.signing.urllib.request.urlopen",
            side_effect=_fake_urlopen,
        ),
    ):
        dispatched, msg = dispatch_signing_workflow(
            cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
        )
    assert dispatched is True
    assert "github-app" in msg
    # The App installation token was used as the Bearer credential, not the PAT.
    assert captured["auth"] == "Bearer app-inst-token"


def test_signing_app_failure_does_not_fall_through_to_pat():
    """If the App is configured but token minting fails, we report the App error
    and do NOT silently use the PAT (that would mask a misconfiguration)."""
    cfg = HardeningConfig(
        github_repo="owner/repo",
        github_app_id="5408664",
        github_app_installation_id="173694041",
        github_app_private_key_secret_arn="arn:...:secret:x",
        github_pat="legacy-pat",
    )
    with patch(
        "app.services.image_hardening.signing.get_installation_token",
        return_value=(None, "Secrets Manager get_secret_value failed: AccessDenied"),
    ):
        dispatched, msg = dispatch_signing_workflow(
            cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
        )
    assert dispatched is False
    assert "github-app auth failed" in msg


def test_signing_falls_back_to_pat_when_app_not_configured():
    """No App fields, but a PAT → dispatch via PAT."""
    cfg = HardeningConfig(github_repo="owner/repo", github_pat="legacy-pat")
    captured = {}

    class _Resp:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def _fake_urlopen(req, timeout=30):
        captured["auth"] = req.get_header("Authorization")
        return _Resp()

    with patch(
        "app.services.image_hardening.signing.urllib.request.urlopen",
        side_effect=_fake_urlopen,
    ):
        dispatched, msg = dispatch_signing_workflow(
            cfg, image_digest="sha256:x", image_tag="v1", sbom_bucket="b"
        )
    assert dispatched is True
    assert "pat" in msg
    assert captured["auth"] == "Bearer legacy-pat"


# ---------------------------------------------------------------------------
# 4b. GitHub App auth (JWT build + token exchange)
# ---------------------------------------------------------------------------
def test_github_app_jwt_build_and_claims():
    """_build_app_jwt produces a decodable RS256 JWT with the right claims."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    import jwt as _jwt
    from app.services.image_hardening.github_app_auth import _build_app_jwt

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_pem = (
        key.public_key()
        .public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )

    token, err = _build_app_jwt("5408664", pem)
    assert err is None
    decoded = _jwt.decode(token, pub_pem, algorithms=["RS256"])
    assert decoded["iss"] == "5408664"
    assert decoded["exp"] > decoded["iat"]


def test_github_app_jwt_build_bad_key_returns_error():
    from app.services.image_hardening.github_app_auth import _build_app_jwt

    token, err = _build_app_jwt("5408664", "not-a-valid-pem")
    assert token is None
    assert err is not None


def test_get_installation_token_not_configured():
    from app.services.image_hardening.github_app_auth import get_installation_token

    token, err = get_installation_token(
        app_id="", installation_id="", private_key_secret_arn="", region="us-east-1"
    )
    assert token is None
    assert "not fully configured" in err


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


# ---- box-side scan summary parsing ----
# Counting now happens ON THE BOX (box_count_command) to avoid SSM's ~24 KB
# stdout truncation of multi-MB trivy reports. parse_box_summary consumes the
# tiny marker-prefixed JSON the box prints, and HARD-FAILS on any failure so an
# unscanned image can never silently pass the gate.
def test_box_count_command_embeds_report_path_and_marker():
    from app.services.image_hardening.scanning import box_count_command

    cmd = box_count_command("/scratch/report.json")
    assert "/scratch/report.json" in cmd
    assert "python3" in cmd
    assert "__HARDEN_SCAN_SUMMARY__" in cmd


def test_parse_box_summary_reads_counts():
    from app.services.image_hardening.scanning import parse_box_summary

    out = (
        "some trivy banner line\n"
        '__HARDEN_SCAN_SUMMARY__ {"ok": true, "os_critical": 2, "os_high": 3, '
        '"dep_critical": 1, "dep_high": 0}\n'
    )
    c = parse_box_summary(out)
    assert c.os_critical == 2
    assert c.os_high == 3
    assert c.dep_critical == 1
    assert c.dep_high == 0
    assert c.total_fixable == 6


def test_parse_box_summary_hard_fails_on_missing_marker():
    from app.services.image_hardening.scanning import ScanParseError, parse_box_summary

    with pytest.raises(ScanParseError):
        parse_box_summary("trivy ran but no summary was printed (truncated?)")


def test_parse_box_summary_hard_fails_on_empty():
    from app.services.image_hardening.scanning import ScanParseError, parse_box_summary

    with pytest.raises(ScanParseError):
        parse_box_summary("")


def test_parse_box_summary_hard_fails_when_box_reports_not_ok():
    from app.services.image_hardening.scanning import ScanParseError, parse_box_summary

    with pytest.raises(ScanParseError):
        parse_box_summary('__HARDEN_SCAN_SUMMARY__ {"ok": false, "error": "no such file"}')


def test_parse_box_summary_reads_os_fields():
    from app.services.image_hardening.scanning import parse_box_summary

    out = (
        '__HARDEN_SCAN_SUMMARY__ {"ok": true, "os_critical": 1, "os_high": 2, '
        '"dep_critical": 0, "dep_high": 0, "os_family": "debian", "os_name": "11.0"}'
    )
    c = parse_box_summary(out)
    assert c.os_family == "debian"
    assert c.os_name == "11.0"


def test_parse_box_summary_os_fields_default_empty_when_absent():
    # Backward compat: older box output without os_* keys must still parse.
    from app.services.image_hardening.scanning import parse_box_summary

    out = (
        '__HARDEN_SCAN_SUMMARY__ {"ok": true, "os_critical": 0, "os_high": 0, '
        '"dep_critical": 0, "dep_high": 0}'
    )
    c = parse_box_summary(out)
    assert c.os_family == ""
    assert c.os_name == ""


def test_box_count_command_extracts_os_metadata():
    from app.services.image_hardening.scanning import box_count_command

    cmd = box_count_command("/scratch/full.json")
    assert "Metadata" in cmd
    assert "os_family" in cmd


# ---- EOL base detection (pure) ----
def test_eol_flags_debian_11():
    from app.services.image_hardening.eol import check_eol

    v = check_eol("debian", "11.0")
    assert v.is_eol is True
    assert v.eol_date == "2026-08-31"
    assert "end-of-life" in v.message.lower()


def test_eol_passes_debian_12():
    from app.services.image_hardening.eol import check_eol

    v = check_eol("debian", "12.5")
    assert v.is_eol is False
    assert v.message == ""


def test_eol_matches_major_only_for_debian_point_release():
    from app.services.image_hardening.eol import check_eol

    # Debian table is keyed by major ("11"); a point release "11.7" must match.
    assert check_eol("debian", "11.7").is_eol is True


def test_eol_matches_ubuntu_major_minor():
    from app.services.image_hardening.eol import check_eol

    assert check_eol("ubuntu", "18.04").is_eol is True
    assert check_eol("ubuntu", "22.04").is_eol is False


def test_eol_fail_open_on_unknown_or_missing_os():
    from app.services.image_hardening.eol import check_eol

    assert check_eol("", "").is_eol is False  # no OS (distroless/scratch)
    assert check_eol("fedora", "40").is_eol is False  # not in table → not blocked
    assert check_eol("debian", "").is_eol is False  # family but no version


# ---- residual extractor (box builds files, prints only counts) ----
def test_box_residual_command_embeds_paths_and_marker():
    from app.services.image_hardening.scanning import box_residual_command

    cmd = box_residual_command(
        "/scratch/full.json",
        out_report_path="/scratch/residual.json",
        out_vex_path="/scratch/vex.json",
        image_ref="nginx:1.25",
        image_digest="sha256:abc",
    )
    assert "/scratch/full.json" in cmd
    assert "/scratch/residual.json" in cmd
    assert "/scratch/vex.json" in cmd
    assert "nginx:1.25" in cmd
    assert "sha256:abc" in cmd
    assert "python3" in cmd
    assert "__HARDEN_RESIDUAL__" in cmd
    assert "FixedVersion" in cmd  # skips fixable
    assert "openvex.dev" in cmd  # builds VEX on box


def test_parse_box_residual_counts_reads_summary():
    from app.services.image_hardening.scanning import parse_box_residual_counts

    out = (
        "trivy noise\n"
        '__HARDEN_RESIDUAL__ {"ok": true, "total": 22, "critical": 1, "high": 21, '
        '"medium": 0, "low": 0, "unknown": 0}\n'
    )
    c = parse_box_residual_counts(out)
    assert c["total"] == 22
    assert c["critical"] == 1
    assert c["high"] == 21


def test_parse_box_residual_counts_hard_fails_on_missing_and_not_ok():
    from app.services.image_hardening.scanning import ScanParseError, parse_box_residual_counts

    with pytest.raises(ScanParseError):
        parse_box_residual_counts("no marker here")
    with pytest.raises(ScanParseError):
        parse_box_residual_counts('__HARDEN_RESIDUAL__ {"ok": false, "error": "boom"}')


# ---- box deps extractor (lang-pkgs subset for the bump leg) ----
def test_box_deps_report_command_embeds_path_and_marker():
    from app.services.image_hardening.scanning import box_deps_report_command

    cmd = box_deps_report_command("/scratch/deps.json")
    assert "/scratch/deps.json" in cmd
    assert "python3" in cmd
    assert "__HARDEN_DEPS__" in cmd
    assert "lang-pkgs" in cmd


def test_parse_box_deps_report_returns_compute_compatible_json():
    import json as _json

    from app.services.image_hardening.dep_bump import compute_pip_bumps
    from app.services.image_hardening.scanning import parse_box_deps_report

    out = (
        "trivy noise\n"
        '__HARDEN_DEPS__ {"ok": true, "report": {"Results": [{"Class": "lang-pkgs", '
        '"Type": "pip", "Vulnerabilities": [{"PkgName": "jinja2", '
        '"FixedVersion": "2.11.3", "Severity": "HIGH", "VulnerabilityID": "CVE-X"}]}]}}\n'
    )
    report_json = parse_box_deps_report(out)
    # Round-trips to the shape compute_pip_bumps consumes.
    assert _json.loads(report_json)["Results"][0]["Type"] == "pip"
    plan = compute_pip_bumps(report_json, "jinja2==2.10\n")
    assert plan.to_pin == {"jinja2": "2.11.3"}


def test_parse_box_deps_report_hard_fails_on_missing_and_not_ok():
    from app.services.image_hardening.scanning import ScanParseError, parse_box_deps_report

    with pytest.raises(ScanParseError):
        parse_box_deps_report("no marker")
    with pytest.raises(ScanParseError):
        parse_box_deps_report('__HARDEN_DEPS__ {"ok": false, "error": "boom"}')


# ---- residual report + OpenVEX builders ----
def _residual_findings():
    return [
        {
            "id": "CVE-2026-6653",
            "severity": "CRITICAL",
            "status": "affected",
            "pkgs": ["libxml2"],
            "installed": "2.9.14",
            "title": "libxml2 DoS",
        },
        {
            "id": "CVE-2026-85091",
            "severity": "HIGH",
            "status": "will_not_fix",
            "pkgs": ["zlib"],
            "installed": "1.2.13",
            "title": "zlib overflow",
        },
        {
            "id": "CVE-2026-18495",
            "severity": "MEDIUM",
            "status": "fix_deferred",
            "pkgs": ["tiff"],
            "installed": "4.5.0",
            "title": "tiff issue",
        },
    ]


def test_build_residual_report_counts_and_orders():
    from app.services.image_hardening.residual import build_residual_report

    rep = build_residual_report(
        findings=_residual_findings(),
        image_ref="r/repo:tag",
        image_digest="sha256:abc",
        artifact_name="nginx:1.25",
    )
    assert rep["counts"] == {
        "total": 3,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 0,
        "unknown": 0,
    }
    # Ordered by severity rank: CRITICAL first.
    assert rep["findings"][0]["severity"] == "CRITICAL"
    assert rep["findings"][0]["id"] == "CVE-2026-6653"
    assert rep["image_digest"] == "sha256:abc"


def test_build_openvex_shape_and_status():
    from app.services.image_hardening.residual import build_openvex

    vex = build_openvex(
        findings=_residual_findings(),
        image_ref="r/repo:tag",
        image_digest="sha256:abc",
    )
    assert vex["@context"].startswith("https://openvex.dev/ns/")
    assert len(vex["statements"]) == 3
    st = vex["statements"][0]
    assert st["status"] == "affected"  # present + unfixable
    assert st["vulnerability"]["name"].startswith("CVE-")
    assert "sha256:abc" in st["products"][0]["@id"]
    assert "no upstream fix" in st["action_statement"].lower()


def test_residual_summary_for_scan():
    from app.services.image_hardening.residual import (
        build_residual_report,
        residual_summary_for_scan,
    )

    rep = build_residual_report(
        findings=_residual_findings(), image_ref="r:t", image_digest="sha256:x"
    )
    s = residual_summary_for_scan(rep)
    assert s["residual_total"] == 3
    assert s["residual_critical"] == 1
    assert s["residual_high"] == 1
    assert s["residual_medium"] == 1


def test_build_residual_report_empty_is_all_zero():
    from app.services.image_hardening.residual import build_residual_report

    rep = build_residual_report(findings=[], image_ref="r:t", image_digest="sha256:x")
    assert rep["counts"]["total"] == 0
    assert rep["findings"] == []


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


# ---- copa -t is a PLAIN tag; patched image is <repo-of-source>:<tag> ----
# copa patch -i <ref> -t <TAG> produces a LOCAL image at <repo-of-ref>:<TAG>.
# -t must NOT be a full registry/repo:tag or copa errors "invalid tag format".
def test_repo_of_strips_tag_and_digest():
    from app.services.image_hardening.copa_strategy import _repo_of

    assert _repo_of("debian:11.0") == "debian"
    assert _repo_of("nginx") == "nginx"
    assert _repo_of("registry.io/foo/bar:tag") == "registry.io/foo/bar"
    # Registry port must not be mistaken for a tag.
    assert _repo_of("registry.io:5000/foo/bar:tag") == "registry.io:5000/foo/bar"
    # Digests stripped (with and without registry).
    assert _repo_of("foo@sha256:abc123") == "foo"
    assert _repo_of("registry.io/foo@sha256:abc123") == "registry.io/foo"


def test_copa_local_patched_ref():
    from app.services.image_hardening.copa_strategy import copa_local_patched_ref

    assert copa_local_patched_ref("debian:11.0", "v1-copa1") == "debian:v1-copa1"
    # Re-iteration: patching the local patched ref again keeps the repo.
    assert copa_local_patched_ref("debian:v1-copa1", "v1-copa2") == "debian:v1-copa2"
    assert copa_local_patched_ref("registry.io:5000/a/b:tag", "x") == "registry.io:5000/a/b:x"


# ---- transient copa failure detection + retry (apt mirror / CDN 404 flake) ----
def _failed_step(stderr):
    return StepResult(
        step_num=1,
        action="copa patch",
        command="copa patch ...",
        stderr=stderr,
        exit_code=1,
        status="failed",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )


def test_capture_hoists_error_line_buried_under_progress_noise():
    """The real error (404) must survive even when far from the tail (run #9 gap)."""
    from app.services.image_hardening.copa_strategy import _capture

    err_line = "#6 1.240   404  Not Found [IP: 146.75.38.132 80]"
    # Error line early, then a huge wall of trailing progress lines that would
    # push it out of a plain char-tail.
    noise = "\n".join(f"#99 {i} progress line pulling bytes" for i in range(400))
    blob = f"#6 apt-get install busybox-static\n{err_line}\n{noise}"
    out = _capture(blob, 1000)
    assert "404  Not Found" in out  # hoisted, not lost
    assert "error signals" in out


def test_capture_handles_empty_and_short():
    from app.services.image_hardening.copa_strategy import _capture

    assert _capture("", 100) == ""
    assert _capture(None, 100) == ""
    # Short clean text with no error signal is returned as-is.
    assert _capture("all good\ndone", 100) == "all good\ndone"


def test_transient_detector_matches_apt_404():
    from app.services.image_hardening.copa_strategy import _is_transient_copa_failure

    s = _failed_step(
        "Err:1 http://deb.debian.org/debian-security bullseye-security/main arm64 "
        "busybox-static arm64 1:1.30.1-6+deb11u1\n  404  Not Found [IP: 146.75.38.132 80]\n"
        'Error: process "apt-get install busybox-static" did not complete successfully'
    )
    assert _is_transient_copa_failure(s) is True


def test_transient_detector_rejects_deterministic_failure():
    from app.services.image_hardening.copa_strategy import _is_transient_copa_failure

    assert _is_transient_copa_failure(_failed_step("Error: invalid report format")) is False
    assert _is_transient_copa_failure(_failed_step("")) is False


def test_patch_retry_recovers_after_transient_then_success(monkeypatch):
    """First attempt 404s (transient) → retry → success. adaptation_note records it."""
    strat = _copa_strat()
    monkeypatch.setattr(
        "app.services.image_hardening.copa_strategy.time.sleep", lambda *_a, **_k: None
    )
    transient = _failed_step("404  Not Found")
    ok = StepResult(
        step_num=1,
        action="copa patch",
        command="copa patch ...",
        exit_code=0,
        status="success",
        started_at=datetime.now(UTC),
        finished_at=datetime.now(UTC),
    )
    with patch.object(strat, "patch_once", side_effect=[transient, ok]):
        out = strat.patch_once_with_retry(_copa_ctx(), "debian:11.0", "/r.json", "t1")
    assert out.status == "success"
    assert "attempt 2" in (out.adaptation_note or "")


def test_patch_retry_fails_fast_on_deterministic(monkeypatch):
    """A deterministic failure is NOT retried (patch_once called exactly once)."""
    strat = _copa_strat()
    monkeypatch.setattr(
        "app.services.image_hardening.copa_strategy.time.sleep", lambda *_a, **_k: None
    )
    det = _failed_step("Error: unsupported image type")
    mock = MagicMock(return_value=det)
    with patch.object(strat, "patch_once", mock):
        out = strat.patch_once_with_retry(_copa_ctx(), "debian:11.0", "/r.json", "t1")
    assert out.status == "failed"
    assert mock.call_count == 1  # no retry on deterministic failure


def test_patch_retry_exhausts_on_persistent_transient(monkeypatch):
    """Transient every time → exhaust retries, note records the persistence."""
    strat = _copa_strat()
    monkeypatch.setattr(
        "app.services.image_hardening.copa_strategy.time.sleep", lambda *_a, **_k: None
    )
    mock = MagicMock(return_value=_failed_step("failed to fetch ... 404 Not Found"))
    with patch.object(strat, "patch_once", mock):
        out = strat.patch_once_with_retry(_copa_ctx(), "debian:11.0", "/r.json", "t1")
    assert out.status == "failed"
    # default copa_transient_retries=2 → 3 total attempts
    assert mock.call_count == 3
    assert "persisted" in (out.adaptation_note or "")


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


# ===========================================================================
# Orchestrator routing + copa lifecycle mapping (Model B)
# ===========================================================================
from app.services.image_hardening import orchestrator as orch  # noqa: E402


class _FakeSB:
    """Minimal supabase stand-in: swallow .table(...).update(...).eq(...).execute()."""

    def table(self, *_a, **_k):
        return self

    def update(self, *_a, **_k):
        return self

    def eq(self, *_a, **_k):
        return self

    def execute(self, *_a, **_k):
        return self


def _clean_scan():
    return CopaScanResult(fixable_critical=0, fixable_high=0, raw_summary="")


def test_run_hardening_mode_patch_routes_to_copa(monkeypatch):
    """mode='patch' must invoke the copa lifecycle, not the rebuild lifecycle."""
    called = {"copa": False, "rebuild": False}

    def fake_copa_lifecycle(*_a, **_k):
        called["copa"] = True
        from app.services.image_hardening.models import HardeningOutcome

        return HardeningOutcome(status="success")

    def fake_rebuild_lifecycle(*_a, **_k):
        called["rebuild"] = True
        from app.services.image_hardening.models import HardeningOutcome

        return HardeningOutcome(status="success")

    monkeypatch.setattr(orch, "_run_copa_lifecycle", fake_copa_lifecycle)
    monkeypatch.setattr(orch, "_run_lifecycle", fake_rebuild_lifecycle)
    monkeypatch.setattr(orch, "resolve_build_instance", lambda _cfg: "i-test")
    monkeypatch.setattr(orch, "finalize_hardening_run", lambda *a, **k: None)

    orch.run_hardening(
        run_id=1,
        source_image_ref="img:latest",
        target_registry="r/repo",
        published_tag="v1",
        auto_sign=False,
        mode=orch.MODE_PATCH,
        sb=_FakeSB(),
        config=HardeningConfig(build_instance_id="i-test"),
    )
    assert called["copa"] is True
    assert called["rebuild"] is False


def test_run_hardening_mode_rebuild_routes_to_rebuild(monkeypatch):
    called = {"copa": False, "rebuild": False}

    def fake_copa_lifecycle(*_a, **_k):
        called["copa"] = True
        from app.services.image_hardening.models import HardeningOutcome

        return HardeningOutcome(status="success")

    def fake_rebuild_lifecycle(*_a, **_k):
        called["rebuild"] = True
        from app.services.image_hardening.models import HardeningOutcome

        return HardeningOutcome(status="success")

    monkeypatch.setattr(orch, "_run_copa_lifecycle", fake_copa_lifecycle)
    monkeypatch.setattr(orch, "_run_lifecycle", fake_rebuild_lifecycle)
    monkeypatch.setattr(orch, "resolve_build_instance", lambda _cfg: "i-test")
    monkeypatch.setattr(orch, "finalize_hardening_run", lambda *a, **k: None)

    orch.run_hardening(
        run_id=1,
        source_image_ref="img:latest",
        target_registry="r/repo",
        published_tag="v1",
        auto_sign=False,
        mode=orch.MODE_REBUILD,
        sb=_FakeSB(),
        config=HardeningConfig(build_instance_id="i-test"),
    )
    assert called["rebuild"] is True
    assert called["copa"] is False


def test_run_hardening_propagates_build_directory_and_dockerfile(monkeypatch):
    """build_directory + dockerfile_path from the trigger must reach the ctx so
    the rebuild leg uses the client's build context (not the default dir)."""
    captured = {}

    def fake_copa_lifecycle(_sb, _rid, _copa, ctx, **_k):
        captured["build_directory"] = ctx.build_directory
        captured["dockerfile_path"] = ctx.dockerfile_path
        from app.services.image_hardening.models import HardeningOutcome

        return HardeningOutcome(status="success")

    monkeypatch.setattr(orch, "_run_copa_lifecycle", fake_copa_lifecycle)
    monkeypatch.setattr(orch, "resolve_build_instance", lambda _cfg: "i-test")
    monkeypatch.setattr(orch, "finalize_hardening_run", lambda *a, **k: None)
    monkeypatch.setattr(orch, "CopaPatchStrategy", lambda **_k: object())

    orch.run_hardening(
        run_id=1,
        source_image_ref="img:latest",
        target_registry="r/repo",
        published_tag="v1",
        auto_sign=False,
        mode=orch.MODE_PATCH,
        dockerfile_path="/opt/image-forge-src/image-forge/base-images/vuln-python-sample/Dockerfile",
        build_directory="/opt/image-forge-src/image-forge/base-images/vuln-python-sample",
        sb=_FakeSB(),
        config=HardeningConfig(build_instance_id="i-test"),
    )
    assert captured["build_directory"].endswith("vuln-python-sample")
    assert captured["dockerfile_path"].endswith("vuln-python-sample/Dockerfile")


# --- decide-from-findings lifecycle (full-scope gate) edge cases ---
from app.services.image_hardening.scanning import ScanClassification  # noqa: E402


def _publish_sets_digest(_copa, c, _ref, _cfg):
    c.published_digest = "sha256:deadbeef"
    # _copa_publish now returns (publish_steps, residual_steps, residual_report).
    return [_ok_step("push patched")], [], None


def _copa_fixture(monkeypatch, *, scans, remediate_result=None, dockerfile=None):
    """Build a CopaPatchStrategy with pre_flight ready, full_scope_scan returning
    the given sequence of ScanClassification, and (optionally) a remediate result.
    Returns (copa, ctx)."""
    cfg = HardeningConfig(build_instance_id="i-test", sbom_bucket="b")
    copa = CopaPatchStrategy(config=cfg, emit_fn=lambda *a, **k: None)
    ctx = _copa_ctx()
    if dockerfile is not None:
        ctx.dockerfile_path = dockerfile
    monkeypatch.setattr(copa, "pre_flight_check", lambda _c: _pf_ready())
    monkeypatch.setattr(copa, "full_scope_scan", _seq(scans))
    if remediate_result is not None:
        monkeypatch.setattr(copa, "remediate", lambda _c, _ref: remediate_result)
    monkeypatch.setattr(orch, "_copa_publish", _publish_sets_digest)
    return copa, ctx, cfg


def _seq(items):
    """Return a function that yields successive items on each call."""
    it = iter(items)
    return lambda *_a, **_k: next(it)


def _clean():
    return ScanClassification()


def _os_only(n=1):
    return ScanClassification(os_critical=n)


def _dep_only(n=1):
    return ScanClassification(dep_critical=n)


def test_lifecycle_already_clean_at_intake_publishes(monkeypatch):
    """0 fixable at intake → success, no copa/rebuild, publish original."""
    copa, ctx, cfg = _copa_fixture(monkeypatch, scans=[_clean()])
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"
    assert out.validation_results[0].passed is True


def test_lifecycle_os_only_runs_copa_then_clean(monkeypatch):
    """OS findings → copa → re-gate clean → success."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[_os_only(), _clean()],  # intake dirty, after copa clean
        remediate_result={
            "status": "clean",
            "iterations": 1,
            "final_image_ref": "img:patched",
            "steps": [],
            "final_scan": None,
            "message": "",
        },
    )
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"
    assert out.published_digest == "sha256:deadbeef"
    # Intake counts persisted so the record proves "came in dirty, went out 0".
    assert out.scan_summary["intake_os_fixable"] == 1
    assert out.scan_summary["intake_total_fixable"] == 1
    assert out.scan_summary["total_fixable"] == 0  # final (post-copa) is clean


def test_lifecycle_merges_residual_summary_into_scan_summary(monkeypatch):
    """When publish returns a residual report, residual_* keys + s3 keys land in
    scan_summary (run stays success — residual is non-gating)."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[_os_only(), _clean()],
        remediate_result={
            "status": "clean",
            "iterations": 1,
            "final_image_ref": "img:patched",
            "steps": [],
            "final_scan": None,
            "message": "",
        },
    )

    def _publish_with_residual(_copa, c, _ref, _cfg):
        c.published_digest = "sha256:deadbeef"
        # (publish_steps, residual_steps, residual_report with uploaded=True)
        report = {
            "counts": {"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "unknown": 0},
            "uploaded": True,
        }
        return [_ok_step("push patched")], [_ok_step("upload residual report")], report

    monkeypatch.setattr(orch, "_copa_publish", _publish_with_residual)
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"
    assert out.scan_summary["residual_total"] == 1
    assert out.scan_summary["residual_high"] == 1
    assert out.scan_summary["residual_s3_key"] == "residual/sha256:deadbeef.json"
    assert out.scan_summary["vex_s3_key"] == "vex/sha256:deadbeef.openvex.json"


def test_lifecycle_residual_upload_failure_is_non_gating(monkeypatch):
    """A residual upload failure (e.g. S3 perms) must NOT fail the run — the
    image is already patched + published. Run stays success; counts recorded,
    S3 keys NOT advertised."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[_os_only(), _clean()],
        remediate_result={
            "status": "clean",
            "iterations": 1,
            "final_image_ref": "img:patched",
            "steps": [],
            "final_scan": None,
            "message": "",
        },
    )

    def _publish_residual_upload_fails(_copa, c, _ref, _cfg):
        c.published_digest = "sha256:deadbeef"
        report = {
            "counts": {"total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0, "unknown": 0},
            "uploaded": False,  # S3 PutObject denied
        }
        failed_upload = StepResult(
            step_num=18,
            action="upload residual report",
            command="aws s3 cp ...",
            stderr="AccessDenied",
            exit_code=1,
            status="failed",
            started_at=datetime.now(UTC),
            finished_at=datetime.now(UTC),
        )
        return [_ok_step("push patched")], [failed_upload], report

    monkeypatch.setattr(orch, "_copa_publish", _publish_residual_upload_fails)
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    # Run is STILL a success despite the residual upload failure.
    assert out.status == "success"
    assert out.scan_summary["residual_total"] == 2
    assert out.scan_summary.get("residual_status") == "computed_not_uploaded"
    assert "residual_s3_key" not in out.scan_summary


def test_lifecycle_eol_base_with_os_findings_fails_fast(monkeypatch):
    """An EOL base (debian 11) WITH OS fixables → fail fast before patching,
    with an eol_base scan_summary and a clear message."""
    eol_intake = ScanClassification(os_critical=5, os_family="debian", os_name="11.0")
    copa, ctx, cfg = _copa_fixture(monkeypatch, scans=[eol_intake])
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "failed"
    assert out.scan_summary.get("eol_base") is True
    assert out.scan_summary.get("eol_date") == "2026-08-31"
    assert "end-of-life" in (out.error_message or "").lower()


def test_lifecycle_eol_base_but_clean_still_publishes(monkeypatch):
    """An EOL base with NOTHING fixable (policy-zero) is still publishable —
    EOL fail-fast only applies when there are OS findings to patch."""
    clean_eol = ScanClassification(os_family="debian", os_name="11.0")  # 0 fixable
    copa, ctx, cfg = _copa_fixture(monkeypatch, scans=[clean_eol])
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"


def test_lifecycle_supported_base_not_blocked(monkeypatch):
    """A supported base (debian 12) with OS findings proceeds to copa normally."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[
            ScanClassification(os_critical=1, os_family="debian", os_name="12.5"),
            _clean(),
        ],
        remediate_result={
            "status": "clean",
            "iterations": 1,
            "final_image_ref": "img:patched",
            "steps": [],
            "final_scan": None,
            "message": "",
        },
    )
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"
    assert out.scan_summary.get("eol_base") is None  # not flagged


def test_lifecycle_already_clean_records_zero_intake(monkeypatch):
    """Clean-at-intake success records intake_total_fixable=0 (provably clean)."""
    copa, ctx, cfg = _copa_fixture(monkeypatch, scans=[_clean()])
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"
    assert out.scan_summary["intake_total_fixable"] == 0


def test_lifecycle_dependency_only_no_dockerfile_is_residual_fail(monkeypatch):
    """THE Q2 CASE: dependency-only CVEs, no Dockerfile → NOT a false pass.
    copa no-ops (os_fixable=0), deps remain, no source → failed/residual."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[_dep_only(), _dep_only()],  # intake has deps; after (no copa) still deps
        dockerfile=None,
    )
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "failed"
    assert out.validation_results[0].passed is False
    assert "residual" in out.scan_summary
    # Intake counts persisted even on a failure path (auditable).
    assert out.scan_summary["intake_dep_fixable"] == 1
    assert out.scan_summary["intake_total_fixable"] == 1


def test_lifecycle_dependency_with_dockerfile_runs_rebuild(monkeypatch):
    """dependency CVEs + Dockerfile → rebuild leg runs → clean → success."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[_dep_only(), _clean()],  # intake deps; after rebuild clean
        dockerfile="/opt/image-forge-src/Dockerfile",
    )
    monkeypatch.setattr(
        orch,
        "_run_rebuild_leg",
        lambda *a, **k: ([_ok_step("docker build (rebuild)")], "img:rebuilt"),
    )
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"


def test_lifecycle_mixed_os_and_dep_with_dockerfile(monkeypatch):
    """mixed: copa (OS) then rebuild (deps) → clean → success."""
    copa, ctx, cfg = _copa_fixture(
        monkeypatch,
        scans=[
            ScanClassification(os_critical=1, dep_critical=1),  # intake mixed
            ScanClassification(dep_critical=1),  # after copa: OS gone, dep remains
            _clean(),  # after rebuild: clean
        ],
        remediate_result={
            "status": "clean",
            "iterations": 1,
            "final_image_ref": "img:patched",
            "steps": [],
            "final_scan": None,
            "message": "",
        },
        dockerfile="/opt/image-forge-src/Dockerfile",
    )
    monkeypatch.setattr(
        orch,
        "_run_rebuild_leg",
        lambda *a, **k: ([_ok_step("docker build (rebuild)")], "img:rebuilt"),
    )
    out = orch._run_copa_lifecycle(_FakeSB(), 1, copa, ctx, cfg=cfg, started_at=_now())
    assert out.status == "success"


def _pf_ready():
    from app.services.image_hardening.models import PreFlightResult

    return PreFlightResult(ready=True)


# ===========================================================================
# scanning.classify_trivy_report — full-scope gate classification
# ===========================================================================
from app.services.image_hardening.scanning import classify_trivy_report  # noqa: E402


def test_classify_splits_os_and_lang_fixable():
    report = json.dumps(
        {
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Vulnerabilities": [
                        {"Severity": "CRITICAL", "FixedVersion": "1.0"},
                        {"Severity": "HIGH", "FixedVersion": "2.0"},
                    ],
                },
                {
                    "Class": "lang-pkgs",
                    "Vulnerabilities": [
                        {"Severity": "HIGH", "FixedVersion": "3.0"},
                        {"Severity": "HIGH", "FixedVersion": None},  # unfixable → excluded
                        {"Severity": "MEDIUM", "FixedVersion": "4.0"},  # not gated
                    ],
                },
            ]
        }
    )
    c = classify_trivy_report(report)
    assert c.os_critical == 1
    assert c.os_high == 1
    assert c.dep_critical == 0
    assert c.dep_high == 1
    assert c.os_fixable == 2
    assert c.dep_fixable == 1
    assert c.gate_passes is False


def test_classify_only_unfixable_gate_passes():
    """Only unfixable findings → gate PASSES (policy-zero = zero *fixable*)."""
    report = json.dumps(
        {
            "Results": [
                {
                    "Class": "os-pkgs",
                    "Vulnerabilities": [{"Severity": "CRITICAL", "FixedVersion": None}],
                }
            ]
        }
    )
    c = classify_trivy_report(report)
    assert c.total_fixable == 0
    assert c.gate_passes is True


def test_classify_unknown_class_treated_as_dependency():
    """Missing/unknown Class → conservatively counted as dependency (not dropped)."""
    report = json.dumps(
        {"Results": [{"Vulnerabilities": [{"Severity": "CRITICAL", "FixedVersion": "1.0"}]}]}
    )
    c = classify_trivy_report(report)
    assert c.dep_critical == 1
    assert c.os_fixable == 0
    assert c.gate_passes is False


def test_classify_empty_report_is_clean():
    # A well-formed but empty report legitimately means "no findings" → clean.
    assert classify_trivy_report("{}").gate_passes is True
    assert classify_trivy_report('{"Results": null}').gate_passes is True


def test_classify_malformed_hard_fails():
    # Unparseable input must HARD-FAIL (never return a silent all-zero that
    # would falsely PASS the gate on an unscanned image).
    from app.services.image_hardening.scanning import ScanParseError

    with pytest.raises(ScanParseError):
        classify_trivy_report("not json")
    with pytest.raises(ScanParseError):
        classify_trivy_report("")
    with pytest.raises(ScanParseError):
        classify_trivy_report("[]")  # JSON array, not an object


# ===========================================================================
# dep_bump — deterministic pip version bumping (rebuild Option b)
# ===========================================================================
from app.services.image_hardening.dep_bump import (  # noqa: E402
    apply_pip_bumps,
    compute_pip_bumps,
    normalize_pkg,
)


def _lang_report(vulns, rtype="pip"):
    return json.dumps(
        {"Results": [{"Class": "lang-pkgs", "Type": rtype, "Vulnerabilities": vulns}]}
    )


def test_normalize_pkg_pep503():
    assert normalize_pkg("Flask") == "flask"
    assert normalize_pkg("foo_bar") == "foo-bar"
    assert normalize_pkg("Foo.Bar") == "foo-bar"


def test_compute_bumps_pins_declared_pip_package():
    report = _lang_report(
        [
            {
                "PkgName": "flask",
                "Severity": "HIGH",
                "FixedVersion": "2.3.2",
                "VulnerabilityID": "CVE-x",
            }
        ]
    )
    plan = compute_pip_bumps(report, "flask==2.0.0\nrequests==2.28.0\n")
    assert plan.to_pin == {"flask": "2.3.2"}
    assert plan.residual == []


def test_compute_bumps_transitive_is_residual():
    """Package not declared in requirements.txt → residual, not pinned."""
    report = _lang_report(
        [
            {
                "PkgName": "urllib3",
                "Severity": "CRITICAL",
                "FixedVersion": "2.0.7",
                "VulnerabilityID": "CVE-y",
            }
        ]
    )
    plan = compute_pip_bumps(report, "requests==2.28.0\n")  # urllib3 not declared
    assert plan.to_pin == {}
    assert len(plan.residual) == 1
    assert "transitive" in plan.residual[0]["reason"]


def test_compute_bumps_non_pip_is_residual():
    report = _lang_report(
        [
            {
                "PkgName": "lodash",
                "Severity": "HIGH",
                "FixedVersion": "4.17.21",
                "VulnerabilityID": "CVE-z",
            }
        ],
        rtype="npm",
    )
    plan = compute_pip_bumps(report, "flask==2.0.0\n")
    assert plan.to_pin == {}
    assert "non-pip" in plan.residual[0]["reason"]


def test_compute_bumps_no_fixed_version_is_residual():
    report = _lang_report(
        [{"PkgName": "flask", "Severity": "HIGH", "FixedVersion": "", "VulnerabilityID": "CVE-n"}]
    )
    plan = compute_pip_bumps(report, "flask==2.0.0\n")
    assert plan.to_pin == {}
    assert "no fixed version" in plan.residual[0]["reason"]


def test_compute_bumps_highest_version_when_multiple():
    report = _lang_report(
        [
            {
                "PkgName": "flask",
                "Severity": "HIGH",
                "FixedVersion": "2.3.2",
                "VulnerabilityID": "a",
            },
            {
                "PkgName": "flask",
                "Severity": "CRITICAL",
                "FixedVersion": "2.3.10",
                "VulnerabilityID": "b",
            },
        ]
    )
    plan = compute_pip_bumps(report, "flask==2.0.0\n")
    assert plan.to_pin == {"flask": "2.3.10"}


def test_apply_bumps_rewrites_only_targeted_lines():
    req = "# app deps\nFlask==2.0.0\nrequests>=2.28.0\n-r other.txt\n"
    plan = compute_pip_bumps(
        _lang_report(
            [
                {
                    "PkgName": "flask",
                    "Severity": "HIGH",
                    "FixedVersion": "2.3.2",
                    "VulnerabilityID": "c",
                }
            ]
        ),
        req,
    )
    out = apply_pip_bumps(req, plan)
    assert "Flask==2.3.2" in out  # pinned (original casing preserved)
    assert "requests>=2.28.0" in out  # untouched
    assert "# app deps" in out  # comment preserved
    assert "-r other.txt" in out  # directive preserved


def test_apply_bumps_handles_unpinned_and_specifier_variants():
    req = "flask\nnumpy~=1.24\n"
    plan = compute_pip_bumps(
        _lang_report(
            [
                {
                    "PkgName": "flask",
                    "Severity": "HIGH",
                    "FixedVersion": "2.3.2",
                    "VulnerabilityID": "d",
                }
            ]
        ),
        req,
    )
    out = apply_pip_bumps(req, plan)
    assert "flask==2.3.2" in out
    assert "numpy~=1.24" in out  # untouched


def test_apply_bumps_noop_when_no_changes():
    req = "flask==2.0.0\n"
    plan = compute_pip_bumps(_lang_report([]), req)
    assert apply_pip_bumps(req, plan) == req
