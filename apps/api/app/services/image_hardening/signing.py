"""Auto-sign dispatch — triggers the GitHub Actions signing workflow.

BEST-EFFORT by design: if auth is missing or GitHub returns an error, we do NOT
fail the hardening run. We return a (dispatched, message) tuple; the orchestrator
records sign_dispatched=False and the operator can dispatch the signing workflow
manually. This mirrors the fixer's best-effort verified-PR hook.

Mechanism: GitHub REST "Create a workflow dispatch event"
  POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches
Requires a token with actions:write.

AUTH PRECEDENCE (most secure first):
  1. GitHub App — mint a short-lived installation token (no long-lived secret).
     Preferred. Used when the App fields are configured.
  2. PAT (github_pat) — legacy fallback for a long-lived token.
  3. Neither configured → skip gracefully (operator signs manually).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .config import HardeningConfig
from .github_app_auth import get_installation_token


def _resolve_dispatch_token(config: HardeningConfig) -> tuple[str | None, str]:
    """Resolve the token to authenticate the workflow_dispatch call.

    GitHub App (preferred) → PAT (fallback) → None. Returns (token, how) where
    `how` describes the auth path for the log/message.
    """
    if (
        config.github_app_id
        and config.github_app_installation_id
        and (config.github_app_private_key_secret_arn)
    ):
        token, err = get_installation_token(
            app_id=config.github_app_id,
            installation_id=config.github_app_installation_id,
            private_key_secret_arn=config.github_app_private_key_secret_arn,
            region=config.aws_region,
        )
        if token:
            return (token, "github-app")
        # App configured but failed — report WHY; do NOT silently fall through
        # to PAT (that would mask a real App misconfiguration).
        return (None, f"github-app auth failed: {err}")
    if config.github_pat:
        return (config.github_pat, "pat")
    return (None, "no auth configured (github-app or pat)")


def dispatch_signing_workflow(
    config: HardeningConfig,
    *,
    image_digest: str,
    image_tag: str,
    sbom_bucket: str,
) -> tuple[bool, str]:
    """Trigger the signing workflow for a published digest. Best-effort.

    Returns (dispatched, message). Never raises — all failures are caught and
    reported so the hardening run can succeed regardless.
    """
    if not config.github_repo:
        return (False, "no github_repo configured — signing not dispatched (dispatch manually)")
    if not image_digest:
        return (False, "no published digest — nothing to sign")

    token, how = _resolve_dispatch_token(config)
    if not token:
        return (False, f"{how} — signing not dispatched (dispatch manually)")

    url = (
        f"https://api.github.com/repos/{config.github_repo}"
        f"/actions/workflows/{config.github_sign_workflow}/dispatches"
    )
    payload = {
        "ref": config.github_sign_ref,
        "inputs": {
            "image_digest": image_digest,
            "image_tag": image_tag,
            "sbom_bucket": sbom_bucket,
        },
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")  # noqa: S310 — fixed https host
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            # 204 No Content = success for workflow_dispatch
            if resp.status in (201, 204):
                return (
                    True,
                    f"signing workflow dispatched via {how} (ref={config.github_sign_ref})",
                )
            return (False, f"unexpected status {resp.status} — signing not dispatched")
    except urllib.error.HTTPError as e:
        # 403/404 = token lacks actions:write or workflow not found. Non-fatal.
        body = ""
        try:
            body = e.read().decode("utf-8")[:200]
        except Exception:  # noqa: BLE001, S110
            pass
        return (False, f"GitHub dispatch failed (HTTP {e.code}): {body} — dispatch manually")
    except (urllib.error.URLError, TimeoutError) as e:
        return (False, f"GitHub dispatch error: {type(e).__name__}: {e} — dispatch manually")
