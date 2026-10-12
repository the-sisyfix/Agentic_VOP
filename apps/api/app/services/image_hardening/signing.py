"""Auto-sign dispatch — triggers the GitHub Actions signing workflow.

BEST-EFFORT by design: if the token is missing or GitHub returns an error, we
do NOT fail the hardening run. We return a (dispatched, message) tuple; the
orchestrator records sign_dispatched=False and the operator can dispatch the
signing workflow manually. This mirrors the fixer's best-effort verified-PR hook.

Mechanism: GitHub REST "Create a workflow dispatch event"
  POST /repos/{owner}/{repo}/actions/workflows/{workflow}/dispatches
Requires a token with actions:write (reused: settings.github_pat).
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

from .config import HardeningConfig


def dispatch_signing_workflow(
    config: HardeningConfig,
    *,
    github_pat: str,
    image_digest: str,
    image_tag: str,
    sbom_bucket: str,
) -> tuple[bool, str]:
    """Trigger the signing workflow for a published digest. Best-effort.

    Returns (dispatched, message). Never raises — all failures are caught and
    reported so the hardening run can succeed regardless.
    """
    if not github_pat:
        return (False, "no GitHub PAT configured — signing not dispatched (dispatch manually)")
    if not config.github_repo:
        return (False, "no github_repo configured — signing not dispatched (dispatch manually)")
    if not image_digest:
        return (False, "no published digest — nothing to sign")

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
    req.add_header("Authorization", f"Bearer {github_pat}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            # 204 No Content = success for workflow_dispatch
            if resp.status in (201, 204):
                return (True, f"signing workflow dispatched (ref={config.github_sign_ref})")
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
