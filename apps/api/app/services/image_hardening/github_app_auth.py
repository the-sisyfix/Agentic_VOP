"""GitHub App authentication — mint a short-lived installation token.

Preferred over a long-lived PAT for programmatically dispatching the signing
workflow. The flow (GitHub App auth, see
https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app):

  1. Build a short JWT (~10 min) signed with the App PRIVATE KEY (RS256). This
     proves "I am this App" to GitHub. The key signs the JWT LOCALLY and is
     never transmitted.
  2. Exchange the JWT for an INSTALLATION ACCESS TOKEN (~1 hour, scoped to the
     installed repos + granted permissions) via
     POST /app/installations/{installation_id}/access_tokens.
  3. Use that installation token as the Bearer credential on the REST call that
     dispatches the workflow.

Security posture: the only durable secret is the App private key, stored in AWS
Secrets Manager (NOT in env/config — config carries only the secret's ARN). The
tokens that cross the wire are short-lived. This mirrors the keyless/no-standing-
secret design used elsewhere in the hardening pipeline.

BEST-EFFORT: every function returns a (value, error) tuple and never raises, so
a misconfiguration degrades to "signing not dispatched" rather than failing the
hardening run.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request

import boto3
import jwt
from botocore.exceptions import BotoCoreError, ClientError


def _fetch_private_key(secret_arn: str, region: str) -> tuple[str | None, str | None]:
    """Fetch the App private key (.pem) from AWS Secrets Manager.

    Returns (pem, None) or (None, reason). Never raises.
    """
    try:
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=secret_arn)
    except (ClientError, BotoCoreError) as e:
        return (None, f"Secrets Manager get_secret_value failed: {type(e).__name__}: {e}")
    pem = resp.get("SecretString")
    if not pem:
        # Binary secret — decode if that is how it was stored.
        blob = resp.get("SecretBinary")
        if blob:
            try:
                pem = blob.decode("utf-8")
            except Exception:  # noqa: BLE001
                return (None, "secret is binary and not UTF-8 decodable")
    if not pem:
        return (None, "secret had no SecretString/SecretBinary value")
    return (pem, None)


def _build_app_jwt(app_id: str, private_key_pem: str) -> tuple[str | None, str | None]:
    """Build a short-lived RS256 JWT signed with the App private key.

    Claims: iat (issued-at, backdated 60s for clock skew), exp (10 min), iss
    (the App id). Returns (jwt, None) or (None, reason). Never raises.
    """
    try:
        now = int(time.time())
        payload = {
            "iat": now - 60,  # backdate to tolerate minor clock skew
            "exp": now + 9 * 60,  # 9 min (< GitHub's 10 min max)
            "iss": app_id,
        }
        token = jwt.encode(payload, private_key_pem, algorithm="RS256")
        # PyJWT >= 2 returns str already; guard for older behavior.
        if isinstance(token, bytes):
            token = token.decode("utf-8")
        return (token, None)
    except Exception as e:  # noqa: BLE001 — any crypto/encoding error → best-effort skip
        return (None, f"JWT build failed: {type(e).__name__}: {e}")


def _exchange_for_installation_token(
    app_jwt: str, installation_id: str
) -> tuple[str | None, str | None]:
    """Exchange the App JWT for an installation access token.

    POST /app/installations/{installation_id}/access_tokens. Returns
    (token, None) or (None, reason). Never raises.
    """
    url = f"https://api.github.com/app/installations/{installation_id}/access_tokens"
    req = urllib.request.Request(url, data=b"", method="POST")  # noqa: S310 — fixed https host
    req.add_header("Authorization", f"Bearer {app_jwt}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            body = resp.read().decode("utf-8")
            data = json.loads(body)
            token = data.get("token")
            if not token:
                return (None, "installation token response had no 'token'")
            return (token, None)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8")[:200]
        except Exception:  # noqa: BLE001, S110
            pass
        return (None, f"installation token HTTP {e.code}: {detail}")
    except (urllib.error.URLError, TimeoutError, ValueError) as e:
        return (None, f"installation token error: {type(e).__name__}: {e}")


def get_installation_token(
    *, app_id: str, installation_id: str, private_key_secret_arn: str, region: str
) -> tuple[str | None, str | None]:
    """Mint a GitHub App installation access token end-to-end.

    Fetch the private key from Secrets Manager → build the App JWT → exchange
    for a short-lived installation token. Returns (token, None) on success or
    (None, reason) on any failure. Never raises — callers treat a None token as
    "could not authenticate, skip dispatch".
    """
    if not (app_id and installation_id and private_key_secret_arn):
        return (None, "GitHub App not fully configured (id/installation/secret arn)")

    pem, err = _fetch_private_key(private_key_secret_arn, region)
    if err:
        return (None, err)

    app_jwt, err = _build_app_jwt(app_id, pem)
    if err:
        return (None, err)

    return _exchange_for_installation_token(app_jwt, installation_id)
