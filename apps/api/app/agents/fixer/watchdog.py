"""Watchdog + reaper for fix_runs.

Guarantees every fix_run reaches a terminal status (`success`/`failed`/
`rolled_back`) within its declared `timeout_seconds`. Three complementary
mechanisms:

1. `check_run_health()` — called at each `_run_lifecycle` phase boundary
   AND inside RemoteExecutor's SSM polling loop. Raises
   `WatchdogTimeout` if elapsed > `timeout_seconds`, or `RunCancelledError`
   if the operator flipped `agent_runs.cancellation_requested`.

2. `run_deadline()` — helper used by RemoteExecutor to shorten its own
   per-command hard cap to `min(command_cap, run_deadline_remaining)`, so
   a single hanging SSM call can't exceed the run-level budget.

3. `sweep_stale_fix_runs()` — background reaper (run every 60s from main.py
   startup) that force-fails any fix_run whose `started_at + timeout_seconds`
   is in the past AND whose status is still non-terminal. Catches process
   crashes / SIGKILL / OOM where no in-process finalize can run.

Same code path works against public.fix_runs and demo.fix_runs — caller
passes the appropriate supabase client.
"""

from __future__ import annotations

from datetime import datetime, timedelta, UTC
from typing import Any

from .models import utcnow

# Statuses considered "still in flight" — anything not in the terminal set.
NON_TERMINAL_STATUSES: tuple[str, ...] = (
    "pending",
    "provisioning",
    "executing",
    "validating",
)


class WatchdogTimeout(Exception):
    """Raised when a fix_run exceeds its declared timeout_seconds."""


class RunCancelledError(Exception):
    """Raised when the operator has requested cancellation on the parent agent_run.

    Distinct from the same-named class in `app.agents.trace_demo`. The fixer
    catches this specific class and treats it as an orderly abort — not a bug.
    """


# =============================================================================
# In-process check — call between phase boundaries + inside polling loops
# =============================================================================
def check_run_health(
    sb: Any,
    *,
    agent_run_id: str,
    fix_run_id: int,
    started_at: datetime,
    timeout_seconds: int,
) -> None:
    """Raise if the fix_run should abort.

    Two conditions:
      - Wall-clock: elapsed since `started_at` > `timeout_seconds`
      - Cancellation: `agent_runs.cancellation_requested = true`

    Both are cheap (one small SELECT per call). Safe to call from tight
    loops. All exceptions raised here are caught by the orchestrator's
    top-level try/finally, which finalizes the row as `failed`.
    """
    now = utcnow()
    elapsed = (now - started_at).total_seconds()
    if elapsed > timeout_seconds:
        raise WatchdogTimeout(
            f"fix_run #{fix_run_id} exceeded timeout_seconds={timeout_seconds} "
            f"(elapsed={int(elapsed)}s)"
        )

    # Cancellation flag lookup — best-effort. If the DB is transiently
    # unavailable, fall through (a stale "no cancel" reading is better
    # than a false-positive abort).
    try:
        resp = (
            sb.table("agent_runs")
            .select("cancellation_requested, status")
            .eq("run_id", agent_run_id)
            .limit(1)
            .execute()
        )
        row = (resp.data or [{}])[0]
    except Exception:  # noqa: BLE001
        return

    if row.get("cancellation_requested"):
        raise RunCancelledError(
            f"agent_run {agent_run_id[:8]} cancellation_requested — aborting fix_run #{fix_run_id}"
        )


def run_deadline_remaining(started_at: datetime, timeout_seconds: int) -> float:
    """Seconds remaining in this fix_run's budget. Never negative."""
    remaining = timeout_seconds - (utcnow() - started_at).total_seconds()
    return max(0.0, remaining)


# =============================================================================
# Reaper — catches out-of-process zombies (SIGKILL, OOM, backend restart)
# =============================================================================
def sweep_stale_fix_runs(sb: Any) -> int:
    """Force-fail any fix_run past its declared timeout that's still marked
    non-terminal. Returns count of rows reaped.

    Designed to be called on a periodic schedule (~60s). Idempotent — a
    fix_run reaped once stays terminal and won't be touched again.

    Uses server-side filtering so a large fix_runs history doesn't cause
    pagination pain.
    """
    now = utcnow()
    resp = (
        sb.table("fix_runs")
        .select("id, package_id, started_at, timeout_seconds, status")
        .in_("status", NON_TERMINAL_STATUSES)
        .limit(200)
        .execute()
    )
    rows = resp.data or []
    reaped = 0
    for r in rows:
        try:
            started_at = _parse_iso(r["started_at"])
        except Exception:  # noqa: BLE001, S112
            continue
        timeout_s = int(r.get("timeout_seconds") or 300)
        # Grace: give an extra 30s so we don't race a fix_run that is
        # actively finalizing at exactly timeout_seconds.
        deadline = started_at + timedelta(seconds=timeout_s + 30)
        if deadline >= now:
            continue

        age_s = int((now - started_at).total_seconds())
        try:
            # Compare-and-set: only update if the row is STILL non-terminal.
            # If finalize_fix_run raced us and already wrote 'success' /
            # 'rolled_back' / 'failed' between our SELECT and this UPDATE,
            # the `.in_("status", NON_TERMINAL_STATUSES)` filter matches 0
            # rows and finalize's authoritative result stands. Never clobber
            # a real finalize with a reaper's fake "failed" status.
            resp = (
                sb.table("fix_runs")
                .update(
                    {
                        "status": "failed",
                        "finished_at": now.isoformat(),
                        "duration_seconds": age_s,
                        "error_message": (
                            f"reaped by watchdog — status was {r['status']!r} "
                            f"{age_s}s after start (timeout_seconds={timeout_s}). "
                            f"Fixer process likely crashed or hung; no in-process "
                            f"finalize occurred."
                        ),
                    }
                )
                .eq("id", r["id"])
                .in_("status", NON_TERMINAL_STATUSES)
                .execute()
            )
            if resp.data:
                reaped += 1
                # Reconcile the parent package. Finalize normally flips the
                # package to 'fix_failed' / 'fixed' / 'rolled_back' — but if
                # the fixer crashed mid-execution finalize never ran, so the
                # package is stuck in an in-flight state (ready_for_execution,
                # provisioning, executing, validating). Mirror the reaped
                # fix_run's outcome onto the package so the UI matches reality.
                pkg_id = r.get("package_id")
                if pkg_id:
                    try:
                        sb.table("remediation_packages").update({"status": "fix_failed"}).eq(
                            "id", pkg_id
                        ).in_(
                            "status",
                            [
                                "ready_for_execution",
                                "provisioning",
                                "executing",
                                "validating",
                                "applying",
                            ],
                        ).execute()
                    except Exception:  # noqa: BLE001, S110
                        # Non-fatal — next sweep is idempotent via the status filter.
                        pass
        except Exception:  # noqa: BLE001, S110
            # Ignoring is safe — next sweep will re-evaluate.
            pass
    return reaped


def _parse_iso(s: str) -> datetime:
    """Robust ISO parser — Supabase timestamps come back with `+00:00`."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt
