"""Cross-process leases backed by `public.run_leases` (migration 0044).

Why a lease table and not a Postgres advisory lock: every supabase-py call
is a separate PostgREST HTTP request, so a session-level advisory lock is
released as soon as the request that took it returns. A row with an expiry
survives between requests, and a heartbeat keeps it alive while the holder
works.

Semantics:
  - One row per `resource`. Whoever inserts it (or takes over an expired
    row) holds the lease; everyone else polls.
  - The holder renews `expires_at` every ttl/3 from a daemon thread. If the
    process dies, the row expires after `ttl_s` and the next waiter takes
    it over — no manual cleanup, no 30-minute stuck lock.
  - Expiry is compared against the caller's clock, so hosts sharing a lease
    must keep their clocks within `ttl_s` of each other (NTP is plenty).

The table always lives in `public`, never in `dev` or `demo`: the things it
guards (the env2 instance, scanner watermarks) are shared by every pipeline
that talks to this Supabase project, whatever schema it writes its own
rows to.
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from postgrest.exceptions import APIError

logger = logging.getLogger(__name__)

LEASE_TABLE = "run_leases"
_UNIQUE_VIOLATION = "23505"


class LeaseTimeout(RuntimeError):
    """Raised when a lease could not be acquired within `wait_max_s`."""

    def __init__(self, resource: str, waited_s: int, holder: dict | None):
        self.resource = resource
        self.waited_s = waited_s
        self.holder = holder
        label = (holder or {}).get("label") or "unknown holder"
        super().__init__(f"lease '{resource}' still held by {label} after {waited_s}s")


def _iso(dt: datetime) -> str:
    # `Z` instead of `+00:00` so the value survives URL query encoding intact.
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _leases_client() -> Any:
    from supabase import create_client  # noqa: PLC0415 — keep import cost off module load

    from .config import settings  # noqa: PLC0415

    return create_client(
        settings.agentic_vop_supabase_url,
        settings.agentic_vop_supabase_service_key,
    )


class Lease:
    """One attempt to hold `resource`. Use `hold_lease()` rather than this directly."""

    def __init__(self, sb: Any, resource: str, label: str, ttl_s: int):
        self.sb = sb
        self.resource = resource
        self.label = label
        self.ttl_s = ttl_s
        self.holder = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:12]}"

    def _row(self) -> dict:
        now = datetime.now(UTC)
        return {
            "resource": self.resource,
            "holder": self.holder,
            "label": self.label,
            "acquired_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=self.ttl_s)),
        }

    def try_acquire(self) -> bool:
        row = self._row()
        try:
            self.sb.table(LEASE_TABLE).insert(row).execute()
            return True
        except APIError as e:
            if getattr(e, "code", None) != _UNIQUE_VIOLATION:
                raise
        # Row exists. Take it over only if it has expired — the WHERE clause
        # makes this a single atomic compare-and-set in Postgres, so two
        # waiters can't both win.
        resp = (
            self.sb.table(LEASE_TABLE)
            .update(row)
            .eq("resource", self.resource)
            .lt("expires_at", row["acquired_at"])
            .execute()
        )
        return bool(resp.data)

    def renew(self) -> bool:
        """Push expires_at forward. False means the lease was lost (expired and taken over)."""
        expires_at = _iso(datetime.now(UTC) + timedelta(seconds=self.ttl_s))
        resp = (
            self.sb.table(LEASE_TABLE)
            .update({"expires_at": expires_at})
            .eq("resource", self.resource)
            .eq("holder", self.holder)
            .execute()
        )
        return bool(resp.data)

    def release(self) -> None:
        self.sb.table(LEASE_TABLE).delete().eq("resource", self.resource).eq(
            "holder", self.holder
        ).execute()

    def current_holder(self) -> dict | None:
        resp = (
            self.sb.table(LEASE_TABLE)
            .select("holder, label, acquired_at, expires_at")
            .eq("resource", self.resource)
            .limit(1)
            .execute()
        )
        rows = resp.data or []
        return rows[0] if rows else None


def _heartbeat(lease: Lease, stop: threading.Event) -> None:
    interval = max(1.0, lease.ttl_s / 3)
    while not stop.wait(interval):
        try:
            if not lease.renew():
                # Another process took the lease over after it expired — most
                # likely this process stalled for longer than ttl_s. Nothing
                # safe to do from a background thread; make it loud.
                logger.error("lease '%s' lost by %s", lease.resource, lease.holder)
                return
        except Exception:  # noqa: BLE001 — transient network error; retry next tick
            logger.warning("lease '%s' renew failed; will retry", lease.resource, exc_info=True)


@contextmanager
def hold_lease(
    resource: str,
    *,
    label: str,
    ttl_s: int = 120,
    wait_max_s: int = 1800,
    poll_s: float = 5,
    on_wait: Callable[[dict | None], None] | None = None,
    check_abort: Callable[[], None] | None = None,
    sb: Any = None,
) -> Iterator[int]:
    """Block until `resource` is held, yield the seconds spent waiting, release on exit.

    Args:
        resource:    lease key, e.g. "fixer:env2" or "sa1:public:tenable"
        label:       human-readable owner shown to waiters ("package #12, run abc…")
        ttl_s:       how long a dead holder can block others
        wait_max_s:  give up and raise LeaseTimeout after this long
        poll_s:      seconds between acquire attempts while waiting
        on_wait:     called once, with the current holder row, when we first have to wait
        check_abort: called before each wait; raise from it to stop waiting (e.g. on cancel)
        sb:          supabase client for `public` (tests inject a fake)
    """
    lease = Lease(sb or _leases_client(), resource, label, ttl_s)
    waited = 0.0
    notified = False
    while not lease.try_acquire():
        if waited >= wait_max_s:
            raise LeaseTimeout(resource, int(waited), lease.current_holder())
        if check_abort is not None:
            check_abort()
        if on_wait is not None and not notified:
            on_wait(lease.current_holder())
            notified = True
        time.sleep(poll_s)
        waited += poll_s

    stop = threading.Event()
    beat = threading.Thread(
        target=_heartbeat, args=(lease, stop), name=f"lease:{resource}", daemon=True
    )
    beat.start()
    try:
        yield int(waited)
    finally:
        stop.set()
        beat.join(timeout=5)
        try:
            lease.release()
        except Exception:  # noqa: BLE001 — row will expire on its own after ttl_s
            logger.warning("lease '%s' release failed; it will expire", resource, exc_info=True)
