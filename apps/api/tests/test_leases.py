"""Unit tests for app.leases against an in-memory stand-in for public.run_leases."""

import threading
import time
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from postgrest.exceptions import APIError

from app import leases
from app.leases import LeaseTimeout, hold_lease


class _Query:
    def __init__(self, store, lock, op, payload=None):
        self.store, self.lock, self.op, self.payload = store, lock, op, payload
        self.filters = []

    def eq(self, col, val):
        self.filters.append(lambda r: r[col] == val)
        return self

    def lt(self, col, val):
        self.filters.append(lambda r: r[col] < val)
        return self

    def select(self, *_):
        return self

    def limit(self, _):
        return self

    def execute(self):
        with self.lock:
            if self.op == "insert":
                if self.payload["resource"] in self.store:
                    raise APIError({"code": "23505", "message": "duplicate key"})
                self.store[self.payload["resource"]] = dict(self.payload)
                return SimpleNamespace(data=[dict(self.payload)])
            hits = [r for r in self.store.values() if all(f(r) for f in self.filters)]
            if self.op == "update":
                for r in hits:
                    r.update(self.payload)
            elif self.op == "delete":
                for r in hits:
                    del self.store[r["resource"]]
            return SimpleNamespace(data=[dict(r) for r in hits])


class FakeLeaseTable:
    """Just enough of the supabase-py builder API for app.leases."""

    def __init__(self):
        self.rows: dict[str, dict] = {}
        self._lock = threading.Lock()

    def table(self, name):
        assert name == leases.LEASE_TABLE
        return SimpleNamespace(
            insert=lambda p: _Query(self.rows, self._lock, "insert", p),
            update=lambda p: _Query(self.rows, self._lock, "update", p),
            delete=lambda: _Query(self.rows, self._lock, "delete"),
            select=lambda *_: _Query(self.rows, self._lock, "select"),
        )


def test_acquire_and_release():
    sb = FakeLeaseTable()
    with hold_lease("r", label="a", sb=sb) as waited:
        assert waited == 0
        assert sb.rows["r"]["label"] == "a"
    assert sb.rows == {}


def test_second_holder_times_out_while_first_holds():
    sb = FakeLeaseTable()
    waits = []
    with hold_lease("r", label="first", sb=sb):
        with pytest.raises(LeaseTimeout) as exc:
            with hold_lease(
                "r", label="second", sb=sb, wait_max_s=0.2, poll_s=0.05, on_wait=waits.append
            ):
                pass
    assert exc.value.holder["label"] == "first"
    assert len(waits) == 1 and waits[0]["label"] == "first"


def test_different_resources_do_not_block():
    sb = FakeLeaseTable()
    with hold_lease("a", label="x", sb=sb), hold_lease("b", label="y", sb=sb, wait_max_s=0):
        assert set(sb.rows) == {"a", "b"}


def test_waiter_gets_lease_after_holder_releases():
    sb = FakeLeaseTable()
    order = []
    first_in = threading.Event()

    def first():
        with hold_lease("r", label="first", sb=sb):
            first_in.set()
            time.sleep(0.2)
            order.append("first done")

    t = threading.Thread(target=first)
    t.start()
    first_in.wait()
    with hold_lease("r", label="second", sb=sb, poll_s=0.05) as waited:
        order.append("second in")
    t.join()
    assert order == ["first done", "second in"]
    assert waited >= 0


def test_expired_lease_from_dead_holder_is_taken_over():
    sb = FakeLeaseTable()
    past = (datetime.now(UTC) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    sb.rows["r"] = {"resource": "r", "holder": "dead", "label": "crashed", "expires_at": past}
    with hold_lease("r", label="new", sb=sb, wait_max_s=0):
        assert sb.rows["r"]["label"] == "new"


def test_heartbeat_keeps_lease_alive_past_ttl():
    sb = FakeLeaseTable()
    with hold_lease("r", label="slow", sb=sb, ttl_s=1):
        first_expiry = sb.rows["r"]["expires_at"]
        time.sleep(1.5)  # longer than ttl; heartbeat runs every ~ttl/3 (min 1s)
        assert sb.rows["r"]["expires_at"] > first_expiry
        with pytest.raises(LeaseTimeout):
            with hold_lease("r", label="other", sb=sb, wait_max_s=0):
                pass


def test_check_abort_stops_waiting():
    sb = FakeLeaseTable()

    class Cancelled(Exception):
        pass

    def abort():
        raise Cancelled

    with hold_lease("r", label="first", sb=sb):
        with pytest.raises(Cancelled):
            with hold_lease("r", label="second", sb=sb, check_abort=abort):
                pass


def test_release_does_not_delete_someone_elses_lease():
    sb = FakeLeaseTable()
    with hold_lease("r", label="mine", sb=sb):
        # Simulate our lease expiring and being taken over mid-run.
        sb.rows["r"]["holder"] = "someone-else"
    assert sb.rows["r"]["holder"] == "someone-else"
