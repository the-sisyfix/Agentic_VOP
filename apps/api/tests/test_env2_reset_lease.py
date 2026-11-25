"""Reset endpoints share the per-instance fix-sandbox lease with SA-4."""

import pytest
from fastapi import HTTPException

from app import leases, main
from app.agents.fixer.orchestrator import env2_lease_resource
from app.leases import hold_lease
from tests.test_leases import FakeLeaseTable


@pytest.fixture
def sb(monkeypatch):
    fake = FakeLeaseTable()
    monkeypatch.setattr(leases, "_leases_client", lambda: fake)
    monkeypatch.setattr(main.settings, "fixer_env2_instance_id", "i-prod")
    return fake


def test_lease_key_is_per_instance():
    assert env2_lease_resource("i-prod") != env2_lease_resource("i-dev")
    assert env2_lease_resource("") == "fixer:default"


def test_reset_runs_and_releases_when_free(sb):
    calls = []

    @main._holds_env2_lease
    def reset() -> dict:
        calls.append(dict(sb.rows))
        return {"ok": True}

    assert reset() == {"ok": True}
    assert "fixer:i-prod" in calls[0]  # held while the reset ran
    assert sb.rows == {}  # released afterwards


def test_reset_409s_while_a_fix_holds_the_same_instance(sb):
    @main._holds_env2_lease
    def reset() -> dict:
        raise AssertionError("reset must not run during a fix")

    with hold_lease("fixer:i-prod", label="package #1", sb=sb):
        with pytest.raises(HTTPException) as exc:
            reset()
    assert exc.value.status_code == 409
    assert "package #1" in exc.value.detail


def test_fix_on_another_instance_does_not_block_reset(sb):
    @main._holds_env2_lease
    def reset() -> dict:
        return {"ok": True}

    with hold_lease("fixer:i-dev", label="dev fix", sb=sb):
        assert reset() == {"ok": True}
