"""ingest-api behaviour with the database and broker faked out."""

import json

import pytest
from fastapi.testclient import TestClient

from triage import hmac_auth
from triage.config import Settings
from triage.ingest.app import create_app

SECRET = "test-secret"


class FakePool:
    def __init__(self):
        self.alerts: dict[str, dict] = {}
        self.audit: list[tuple] = []

    async def fetchrow(self, sql, alert_id, *args):
        row = self.alerts.get(alert_id)
        if row is None:
            self.alerts[alert_id] = {"queued_at": None}
            return {"queued_at": None, "inserted": True}
        return {"queued_at": row["queued_at"], "inserted": False}

    async def execute(self, sql, *args):
        if sql.startswith("UPDATE alerts"):
            self.alerts[args[0]]["queued_at"] = "now"
        elif "audit_append" in sql:
            self.audit.append(args)

    async def fetchval(self, sql):
        return 1


class FakeExchange:
    name = "triage.alerts"

    def __init__(self):
        self.published = []

    async def publish(self, message, routing_key, mandatory=True):
        self.published.append((routing_key, message))


class FakeTopology:
    def __init__(self):
        self.alerts = FakeExchange()


@pytest.fixture
def client():
    app = create_app(Settings(hmac_secrets=SECRET, otlp_endpoint=None))
    app.state.pool = FakePool()
    app.state.topology = FakeTopology()
    return TestClient(app), app


def _post(c, payload, secret=SECRET, fmt="generic"):
    body = json.dumps(payload).encode()
    headers = hmac_auth.sign(secret.encode(), body) | {"content-type": "application/json"}
    return c.post(f"/alerts?format={fmt}", content=body, headers=headers)


PAYLOAD = {"rule_title": "Mimikatz", "timestamp": "2024-01-01T00:00:00Z", "source_ref": "evt-1",
           "severity": "high"}


def test_valid_alert_is_queued_once(client):
    c, app = client
    r = _post(c, PAYLOAD)
    assert r.status_code == 202 and r.json()["status"] == "queued"
    r2 = _post(c, PAYLOAD)
    assert r2.status_code == 200 and r2.json()["status"] == "duplicate"
    assert len(app.state.topology.alerts.published) == 1
    routing_key, message = app.state.topology.alerts.published[0]
    assert routing_key == "alert"
    assert message.message_id == r.json()["alert_id"]
    assert json.loads(message.body)["rule_title"] == "Mimikatz"
    assert len(app.state.pool.audit) == 1


def test_bad_signature_is_401_and_not_queued(client):
    c, app = client
    r = _post(c, PAYLOAD, secret="wrong")
    assert r.status_code == 401
    assert app.state.topology.alerts.published == []


def test_invalid_alert_is_422(client):
    c, _ = client
    assert _post(c, {"timestamp": "2024-01-01T00:00:00Z"}).status_code == 422


def test_oversized_body_is_413(client):
    c, _ = client
    big = PAYLOAD | {"description": "x" * 300_000}
    assert _post(c, big).status_code == 413
