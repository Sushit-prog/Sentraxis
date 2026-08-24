"""Integration tests: JWT auth flow + incident API contracts + RBAC."""

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient

pytestmark = [pytest.mark.integration]

T0 = datetime(2026, 8, 24, 9, 0, 0, tzinfo=UTC)
ADMIN_EMAIL = "admin@test.local"
ADMIN_PASSWORD = "test-admin-pass"
USER_EMAIL = "approver@test.local"


def _login(client: TestClient, email: str, password: str):
    return client.post("/api/v1/auth/token", data={"username": email, "password": password})


def _auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_login_success_returns_bearer_token(app_client) -> None:
    resp = _login(app_client, ADMIN_EMAIL, ADMIN_PASSWORD)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["token_type"] == "bearer" and body["access_token"] and body["role"] == "admin"


def test_login_wrong_password_401(app_client) -> None:
    assert _login(app_client, ADMIN_EMAIL, "wrong").status_code == 401


def test_incidents_require_authentication(app_client) -> None:
    assert app_client.get("/api/v1/incidents").status_code == 401


def test_incident_list_and_detail_contract(app_client, _module_session_factory) -> None:
    token = _login(app_client, ADMIN_EMAIL, ADMIN_PASSWORD).json()["access_token"]
    headers = _auth_headers(token)

    # seed one incident + linked detection/evidence
    import uuid as uuid_mod

    from app.persistence.models import (
        DetectionRow,
        EntityRow,
        EventRow,
        IncidentDetectionRow,
        IncidentRow,
    )

    with _module_session_factory() as s, s.begin():
        ent = s.query(EntityRow).filter_by(type="host", identifier="203.0.113.77").first()
        if ent is None:
            ent = EntityRow(type="host", identifier="203.0.113.77")
            s.add(ent)
            s.flush()
        # drop artifacts from prior runs (DB cascades incident_detections)
        stale = s.query(IncidentRow).filter(IncidentRow.title.like("Sweep incident%")).all()
        for old in stale:
            s.delete(old)
        ev = EventRow(
            event_id=uuid_mod.uuid4(),
            ts=T0,
            source="network_flow",
            src_entity_id=ent.id,
            features={"dst_port": 21},
        )
        s.add(ev)
        s.flush()
        det = DetectionRow(
            event_id=ev.id,
            entity_id=ent.id,
            detector="port_velocity",
            detector_version=1,
            score=0.55,
            severity=2,
            details={"observed": 11},
        )
        s.add(det)
        s.flush()
        inc = IncidentRow(
            status="open",
            title="Sweep incident (contract test)",
            narrative="Contract test incident.",
            risk_score=0.55,
            techniques=[
                {
                    "id": "T1046",
                    "name": "Network Service Discovery",
                    "confidence": 0.8,
                    "evidence_detection_ids": [det.id],
                }
            ],
            correlation_mode="rules",
            entity_id=ent.id,
            detection_count=1,
            first_seen_at=T0,
            last_seen_at=T0,
        )
        s.add(inc)
        s.flush()
        s.add(IncidentDetectionRow(incident_id=inc.id, detection_id=det.id))
        inc_id = inc.id

    listed = app_client.get("/api/v1/incidents", headers=headers).json()
    assert listed["total"] >= 1
    match = next(i for i in listed["items"] if i["id"] == inc_id)
    assert match["title"].startswith("Sweep incident")
    assert match["techniques"][0]["id"] == "T1046"

    detail = app_client.get(f"/api/v1/incidents/{inc_id}", headers=headers).json()
    assert detail["detections"][0]["detector"] == "port_velocity"

    assert app_client.get("/api/v1/incidents/999999", headers=headers).status_code == 404


def test_analyze_requires_analyst_or_admin(app_client) -> None:
    approver_token = _login(app_client, USER_EMAIL, "approver-pass").json()["access_token"]
    resp = app_client.post("/api/v1/incidents/1/analyze", headers=_auth_headers(approver_token))
    assert resp.status_code == 403


def test_analyze_without_providers_is_503(app_client, _module_session_factory) -> None:
    from app.persistence.models import IncidentRow

    token = _login(app_client, ADMIN_EMAIL, ADMIN_PASSWORD).json()["access_token"]
    headers = _auth_headers(token)

    with _module_session_factory() as s:
        target = s.query(IncidentRow).first()
        assert target is not None
        inc_id = target.id

    resp = app_client.post(f"/api/v1/incidents/{inc_id}/analyze", headers=headers)
    assert resp.status_code == 503
    assert "not configured" in resp.json()["detail"]
