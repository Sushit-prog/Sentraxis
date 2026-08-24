"""Security review tests (M6): authn/z boundaries, injection resistance, abuse limits."""

import pytest
from fastapi.testclient import TestClient

from tests.integration.conftest import ADMIN_EMAIL, ADMIN_PASSWORD

pytestmark = [pytest.mark.integration]


def _token(client: TestClient) -> str:
    return client.post(
        "/api/v1/auth/token", data={"username": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    ).json()["access_token"]


def _hdr(client: TestClient) -> dict[str, str]:
    return {"Authorization": f"Bearer {_token(client)}"}


# ---- token integrity --------------------------------------------------------


def test_tampered_token_rejected(app_client) -> None:
    good = _token(app_client)
    tampered = good[:-6] + ("aaaaaa" if not good.endswith("aaaaaa") else "bbbbbb")
    resp = app_client.get("/api/v1/incidents", headers={"Authorization": f"Bearer {tampered}"})
    assert resp.status_code == 401


def test_garbage_scheme_rejected(app_client) -> None:
    for header in (
        "Basic dXNlcjpwYXNz",
        "Bearer",
        "Bearer ",
        f"Token {_token(app_client)}",
    ):
        resp = app_client.get("/api/v1/incidents", headers={"Authorization": header})
        assert resp.status_code == 401, header


# ---- RBAC matrix ------------------------------------------------------------


def test_analyst_cannot_approve_actions(app_client, _module_session_factory) -> None:
    """Approver role exists precisely so analysts cannot execute containment."""
    from app.persistence.models import ActionRow, UserRow
    from app.security import hash_password

    with _module_session_factory() as s, s.begin():
        s.query(UserRow).filter(UserRow.email == "analyst@test.local").delete(
            synchronize_session=False
        )
        s.add(
            UserRow(
                email="analyst@test.local",
                password_hash=hash_password("analyst-pass"),
                role="analyst",
            )
        )

    analyst_token = app_client.post(
        "/api/v1/auth/token", data={"username": "analyst@test.local", "password": "analyst-pass"}
    ).json()["access_token"]

    with _module_session_factory() as s:
        target = s.query(ActionRow).first()
        action_id = target.id if target else 999999

    resp = app_client.post(
        f"/api/v1/actions/{action_id}/approve",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"reason": "should be forbidden"},
    )
    assert resp.status_code == 403


# ---- injection / abuse resistance -------------------------------------------


def test_status_filter_injection_is_safe(app_client) -> None:
    malicious = "open'; DROP TABLE incidents; --"
    resp = app_client.get(
        "/api/v1/incidents", params={"status": malicious}, headers=_hdr(app_client)
    )
    assert resp.status_code in (200, 422), "must not 500"
    # table still functional afterwards
    ok = app_client.get("/api/v1/incidents", headers=_hdr(app_client))
    assert ok.status_code == 200


def test_limit_parameter_clamped(app_client) -> None:
    resp = app_client.get("/api/v1/incidents", params={"limit": 100000}, headers=_hdr(app_client))
    assert resp.status_code == 422


def test_negative_offset_rejected(app_client) -> None:
    resp = app_client.get("/api/v1/incidents", params={"offset": -5}, headers=_hdr(app_client))
    assert resp.status_code == 422


# ---- metrics exposure -------------------------------------------------------


def test_metrics_require_auth_and_expose_core_series(app_client) -> None:
    assert app_client.get("/api/v1/metrics").status_code == 401
    body = app_client.get("/api/v1/metrics", headers=_hdr(app_client))
    assert body.status_code == 200
    text = body.text
    for series in (
        "sentraxis_events_total",
        "sentraxis_incidents_total",
        "sentraxis_actions_total",
        "sentraxis_llm_calls_total",
    ):
        assert series in text, series
