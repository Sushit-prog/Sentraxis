from fastapi.testclient import TestClient

from app.main import create_app


def test_healthz_returns_ok_contract() -> None:
    client = TestClient(create_app())
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_app_factory_isolates_state() -> None:
    """Two app instances must not share mutable state objects."""
    app_one = create_app()
    app_two = create_app()
    assert app_one.state.engine is not app_two.state.engine
    assert app_one.state.session_factory is not app_two.state.session_factory
