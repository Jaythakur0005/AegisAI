from fastapi.testclient import TestClient

from app.api.v1 import health
from app.main import create_app


def make_client() -> TestClient:
    app = create_app()
    return TestClient(app)


def test_health_returns_healthy_when_mongodb_is_up(monkeypatch):
    async def mongo_is_up():
        return True

    monkeypatch.setattr(health, "check_mongo_health", mongo_is_up)

    with make_client() as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 200

    body = response.json()

    assert body["status"] == "healthy"
    assert body["dependencies"] == [
        {"name": "mongodb", "status": "up"}
    ]
    assert body["app_name"]
    assert body["app_env"]
    assert body["model_version"]
    assert body["timestamp"]


def test_health_returns_degraded_when_mongodb_is_down(monkeypatch):
    async def mongo_is_down():
        return False

    monkeypatch.setattr(health, "check_mongo_health", mongo_is_down)

    with make_client() as client:
        response = client.get("/api/v1/health")

    assert response.status_code == 503

    body = response.json()

    assert body["status"] == "degraded"
    assert body["dependencies"] == [
        {"name": "mongodb", "status": "down"}
    ]


def test_pipeline_rejects_empty_log_list():
    with make_client() as client:
        response = client.post(
            "/api/v1/pipeline/run",
            json={"logs": []},
        )

    assert response.status_code == 422


def test_pipeline_rejects_missing_logs_field():
    with make_client() as client:
        response = client.post(
            "/api/v1/pipeline/run",
            json={},
        )

    assert response.status_code == 422


def test_incident_detail_rejects_invalid_object_id():
    with make_client() as client:
        response = client.get(
            "/api/v1/incidents/not-a-valid-object-id"
        )

    assert response.status_code == 400
    assert "Invalid incident_id" in response.json()["detail"]


def test_investigation_rejects_invalid_object_id():
    with make_client() as client:
        response = client.get(
            "/api/v1/investigation/not-a-valid-object-id"
        )

    assert response.status_code == 400
    assert "Invalid incident_id" in response.json()["detail"]


def test_openapi_exposes_core_aegisai_routes():
    app = create_app()
    paths = app.openapi()["paths"]

    expected_paths = {
        "/api/v1/health",
        "/api/v1/pipeline/run",
        "/api/v1/incidents",
        "/api/v1/incidents/{incident_id}",
        "/api/v1/investigation/{incident_id}",
        "/api/v1/investigation/{incident_id}/generate",
    }

    assert expected_paths.issubset(paths.keys())
