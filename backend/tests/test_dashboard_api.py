from fastapi.testclient import TestClient

from app.api.v1 import dashboard
from app.main import create_app


def make_client() -> TestClient:
    app = create_app()
    return TestClient(app)


class _FakeCursor:
    """Minimal async-compatible stand-in for a Motor cursor."""

    def __init__(self, results):
        self._results = results

    def sort(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def skip(self, *args, **kwargs):
        return self

    async def to_list(self, length=None):
        return self._results


class _FakeCollection:
    """
    Minimal async-compatible stand-in for a Motor collection.

    `count_documents_result` is either an int (returned regardless of
    filter) or a callable(filter) -> int for filter-sensitive counts.
    `aggregate_result` and `find_result` are lists returned by the
    resulting cursor's `to_list`. `distinct_result` is the list
    returned by `distinct`.
    """

    def __init__(
        self,
        count_documents_result=0,
        aggregate_result=None,
        find_result=None,
        distinct_result=None,
        raise_error=None,
    ):
        self._count_documents_result = count_documents_result
        self._aggregate_result = aggregate_result if aggregate_result is not None else []
        self._find_result = find_result if find_result is not None else []
        self._distinct_result = distinct_result if distinct_result is not None else []
        self._raise_error = raise_error

    async def count_documents(self, filter):
        if self._raise_error is not None:
            raise self._raise_error
        if callable(self._count_documents_result):
            return self._count_documents_result(filter)
        return self._count_documents_result

    def aggregate(self, pipeline):
        if self._raise_error is not None:
            return _RaisingCursor(self._raise_error)
        return _FakeCursor(self._aggregate_result)

    def find(self, *args, **kwargs):
        if self._raise_error is not None:
            return _RaisingCursor(self._raise_error)
        return _FakeCursor(self._find_result)

    async def distinct(self, field):
        if self._raise_error is not None:
            raise self._raise_error
        return self._distinct_result


class _RaisingCursor:
    """Cursor whose to_list raises, for simulating aggregate/find failures."""

    def __init__(self, error):
        self._error = error

    def sort(self, *args, **kwargs):
        return self

    def limit(self, *args, **kwargs):
        return self

    def skip(self, *args, **kwargs):
        return self

    async def to_list(self, length=None):
        raise self._error


class _FakeDatabase:
    """Maps collection names to fake collections, mirroring db[name] access."""

    def __init__(self, collections: dict):
        self._collections = collections

    def __getitem__(self, name):
        return self._collections[name]


def _build_healthy_db():
    """
    A fully populated fake database matching dashboard.py's expected
    query patterns, used as a baseline that individual tests override.
    """
    return _FakeDatabase(
        {
            dashboard._RAW_LOGS_COLLECTION: _FakeCollection(
                count_documents_result=100
            ),
            dashboard._PROCESSED_EVENTS_COLLECTION: _FakeCollection(
                count_documents_result=80
            ),
            dashboard._ANOMALIES_COLLECTION: _FakeCollection(
                count_documents_result=lambda f: 20 if f.get("is_anomalous") else 50,
                aggregate_result=[
                    {
                        "avg_error": 0.42,
                        "max_error": 0.99,
                        "avg_threshold": 0.35,
                    }
                ],
                distinct_result=["host-a", "host-b", "host-c"],
            ),
            dashboard._INCIDENTS_COLLECTION: _FakeCollection(
                count_documents_result=10
            ),
            dashboard._ATTACK_MAPPINGS_COLLECTION: _FakeCollection(
                count_documents_result=15
            ),
            dashboard._RISK_SCORES_COLLECTION: _FakeCollection(
                count_documents_result=10,
                aggregate_result=[
                    {"avg_score": 0.6, "max_score": 0.95},
                ],
            ),
            dashboard._INVESTIGATIONS_COLLECTION: _FakeCollection(
                count_documents_result=5
            ),
            dashboard._MODEL_METADATA_COLLECTION: _FakeCollection(
                find_result=[
                    {
                        "model_version": "v1.2.0",
                        "training_date": "2026-01-01T00:00:00Z",
                        "threshold_value": 0.35,
                        "metrics": {"loss": 0.05, "val_loss": 0.07},
                    }
                ]
            ),
        }
    )


class _MultiAggregateAnomaliesCollection(_FakeCollection):
    """
    Anomalies collection whose `aggregate` returns different results
    depending on the pipeline shape, needed because dashboard.py issues
    two distinct aggregations against this collection (error/threshold
    stats, and top-anomalous-hosts grouping).
    """

    def __init__(
        self,
        count_documents_result,
        stats_result,
        top_hosts_result,
        distinct_result,
    ):
        super().__init__(
            count_documents_result=count_documents_result,
            distinct_result=distinct_result,
        )
        self._stats_result = stats_result
        self._top_hosts_result = top_hosts_result

    def aggregate(self, pipeline):
        is_top_hosts_pipeline = any("$match" in stage for stage in pipeline)
        if is_top_hosts_pipeline:
            return _FakeCursor(self._top_hosts_result)
        return _FakeCursor(self._stats_result)


class _MultiAggregateRiskScoresCollection(_FakeCollection):
    """
    Risk scores collection whose `aggregate` returns different results
    depending on the pipeline shape, needed because dashboard.py issues
    two distinct aggregations against this collection (score stats,
    and severity_counts grouping by risk_label).
    """

    def __init__(self, count_documents_result, score_stats_result, severity_result):
        super().__init__(count_documents_result=count_documents_result)
        self._score_stats_result = score_stats_result
        self._severity_result = severity_result

    def aggregate(self, pipeline):
        group_stage = next(
            (stage["$group"] for stage in pipeline if "$group" in stage), {}
        )
        if group_stage.get("_id") == "$risk_label":
            return _FakeCursor(self._severity_result)
        return _FakeCursor(self._score_stats_result)


def test_dashboard_summary_maps_mocked_database_values(monkeypatch):
    db = _build_healthy_db()
    db._collections[dashboard._ANOMALIES_COLLECTION] = (
        _MultiAggregateAnomaliesCollection(
            count_documents_result=lambda f: 20 if f.get("is_anomalous") else 50,
            stats_result=[
                {"avg_error": 0.42, "max_error": 0.99, "avg_threshold": 0.35}
            ],
            top_hosts_result=[
                {"_id": "host-a", "anomaly_count": 12},
                {"_id": "host-b", "anomaly_count": 8},
            ],
            distinct_result=["host-a", "host-b", "host-c"],
        )
    )
    db._collections[dashboard._RISK_SCORES_COLLECTION] = (
        _MultiAggregateRiskScoresCollection(
            count_documents_result=10,
            score_stats_result=[{"avg_score": 0.6, "max_score": 0.95}],
            severity_result=[
                {"_id": "Low", "count": 4},
                {"_id": "High", "count": 6},
            ],
        )
    )

    monkeypatch.setattr(dashboard, "get_database", lambda: db)

    with make_client() as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    body = response.json()

    assert body["counts"] == {
        "raw_logs": 100,
        "processed_events": 80,
        "anomaly_scores": 50,
        "anomalous": 20,
        "incidents": 10,
        "attack_mappings": 15,
        "risk_scores": 10,
        "investigations": 5,
    }

    assert body["anomaly_summary"]["average_reconstruction_error"] == 0.42
    assert body["anomaly_summary"]["maximum_reconstruction_error"] == 0.99
    assert body["anomaly_summary"]["average_threshold"] == 0.35

    assert body["risk_summary"]["average_final_score"] == 0.6
    assert body["risk_summary"]["maximum_final_score"] == 0.95
    assert body["risk_summary"]["severity_counts"] == {"Low": 4, "High": 6}

    assert body["model"]["model_version"] == "v1.2.0"
    assert body["model"]["threshold_value"] == 0.35
    assert body["model"]["training_loss"] == 0.05
    assert body["model"]["validation_loss"] == 0.07

    assert body["hosts"]["unique_scored_host_count"] == 3
    assert body["hosts"]["top_anomalous_hosts"] == [
        {"host": "host-a", "anomaly_count": 12},
        {"host": "host-b", "anomaly_count": 8},
    ]


def test_dashboard_summary_calculates_anomaly_rate_correctly(monkeypatch):
    db = _build_healthy_db()
    db._collections[dashboard._ANOMALIES_COLLECTION] = (
        _MultiAggregateAnomaliesCollection(
            count_documents_result=lambda f: 25 if f.get("is_anomalous") else 200,
            stats_result=[
                {"avg_error": 0.3, "max_error": 0.8, "avg_threshold": 0.25}
            ],
            top_hosts_result=[],
            distinct_result=["host-a"],
        )
    )
    db._collections[dashboard._RISK_SCORES_COLLECTION] = (
        _MultiAggregateRiskScoresCollection(
            count_documents_result=0,
            score_stats_result=[],
            severity_result=[],
        )
    )

    monkeypatch.setattr(dashboard, "get_database", lambda: db)

    with make_client() as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    body = response.json()

    # 25 / 200 * 100 == 12.5
    assert body["anomaly_summary"]["anomaly_rate"] == 12.5
    assert body["counts"]["anomalous"] == 25
    assert body["counts"]["anomaly_scores"] == 200


def test_dashboard_summary_returns_safe_zeros_for_empty_collections(monkeypatch):
    empty_collection = _FakeCollection(count_documents_result=0)
    anomalies_collection = _MultiAggregateAnomaliesCollection(
        count_documents_result=0,
        stats_result=[],
        top_hosts_result=[],
        distinct_result=[],
    )
    risk_scores_collection = _MultiAggregateRiskScoresCollection(
        count_documents_result=0,
        score_stats_result=[],
        severity_result=[],
    )
    model_metadata_collection = _FakeCollection(find_result=[])

    db = _FakeDatabase(
        {
            dashboard._RAW_LOGS_COLLECTION: empty_collection,
            dashboard._PROCESSED_EVENTS_COLLECTION: empty_collection,
            dashboard._ANOMALIES_COLLECTION: anomalies_collection,
            dashboard._INCIDENTS_COLLECTION: empty_collection,
            dashboard._ATTACK_MAPPINGS_COLLECTION: empty_collection,
            dashboard._RISK_SCORES_COLLECTION: risk_scores_collection,
            dashboard._INVESTIGATIONS_COLLECTION: empty_collection,
            dashboard._MODEL_METADATA_COLLECTION: model_metadata_collection,
        }
    )

    monkeypatch.setattr(dashboard, "get_database", lambda: db)

    with make_client() as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    body = response.json()

    assert body["counts"] == {
        "raw_logs": 0,
        "processed_events": 0,
        "anomaly_scores": 0,
        "anomalous": 0,
        "incidents": 0,
        "attack_mappings": 0,
        "risk_scores": 0,
        "investigations": 0,
    }

    assert body["anomaly_summary"] == {
        "anomaly_rate": 0.0,
        "average_reconstruction_error": 0.0,
        "maximum_reconstruction_error": 0.0,
        "average_threshold": 0.0,
    }

    assert body["risk_summary"] == {
        "average_final_score": 0.0,
        "maximum_final_score": 0.0,
        "severity_counts": {},
    }

    assert body["model"] is None

    assert body["hosts"] == {
        "unique_scored_host_count": 0,
        "top_anomalous_hosts": [],
    }


def test_dashboard_summary_returns_null_model_when_metadata_missing(monkeypatch):
    db = _build_healthy_db()
    db._collections[dashboard._ANOMALIES_COLLECTION] = (
        _MultiAggregateAnomaliesCollection(
            count_documents_result=lambda f: 20 if f.get("is_anomalous") else 50,
            stats_result=[
                {"avg_error": 0.42, "max_error": 0.99, "avg_threshold": 0.35}
            ],
            top_hosts_result=[],
            distinct_result=["host-a"],
        )
    )
    db._collections[dashboard._RISK_SCORES_COLLECTION] = (
        _MultiAggregateRiskScoresCollection(
            count_documents_result=10,
            score_stats_result=[{"avg_score": 0.6, "max_score": 0.95}],
            severity_result=[],
        )
    )
    db._collections[dashboard._MODEL_METADATA_COLLECTION] = _FakeCollection(
        find_result=[]
    )

    monkeypatch.setattr(dashboard, "get_database", lambda: db)

    with make_client() as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 200
    body = response.json()

    assert body["model"] is None


def test_dashboard_summary_returns_500_on_mongo_failure_without_exposing_details(
    monkeypatch,
):
    from pymongo.errors import PyMongoError

    secret_error = PyMongoError(
        "internal connection string leaked: mongodb://admin:s3cr3t@host"
    )

    failing_collection = _FakeCollection(raise_error=secret_error)

    db = _FakeDatabase(
        {
            dashboard._RAW_LOGS_COLLECTION: failing_collection,
            dashboard._PROCESSED_EVENTS_COLLECTION: failing_collection,
            dashboard._ANOMALIES_COLLECTION: failing_collection,
            dashboard._INCIDENTS_COLLECTION: failing_collection,
            dashboard._ATTACK_MAPPINGS_COLLECTION: failing_collection,
            dashboard._RISK_SCORES_COLLECTION: failing_collection,
            dashboard._INVESTIGATIONS_COLLECTION: failing_collection,
            dashboard._MODEL_METADATA_COLLECTION: failing_collection,
        }
    )

    monkeypatch.setattr(dashboard, "get_database", lambda: db)

    with make_client() as client:
        response = client.get("/api/v1/dashboard/summary")

    assert response.status_code == 500

    body = response.json()
    detail = body["detail"]

    assert "s3cr3t" not in detail
    assert "mongodb://" not in detail
    assert detail == "Failed to retrieve dashboard counts."


def test_openapi_exposes_dashboard_summary_route():
    app = create_app()
    paths = app.openapi()["paths"]

    assert "/api/v1/dashboard/summary" in paths