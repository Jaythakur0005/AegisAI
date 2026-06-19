"""
Anomaly detection service.

Implements Stage 3 (Autoencoder Anomaly Detection) from
ARCHITECTURE_V2.md: reads `ProcessedEvent` documents from
`processed_events`, runs them through the pretrained TensorFlow
autoencoder, computes reconstruction error per event, compares it
against a threshold, and persists the resulting `Anomaly` documents
into the `anomalies` collection.

This module performs inference only — it does not train or fit any
model or scaler (see ARCHITECTURE_V2.md's `app/core/ml/train.py`,
which is out of scope here). It loads pre-trained artifacts from the
paths configured in `Settings.autoencoder_model_path` and
`Settings.feature_scaler_path`.

Threshold resolution order (since `Settings.anomaly_threshold_value` is
optional, per its description that an unset value falls back to
percentile-based thresholding):

    1. `Settings.anomaly_threshold_value`, if explicitly set.
    2. The threshold value recorded in `model_metadata` for the loaded
       model's `Settings.model_version`, if such a record exists.
    3. A per-batch fallback: the `Settings.anomaly_threshold_percentile`
       percentile of the current batch's own reconstruction errors.
       This fallback only applies when no stored threshold is
       available at all (e.g. first run before any model_metadata
       record exists) and is logged loudly, since it means the
       threshold is not stable across runs.

This module reads from and writes to MongoDB directly via
`app.db.mongo_client.get_database()`, consistent with the precedent set
in `app.services.log_ingestion` and `app.services.feature_engineering`
(no repository layer exists yet for `processed_events`/`anomalies`).
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, Sequence

import numpy as np
from pymongo.errors import PyMongoError

from app.core.config import Settings, get_settings
from app.core.logging import get_logger
from app.db.mongo_client import get_database
from app.models.anomaly import Anomaly
from app.models.processed_event import ProcessedEvent
from app.models.raw_log import PyObjectId

logger = get_logger(__name__)

_PROCESSED_EVENTS_COLLECTION = "processed_events"
_ANOMALIES_COLLECTION = "anomalies"
_MODEL_METADATA_COLLECTION = "model_metadata"

# Reconstruction error is computed as mean squared error between the
# scaled input feature vector and the autoencoder's reconstruction of
# it, averaged across feature dimensions. This is the standard,
# auditable choice for autoencoder-based anomaly scoring and is not
# further parameterized.
_MSE_AXIS = -1


class AnomalyDetectionError(RuntimeError):
    """
    Raised for failures that prevent anomaly detection from proceeding
    at all (e.g. the model/scaler artifacts can't be loaded, or the
    database is unreachable), as distinct from a single malformed
    ProcessedEvent, which is skipped and logged rather than raised.
    """


class _ScalerProtocol(Protocol):
    """
    Structural type for the loaded feature scaler.

    Matches the `transform` method signature shared by scikit-learn
    scalers (e.g. StandardScaler, MinMaxScaler), without depending on
    sklearn's concrete types at the type-checking level.
    """

    def transform(self, X: np.ndarray) -> np.ndarray: ...  # noqa: N803


class _AutoencoderProtocol(Protocol):
    """
    Structural type for the loaded autoencoder model.

    Matches the `predict` method signature shared by Keras/TensorFlow
    models, without depending on tensorflow's concrete types at the
    type-checking level.
    """

    def predict(self, x: np.ndarray, verbose: int = 0) -> np.ndarray: ...


@dataclass
class AnomalyDetectionResult:
    """
    Outcome of an anomaly-detection run.

    `inserted_ids` holds the Mongo `_id` of every `Anomaly` document
    successfully written. `skipped_processed_events` records any
    `ProcessedEvent` documents that could not be scored (e.g.
    malformed feature vectors), each with a reason, without aborting
    the rest of the run.
    """

    inserted_ids: List[str] = field(default_factory=list)
    skipped_processed_events: List[Dict[str, Any]] = field(default_factory=list)
    anomalous_count: int = 0
    benign_count: int = 0

    @property
    def total_scored(self) -> int:
        """Total number of ProcessedEvent documents successfully scored."""
        return self.anomalous_count + self.benign_count


def _load_scaler(scaler_path: str) -> _ScalerProtocol:
    """
    Load the pre-fitted feature scaler from disk.

    Args:
        scaler_path: Path to the pickled scaler artifact (per
            `Settings.feature_scaler_path`).

    Raises:
        AnomalyDetectionError: If the file does not exist or fails to
            unpickle.
    """
    path = Path(scaler_path)
    if not path.is_file():
        raise AnomalyDetectionError(
            f"Feature scaler not found at path: {scaler_path}"
        )

    try:
        with path.open("rb") as handle:
            scaler = pickle.load(handle)  # noqa: S301 - trusted artifact path
    except (OSError, pickle.UnpicklingError) as exc:
        raise AnomalyDetectionError(
            f"Failed to load feature scaler from {scaler_path}: {exc}"
        ) from exc

    if not hasattr(scaler, "transform"):
        raise AnomalyDetectionError(
            f"Loaded scaler object from {scaler_path} has no 'transform' "
            "method; unexpected artifact type."
        )

    logger.info("Loaded feature scaler", extra={"scaler_path": scaler_path})
    return scaler


def _load_autoencoder(model_path: str) -> _AutoencoderProtocol:
    """
    Load the pre-trained TensorFlow/Keras autoencoder from disk.

    Args:
        model_path: Path to the saved Keras model artifact (per
            `Settings.autoencoder_model_path`).

    Raises:
        AnomalyDetectionError: If the file does not exist or fails to
            load.
    """
    path = Path(model_path)
    if not path.is_file():
        raise AnomalyDetectionError(
            f"Autoencoder model not found at path: {model_path}"
        )

    try:
        # Imported lazily so this module can be imported (e.g. for
        # type checking or in contexts that don't run inference)
        # without requiring tensorflow to be installed/loaded.
        import tensorflow as tf

        model = tf.keras.models.load_model(path)
    except Exception as exc:  # noqa: BLE001 - tf raises various error types
        raise AnomalyDetectionError(
            f"Failed to load autoencoder model from {model_path}: {exc}"
        ) from exc

    logger.info("Loaded autoencoder model", extra={"model_path": model_path})
    return model


async def _fetch_stored_threshold(
    db: Any, model_version: str
) -> Optional[float]:
    """
    Look up the trained threshold for `model_version` from
    `model_metadata`, if a record exists.

    Returns None if no matching record is found, rather than raising,
    since this is one step in a documented fallback chain.
    """
    try:
        document = await db[_MODEL_METADATA_COLLECTION].find_one(
            {"model_version": model_version}
        )
    except PyMongoError as exc:
        logger.warning(
            "Failed to query model_metadata for threshold; will fall "
            "back to next resolution step: %s",
            exc,
        )
        return None

    if document is None:
        return None

    threshold_value = document.get("threshold_value")
    if threshold_value is None:
        return None

    return float(threshold_value)


async def _resolve_threshold(
    settings: Settings, db: Any, batch_errors: Sequence[float]
) -> float:
    """
    Resolve the anomaly threshold to compare reconstruction errors
    against, per the module's documented resolution order.

    Args:
        settings: Application settings.
        db: Active MongoDB database handle.
        batch_errors: Reconstruction errors for the current batch,
            used only as a last-resort fallback.

    Returns:
        The resolved threshold value.
    """
    if settings.anomaly_threshold_value is not None:
        logger.debug(
            "Using configured anomaly_threshold_value",
            extra={"threshold": settings.anomaly_threshold_value},
        )
        return settings.anomaly_threshold_value

    stored_threshold = await _fetch_stored_threshold(db, settings.model_version)
    if stored_threshold is not None:
        logger.debug(
            "Using stored model_metadata threshold",
            extra={
                "threshold": stored_threshold,
                "model_version": settings.model_version,
            },
        )
        return stored_threshold

    if not batch_errors:
        raise AnomalyDetectionError(
            "Cannot resolve an anomaly threshold: no configured "
            "anomaly_threshold_value, no stored model_metadata "
            "threshold, and the current batch is empty."
        )

    fallback_threshold = float(
        np.percentile(
            np.asarray(batch_errors, dtype=np.float64),
            settings.anomaly_threshold_percentile,
        )
    )
    logger.warning(
        "No configured or stored threshold found; falling back to "
        "per-batch percentile threshold. This threshold is NOT stable "
        "across runs and should be replaced by a model_metadata "
        "record once training/calibration has been performed.",
        extra={
            "fallback_threshold": fallback_threshold,
            "percentile": settings.anomaly_threshold_percentile,
            "batch_size": len(batch_errors),
        },
    )
    return fallback_threshold


async def _fetch_unprocessed_events() -> List[ProcessedEvent]:
    """
    Fetch all `processed_events` documents not yet referenced by an
    existing `anomalies` document, parsed into `ProcessedEvent`
    instances.

    Malformed documents (failing `ProcessedEvent` validation) are
    logged and skipped individually rather than aborting the fetch.

    Raises:
        AnomalyDetectionError: If querying MongoDB fails.
    """
    db = get_database()

    try:
        already_scored_refs = {
            doc["feature_ref"]
            async for doc in db[_ANOMALIES_COLLECTION].find({}, {"feature_ref": 1})
        }
    except PyMongoError as exc:
        logger.exception("Failed to fetch existing anomalies feature_refs")
        raise AnomalyDetectionError(
            f"Failed to query anomalies: {exc}"
        ) from exc

    processed_events: List[ProcessedEvent] = []
    try:
        cursor = db[_PROCESSED_EVENTS_COLLECTION].find({})
        async for document in cursor:
            if document.get("_id") in already_scored_refs:
                continue
            try:
                processed_events.append(ProcessedEvent(**document))
            except Exception:  # noqa: BLE001 - isolate one bad document
                logger.warning(
                    "Skipping malformed processed_events document",
                    extra={"processed_event_id": str(document.get("_id"))},
                )
    except PyMongoError as exc:
        logger.exception("Failed to fetch processed_events documents")
        raise AnomalyDetectionError(
            f"Failed to query processed_events: {exc}"
        ) from exc

    logger.info(
        "Fetched unscored processed_events", extra={"count": len(processed_events)}
    )
    return processed_events


def _build_feature_matrix(
    processed_events: Sequence[ProcessedEvent],
) -> tuple[np.ndarray, List[ProcessedEvent], List[Dict[str, Any]]]:
    """
    Convert a sequence of `ProcessedEvent` feature vectors into a 2D
    numpy array suitable for scaler/model input.

    Events whose `feature_vector` is malformed (wrong length relative
    to the first valid vector seen, non-numeric values, etc.) are
    excluded and reported, rather than aborting the whole batch.

    Returns:
        A tuple of (feature_matrix, valid_events, skipped_entries),
        where `valid_events[i]` corresponds to `feature_matrix[i]`.
    """
    valid_events: List[ProcessedEvent] = []
    skipped_entries: List[Dict[str, Any]] = []
    rows: List[List[float]] = []
    expected_length: Optional[int] = None

    for processed_event in processed_events:
        vector = processed_event.feature_vector

        if expected_length is None:
            expected_length = len(vector)
        elif len(vector) != expected_length:
            logger.warning(
                "Skipping processed_event with mismatched feature_vector "
                "length",
                extra={
                    "processed_event_id": str(processed_event.id),
                    "expected_length": expected_length,
                    "actual_length": len(vector),
                },
            )
            skipped_entries.append(
                {
                    "processed_event_id": str(processed_event.id),
                    "reason": (
                        f"feature_vector length {len(vector)} does not "
                        f"match expected length {expected_length}"
                    ),
                }
            )
            continue

        try:
            row = [float(value) for value in vector]
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Skipping processed_event with non-numeric feature_vector",
                extra={"processed_event_id": str(processed_event.id)},
            )
            skipped_entries.append(
                {
                    "processed_event_id": str(processed_event.id),
                    "reason": f"Non-numeric value in feature_vector: {exc}",
                }
            )
            continue

        rows.append(row)
        valid_events.append(processed_event)

    feature_matrix = np.asarray(rows, dtype=np.float64)
    return feature_matrix, valid_events, skipped_entries


def _compute_reconstruction_errors(
    feature_matrix: np.ndarray,
    scaler: _ScalerProtocol,
    autoencoder: _AutoencoderProtocol,
) -> np.ndarray:
    """
    Scale the input feature matrix, run it through the autoencoder,
    and compute per-row mean squared reconstruction error.

    Raises:
        AnomalyDetectionError: If scaling or inference fails.
    """
    try:
        scaled_features = scaler.transform(feature_matrix)
    except Exception as exc:  # noqa: BLE001 - scaler may raise various types
        raise AnomalyDetectionError(
            f"Feature scaling failed: {exc}"
        ) from exc

    try:
        reconstructed = autoencoder.predict(scaled_features, verbose=0)
    except Exception as exc:  # noqa: BLE001 - tf may raise various types
        raise AnomalyDetectionError(
            f"Autoencoder inference failed: {exc}"
        ) from exc

    squared_errors = np.square(scaled_features - reconstructed)
    reconstruction_errors = np.mean(squared_errors, axis=_MSE_AXIS)
    return reconstruction_errors


async def _insert_anomalies(anomalies: List[Anomaly]) -> List[str]:
    """
    Persist a list of `Anomaly` instances into `anomalies`.

    Raises:
        AnomalyDetectionError: If the insert operation fails.
    """
    if not anomalies:
        return []

    db = get_database()
    documents = [
        anomaly.model_dump(by_alias=True, exclude={"id"}) for anomaly in anomalies
    ]

    try:
        if len(documents) == 1:
            result = await db[_ANOMALIES_COLLECTION].insert_one(documents[0])
            inserted_ids = [str(result.inserted_id)]
        else:
            result = await db[_ANOMALIES_COLLECTION].insert_many(
                documents, ordered=False
            )
            inserted_ids = [str(_id) for _id in result.inserted_ids]
    except PyMongoError as exc:
        logger.exception(
            "Failed to insert anomalies documents",
            extra={"attempted_count": len(documents)},
        )
        raise AnomalyDetectionError(
            f"Failed to persist {len(documents)} anomalies document(s): {exc}"
        ) from exc

    logger.info("Inserted anomalies documents", extra={"inserted_count": len(inserted_ids)})
    return inserted_ids


async def run_anomaly_detection() -> AnomalyDetectionResult:
    """
    Run Stage 3 (Autoencoder Anomaly Detection) end-to-end.

    Loads the configured scaler and autoencoder artifacts, fetches all
    `ProcessedEvent` documents not yet scored, runs batch inference to
    compute reconstruction error per event, resolves the anomaly
    threshold, and persists an `Anomaly` document for every
    successfully scored event.

    Returns:
        An `AnomalyDetectionResult` summarizing every Anomaly inserted
        and every ProcessedEvent skipped.

    Raises:
        AnomalyDetectionError: If loading model artifacts, querying
            MongoDB, or persisting anomalies fails at the
            infrastructure level.
    """
    settings = get_settings()
    db = get_database()

    logger.info(
        "Starting anomaly detection run",
        extra={
            "model_version": settings.model_version,
            "scaler_path": settings.feature_scaler_path,
            "model_path": settings.autoencoder_model_path,
        },
    )

    result = AnomalyDetectionResult()

    processed_events = await _fetch_unprocessed_events()
    if not processed_events:
        logger.info("No unscored processed_events found; nothing to detect")
        return result

    scaler = _load_scaler(settings.feature_scaler_path)
    autoencoder = _load_autoencoder(settings.autoencoder_model_path)

    feature_matrix, valid_events, skipped_entries = _build_feature_matrix(
        processed_events
    )
    result.skipped_processed_events.extend(skipped_entries)

    if feature_matrix.size == 0:
        logger.warning(
            "No valid feature vectors remained after filtering; "
            "nothing to score"
        )
        return result

    reconstruction_errors = _compute_reconstruction_errors(
        feature_matrix, scaler, autoencoder
    )

    threshold = await _resolve_threshold(
        settings, db, reconstruction_errors.tolist()
    )

    anomalies: List[Anomaly] = []
    detected_at = datetime.now(timezone.utc)

    for processed_event, reconstruction_error in zip(
        valid_events, reconstruction_errors
    ):
        try:
            is_anomalous = bool(reconstruction_error > threshold)
            anomaly = Anomaly(
                feature_ref=processed_event.id,
                host=processed_event.host,
                reconstruction_error=float(reconstruction_error),
                threshold_used=float(threshold),
                is_anomalous=is_anomalous,
                model_version=settings.model_version,
                detected_at=detected_at,
            )
            anomalies.append(anomaly)

            if is_anomalous:
                result.anomalous_count += 1
            else:
                result.benign_count += 1
        except Exception:  # noqa: BLE001 - isolate one bad record
            logger.exception(
                "Failed to construct Anomaly for processed_event",
                extra={"processed_event_id": str(processed_event.id)},
            )
            result.skipped_processed_events.append(
                {
                    "processed_event_id": str(processed_event.id),
                    "reason": "Anomaly model construction failed",
                }
            )

    inserted_ids = await _insert_anomalies(anomalies)
    result.inserted_ids.extend(inserted_ids)

    logger.info(
        "Completed anomaly detection run",
        extra={
            "total_scored": result.total_scored,
            "anomalous_count": result.anomalous_count,
            "benign_count": result.benign_count,
            "skipped_count": len(result.skipped_processed_events),
            "threshold_used": threshold,
        },
    )
    return result