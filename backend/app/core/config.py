"""
Application configuration module.

Centralizes all environment-driven settings for the AegisAI backend using
pydantic-settings. This is the single source of truth for configuration —
no other module should read os.environ directly.

Usage:
    from app.core.config import get_settings

    settings = get_settings()
    client = MongoClient(settings.mongo_uri)
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import List, Optional

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Strongly-typed application settings, populated from environment
    variables (and, in local development, a `.env` file).

    Field names map 1:1 to the variables documented in `.env.example`,
    lower-cased per pydantic-settings' default env var matching.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ---------------- Application ----------------
    app_name: str = Field(default="AegisAI")
    app_env: str = Field(default="development")
    app_debug: bool = Field(default=True)
    api_v1_prefix: str = Field(default="/api/v1")

    # ---------------- Server ----------------
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8000)

    # ---------------- CORS ----------------
    cors_origins: str = Field(default="http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173")

    # ---------------- MongoDB ----------------
    mongo_uri: str = Field(default="mongodb://localhost:27017")
    mongo_db_name: str = Field(default="aegisai")
    mongo_connect_timeout_ms: int = Field(default=5000)
    mongo_server_selection_timeout_ms: int = Field(default=5000)

    # ---------------- OpenAI ----------------
    openai_api_key: str = Field(default="")
    openai_model: str = Field(default="gpt-4o")
    openai_max_tokens: int = Field(default=1500)
    openai_temperature: float = Field(default=0.2)
    openai_request_timeout_seconds: int = Field(default=60)

    # ---------------- ML Model Artifacts ----------------
    model_artifacts_dir: str = Field(default="./model_artifacts")
    autoencoder_model_path: str = Field(
        default="./model_artifacts/autoencoder.keras"
    )
    feature_scaler_path: str = Field(default="./model_artifacts/scaler.pkl")
    model_version: str = Field(default="v1.0.0")

    # ---------------- Anomaly Detection Thresholds ----------------
    anomaly_threshold_percentile: float = Field(default=95.0)
    anomaly_threshold_value: Optional[float] = Field(default=None)

    # ---------------- Incident Timeline Builder ----------------
    feature_window_minutes: int = Field(default=1)
    incident_window_minutes: int = Field(default=20)

    # ---------------- MITRE ATT&CK Local Cache ----------------
    mitre_lookup_path: str = Field(
        default="./app/core/mitre/attack_lookup.json"
    )

    # ---------------- Risk Scoring Weights ----------------
    risk_weight_anomaly: float = Field(default=0.4)
    risk_weight_technique_severity: float = Field(default=0.4)
    risk_weight_asset_criticality: float = Field(default=0.2)

    # ---------------- Logging ----------------
    log_level: str = Field(default="INFO")
    log_format: str = Field(default="json")
    log_file_path: str = Field(default="./logs/aegisai.log")
    log_to_console: bool = Field(default=True)
    log_to_file: bool = Field(default=False)

    # ---------------- Validators ----------------

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, value: str) -> str:
        """Ensure log_level is one of the standard logging levels."""
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        normalized = value.upper()
        if normalized not in valid_levels:
            raise ValueError(
                f"log_level must be one of {sorted(valid_levels)}, "
                f"got '{value}'"
            )
        return normalized

    @field_validator("log_format")
    @classmethod
    def validate_log_format(cls, value: str) -> str:
        """Ensure log_format is either 'json' or 'text'."""
        normalized = value.lower()
        if normalized not in {"json", "text"}:
            raise ValueError(
                f"log_format must be 'json' or 'text', got '{value}'"
            )
        return normalized

    @field_validator(
        "risk_weight_anomaly",
        "risk_weight_technique_severity",
        "risk_weight_asset_criticality",
    )
    @classmethod
    def validate_weight_range(cls, value: float) -> float:
        """Ensure individual risk weights are within [0, 1]."""
        if not 0.0 <= value <= 1.0:
            raise ValueError(
                f"Risk weight must be between 0.0 and 1.0, got {value}"
            )
        return value

    # ---------------- Derived properties ----------------

    @property
    def cors_origins_list(self) -> List[str]:
        """Parse the comma-separated CORS_ORIGINS string into a list."""
        return [
            origin.strip()
            for origin in self.cors_origins.split(",")
            if origin.strip()
        ]

    @property
    def is_production(self) -> bool:
        """True if running in a production environment."""
        return self.app_env.lower() == "production"

    @property
    def risk_weights_sum_to_one(self) -> bool:
        """
        Sanity check that the three risk component weights sum to ~1.0.
        Does not raise — callers (e.g. risk_scoring module) decide how
        to react to an unnormalized weight configuration.
        """
        total = (
            self.risk_weight_anomaly
            + self.risk_weight_technique_severity
            + self.risk_weight_asset_criticality
        )
        return abs(total - 1.0) < 1e-6

    def resolve_path(self, relative_path: str) -> Path:
        """
        Resolve a configured relative path (e.g. model artifact or MITRE
        lookup file) to an absolute Path object.
        """
        return Path(relative_path).resolve()


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """
    Return a cached singleton Settings instance.

    Using lru_cache ensures the environment is parsed once per process,
    avoiding repeated file/env reads while still allowing tests to
    override settings via dependency injection (e.g. FastAPI's
    `app.dependency_overrides`).
    """
    return Settings()