"""
Logging configuration module.

Sets up application-wide structured logging based on environment-driven
settings (see app.core.config.Settings). Supports both JSON and plain-text
output, console and/or file handlers, and provides a single `get_logger`
entry point so every module logs consistently.

Usage:
    from app.core.logging import get_logger

    logger = get_logger(__name__)
    logger.info("Ingestion started", extra={"host": "WIN-LAB01"})
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Dict

from app.core.config import get_settings

_LOGGING_CONFIGURED = False

# Standard LogRecord attributes we don't want duplicated into the
# "extra" payload of a JSON log line.
_RESERVED_LOG_RECORD_ATTRS = {
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName",
}


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        payload: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Include any custom fields passed via `extra={...}`
        for key, value in record.__dict__.items():
            if key not in _RESERVED_LOG_RECORD_ATTRS and not key.startswith(
                "_"
            ):
                payload[key] = value

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        return json.dumps(payload, default=str)


class TextFormatter(logging.Formatter):
    """Human-readable plain-text formatter for local development."""

    def __init__(self) -> None:
        super().__init__(
            fmt=(
                "%(asctime)s | %(levelname)-8s | %(name)s | "
                "%(module)s:%(funcName)s:%(lineno)d | %(message)s"
            ),
            datefmt="%Y-%m-%d %H:%M:%S",
        )


def _build_formatter(log_format: str) -> logging.Formatter:
    """Return the appropriate formatter instance for the given format."""
    if log_format == "json":
        return JsonFormatter()
    return TextFormatter()


def configure_logging() -> None:
    """
    Configure the root logger once, based on application Settings.

    Idempotent: subsequent calls are no-ops so importing this module
    multiple times (e.g. across FastAPI routers) never duplicates
    handlers or log lines.
    """
    global _LOGGING_CONFIGURED
    if _LOGGING_CONFIGURED:
        return

    settings = get_settings()
    root_logger = logging.getLogger()
    root_logger.setLevel(settings.log_level)

    # Clear any default handlers (e.g. from uvicorn's own setup) to avoid
    # duplicate log lines.
    root_logger.handlers.clear()

    formatter = _build_formatter(settings.log_format)

    if settings.log_to_console:
        console_handler = logging.StreamHandler(stream=sys.stdout)
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)

    if settings.log_to_file:
        try:
            log_path = Path(settings.log_file_path)
            log_path.parent.mkdir(parents=True, exist_ok=True)

            file_handler = RotatingFileHandler(
                filename=str(log_path),
                maxBytes=10 * 1024 * 1024,  # 10 MB per file
                backupCount=5,
                encoding="utf-8",
            )
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except OSError as exc:
            # Fall back to console-only logging rather than crashing
            # the application over a logging configuration issue.
            root_logger.addHandler(logging.StreamHandler(stream=sys.stdout))
            root_logger.error(
                "Failed to configure file logging, falling back to "
                "console only: %s",
                exc,
            )

    # Tame noisy third-party loggers without losing warnings/errors.
    for noisy_logger in (
        "pymongo",
        "motor",
        "httpx",
        "httpcore",
        "openai",
        "tensorflow",
    ):
        logging.getLogger(noisy_logger).setLevel(logging.WARNING)

    _LOGGING_CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured logger for the given module name.

    Ensures `configure_logging()` has run before returning, so callers
    can simply do `logger = get_logger(__name__)` at module import time
    without worrying about initialization order.

    Args:
        name: Typically `__name__` of the calling module.

    Returns:
        A standard library `logging.Logger` instance.
    """
    configure_logging()
    return logging.getLogger(name)