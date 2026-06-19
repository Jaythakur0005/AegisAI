"""
AegisAI FastAPI application entrypoint.

Per ARCHITECTURE_V2.md Section 4 (Folder Structure), this module is
responsible only for application wiring: logging setup, middleware,
lifespan-managed resource (MongoDB) startup/shutdown, router mounting,
and top-level exception handling. No business logic lives here.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.db.mongo_client import close_mongo_connection, connect_to_mongo

# Logging must be configured before anything else logs.
configure_logging()
logger = get_logger(__name__)

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """
    Manage application startup/shutdown.

    Establishes the MongoDB connection before the app starts accepting
    requests, and tears it down cleanly on shutdown. If startup fails,
    the exception propagates so the process exits rather than serving
    traffic against a broken dependency.
    """
    logger.info(
        "Starting AegisAI backend",
        extra={"app_env": settings.app_env, "app_debug": settings.app_debug},
    )

    try:
        await connect_to_mongo()
    except Exception:
        logger.exception(
            "Application startup aborted: failed to connect to MongoDB"
        )
        raise

    yield

    logger.info("Shutting down AegisAI backend")
    try:
        await close_mongo_connection()
    except Exception:
        # Don't let a shutdown error mask a clean exit; just log it.
        logger.exception("Error during MongoDB disconnect on shutdown")


def create_app() -> FastAPI:
    """
    Construct and configure the FastAPI application instance.

    Factory function (rather than a bare module-level `app`) so tests
    can create fresh app instances with overridden settings/dependencies
    if needed.
    """
    application = FastAPI(
        title=settings.app_name,
        description=(
            "AegisAI — Autonomous Zero-Day Threat Investigation and "
            "Explainability Engine"
        ),
        version=settings.model_version,
        debug=settings.app_debug,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    application.include_router(api_router, prefix=settings.api_v1_prefix)

    @application.exception_handler(Exception)
    async def unhandled_exception_handler(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all handler for any exception not handled by a more
        specific handler. Logs the full traceback server-side and
        returns a generic 500 response, avoiding leaking internals
        to the client.
        """
        logger.exception(
            "Unhandled exception while processing request",
            extra={"path": request.url.path, "method": request.method},
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "Internal server error"},
        )

    logger.info(
        "FastAPI application configured",
        extra={
            "api_prefix": settings.api_v1_prefix,
            "cors_origins": settings.cors_origins_list,
        },
    )

    return application


app = create_app()