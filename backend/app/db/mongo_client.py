"""
MongoDB client module.

Manages the application's single async MongoDB connection (via Motor),
exposing lifecycle hooks for FastAPI startup/shutdown and a health-check
helper. All other modules (repositories, routes) should obtain the
database handle through `get_database()` rather than creating their own
client instances.

Usage:
    # On app startup
    await connect_to_mongo()

    # Anywhere a DB handle is needed
    db = get_database()
    await db["raw_logs"].find_one({...})

    # On app shutdown
    await close_mongo_connection()
"""

from __future__ import annotations

from typing import Optional

from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from pymongo.errors import PyMongoError

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class MongoNotConnectedError(RuntimeError):
    """Raised when the database handle is accessed before connecting."""


class MongoConnectionManager:
    """
    Encapsulates the Motor client and database handle as process-wide
    singletons, with explicit connect/disconnect lifecycle methods.

    Kept as a class (rather than bare module globals) so connection
    state is easy to reason about and reset in tests.
    """

    def __init__(self) -> None:
        self._client: Optional[AsyncIOMotorClient] = None
        self._database: Optional[AsyncIOMotorDatabase] = None

    async def connect(self) -> None:
        """
        Initialize the Motor client and verify connectivity with a
        `ping` command.

        Raises:
            PyMongoError: If the initial connectivity check fails.
        """
        if self._client is not None:
            logger.debug("MongoDB client already initialized; skipping.")
            return

        settings = get_settings()

        logger.info(
            "Connecting to MongoDB",
            extra={"db_name": settings.mongo_db_name},
        )

        try:
            self._client = AsyncIOMotorClient(
                settings.mongo_uri,
                connectTimeoutMS=settings.mongo_connect_timeout_ms,
                serverSelectionTimeoutMS=(
                    settings.mongo_server_selection_timeout_ms
                ),
            )
            self._database = self._client[settings.mongo_db_name]

            # Force a round-trip so connection issues surface at
            # startup rather than on the first real query.
            await self._client.admin.command("ping")

            logger.info(
                "MongoDB connection established",
                extra={"db_name": settings.mongo_db_name},
            )
        except PyMongoError:
            logger.exception("Failed to connect to MongoDB")
            self._client = None
            self._database = None
            raise

    async def disconnect(self) -> None:
        """Close the Motor client connection, if open."""
        if self._client is None:
            logger.debug("MongoDB client not initialized; nothing to close.")
            return

        logger.info("Closing MongoDB connection")
        try:
            self._client.close()
        except PyMongoError:
            logger.exception("Error while closing MongoDB connection")
            raise
        finally:
            self._client = None
            self._database = None

    def get_database(self) -> AsyncIOMotorDatabase:
        """
        Return the active database handle.

        Raises:
            MongoNotConnectedError: If called before `connect()`.
        """
        if self._database is None:
            raise MongoNotConnectedError(
                "MongoDB is not connected. Call connect_to_mongo() "
                "during application startup before accessing the "
                "database."
            )
        return self._database

    async def ping(self) -> bool:
        """
        Check connectivity to MongoDB.

        Returns:
            True if the server responds to `ping`, False otherwise
            (including if the client was never connected).
        """
        if self._client is None:
            return False

        try:
            await self._client.admin.command("ping")
            return True
        except PyMongoError:
            logger.exception("MongoDB ping failed")
            return False

    @property
    def is_connected(self) -> bool:
        """True if connect() has succeeded and not been followed by disconnect()."""
        return self._client is not None and self._database is not None


# Process-wide singleton instance.
_mongo_manager = MongoConnectionManager()


async def connect_to_mongo() -> None:
    """Connect the singleton MongoConnectionManager. Intended for app startup."""
    await _mongo_manager.connect()


async def close_mongo_connection() -> None:
    """Disconnect the singleton MongoConnectionManager. Intended for app shutdown."""
    await _mongo_manager.disconnect()


def get_database() -> AsyncIOMotorDatabase:
    """
    Return the active MongoDB database handle.

    Intended for use as a FastAPI dependency or direct import within
    repository modules.

    Raises:
        MongoNotConnectedError: If the application has not yet called
            `connect_to_mongo()`.
    """
    return _mongo_manager.get_database()


async def check_mongo_health() -> bool:
    """Return True if MongoDB is reachable, False otherwise."""
    return await _mongo_manager.ping()