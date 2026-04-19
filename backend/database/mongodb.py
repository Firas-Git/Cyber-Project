from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from config import get_settings

_client: AsyncIOMotorClient | None = None
_db: AsyncIOMotorDatabase | None = None


async def connect_db() -> None:
    global _client, _db
    settings = get_settings()
    _client = AsyncIOMotorClient(settings.mongodb_url, serverSelectionTimeoutMS=5000)
    _db = _client[settings.database_name]
    await _ensure_indexes()


async def close_db() -> None:
    global _client
    if _client:
        _client.close()


def get_db() -> AsyncIOMotorDatabase:
    if _db is None:
        raise RuntimeError("Database not connected. Call connect_db() first.")
    return _db


async def _ensure_indexes() -> None:
    db = get_db()
    await db.users.create_index("email", unique=True)
    await db.users.create_index("username", unique=True)
    await db.predictions.create_index("user_id")
    await db.predictions.create_index("timestamp")
    await db.predictions.create_index("risk_level")
    await db.alerts.create_index("timestamp")
    await db.alerts.create_index("risk_level")
    await db.datasets.create_index("user_id")
    await db.datasets.create_index("uploaded_at")
