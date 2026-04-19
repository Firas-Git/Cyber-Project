from datetime import datetime, timedelta, timezone
from typing import Optional
from jose import JWTError, jwt
from config import get_settings


def _settings():
    return get_settings()


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    settings = _settings()
    payload = data.copy()
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.jwt_expire_minutes)
    )
    payload["exp"] = expire
    payload["iat"] = datetime.now(timezone.utc)
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict:
    settings = _settings()
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError:
        return {}


def extract_user_id(token: str) -> Optional[str]:
    payload = decode_token(token)
    return payload.get("sub")
