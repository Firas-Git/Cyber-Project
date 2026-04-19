from fastapi import Depends, HTTPException, status, WebSocket
from fastapi.security import OAuth2PasswordBearer
from database.mongodb import get_db
from database.models import doc_to_dict
from auth.jwt_handler import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

ROLE_HIERARCHY = {"viewer": 0, "analyst": 1, "admin": 2}


async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_token(token)
    if not payload:
        raise credentials_exc

    user_id: str = payload.get("sub", "")
    if not user_id:
        raise credentials_exc

    db = get_db()
    from bson import ObjectId
    try:
        doc = await db.users.find_one({"_id": ObjectId(user_id)})
    except Exception:
        raise credentials_exc

    if doc is None:
        raise credentials_exc

    user = doc_to_dict(doc)
    if not user.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated.")
    return user


def require_role(*allowed_roles: str):
    """Dependency factory: require user role to be in allowed_roles."""
    async def _check(current_user: dict = Depends(get_current_user)) -> dict:
        user_level = ROLE_HIERARCHY.get(current_user.get("role", "viewer"), 0)
        required_level = min(ROLE_HIERARCHY.get(r, 0) for r in allowed_roles)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user['role']}' is not permitted for this action.",
            )
        return current_user
    return _check


async def get_ws_user(websocket: WebSocket, token: str) -> dict | None:
    """Authenticate WebSocket connections via query param token."""
    if not token:
        return None
    payload = decode_token(token)
    user_id = payload.get("sub", "")
    if not user_id:
        return None
    db = get_db()
    from bson import ObjectId
    try:
        doc = await db.users.find_one({"_id": ObjectId(user_id)})
        return doc_to_dict(doc) if doc else None
    except Exception:
        return None
