from datetime import timedelta
from fastapi import HTTPException, status
from bson import ObjectId

from database.mongodb import get_db
from database.models import UserInDB, doc_to_dict
from auth.password import hash_password, verify_password
from auth.jwt_handler import create_access_token
from config import get_settings


async def register_user(username: str, email: str, password: str, role: str = "analyst") -> dict:
    db = get_db()

    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email already registered.")
    if await db.users.find_one({"username": username}):
        raise HTTPException(status_code=400, detail="Username already taken.")

    user = UserInDB(
        username=username,
        email=email,
        hashed_password=hash_password(password),
        role=role,
    )
    result = await db.users.insert_one(user.model_dump(exclude={"id"}))
    token = create_access_token({"sub": str(result.inserted_id), "role": role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": str(result.inserted_id),
            "username": username,
            "email": email,
            "role": role,
        },
    }


async def login_user(email: str, password: str) -> dict:
    db = get_db()
    doc = await db.users.find_one({"email": email})

    if not doc or not verify_password(password, doc["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not doc.get("is_active", True):
        raise HTTPException(status_code=403, detail="Account deactivated.")

    user_id = str(doc["_id"])
    role = doc.get("role", "analyst")
    token = create_access_token({"sub": user_id, "role": role})
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "username": doc["username"],
            "email": doc["email"],
            "role": role,
        },
    }


async def get_all_users() -> list:
    db = get_db()
    cursor = db.users.find({}, {"hashed_password": 0})
    return [doc_to_dict(doc) async for doc in cursor]
