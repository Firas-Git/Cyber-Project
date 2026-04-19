from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, EmailStr, Field
from bson import ObjectId


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


# ─── Users ────────────────────────────────────────────────────────────────────

class UserInDB(BaseModel):
    id: Optional[str] = None
    username: str
    email: str
    hashed_password: str
    role: str = "analyst"  # admin | analyst | viewer
    is_active: bool = True
    created_at: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True


class UserPublic(BaseModel):
    id: str
    username: str
    email: str
    role: str
    created_at: datetime


# ─── Predictions ──────────────────────────────────────────────────────────────

class PredictionRecord(BaseModel):
    id: Optional[str] = None
    user_id: str
    username: str
    input_features: dict
    prediction: str
    prediction_class: int
    attack_type: str
    confidence: float
    risk_level: str
    risk_score: float
    probabilities: dict
    feature_contributions: list
    explanation: str
    recommended_action: str
    timestamp: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True


# ─── Alerts ───────────────────────────────────────────────────────────────────

class AlertRecord(BaseModel):
    id: Optional[str] = None
    prediction_id: str
    user_id: str
    username: str
    attack_type: str
    risk_level: str
    confidence: float
    risk_score: float
    recommended_action: str
    source_ip_score: float
    protocol: str
    timestamp: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True


# ─── Datasets ─────────────────────────────────────────────────────────────────

class DatasetRecord(BaseModel):
    id: Optional[str] = None
    user_id: str
    username: str
    filename: str
    rows: int
    columns: int
    attack_count: int
    normal_count: int
    missing_values: dict
    uploaded_at: datetime = Field(default_factory=utc_now)

    class Config:
        populate_by_name = True


# ─── Helpers ──────────────────────────────────────────────────────────────────

def doc_to_dict(doc: dict) -> dict:
    """Convert MongoDB document (with _id) to plain dict with string id."""
    if doc is None:
        return {}
    d = dict(doc)
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    return d
