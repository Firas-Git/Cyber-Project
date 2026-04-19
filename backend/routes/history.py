from fastapi import APIRouter, Depends, Query
from bson import ObjectId

from database.mongodb import get_db
from database.models import doc_to_dict
from auth.dependencies import get_current_user, require_role

router = APIRouter()


@router.get("/predictions")
async def get_prediction_history(
    limit: int = Query(50, ge=1, le=200),
    risk_level: str = Query(None),
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    filt = {}
    if current_user["role"] != "admin":
        filt["user_id"] = current_user["id"]
    if risk_level:
        filt["risk_level"] = risk_level

    cursor = db.predictions.find(filt).sort("timestamp", -1).limit(limit)
    return [doc_to_dict(doc) async for doc in cursor]


@router.get("/alerts")
async def get_alert_history(
    limit: int = Query(50, ge=1, le=200),
    risk_level: str = Query(None),
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    filt = {}
    if risk_level:
        filt["risk_level"] = risk_level
    cursor = db.alerts.find(filt).sort("timestamp", -1).limit(limit)
    return [doc_to_dict(doc) async for doc in cursor]


@router.get("/datasets")
async def get_dataset_history(
    current_user: dict = Depends(get_current_user),
):
    db = get_db()
    filt = {} if current_user["role"] == "admin" else {"user_id": current_user["id"]}
    cursor = db.datasets.find(filt).sort("uploaded_at", -1).limit(20)
    return [doc_to_dict(doc) async for doc in cursor]


@router.get("/stats")
async def get_dashboard_stats(current_user: dict = Depends(get_current_user)):
    db = get_db()
    total_predictions = await db.predictions.count_documents({})
    total_attacks = await db.predictions.count_documents({"prediction_class": 1})
    total_alerts = await db.alerts.count_documents({})
    critical_alerts = await db.alerts.count_documents({"risk_level": "Critical"})

    pipeline = [
        {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    attack_breakdown_cursor = db.alerts.aggregate(pipeline)
    attack_breakdown = [doc async for doc in attack_breakdown_cursor]

    recent_alerts = []
    async for doc in db.alerts.find({}).sort("timestamp", -1).limit(10):
        recent_alerts.append(doc_to_dict(doc))

    return {
        "total_predictions": total_predictions,
        "total_attacks": total_attacks,
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "attack_rate": round(total_attacks / total_predictions * 100, 2) if total_predictions else 0,
        "attack_breakdown": [{"type": d["_id"], "count": d["count"]} for d in attack_breakdown],
        "recent_alerts": recent_alerts,
    }


@router.delete("/predictions/{prediction_id}", dependencies=[Depends(require_role("admin"))])
async def delete_prediction(prediction_id: str):
    db = get_db()
    result = await db.predictions.delete_one({"_id": ObjectId(prediction_id)})
    return {"deleted": result.deleted_count}
