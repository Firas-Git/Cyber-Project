from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field

from services.model_service import predict as model_predict
from services.preprocessing import encode_input, infer_attack_type
from services.ws_manager import ws_manager
from database.mongodb import get_db
from database.models import PredictionRecord, AlertRecord
from auth.dependencies import get_current_user, require_role

router = APIRouter()


class PredictRequest(BaseModel):
    network_packet_size: int = Field(..., ge=64, le=1500)
    protocol_type: str = Field(..., description="TCP | UDP | ICMP")
    login_attempts: int = Field(..., ge=1, le=20)
    session_duration: float = Field(..., ge=0)
    encryption_used: str = Field(..., description="AES | DES")
    ip_reputation_score: float = Field(..., ge=0.0, le=1.0)
    failed_logins: int = Field(..., ge=0, le=10)
    browser_type: str = Field(..., description="Chrome | Firefox | Edge | Safari | Unknown")
    unusual_time_access: int = Field(..., ge=0, le=1)


def _compute_risk_level(confidence: float, prediction: int) -> dict:
    if prediction == 0:
        return {"level": "Low", "score": round((1 - confidence / 100) * 30, 1), "color": "#00ff88"}
    if confidence >= 90:
        return {"level": "Critical", "score": round(70 + confidence * 0.3, 1), "color": "#ff0000"}
    if confidence >= 75:
        return {"level": "High", "score": round(55 + confidence * 0.2, 1), "color": "#ff4757"}
    return {"level": "Medium", "score": round(35 + confidence * 0.2, 1), "color": "#ffa502"}


def _build_explanation(attack_info: dict, contributions: list) -> str:
    top = contributions[:3]
    parts = [f"• {c['feature'].replace('_', ' ').title()} (importance: {c['importance']})" for c in top]
    if attack_info["type"] != "Normal Traffic":
        return (
            f"The model detected a {attack_info['type']} based on top contributing features:\n"
            + "\n".join(parts)
            + "\nThese patterns are consistent with known attack signatures."
        )
    return "Traffic appears normal. Key features within expected ranges:\n" + "\n".join(parts)


def _recommended_action(prediction: int, risk_level: str) -> str:
    if prediction == 0:
        return "MONITOR — Continue standard monitoring. No immediate action required."
    actions = {
        "Critical": "BLOCK IMMEDIATELY — Isolate source IP, escalate to SOC team, open incident ticket.",
        "High": "BLOCK — Block source IP, review firewall rules, alert security team.",
        "Medium": "ALERT — Flag for investigation, increase monitoring frequency, review IDS rules.",
    }
    return actions.get(risk_level, "MONITOR — Investigate further.")


@router.post("/")
async def predict_attack(
    req: PredictRequest,
    current_user: dict = Depends(require_role("analyst", "admin")),
):
    try:
        features = encode_input(req.model_dump())
        result = model_predict(features)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")

    prediction = result["prediction"]
    confidence = result["confidence"]
    risk = _compute_risk_level(confidence, prediction)
    attack_info = infer_attack_type(req.model_dump(), prediction)

    response = {
        "prediction": "Attack Detected" if prediction == 1 else "Normal Traffic",
        "prediction_class": prediction,
        "attack_type": attack_info["type"],
        "attack_icon": attack_info["icon"],
        "attack_color": attack_info["color"],
        "confidence": confidence,
        "probabilities": result["probabilities"],
        "risk_level": risk["level"],
        "risk_score": risk["score"],
        "risk_color": risk["color"],
        "explanation": _build_explanation(attack_info, result["feature_contributions"]),
        "recommended_action": _recommended_action(prediction, risk["level"]),
        "feature_contributions": result["feature_contributions"],
        "model_used": result.get("model_used", "random_forest"),
        "model_display": result.get("model_display", "Random Forest"),
    }

    # ── Persist prediction to MongoDB ──────────────────────────────────────────
    db = get_db()
    record = PredictionRecord(
        user_id=current_user["id"],
        username=current_user["username"],
        input_features=req.model_dump(),
        prediction=response["prediction"],
        prediction_class=prediction,
        attack_type=attack_info["type"],
        confidence=confidence,
        risk_level=risk["level"],
        risk_score=risk["score"],
        probabilities=result["probabilities"],
        feature_contributions=result["feature_contributions"],
        explanation=response["explanation"],
        recommended_action=response["recommended_action"],
    )
    pred_result = await db.predictions.insert_one(record.model_dump(exclude={"id"}))
    prediction_id = str(pred_result.inserted_id)
    response["prediction_id"] = prediction_id

    # ── Log alert for High/Critical attacks ────────────────────────────────────
    if prediction == 1 and risk["level"] in ("High", "Critical", "Medium"):
        alert = AlertRecord(
            prediction_id=prediction_id,
            user_id=current_user["id"],
            username=current_user["username"],
            attack_type=attack_info["type"],
            risk_level=risk["level"],
            confidence=confidence,
            risk_score=risk["score"],
            recommended_action=response["recommended_action"],
            source_ip_score=req.ip_reputation_score,
            protocol=req.protocol_type,
        )
        await db.alerts.insert_one(alert.model_dump(exclude={"id"}))

    # ── Broadcast via WebSocket for High/Critical attacks ──────────────────────
    if prediction == 1 and risk["level"] in ("High", "Critical"):
        event = ws_manager.build_attack_event(response, current_user["username"])
        await ws_manager.broadcast(event)

    return response
