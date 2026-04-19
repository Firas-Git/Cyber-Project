import joblib
import numpy as np
from pathlib import Path
from typing import Optional

_model = None

MODEL_PATH = Path(__file__).parent.parent / "random_forest_model.pkl"

FEATURE_NAMES = [
    "network_packet_size",
    "protocol_type",
    "login_attempts",
    "session_duration",
    "encryption_used",
    "ip_reputation_score",
    "failed_logins",
    "browser_type",
    "unusual_time_access",
]


def load_model():
    global _model
    _model = joblib.load(MODEL_PATH)
    return _model


def get_model():
    if _model is None:
        load_model()
    return _model


def predict(features: list) -> dict:
    model = get_model()
    arr = np.array([features])
    prediction = int(model.predict(arr)[0])
    proba = model.predict_proba(arr)[0]
    confidence = float(proba[prediction])

    importances = model.feature_importances_.tolist()
    feature_contributions = [
        {"feature": name, "importance": round(imp, 4), "value": features[i]}
        for i, (name, imp) in enumerate(zip(FEATURE_NAMES, importances))
    ]
    feature_contributions.sort(key=lambda x: x["importance"], reverse=True)

    return {
        "prediction": prediction,
        "confidence": round(confidence * 100, 2),
        "probabilities": {
            "normal": round(float(proba[0]) * 100, 2),
            "attack": round(float(proba[1]) * 100, 2),
        },
        "feature_contributions": feature_contributions,
    }


def get_feature_importances() -> dict:
    model = get_model()
    importances = model.feature_importances_.tolist()
    return {name: round(imp, 4) for name, imp in zip(FEATURE_NAMES, importances)}


def get_model_classes() -> list:
    return get_model().classes_.tolist()
