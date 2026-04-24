import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, classification_report, confusion_matrix,
)

BACKEND_DIR = Path(__file__).parent.parent

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

# Candidate filenames per model (first found wins)
_MODEL_FILES = {
    "random_forest":       ["randomforest_model.pkl", "random_forest_model.pkl"],
    "logistic_regression": ["logistic_regression_model.pkl"],
    "knn":                 ["knn_model.pkl"],
}

MODEL_DISPLAY = {
    "random_forest":       "Random Forest",
    "logistic_regression": "Logistic Regression",
    "knn":                 "K-Nearest Neighbors",
}

MODEL_INFO = {
    "random_forest": {
        "algorithm": "Random Forest Classifier",
        "notes": "Ensemble of decision trees. No feature scaling required.",
        "strengths": "High accuracy, feature importance, handles non-linearity",
    },
    "logistic_regression": {
        "algorithm": "Logistic Regression",
        "notes": "Linear classifier. Requires StandardScaler.",
        "strengths": "Fast, interpretable coefficients, good baseline",
    },
    "knn": {
        "algorithm": "K-Nearest Neighbors (k=5)",
        "notes": "Distance-based classifier. Requires StandardScaler.",
        "strengths": "Non-parametric, no training phase, intuitive",
    },
}

NEEDS_SCALING = {"logistic_regression", "knn"}

_models: dict = {}
_scaler: Optional[StandardScaler] = None
_comparison_metrics: dict = {}


def _load_one(model_key: str):
    for filename in _MODEL_FILES[model_key]:
        path = BACKEND_DIR / filename
        if path.exists():
            try:
                return joblib.load(path)
            except Exception as e:
                print(f"  ⚠️  Failed to load {filename}: {e}")
    return None


def _encode_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "session_id" in df.columns:
        df.drop(columns=["session_id"], inplace=True)
    if "encryption_used" in df.columns and df["encryption_used"].dtype == object:
        df["encryption_used"] = df["encryption_used"].fillna(df["encryption_used"].mode()[0])
    cat_cols = ["protocol_type", "encryption_used", "browser_type"]
    for col in cat_cols:
        if col in df.columns and df[col].dtype == object:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
    return df


def _fit_scaler_and_evaluate():
    global _scaler, _comparison_metrics

    dataset_path = BACKEND_DIR / "cybersecurity_intrusion_data.pkl"
    if not dataset_path.exists():
        print("  ⚠️  cybersecurity_intrusion_data.pkl not found — skipping metric computation")
        return

    try:
        raw = joblib.load(dataset_path)
    except Exception as e:
        print(f"  ⚠️  Could not load dataset pkl: {e}")
        return

    if not isinstance(raw, pd.DataFrame):
        print("  ⚠️  Dataset pkl is not a DataFrame — skipping metric computation")
        return

    df = _encode_dataframe(raw)

    if "attack_detected" not in df.columns:
        print("  ⚠️  Dataset has no 'attack_detected' column — skipping metric computation")
        return

    features = [f for f in FEATURE_NAMES if f in df.columns]
    x = df[features].values.astype(float)
    y = df["attack_detected"].values

    x_train, x_test, y_train, y_test = train_test_split(
        x, y, test_size=0.3, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    x_train_scaled = scaler.fit_transform(x_train)
    x_test_scaled = scaler.transform(x_test)
    _scaler = scaler

    for key, model in _models.items():
        if model is None:
            continue
        try:
            x_eval = x_test_scaled if key in NEEDS_SCALING else x_test
            y_pred = model.predict(x_eval)

            cr = classification_report(y_test, y_pred, output_dict=True)
            cm = confusion_matrix(y_test, y_pred).tolist()

            train_eval = x_train_scaled if key in NEEDS_SCALING else x_train
            train_acc = round(float(model.score(train_eval, y_train)) * 100, 2)

            _comparison_metrics[key] = {
                "accuracy":        round(accuracy_score(y_test, y_pred) * 100, 2),
                "precision":       round(precision_score(y_test, y_pred) * 100, 2),
                "recall":          round(recall_score(y_test, y_pred) * 100, 2),
                "f1_score":        round(f1_score(y_test, y_pred) * 100, 2),
                "train_accuracy":  train_acc,
                "test_accuracy":   round(accuracy_score(y_test, y_pred) * 100, 2),
                "overfitting_gap": round(train_acc - accuracy_score(y_test, y_pred) * 100, 2),
                "classification_report": {
                    "normal (0)": {
                        "precision": round(cr["0"]["precision"], 4),
                        "recall":    round(cr["0"]["recall"], 4),
                        "f1_score":  round(cr["0"]["f1-score"], 4),
                        "support":   int(cr["0"]["support"]),
                    },
                    "attack (1)": {
                        "precision": round(cr["1"]["precision"], 4),
                        "recall":    round(cr["1"]["recall"], 4),
                        "f1_score":  round(cr["1"]["f1-score"], 4),
                        "support":   int(cr["1"]["support"]),
                    },
                    "weighted_avg": {
                        "precision": round(cr["weighted avg"]["precision"], 4),
                        "recall":    round(cr["weighted avg"]["recall"], 4),
                        "f1_score":  round(cr["weighted avg"]["f1-score"], 4),
                    },
                },
                "confusion_matrix": {
                    "labels": ["Normal (0)", "Attack (1)"],
                    "matrix": cm,
                    "TN": cm[0][0], "FP": cm[0][1],
                    "FN": cm[1][0], "TP": cm[1][1],
                },
                "dataset_info": {
                    "total_samples": len(x),
                    "train_samples": len(x_train),
                    "test_samples":  len(x_test),
                    "features":      len(features),
                },
            }
            print(f"  ✅ {MODEL_DISPLAY[key]}: {_comparison_metrics[key]['accuracy']}% accuracy")
        except Exception as e:
            print(f"  ⚠️  Could not evaluate {MODEL_DISPLAY[key]}: {e}")


def load_models():
    global _models
    print("Loading ML models…")
    for key in _MODEL_FILES:
        _models[key] = _load_one(key)
        status = "✅ loaded" if _models[key] is not None else "⚠️  file not found"
        print(f"  {MODEL_DISPLAY[key]}: {status}")

    print("Computing comparison metrics…")
    _fit_scaler_and_evaluate()


# Legacy alias kept for backward compat (main.py calls load_model())
def load_model():
    load_models()


def _get_feature_contributions(model, model_key: str, features: list) -> list:
    if hasattr(model, "feature_importances_"):
        importances = model.feature_importances_.tolist()
    elif hasattr(model, "coef_"):
        raw = np.abs(model.coef_[0]).tolist()
        total = sum(raw) or 1.0
        importances = [v / total for v in raw]
    else:
        importances = [1.0 / len(FEATURE_NAMES)] * len(FEATURE_NAMES)

    contributions = [
        {"feature": name, "importance": round(imp, 4), "value": features[i]}
        for i, (name, imp) in enumerate(zip(FEATURE_NAMES, importances))
    ]
    contributions.sort(key=lambda x: x["importance"], reverse=True)
    return contributions


def predict(features: list, model_key: Optional[str] = None) -> dict:
    import state
    key = model_key or state.get_active_model()
    model = _models.get(key)

    if model is None:
        # fall back to whichever is loaded
        for fallback_key, fallback_model in _models.items():
            if fallback_model is not None:
                key, model = fallback_key, fallback_model
                break

    if model is None:
        raise RuntimeError("No ML model is loaded.")

    arr = np.array([features], dtype=float)
    if key in NEEDS_SCALING and _scaler is not None:
        arr = _scaler.transform(arr)

    prediction = int(model.predict(arr)[0])
    proba = model.predict_proba(arr)[0]
    confidence = float(proba[prediction])

    return {
        "prediction":           prediction,
        "confidence":           round(confidence * 100, 2),
        "probabilities": {
            "normal": round(float(proba[0]) * 100, 2),
            "attack": round(float(proba[1]) * 100, 2),
        },
        "model_used":           key,
        "model_display":        MODEL_DISPLAY.get(key, key),
        "feature_contributions": _get_feature_contributions(model, key, features),
    }


def get_feature_importances() -> dict:
    model = _models.get("random_forest")
    if model is None or not hasattr(model, "feature_importances_"):
        return {name: 0.0 for name in FEATURE_NAMES}
    importances = model.feature_importances_.tolist()
    return {name: round(imp, 4) for name, imp in zip(FEATURE_NAMES, importances)}


def get_model_classes() -> list:
    import state
    model = _models.get(state.get_active_model())
    if model is None:
        return [0, 1]
    return model.classes_.tolist()


def get_comparison_metrics() -> dict:
    return _comparison_metrics


def get_models_info() -> dict:
    return {
        key: {
            "display_name":  MODEL_DISPLAY[key],
            "loaded":        _models.get(key) is not None,
            "needs_scaling": key in NEEDS_SCALING,
            "metrics":       _comparison_metrics.get(key, {}),
            **MODEL_INFO.get(key, {}),
        }
        for key in _MODEL_FILES
    }
