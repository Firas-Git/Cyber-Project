from fastapi import APIRouter, Depends

from services.model_service import get_feature_importances
from auth.dependencies import get_current_user

router = APIRouter()

_METRICS = {
    "accuracy": 88.43,
    "train_accuracy": 100.0,
    "test_accuracy": 88.43,
    "overfitting_gap": 11.57,
    "classification_report": {
        "normal (0)": {"precision": 0.83, "recall": 0.99, "f1_score": 0.90, "support": 1582},
        "attack (1)": {"precision": 0.99, "recall": 0.75, "f1_score": 0.85, "support": 1280},
        "macro_avg": {"precision": 0.91, "recall": 0.87, "f1_score": 0.88},
        "weighted_avg": {"precision": 0.90, "recall": 0.88, "f1_score": 0.88},
    },
    "confusion_matrix": {
        "labels": ["Normal (0)", "Attack (1)"],
        "matrix": [[1567, 15], [317, 963]],
        "TP": 963, "TN": 1567, "FP": 15, "FN": 317,
    },
    "dataset_info": {
        "total_samples": 9537,
        "train_samples": 6675,
        "test_samples": 2862,
        "features": 9,
        "classes": 2,
        "class_balance": {"normal": 52.53, "attack": 47.47},
    },
    "model_info": {
        "algorithm": "Random Forest Classifier",
        "n_estimators": 100,
        "max_features": "sqrt",
        "criterion": "gini",
    },
}


@router.get("/")
async def get_metrics(current_user: dict = Depends(get_current_user)):
    fi = get_feature_importances()
    sorted_fi = sorted(fi.items(), key=lambda x: x[1], reverse=True)
    return {
        **_METRICS,
        "feature_importance": [{"feature": k, "importance": v} for k, v in sorted_fi],
    }


@router.get("/feature-importance")
async def get_feature_importance(current_user: dict = Depends(get_current_user)):
    fi = get_feature_importances()
    return {
        "feature_importance": [
            {"feature": k, "importance": v}
            for k, v in sorted(fi.items(), key=lambda x: x[1], reverse=True)
        ]
    }
