from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from services.model_service import get_models_info, get_comparison_metrics, MODEL_DISPLAY
from auth.dependencies import get_current_user, require_role
import state

router = APIRouter()

VALID_MODELS = {"random_forest", "logistic_regression", "knn"}


class SelectModelRequest(BaseModel):
    model: str


@router.get("/")
async def list_models(current_user: dict = Depends(get_current_user)):
    return {
        "models":       get_models_info(),
        "active_model": state.get_active_model(),
    }


@router.get("/compare")
async def compare_models(current_user: dict = Depends(get_current_user)):
    metrics = get_comparison_metrics()
    return {
        "comparison":   metrics,
        "active_model": state.get_active_model(),
        "model_keys":   list(VALID_MODELS),
    }


@router.post("/select")
async def select_model(
    req: SelectModelRequest,
    current_user: dict = Depends(require_role("analyst", "admin")),
):
    if req.model not in VALID_MODELS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid model key '{req.model}'. Valid options: {sorted(VALID_MODELS)}",
        )
    info = get_models_info()
    if not info.get(req.model, {}).get("loaded", False):
        raise HTTPException(
            status_code=503,
            detail=f"Model '{req.model}' is not loaded. Check that the .pkl file exists in the backend directory.",
        )
    state.set_active_model(req.model)
    return {
        "active_model": req.model,
        "display_name": MODEL_DISPLAY.get(req.model, req.model),
        "message": f"Switched to {MODEL_DISPLAY.get(req.model, req.model)}",
    }


@router.get("/active")
async def get_active_model(current_user: dict = Depends(get_current_user)):
    info = get_models_info()
    active = state.get_active_model()
    model_info = info.get(active, {})
    return {
        "active_model": active,
        "display_name": model_info.get("display_name", active),
        "loaded":       model_info.get("loaded", False),
        "metrics":      model_info.get("metrics", {}),
        "notes":        model_info.get("notes", ""),
        "strengths":    model_info.get("strengths", ""),
    }
