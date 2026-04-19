import io
import pandas as pd
from fastapi import APIRouter, File, HTTPException, UploadFile, Depends

import state
from services.preprocessing import preprocess_dataframe
from database.mongodb import get_db
from database.models import DatasetRecord
from auth.dependencies import get_current_user, require_role

router = APIRouter()


@router.post("/")
async def upload_csv(
    file: UploadFile = File(...),
    current_user: dict = Depends(require_role("analyst", "admin")),
):
    if not file.filename.lower().endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV files are accepted.")

    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Failed to parse CSV: {str(e)}")

    df = preprocess_dataframe(df)
    state.set_dataset(df)

    attack_dist = {}
    if "attack_detected" in df.columns:
        vc = df["attack_detected"].value_counts()
        attack_dist = {"normal": int(vc.get(0, 0)), "attack": int(vc.get(1, 0))}

    protocol_dist = {}
    if "protocol_type" in df.columns:
        protocol_dist = {str(k): int(v) for k, v in df["protocol_type"].value_counts().items()}

    browser_dist = {}
    if "browser_type" in df.columns:
        browser_dist = {str(k): int(v) for k, v in df["browser_type"].value_counts().items()}

    missing = {k: int(v) for k, v in df.isnull().sum().items()}
    stats_raw = df.describe(include="all").fillna("N/A")
    basic_stats = {col: stats_raw[col].to_dict() for col in stats_raw.columns}

    # ── Persist dataset metadata to MongoDB ────────────────────────────────────
    db = get_db()
    record = DatasetRecord(
        user_id=current_user["id"],
        username=current_user["username"],
        filename=file.filename,
        rows=int(df.shape[0]),
        columns=int(df.shape[1]),
        attack_count=attack_dist.get("attack", 0),
        normal_count=attack_dist.get("normal", 0),
        missing_values=missing,
    )
    await db.datasets.insert_one(record.model_dump(exclude={"id"}))

    return {
        "filename": file.filename,
        "uploaded_by": current_user["username"],
        "shape": {"rows": int(df.shape[0]), "columns": int(df.shape[1])},
        "columns": df.columns.tolist(),
        "missing_values": missing,
        "attack_distribution": attack_dist,
        "protocol_distribution": protocol_dist,
        "browser_distribution": browser_dist,
        "basic_stats": basic_stats,
        "preview": df.head(10).fillna("N/A").to_dict(orient="records"),
    }
