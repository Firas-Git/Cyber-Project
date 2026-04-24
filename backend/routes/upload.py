import io
import numpy as np
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

    # ── Basic counts ────────────────────────────────────────────────────────────
    attack_dist: dict = {}
    if "attack_detected" in df.columns:
        vc = df["attack_detected"].value_counts()
        total = len(df)
        n_normal = int(vc.get(0, 0))
        n_attack = int(vc.get(1, 0))
        attack_dist = {
            "normal":      n_normal,
            "attack":      n_attack,
            "attack_rate": round(n_attack / total * 100, 2) if total else 0,
            "normal_rate": round(n_normal / total * 100, 2) if total else 0,
        }

    protocol_dist: dict = {}
    if "protocol_type" in df.columns:
        protocol_dist = {str(k): int(v) for k, v in df["protocol_type"].value_counts().items()}

    browser_dist: dict = {}
    if "browser_type" in df.columns:
        browser_dist = {str(k): int(v) for k, v in df["browser_type"].value_counts().items()}

    encryption_dist: dict = {}
    if "encryption_used" in df.columns:
        encryption_dist = {str(k): int(v) for k, v in df["encryption_used"].value_counts().items()}

    # ── Numeric column summaries ──────────────────────────────────────────────
    numeric_cols = ["network_packet_size", "login_attempts", "session_duration",
                    "ip_reputation_score", "failed_logins", "unusual_time_access"]
    numeric_summary: dict = {}
    for col in numeric_cols:
        if col in df.columns:
            s = df[col].dropna()
            numeric_summary[col] = {
                "mean":   round(float(s.mean()), 3),
                "std":    round(float(s.std()), 3),
                "min":    round(float(s.min()), 3),
                "max":    round(float(s.max()), 3),
                "median": round(float(s.median()), 3),
            }

    # ── Missing values ─────────────────────────────────────────────────────────
    missing = {k: int(v) for k, v in df.isnull().sum().items()}
    missing_pct = {k: round(v / len(df) * 100, 1) for k, v in missing.items()}

    # ── Session duration histogram ─────────────────────────────────────────────
    session_hist: list = []
    if "session_duration" in df.columns:
        sd = df["session_duration"].dropna()
        hist, edges = np.histogram(sd, bins=8)
        session_hist = [
            {"range": f"{int(edges[i])}–{int(edges[i+1])}s", "count": int(hist[i])}
            for i in range(len(hist))
        ]

    # ── Persist metadata ───────────────────────────────────────────────────────
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
        "filename":            file.filename,
        "uploaded_by":         current_user["username"],
        "shape":               {"rows": int(df.shape[0]), "columns": int(df.shape[1])},
        "columns":             df.columns.tolist(),
        "missing_values":      missing,
        "missing_pct":         missing_pct,
        "attack_distribution": attack_dist,
        "protocol_distribution":   protocol_dist,
        "browser_distribution":    browser_dist,
        "encryption_distribution": encryption_dist,
        "numeric_summary":     numeric_summary,
        "session_histogram":   session_hist,
        "preview":             df.head(10).fillna("N/A").to_dict(orient="records"),
    }
