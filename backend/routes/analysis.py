from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import Optional
import numpy as np

import state
from auth.dependencies import get_current_user

router = APIRouter()


class FilterRequest(BaseModel):
    protocol_type:      Optional[str] = None
    encryption_used:    Optional[str] = None
    browser_type:       Optional[str] = None
    unusual_time_access: Optional[int] = None


def _require_dataset():
    df = state.get_dataset()
    if df is None:
        raise HTTPException(
            status_code=400,
            detail="No dataset loaded. Please upload a CSV file first.",
        )
    return df


@router.get("/summary")
async def get_summary(current_user: dict = Depends(get_current_user)):
    df = _require_dataset()
    result = {"total_records": int(len(df))}

    # ── Attack stats ────────────────────────────────────────────────────────────
    if "attack_detected" in df.columns:
        result["attack_count"]  = int(df["attack_detected"].sum())
        result["normal_count"]  = int((df["attack_detected"] == 0).sum())
        result["attack_rate"]   = round(float(df["attack_detected"].mean()) * 100, 2)

    # ── Categorical breakdowns ───────────────────────────────────────────────────
    if "protocol_type" in df.columns:
        result["protocol_breakdown"] = {
            str(k): int(v) for k, v in df["protocol_type"].value_counts().items()
        }
    if "browser_type" in df.columns:
        result["browser_breakdown"] = {
            str(k): int(v) for k, v in df["browser_type"].value_counts().items()
        }
    if "encryption_used" in df.columns:
        result["encryption_breakdown"] = {
            str(k): int(v) for k, v in df["encryption_used"].value_counts().items()
        }

    # ── Numeric stats ───────────────────────────────────────────────────────────
    if "ip_reputation_score" in df.columns:
        result["ip_reputation"] = {
            "mean": round(float(df["ip_reputation_score"].mean()), 4),
            "max":  round(float(df["ip_reputation_score"].max()), 4),
            "min":  round(float(df["ip_reputation_score"].min()), 4),
        }
    if "unusual_time_access" in df.columns:
        result["unusual_time_rate"] = round(
            float(df["unusual_time_access"].mean()) * 100, 2
        )
    if "network_packet_size" in df.columns:
        result["packet_size_stats"] = {
            "mean": round(float(df["network_packet_size"].mean()), 2),
            "max":  int(df["network_packet_size"].max()),
            "min":  int(df["network_packet_size"].min()),
        }

    # ── Distributions ────────────────────────────────────────────────────────────
    if "failed_logins" in df.columns:
        result["failed_logins_dist"] = {
            str(k): int(v)
            for k, v in df["failed_logins"].value_counts().sort_index().items()
        }
    if "login_attempts" in df.columns:
        result["login_attempts_dist"] = {
            str(k): int(v)
            for k, v in df["login_attempts"].value_counts().sort_index().items()
        }

    # ── IP reputation histogram (10 bins) ───────────────────────────────────────
    if "ip_reputation_score" in df.columns:
        hist, edges = np.histogram(df["ip_reputation_score"].dropna(), bins=10)
        result["ip_reputation_histogram"] = [
            {"range": f"{edges[i]:.2f}–{edges[i+1]:.2f}", "count": int(hist[i])}
            for i in range(len(hist))
        ]

    # ── Session duration histogram (8 bins) ─────────────────────────────────────
    if "session_duration" in df.columns:
        sd = df["session_duration"].dropna()
        hist_sd, edges_sd = np.histogram(sd, bins=8)
        result["session_duration_histogram"] = [
            {"range": f"{int(edges_sd[i])}–{int(edges_sd[i+1])}s", "count": int(hist_sd[i])}
            for i in range(len(hist_sd))
        ]
        result["session_duration_stats"] = {
            "mean":   round(float(sd.mean()), 1),
            "median": round(float(sd.median()), 1),
            "max":    round(float(sd.max()), 1),
            "min":    round(float(sd.min()), 1),
        }

    # ── Network packet size histogram (10 bins) ──────────────────────────────────
    if "network_packet_size" in df.columns:
        ps = df["network_packet_size"].dropna()
        hist_ps, edges_ps = np.histogram(ps, bins=10)
        result["packet_size_histogram"] = [
            {"range": f"{int(edges_ps[i])}–{int(edges_ps[i+1])}", "count": int(hist_ps[i])}
            for i in range(len(hist_ps))
        ]

    # ── Cross-tab: attack by protocol ────────────────────────────────────────────
    if "attack_detected" in df.columns and "protocol_type" in df.columns:
        cross = df.groupby("protocol_type")["attack_detected"].agg(["sum", "count"])
        cross["attack_rate"] = (cross["sum"] / cross["count"] * 100).round(2)
        result["attack_by_protocol"] = (
            cross.reset_index()
            .rename(columns={"protocol_type": "protocol", "sum": "attacks", "count": "total"})
            .to_dict(orient="records")
        )

    # ── Cross-tab: attack by browser ─────────────────────────────────────────────
    if "attack_detected" in df.columns and "browser_type" in df.columns:
        cross_b = df.groupby("browser_type")["attack_detected"].agg(["sum", "count"])
        cross_b["attack_rate"] = (cross_b["sum"] / cross_b["count"] * 100).round(2)
        result["attack_by_browser"] = (
            cross_b.reset_index()
            .rename(columns={"browser_type": "browser", "sum": "attacks", "count": "total"})
            .to_dict(orient="records")
        )

    # ── Cross-tab: attack by encryption ──────────────────────────────────────────
    if "attack_detected" in df.columns and "encryption_used" in df.columns:
        cross_e = df.groupby("encryption_used")["attack_detected"].agg(["sum", "count"])
        cross_e["attack_rate"] = (cross_e["sum"] / cross_e["count"] * 100).round(2)
        result["attack_by_encryption"] = (
            cross_e.reset_index()
            .rename(columns={"encryption_used": "encryption", "sum": "attacks", "count": "total"})
            .to_dict(orient="records")
        )

    # ── Attack at unusual vs normal times ────────────────────────────────────────
    if "attack_detected" in df.columns and "unusual_time_access" in df.columns:
        cross_t = df.groupby("unusual_time_access")["attack_detected"].agg(["sum", "count"])
        cross_t["attack_rate"] = (cross_t["sum"] / cross_t["count"] * 100).round(2)
        result["attack_by_time"] = (
            cross_t.reset_index()
            .rename(columns={"unusual_time_access": "unusual", "sum": "attacks", "count": "total"})
            .to_dict(orient="records")
        )

    # ── Key correlations with attack_detected ────────────────────────────────────
    if "attack_detected" in df.columns:
        numeric_cols = df.select_dtypes(include=[float, int]).columns.tolist()
        if "attack_detected" in numeric_cols:
            corr = df[numeric_cols].corr()["attack_detected"].drop("attack_detected")
            result["attack_correlations"] = [
                {"feature": feat, "correlation": round(float(val), 4)}
                for feat, val in corr.sort_values(key=abs, ascending=False).items()
            ]

    return result


@router.post("/filter")
async def filter_data(
    filters: FilterRequest,
    current_user: dict = Depends(get_current_user),
):
    df = _require_dataset()
    filtered = df.copy()

    if filters.protocol_type:
        filtered = filtered[filtered["protocol_type"] == filters.protocol_type]
    if filters.encryption_used:
        filtered = filtered[filtered["encryption_used"] == filters.encryption_used]
    if filters.browser_type:
        filtered = filtered[filtered["browser_type"] == filters.browser_type]
    if filters.unusual_time_access is not None:
        filtered = filtered[filtered["unusual_time_access"] == filters.unusual_time_access]

    if len(filtered) == 0:
        return {"total_records": 0, "message": "No records match the selected filters."}

    result = {
        "total_records": int(len(filtered)),
        "attack_count":  int(filtered["attack_detected"].sum()) if "attack_detected" in filtered else 0,
        "normal_count":  int((filtered["attack_detected"] == 0).sum()) if "attack_detected" in filtered else 0,
    }
    if "ip_reputation_score" in filtered.columns:
        result["avg_ip_reputation"] = round(float(filtered["ip_reputation_score"].mean()), 4)
    if "network_packet_size" in filtered.columns:
        result["avg_packet_size"] = round(float(filtered["network_packet_size"].mean()), 2)
    if "failed_logins" in filtered.columns:
        result["avg_failed_logins"] = round(float(filtered["failed_logins"].mean()), 2)
    if "session_duration" in filtered.columns:
        result["avg_session_duration"] = round(float(filtered["session_duration"].mean()), 1)
    if "attack_detected" in filtered.columns:
        result["attack_rate"] = round(float(filtered["attack_detected"].mean()) * 100, 2)

    return result


@router.get("/timeseries")
async def get_attack_simulation(current_user: dict = Depends(get_current_user)):
    import random
    import datetime

    now = datetime.datetime.utcnow()
    series = []
    for i in range(24):
        ts = (now - datetime.timedelta(hours=23 - i)).strftime("%H:00")
        series.append({
            "time":          ts,
            "total_traffic": random.randint(80, 300),
            "attacks":       random.randint(0, 60),
            "anomaly_score": round(random.uniform(0.1, 0.9), 2),
        })
    return {"series": series}
