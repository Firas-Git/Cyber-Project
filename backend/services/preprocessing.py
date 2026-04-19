import pandas as pd
from typing import Any

# LabelEncoder alphabetical mappings (must match training pipeline exactly)
PROTOCOL_MAP = {"ICMP": 0, "TCP": 1, "UDP": 2}
ENCRYPTION_MAP = {"AES": 0, "DES": 1}
BROWSER_MAP = {"Chrome": 0, "Edge": 1, "Firefox": 2, "Safari": 3, "Unknown": 4}

PROTOCOL_REVERSE = {v: k for k, v in PROTOCOL_MAP.items()}
ENCRYPTION_REVERSE = {v: k for k, v in ENCRYPTION_MAP.items()}
BROWSER_REVERSE = {v: k for k, v in BROWSER_MAP.items()}

FEATURE_ORDER = [
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

ENCRYPTION_MODE = "AES"  # mode from training data


def encode_input(data: dict) -> list:
    encoded = {
        "network_packet_size": int(data["network_packet_size"]),
        "protocol_type": PROTOCOL_MAP.get(str(data["protocol_type"]), 1),
        "login_attempts": int(data["login_attempts"]),
        "session_duration": float(data["session_duration"]),
        "encryption_used": ENCRYPTION_MAP.get(str(data["encryption_used"]), 0),
        "ip_reputation_score": float(data["ip_reputation_score"]),
        "failed_logins": int(data["failed_logins"]),
        "browser_type": BROWSER_MAP.get(str(data["browser_type"]), 4),
        "unusual_time_access": int(data["unusual_time_access"]),
    }
    return [encoded[f] for f in FEATURE_ORDER]


def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    if "session_id" in df.columns:
        df.drop(columns=["session_id"], inplace=True)
    if "encryption_used" in df.columns:
        df["encryption_used"] = df["encryption_used"].fillna(ENCRYPTION_MODE)
    return df


def infer_attack_type(features: dict, prediction: int) -> dict:
    """Heuristic attack-type classification when prediction == 1 (attack detected)."""
    if prediction == 0:
        return {"type": "Normal Traffic", "color": "#00ff88", "icon": "✅"}

    packet_size = int(features.get("network_packet_size", 500))
    failed = int(features.get("failed_logins", 0))
    login_att = int(features.get("login_attempts", 4))
    unusual = int(features.get("unusual_time_access", 0))
    ip_rep = float(features.get("ip_reputation_score", 0.3))

    # Simple heuristic scoring
    ddos_score = (1 if packet_size > 800 else 0) + (1 if ip_rep > 0.5 else 0)
    intrusion_score = (1 if failed >= 3 else 0) + (1 if login_att >= 7 else 0)
    malware_score = (1 if unusual == 1 else 0) + (1 if ip_rep > 0.4 else 0)

    scores = {"DDoS Attack": ddos_score, "Intrusion Attempt": intrusion_score, "Malware Activity": malware_score}
    attack_type = max(scores, key=lambda k: scores[k])

    colors = {
        "DDoS Attack": "#ff4757",
        "Intrusion Attempt": "#ffa502",
        "Malware Activity": "#ff6b81",
    }
    icons = {"DDoS Attack": "🌊", "Intrusion Attempt": "🔐", "Malware Activity": "🦠"}

    return {"type": attack_type, "color": colors[attack_type], "icon": icons[attack_type]}
