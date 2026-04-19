import asyncio
import json
from datetime import datetime, timezone
from fastapi import WebSocket
from typing import NamedTuple


class Connection(NamedTuple):
    websocket: WebSocket
    user_id: str
    username: str
    role: str


class ConnectionManager:
    def __init__(self):
        self._connections: list[Connection] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user: dict) -> None:
        await websocket.accept()
        async with self._lock:
            self._connections.append(
                Connection(
                    websocket=websocket,
                    user_id=user.get("id", ""),
                    username=user.get("username", "unknown"),
                    role=user.get("role", "viewer"),
                )
            )

    async def disconnect(self, websocket: WebSocket) -> None:
        async with self._lock:
            self._connections = [c for c in self._connections if c.websocket is not websocket]

    async def broadcast(self, event: dict) -> None:
        if not self._connections:
            return
        message = json.dumps(event, default=str)
        dead: list[WebSocket] = []
        async with self._lock:
            targets = list(self._connections)
        for conn in targets:
            try:
                await conn.websocket.send_text(message)
            except Exception:
                dead.append(conn.websocket)
        if dead:
            async with self._lock:
                self._connections = [c for c in self._connections if c.websocket not in dead]

    async def send_to_user(self, user_id: str, event: dict) -> None:
        message = json.dumps(event, default=str)
        async with self._lock:
            targets = [c for c in self._connections if c.user_id == user_id]
        for conn in targets:
            try:
                await conn.websocket.send_text(message)
            except Exception:
                pass

    @property
    def active_connections(self) -> int:
        return len(self._connections)

    def build_attack_event(self, prediction_result: dict, username: str) -> dict:
        return {
            "event": "attack_detected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "analyst": username,
            "attack_type": prediction_result.get("attack_type"),
            "risk_level": prediction_result.get("risk_level"),
            "risk_score": prediction_result.get("risk_score"),
            "confidence": prediction_result.get("confidence"),
            "prediction": prediction_result.get("prediction"),
            "recommended_action": prediction_result.get("recommended_action"),
            "attack_color": prediction_result.get("attack_color"),
            "attack_icon": prediction_result.get("attack_icon"),
        }

    def build_ping_event(self) -> dict:
        return {
            "event": "ping",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "active_connections": self.active_connections,
        }


# Singleton — imported everywhere
ws_manager = ConnectionManager()
