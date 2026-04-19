import asyncio
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query

from auth.dependencies import get_ws_user
from services.ws_manager import ws_manager

router = APIRouter()


@router.websocket("/ws")
async def websocket_endpoint(
    websocket: WebSocket,
    token: str = Query(""),
):
    user = await get_ws_user(websocket, token)

    if user is None:
        await websocket.accept()
        await websocket.send_text('{"event":"error","message":"Unauthorized"}')
        await websocket.close(code=4001)
        return

    await ws_manager.connect(websocket, user)

    try:
        # Send initial connected confirmation
        await websocket.send_text(
            f'{{"event":"connected","message":"Live feed active","user":"{user["username"]}","active_connections":{ws_manager.active_connections}}}'
        )

        # Keep connection alive, handle pings from client
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text('{"event":"pong"}')
            except asyncio.TimeoutError:
                # Send server-side ping every 30s to keep alive
                await websocket.send_text('{"event":"heartbeat"}')

    except WebSocketDisconnect:
        pass
    finally:
        await ws_manager.disconnect(websocket)
