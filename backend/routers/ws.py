"""
backend/routers/ws.py
---------------------
WebSocket Connection Manager and console broadcast route for Chimera SOC.

All connected clients on /ws/console receive live JSON event broadcasts
whenever new security events are ingested or incidents are approved.
"""

import json
from typing import List

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter(tags=["WebSocket"])


class ConnectionManager:
    """Manages active WebSocket connections and provides broadcast capability."""

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"[ws] Client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket connection from the active pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        print(f"[ws] Client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict) -> None:
        """
        Broadcast a JSON message to all currently active WebSocket connections.
        Silently removes connections that have become stale or disconnected.
        """
        dead: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_text(json.dumps(message))
            except Exception:
                dead.append(connection)
        for conn in dead:
            self.disconnect(conn)


# Singleton manager shared across the application
manager = ConnectionManager()


@router.websocket("/ws/console")
async def websocket_console(websocket: WebSocket) -> None:
    """
    WebSocket endpoint for the live SOC console stream.

    Clients that connect here will receive real-time JSON broadcasts for:
    - New security event ingestion + AI triage results
    - Risk engine decisions
    - Analyst approval events
    """
    await manager.connect(websocket)
    try:
        while True:
            # Keep the connection alive; client can send pings or any text
            data = await websocket.receive_text()
            # Echo back a simple acknowledgement
            await websocket.send_text(json.dumps({"type": "ack", "echo": data}))
    except WebSocketDisconnect:
        manager.disconnect(websocket)
