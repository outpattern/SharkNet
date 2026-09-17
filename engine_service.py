"""
Headless SharkNet engine — the network engine + local API/WebSocket server
WITHOUT any UI. This is the clean separation point: the UI (run.py / PyWebView,
or any future Windows UI) is just a client of this server.

Run it standalone to operate SharkNet as a background service:
    python engine_service.py                # http://127.0.0.1:8734

The desktop app (run.py) starts the same server internally; this entry point
lets a different front-end (or a Windows service wrapper) reuse the engine
untouched.
"""
from __future__ import annotations

import os

import uvicorn

HOST = os.environ.get("SHARKNET_HOST", "127.0.0.1")
PORT = int(os.environ.get("SHARKNET_PORT", "8734"))


def main() -> None:
    from backend.server import app
    uvicorn.run(app, host=HOST, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
