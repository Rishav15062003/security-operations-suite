"""Run FastAPI with: python -m mini_ares"""
from __future__ import annotations

import os

import uvicorn

if __name__ == "__main__":
    host = os.environ.get("MINI_ARES_HOST", "127.0.0.1")
    port = int(os.environ.get("MINI_ARES_PORT", "8765"))
    uvicorn.run("mini_ares.api:app", host=host, port=port, reload=False)
