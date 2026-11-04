"""
SentinelGrid - Central Control Plane & Management API Server
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

import sys
from pathlib import Path

# Ensure backend root is always in sys.path regardless of execution context
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from app.api.v1.policies import router as policies_router
from app.api.v1.console import router as console_router
from app.api.v1.auth import router as auth_router
import os

app = FastAPI(
    title="SentinelGrid WAAP Management & Control Plane",
    description="Central control plane with in-line inspection, policy simulation, and web console.",
    version="1.0.0"
)

# Standard Cloud & Local CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|.*\.vercel\.app|.*\.github\.io|.*\.onrender\.com)(:\d+)?$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers
app.include_router(policies_router)
app.include_router(console_router)
app.include_router(auth_router)


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "sentinelgrid-management-api",
        "version": "1.0.0"
    }


# Mount Web Console frontend static build with candidate directory discovery
candidate_static_dirs = [
    os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "public"),
    os.path.join(os.getcwd(), "frontend", "public"),
    os.path.join(os.getcwd(), "public"),
]
static_dir = next((d for d in candidate_static_dirs if os.path.isdir(d)), None)
if static_dir:
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
