"""
SentinelGrid - Central Control Plane & Management API Server
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

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

# Standard CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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


# Mount Web Console frontend static build
static_dir = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "public")
if os.path.exists(static_dir):
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="static")
