"""
SentinelGrid - Central Control Plane & Management API Server
Author: Anup Dhokiya (@anup-dhokiya) - Developer 1 / Lead Architect
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.v1.policies import router as policies_router

app = FastAPI(
    title="SentinelGrid Management & Control Plane API",
    description="Central control plane for policy signing, simulation, API discovery, and multi-tenant telemetry.",
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


@app.get("/health", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": "sentinelgrid-management-api",
        "version": "1.0.0"
    }
