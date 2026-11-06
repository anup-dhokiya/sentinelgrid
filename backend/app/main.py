"""
SentinelGrid - Central Control Plane & Management API Server
Author: SentinelGrid Architecture Core Team
"""

import sys
from pathlib import Path

# Ensure backend root is always in sys.path regardless of execution context
_BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(_BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(_BACKEND_DIR))

from fastapi import FastAPI, Request
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

# Explicit Whitelist CORS Configuration (Prevents Wildcard & Internal Subnet Leakage)
ALLOWED_ORIGINS = [
    "https://sentinelgrid-one.vercel.app",
    "https://aegispro.vercel.app",
    "https://aegispro-murex.vercel.app",
    "https://anup-dhokiya.github.io",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://([a-zA-Z0-9-]+\.)*(vercel\.app|github\.io)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    """Enforces strict defense-in-depth HTTP response headers and sanitizes inline dispositions."""
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"
    if "content-disposition" in response.headers and response.headers["content-disposition"] == "inline":
        del response.headers["content-disposition"]
    return response

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
