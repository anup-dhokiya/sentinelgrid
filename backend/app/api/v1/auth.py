"""
SentinelGrid - Authentication & Identity API Router
Provides JWT/Token-based Login, Signup, and User Session Verification.
"""

import hashlib
from datetime import datetime, timezone
from uuid import uuid4
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.core.database import get_db_connection

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: str


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


@router.post("/login")
async def login(req: LoginRequest):
    pwd_hash = hash_password(req.password)
    conn = get_db_connection()
    with conn:
        row = conn.execute(
            "SELECT id, email, full_name, role FROM users WHERE email = ? AND password_hash = ?",
            (req.email.lower().strip(), pwd_hash)
        ).fetchone()

    if not row:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Verify your email and password."
        )

    # In production, this issues an asymmetric signed JWT token
    token = f"sg_session_{uuid4().hex}"

    return {
        "status": "authenticated",
        "token": token,
        "user": {
            "id": row["id"],
            "email": row["email"],
            "full_name": row["full_name"],
            "role": row["role"]
        }
    }


@router.post("/signup")
async def signup(req: SignupRequest):
    pwd_hash = hash_password(req.password)
    user_id = f"usr-{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                "INSERT INTO users (id, email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, 'analyst', ?)",
                (user_id, req.email.lower().strip(), pwd_hash, req.full_name.strip(), now)
            )
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists."
            )
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))

    token = f"sg_session_{uuid4().hex}"

    return {
        "status": "created",
        "token": token,
        "user": {
            "id": user_id,
            "email": req.email,
            "full_name": req.full_name,
            "role": "analyst"
        }
    }
