"""
SentinelGrid - Authentication & Identity API Router
Provides JWT/Token-based Login, Signup, and User Session Verification.
"""

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from typing import Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status, Header, Depends
from pydantic import BaseModel

from app.core.database import get_db_connection, get_db

router = APIRouter(prefix="/v1/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: str
    password: str


class SignupRequest(BaseModel):
    email: str
    password: str
    full_name: str
    role: str = "member"  # 'manager', 'team_leader', 'member'

ALLOWED_ROLES = {"manager", "team_leader", "member"}


def hash_password(password: str) -> str:
    """Computes a cryptographically salted PBKDF2-HMAC-SHA256 hash (100,000 rounds)."""
    salt = secrets.token_hex(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"pbkdf2:sha256:100000${salt}${key.hex()}"


def verify_password(plain_password: str, stored_hash: str) -> bool:
    """Verifies plain password against PBKDF2 hash or legacy unsalted SHA-256."""
    if not stored_hash:
        return False
    if stored_hash.startswith("pbkdf2:sha256:"):
        try:
            parts = stored_hash.split("$")
            rounds = int(parts[0].split(":")[2])
            salt = parts[1]
            expected_hex = parts[2]
            computed = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt.encode("utf-8"), rounds).hex()
            return secrets.compare_digest(computed, expected_hex)
        except Exception:
            return False
    # Legacy unsalted SHA-256 fallback (e.g. initial seeded accounts)
    legacy = hashlib.sha256(plain_password.encode("utf-8")).hexdigest()
    return secrets.compare_digest(legacy, stored_hash)


def create_session(user_id: str) -> str:
    """Persists a new cryptographically random session token in SQLite with 7-day TTL."""
    token = f"sg_session_{secrets.token_hex(24)}"
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=7)
    with get_db() as conn:
        with conn:
            conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, now.isoformat(), expires.isoformat())
            )
    return token


def verify_session(token: str) -> Optional[Dict[str, Any]]:
    """Validates session token expiration and returns user record if active."""
    if not token:
        return None
    now_iso = datetime.now(timezone.utc).isoformat()
    with get_db() as conn:
        row = conn.execute("""
            SELECT u.id, u.email, u.full_name, u.role, s.expires_at
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ? AND s.expires_at > ?
        """, (token.strip(), now_iso)).fetchone()
    if row:
        return dict(row)
    return None


@router.post("/login")
async def login(req: LoginRequest):
    with get_db() as conn:
        row = conn.execute(
            "SELECT id, email, password_hash, full_name, role FROM users WHERE email = ?",
            (req.email.lower().strip(),)
        ).fetchone()

    if not row or not verify_password(req.password, row["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Verify your email and password."
        )

    # Issue persistent session token
    token = create_session(row["id"])

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
    role_clean = req.role.lower().strip()
    if role_clean not in ALLOWED_ROLES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid role. Allowed operational roles are: {', '.join(sorted(ALLOWED_ROLES))}"
        )

    if len(req.password) < 6:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 6 characters."
        )

    pwd_hash = hash_password(req.password)
    user_id = f"usr-{uuid4().hex[:8]}"
    now = datetime.now(timezone.utc).isoformat()

    try:
        with get_db() as conn:
            with conn:
                conn.execute(
                    "INSERT INTO users (id, email, password_hash, full_name, role, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (user_id, req.email.lower().strip(), pwd_hash, req.full_name.strip(), role_clean, now)
                )
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="An account with this email address already exists."
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to register user. An internal database error occurred."
        )

    token = create_session(user_id)

    return {
        "status": "created",
        "token": token,
        "user": {
            "id": user_id,
            "email": req.email.lower().strip(),
            "full_name": req.full_name.strip(),
            "role": role_clean
        }
    }


@router.get("/me")
async def get_current_user_profile(authorization: Optional[str] = Header(None)):
    """Returns active user identity and RBAC role from Bearer token."""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing or invalid Bearer token.")

    token = authorization.split("Bearer ", 1)[1].strip()
    user = verify_session(token)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid.")

    return {
        "id": user["id"],
        "email": user["email"],
        "full_name": user["full_name"],
        "role": user["role"]
    }


@router.post("/logout")
async def logout(authorization: Optional[str] = Header(None)):
    """Revokes session token from database."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()
        with get_db() as conn:
            with conn:
                conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
    return {"status": "logged_out", "message": "Session invalidated successfully."}
