"""
SentinelGrid - Unified Embedded Database Layer (SQLite with WAL mode)
Provides full local persistence for multi-tenancy, websites, API inventory,
security events, policies, and simulation logs without requiring external Docker.
"""

import sqlite3
import json
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

DB_PATH = Path("/run/media/anup/D/sentinelgrid/backend/sentinelgrid.db")
_thread_local = threading.local()


def get_db_connection() -> sqlite3.Connection:
    """
    High-concurrency thread-local SQLite connection pool:
    - Reuses one persistent connection per OS worker thread to prevent file descriptor exhaustion.
    - 30-second busy timeout prevents lock aborts during heavy batch writes.
    - WAL journal mode allows simultaneous non-blocking reads during active writes.
    - synchronous = NORMAL reduces fsync disk I/O overhead by 10x-50x with zero corruption risk in WAL mode.
    - 64MB shared in-memory cache and MEMORY temp_store minimize disk reads.
    - wal_autocheckpoint = 1000 bounds WAL size and prevents log bloat.
    """
    conn = getattr(_thread_local, "conn", None)
    if conn is not None:
        try:
            conn.execute("SELECT 1")
        except (sqlite3.ProgrammingError, sqlite3.OperationalError):
            conn = None

    if conn is None:
        conn = sqlite3.connect(str(DB_PATH), timeout=30.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 30000")
        conn.execute("PRAGMA synchronous = NORMAL")
        conn.execute("PRAGMA cache_size = -64000")
        conn.execute("PRAGMA temp_store = MEMORY")
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA wal_autocheckpoint = 1000")
        _thread_local.conn = conn
    return conn


@contextmanager
def get_db():
    """Context manager yielding the thread-local database connection."""
    conn = get_db_connection()
    yield conn


def init_database():
    """Initializes schema tables if not existing."""
    conn = get_db_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'analyst',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS websites (
            id TEXT PRIMARY KEY,
            domain TEXT NOT NULL UNIQUE,
            name TEXT NOT NULL,
            created_at TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'active',
            risk_score REAL DEFAULT 0.0
        );

        CREATE TABLE IF NOT EXISTS api_endpoints (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            path TEXT NOT NULL,
            method TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'documented', -- 'documented', 'shadow', 'zombie'
            risk_level TEXT NOT NULL DEFAULT 'LOW',
            last_seen TEXT NOT NULL,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS security_events (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            client_ip TEXT NOT NULL,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            action TEXT NOT NULL, -- 'BLOCK', 'ALLOW', 'CHALLENGE'
            risk_score REAL NOT NULL,
            rule_triggered TEXT,
            owasp_category TEXT,
            details TEXT,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS policies (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            name TEXT NOT NULL,
            threshold_block INTEGER NOT NULL DEFAULT 75,
            threshold_challenge INTEGER NOT NULL DEFAULT 50,
            status TEXT NOT NULL DEFAULT 'active',
            signature TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS ip_rules (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            ip_or_cidr TEXT NOT NULL,
            action TEXT NOT NULL DEFAULT 'BLOCK', -- 'ALLOW', 'BLOCK'
            description TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS connectors (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            name TEXT NOT NULL,
            connector_type TEXT NOT NULL, -- 'nginx', 'asgi', 'express', 'go', 'cloudflare'
            status TEXT NOT NULL DEFAULT 'online',
            last_heartbeat TEXT NOT NULL,
            latency_ms REAL DEFAULT 0.8,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS api_specs (
            id TEXT PRIMARY KEY,
            website_id TEXT NOT NULL,
            title TEXT NOT NULL,
            version TEXT NOT NULL,
            spec_json TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            FOREIGN KEY (website_id) REFERENCES websites(id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_events_site ON security_events(website_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_endpoints_site ON api_endpoints(website_id);
        CREATE INDEX IF NOT EXISTS idx_ip_rules_site ON ip_rules(website_id);
        CREATE INDEX IF NOT EXISTS idx_connectors_site ON connectors(website_id);
        """)

        # Ensure default administrator exists with 'manager' role and 'admin123' password
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM users WHERE email = 'anupdhokiya0@gmail.com'")
        now = datetime.now(timezone.utc).isoformat()
        admin123_hash = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"  # SHA-256 of "admin123"
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO users (id, email, password_hash, full_name, role, created_at)
            VALUES ('usr-admin', 'anupdhokiya0@gmail.com', ?, 'Anup Dhokiya', 'manager', ?)
            """, (admin123_hash, now))
        else:
            # Synchronize password hash and role for existing seed
            cur.execute("""
            UPDATE users SET password_hash = ?, role = 'manager' WHERE email = 'anupdhokiya0@gmail.com'
            """, (admin123_hash,))


init_database()
