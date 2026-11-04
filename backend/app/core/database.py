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

import os
import tempfile
from pathlib import Path

# Dynamic DB resolution: uses DATA_DIR if set, D-drive if mounted, or relative to backend root
_env_dir = os.getenv("DATA_DIR")
if _env_dir:
    DB_PATH = Path(_env_dir) / "sentinelgrid.db"
elif Path("/run/media/anup/D/sentinelgrid/backend").is_dir():
    DB_PATH = Path("/run/media/anup/D/sentinelgrid/backend/sentinelgrid.db")
else:
    _base_dir = Path(__file__).resolve().parent.parent.parent
    DB_PATH = _base_dir / "sentinelgrid.db" if os.access(_base_dir, os.W_OK) else Path(tempfile.gettempdir()) / "sentinelgrid.db"
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
        conn.execute("PRAGMA mmap_size = 268435456")
        conn.execute("PRAGMA journal_size_limit = 67108864")
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
        CREATE INDEX IF NOT EXISTS idx_events_action_ts ON security_events(action, timestamp);
        CREATE INDEX IF NOT EXISTS idx_events_ip_ts ON security_events(client_ip, timestamp);
        CREATE INDEX IF NOT EXISTS idx_endpoints_site ON api_endpoints(website_id);
        CREATE INDEX IF NOT EXISTS idx_ip_rules_site ON ip_rules(website_id);
        CREATE INDEX IF NOT EXISTS idx_connectors_site ON connectors(website_id);
        """)

        # Ensure single master administrator exists with 'manager' role and 'anup@5212' password
        cur = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()
        admin_pwd_hash = "4459e7230b6833797dae7f90cda556b5eef40def095a99e83ec9dbadff7080cf"  # SHA-256 of "anup@5212"
        cur.execute("SELECT count(*) FROM users WHERE email = 'a@123'")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO users (id, email, password_hash, full_name, role, created_at)
            VALUES ('usr-admin', 'a@123', ?, 'System Administrator', 'manager', ?)
            """, (admin_pwd_hash, now))
        else:
            cur.execute("""
            UPDATE users SET password_hash = ?, role = 'manager' WHERE email = 'a@123'
            """, (admin_pwd_hash,))

        # Ensure default website for aegispro.vercel.app exists
        cur.execute("SELECT count(*) FROM websites WHERE id = 'site-agispro' OR domain = 'aegispro.vercel.app'")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO websites (id, domain, name, created_at, status, risk_score)
            VALUES ('site-agispro', 'aegispro.vercel.app', 'AegisPro Vercel Platform', ?, 'active', 0.0)
            """, (now,))
            cur.execute("""
            INSERT INTO policies (id, website_id, version, name, threshold_block, threshold_challenge, status, created_at)
            VALUES ('pol-agispro-v1', 'site-agispro', 1, 'Production NextGen Edge Security Policy', 75, 50, 'active', ?)
            """, (now,))
        else:
            cur.execute("UPDATE websites SET domain = 'aegispro.vercel.app' WHERE id = 'site-agispro'")

        # Seed baseline online connectors if empty
        cur.execute("SELECT count(*) FROM connectors")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO connectors (id, website_id, name, connector_type, status, last_heartbeat, latency_ms)
            VALUES 
            ('conn-edge-vercel', 'site-agispro', 'Vercel Global Edge Interceptor (Anycast)', 'edge-middleware', 'online', ?, 0.18),
            ('conn-cloud-waap', 'site-agispro', 'SentinelGrid NextGen WAAP Core', 'python-asgi-serverless', 'online', ?, 0.32)
            """, (now, now))

        # Seed documented and shadow API endpoints if empty
        cur.execute("SELECT count(*) FROM api_endpoints")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO api_endpoints (id, website_id, path, method, status, risk_level, last_seen)
            VALUES
            ('ep-root', 'site-agispro', '/', 'GET', 'documented', 'LOW', ?),
            ('ep-login', 'site-agispro', '/login', 'POST', 'documented', 'MEDIUM', ?),
            ('ep-dashboard', 'site-agispro', '/dashboard', 'GET', 'documented', 'LOW', ?),
            ('ep-google-auth', 'site-agispro', '/api/auth/google', 'POST', 'shadow', 'MEDIUM', ?),
            ('ep-inspect', 'site-agispro', '/v1/inspect', 'POST', 'documented', 'LOW', ?)
            """, (now, now, now, now, now))

        # Seed initial IP rules if empty
        cur.execute("SELECT count(*) FROM ip_rules")
        if cur.fetchone()[0] == 0:
            cur.execute("""
            INSERT INTO ip_rules (id, website_id, ip_or_cidr, action, description, created_at)
            VALUES
            ('rule-scanner-quarantine', 'site-agispro', '198.51.100.42', 'BLOCK', 'Known Automated Vulnerability Scanner', ?),
            ('rule-trusted-noc', 'site-agispro', '10.0.0.0/8', 'ALLOW', 'Internal Trusted Operations Subnet', ?)
            """, (now, now))

        # Always purge any accidental loopback blocks and guarantee localhost whitelist
        cur.execute("DELETE FROM ip_rules WHERE ip_or_cidr IN ('127.0.0.1', '::1', 'localhost', 'unknown', 'unknown-client') AND action = 'BLOCK'")
        cur.execute("""
        INSERT OR REPLACE INTO ip_rules (id, website_id, ip_or_cidr, action, description, created_at)
        VALUES ('rule-whitelist-loopback', 'site-agispro', '127.0.0.1', 'ALLOW', 'System Localhost Loopback', ?)
        """, (now,))


init_database()
