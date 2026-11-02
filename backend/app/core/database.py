"""
SentinelGrid - Unified Embedded Database Layer (SQLite with WAL mode)
Provides full local persistence for multi-tenancy, websites, API inventory,
security events, policies, and simulation logs without requiring external Docker.
"""

import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

DB_PATH = Path("/run/media/anup/D/sentinelgrid/backend/sentinelgrid.db")


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


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

        CREATE INDEX IF NOT EXISTS idx_events_site ON security_events(website_id, timestamp);
        CREATE INDEX IF NOT EXISTS idx_endpoints_site ON api_endpoints(website_id);
        CREATE INDEX IF NOT EXISTS idx_ip_rules_site ON ip_rules(website_id);
        CREATE INDEX IF NOT EXISTS idx_connectors_site ON connectors(website_id);
        """)

        # Ensure default administrator exists
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM users WHERE email = 'anupdhokiya0@gmail.com'")
        if cur.fetchone()[0] == 0:
            now = datetime.now(timezone.utc).isoformat()
            cur.execute("""
            INSERT INTO users (id, email, password_hash, full_name, role, created_at)
            VALUES ('usr-admin', 'anupdhokiya0@gmail.com', '8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918', 'Anup Dhokiya', 'admin', ?)
            """, (now,))
    conn.close()


init_database()
