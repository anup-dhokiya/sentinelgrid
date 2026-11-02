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
        """)

        # Insert seed data if websites empty
        cur = conn.cursor()
        cur.execute("SELECT count(*) FROM websites")
        if cur.fetchone()[0] == 0:
            now = datetime.now(timezone.utc).isoformat()
            conn.executescript(f"""
            INSERT INTO websites (id, domain, name, created_at, status, risk_score) VALUES
            ('site-1', 'api.artisan-travel.com', 'Artisan Travel & Goods API', '{now}', 'active', 28.4),
            ('site-2', 'shop.wellness-pure.io', 'Wellness Pure E-Commerce', '{now}', 'active', 64.2);

            INSERT INTO api_endpoints (id, website_id, path, method, status, risk_level, last_seen) VALUES
            ('ep-1', 'site-1', '/api/v1/tours/search', 'GET', 'documented', 'LOW', '{now}'),
            ('ep-2', 'site-1', '/api/v1/checkout/stripe', 'POST', 'documented', 'HIGH', '{now}'),
            ('ep-3', 'site-1', '/api/v2/internal/debug-export', 'GET', 'shadow', 'CRITICAL', '{now}'),
            ('ep-4', 'site-2', '/api/auth/login', 'POST', 'documented', 'MEDIUM', '{now}'),
            ('ep-5', 'site-2', '/api/legacy/orders/dump', 'GET', 'zombie', 'HIGH', '{now}');

            INSERT INTO security_events (id, website_id, timestamp, client_ip, method, path, action, risk_score, rule_triggered, owasp_category, details) VALUES
            ('ev-101', 'site-1', '{now}', '198.51.100.42', 'POST', '/api/v1/checkout/stripe', 'BLOCK', 92.5, 'SQLi-UNION-Select', 'A03:Injection', 'UNION SELECT credit_card FROM payments'),
            ('ev-102', 'site-1', '{now}', '203.0.113.19', 'GET', '/api/v2/internal/debug-export', 'BLOCK', 88.0, 'Shadow-API-Probe', 'A01:Broken Access Control', 'Unauthenticated probe on undocumented endpoint'),
            ('ev-103', 'site-2', '{now}', '192.0.2.77', 'POST', '/api/auth/login', 'CHALLENGE', 65.0, 'Credential-Stuffing-Bot', 'A07:Identification and Authentication Failures', 'High frequency failed login attempts'),
            ('ev-104', 'site-1', '{now}', '66.249.66.1', 'GET', '/api/v1/tours/search', 'ALLOW', 8.5, 'None', 'None', 'Legitimate Googlebot indexing');

            INSERT INTO policies (id, website_id, version, name, threshold_block, threshold_challenge, status, signature, created_at) VALUES
            ('pol-1', 'site-1', 1, 'Production High-Assurance WAAP', 75, 50, 'active', 'ED25519-SIG-ACTIVE-v1-OK', '{now}'),
            ('pol-2', 'site-2', 1, 'Standard E-commerce Guard', 75, 50, 'active', 'ED25519-SIG-ACTIVE-v1-OK', '{now}');
            """)
    conn.close()


init_database()
