-- ==============================================================================
-- SentinelGrid Database Initialization DDL (PostgreSQL 16)
-- Multi-Tenant WAAP (Web Application & API Protection) Platform
-- ==============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ------------------------------------------------------------------------------
-- 1. Organizations & Tenancy
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    plan_tier VARCHAR(50) NOT NULL DEFAULT 'starter',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 2. Users, Roles & Memberships
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS roles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID NOT NULL REFERENCES roles(id) ON DELETE RESTRICT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, user_id)
);

-- ------------------------------------------------------------------------------
-- 3. Websites & Connectors
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS websites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) NOT NULL,
    environment VARCHAR(50) NOT NULL DEFAULT 'production',
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (organization_id, domain, environment)
);

CREATE TABLE IF NOT EXISTS connectors (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    connector_type VARCHAR(50) NOT NULL, -- python, php, wordpress, nodejs, agent
    version VARCHAR(50) NOT NULL,
    hostname VARCHAR(255),
    ip_address INET,
    last_heartbeat_at TIMESTAMPTZ,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS connector_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connector_id UUID NOT NULL REFERENCES connectors(id) ON DELETE CASCADE,
    key_id VARCHAR(64) UNIQUE NOT NULL,
    secret_hash VARCHAR(255) NOT NULL,
    public_verification_key VARCHAR(255), -- Ed25519 public key
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 4. WAAP: API Discovery & Endpoint Inventory
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS api_endpoints (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    path_pattern VARCHAR(2048) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- documented, shadow_detected, zombie_deprecated
    parameters_schema JSONB DEFAULT '{}'::jsonb,
    risk_level VARCHAR(20) NOT NULL DEFAULT 'low', -- low, medium, high, critical
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (website_id, path_pattern, method)
);

CREATE INDEX IF NOT EXISTS idx_api_endpoints_site_pattern ON api_endpoints (website_id, path_pattern);

-- ------------------------------------------------------------------------------
-- 5. Policies, Versioning & Dry-Run Simulations
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    current_version INT NOT NULL DEFAULT 1,
    mode VARCHAR(50) NOT NULL DEFAULT 'active_protection',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (website_id)
);

CREATE TABLE IF NOT EXISTS policy_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    version INT NOT NULL,
    payload JSONB NOT NULL,
    signature VARCHAR(512) NOT NULL,
    signature_algorithm VARCHAR(50) NOT NULL DEFAULT 'Ed25519',
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (policy_id, version)
);

CREATE TABLE IF NOT EXISTS policy_simulations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID NOT NULL REFERENCES security_policies(id) ON DELETE CASCADE,
    proposed_payload JSONB NOT NULL,
    status VARCHAR(30) NOT NULL DEFAULT 'running', -- running, completed, failed
    sample_window_days INT NOT NULL DEFAULT 7,
    events_evaluated_count INT NOT NULL DEFAULT 0,
    projected_blocks_count INT NOT NULL DEFAULT 0,
    estimated_false_positive_rate NUMERIC(5,2) NOT NULL DEFAULT 0.0,
    impact_summary JSONB DEFAULT '{}'::jsonb,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 6. Partitioned Security Events
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id UUID NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    organization_id UUID NOT NULL,
    website_id UUID NOT NULL,
    connector_id UUID NOT NULL,
    client_ip INET NOT NULL,
    client_ip_hash VARCHAR(64),
    country_code CHAR(2),
    user_agent VARCHAR(512),
    method VARCHAR(10) NOT NULL,
    path VARCHAR(2048) NOT NULL,
    risk_score NUMERIC(5,2) NOT NULL,
    action_taken VARCHAR(20) NOT NULL,
    http_status INT,
    execution_duration_ms NUMERIC(8,3),
    detection_data JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE TABLE IF NOT EXISTS security_events_2026_10 PARTITION OF security_events
    FOR VALUES FROM ('2026-10-01 00:00:00+00') TO ('2026-11-01 00:00:00+00');

CREATE TABLE IF NOT EXISTS security_events_2026_11 PARTITION OF security_events
    FOR VALUES FROM ('2026-11-01 00:00:00+00') TO ('2026-12-01 00:00:00+00');

CREATE INDEX IF NOT EXISTS idx_sec_events_org_ts ON security_events (organization_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_web_ts ON security_events (website_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_action_ts ON security_events (action_taken, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sec_events_ip_ts ON security_events (client_ip, timestamp DESC);

-- ------------------------------------------------------------------------------
-- 7. Incidents, Mitigations & Outbound DLP
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL, -- low, medium, high, critical
    status VARCHAR(30) NOT NULL DEFAULT 'open', -- open, investigating, mitigated, resolved, false_positive
    category VARCHAR(50) NOT NULL,
    event_count INT NOT NULL DEFAULT 1,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL,
    summary TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id UUID NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (incident_id, event_id, event_timestamp)
);

CREATE TABLE IF NOT EXISTS response_actions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id UUID NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    action_type VARCHAR(50) NOT NULL, -- temporary_block_ip, challenge_client, rate_limit_endpoint
    target_value VARCHAR(255) NOT NULL,
    applied_by VARCHAR(50) NOT NULL, -- automated_policy, analyst_manual
    status VARCHAR(50) NOT NULL DEFAULT 'active', -- active, expired, rolled_back
    blast_radius_summary JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS dlp_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    website_id UUID NOT NULL REFERENCES websites(id) ON DELETE CASCADE,
    endpoint_id UUID REFERENCES api_endpoints(id) ON DELETE SET NULL,
    leak_type VARCHAR(50) NOT NULL, -- credit_card, ssn, jwt_token, private_key
    masked_snippet VARCHAR(255) NOT NULL,
    action_taken VARCHAR(20) NOT NULL, -- masked_in_flight, alert_only, blocked
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ------------------------------------------------------------------------------
-- 8. Enterprise SIEM & Compliance Posture
-- ------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS siem_integrations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    integration_type VARCHAR(50) NOT NULL, -- splunk, elastic, sentinel, syslog_cef, webhook
    endpoint_url VARCHAR(2048) NOT NULL,
    auth_token_encrypted TEXT,
    filter_severities JSONB DEFAULT '["high", "critical"]'::jsonb,
    status VARCHAR(30) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS compliance_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    standard_name VARCHAR(50) NOT NULL, -- pci_dss_4, soc2_type2, hipaa, iso27001
    score_percentage NUMERIC(5,2) NOT NULL DEFAULT 100.0,
    report_payload JSONB NOT NULL,
    generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS threat_indicators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    indicator_type VARCHAR(50) NOT NULL, -- ip, cidr, asn, user_agent_pattern
    indicator_value VARCHAR(255) NOT NULL,
    reputation_score INT NOT NULL DEFAULT 0,
    source VARCHAR(100) NOT NULL,
    confidence NUMERIC(3,2) NOT NULL DEFAULT 1.0,
    expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (indicator_type, indicator_value)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    details JSONB DEFAULT '{}'::jsonb,
    ip_address INET,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
