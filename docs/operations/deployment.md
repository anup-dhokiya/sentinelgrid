# SentinelGrid Infrastructure, Deployment & Operations Guide

## 1. Local Development & Docker Orchestration
SentinelGrid provides a complete `docker-compose.yml` environment running all infrastructure and application components:
- **`postgres`**: PostgreSQL 16 relational database with persistent storage and partitioned tables.
- **`redis`**: Redis 7 for rate limiting, token buckets, and distributed lock caching.
- **`rabbitmq`**: RabbitMQ 3.12 with management UI for asynchronous event ingestion and worker tasks.
- **`backend-api`**: FastAPI REST API control plane.
- **`backend-worker`**: Asynchronous Celery / Python workers consuming from RabbitMQ.
- **`frontend`**: Next.js 14 management console.
- **`test-vulnerable-app`**: Intentionally vulnerable DVWA/custom Python FastAPI application with SentinelGrid connector attached for live attack demonstration.

## 2. RabbitMQ Message Topologies

```
Exchange: sentinelgrid.direct (type: direct, durable: true)
│
├── Routing Key: event.ingest  ──> Queue: sentinelgrid.events.raw (durable: true)
├── Routing Key: incident.eval ──> Queue: sentinelgrid.incidents.correlate (durable: true)
└── Routing Key: ai.window     ──> Queue: sentinelgrid.ai.features (durable: true)
```

- **Dead Letter Exchange (DLX)**: `sentinelgrid.dlx` catches malformed messages or processing failures after 3 retry attempts.
- **Backpressure**: RabbitMQ consumer prefetch set to 100 to prevent worker memory exhaustion during 1,000+ events/sec bursts.

## 3. Disaster Recovery & Zero-Data-Loss Ingestion
1. **Connector Resynchronization**: If the control plane is offline, connectors accumulate events up to their 5,000-event local buffer. Upon restoration, events flush in batches of 100 with exponential jitter to prevent thundering herd.
2. **Postgres Backup & Partition Rolling**: Automated cron scripts execute `pg_dump` daily. Partition creation scripts run monthly to provision future partitions ahead of time.
3. **Health Check Probes**:
   - `/health/live`: Basic process liveness probe.
   - `/health/ready`: Deep probe verifying connectivity to PostgreSQL, Redis, and RabbitMQ.
