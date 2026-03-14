# Architecture Overview

This section documents the distributed systems architecture for ThreatSimGPT, aligned to the current codebase and deployment model (Kubernetes, single cloud and on-prem).

## Architecture Decisions

- Event-driven separation of API and long-running work: [docs/architecture/adr-001-event-driven-architecture.md](docs/architecture/adr-001-event-driven-architecture.md)
- Redis as the queue and cache substrate: [docs/architecture/adr-002-queue-redis.md](docs/architecture/adr-002-queue-redis.md)
- Postgres as system of record with object and vector stores: [docs/architecture/adr-003-stateful-stores.md](docs/architecture/adr-003-stateful-stores.md)

## Core Components

- API service (FastAPI): validates requests, starts jobs, and exposes status endpoints.
- Simulation engine: orchestrates multi-step threat simulations.
- LLM generation: provider selection, retries, and safety checks.
- RAG pipeline: ingestion, vector storage, retrieval, and playbook generation.
- Deployment services: outbound campaign execution and metrics collection.

## Data Stores

- Postgres: persistent state for jobs, runs, audit logs, and metadata.
- Redis: queueing, caching, and rate limits.
- Object store: artifacts and generated outputs (S3 or S3-compatible on-prem).
- Vector store: embeddings for RAG (Chroma, FAISS, or Neo4j based on configuration).

## Data Flows

- API requests create jobs and enqueue work.
- Workers process jobs asynchronously and persist results.
- RAG ingestion runs on schedules and updates the vector store.
- Deployment workers execute campaigns and record metrics.

## Failure Handling

- At-least-once delivery with idempotency keys.
- Retries with backoff for LLM and integration calls.
- Safe handling of partial failures through job state transitions.

## Observability

- Structured logs with job_id and scenario_id.
- Metrics for latency, queue depth, error rates, and throughput.
- Tracing for cross-service execution paths.

## Security

- API authentication and authorization.
- Secret management for provider keys.
- Audit logging for compliance.

## Diagrams

- Deployment and data flow: [docs/architecture/deployment-diagram.md](docs/architecture/deployment-diagram.md)
