# ADR 001: Event-Driven Architecture with Async Workers

Status: Accepted
Date: 2026-02-10

## Context

ThreatSimGPT handles long-running simulations, LLM generation, RAG workflows, and deployment actions. These workloads are asynchronous, variable in latency, and not suitable for synchronous API request lifecycles. The system must support Kubernetes deployments across single cloud and on-prem environments, with eventual consistency and tolerance for duplicate processing.

## Decision

Adopt an event-driven architecture where the API service submits jobs to a queue, and workers process them asynchronously. Job state transitions are persisted in Postgres with idempotency keys to ensure safe retries and at-least-once delivery.

## Consequences

- API remains responsive and scalable under long-running workloads.
- Workers can scale independently based on queue depth.
- Idempotency and durable job state are mandatory to prevent duplicate side effects.
- Operational visibility improves through explicit job lifecycle tracking.
