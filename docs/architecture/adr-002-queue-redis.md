# ADR 002: Redis as Queue and Cache Substrate

Status: Accepted
Date: 2026-02-10

## Context

The system needs a simple, reliable queue and cache for job coordination, deduplication, and rate limiting. The deployment model includes single cloud and on-prem Kubernetes clusters with constrained operational overhead. The current stack already includes Redis in the Docker deployment.

## Decision

Use Redis as the primary queue and cache substrate for asynchronous job dispatch and caching. This aligns with existing infrastructure and simplifies operational management.

## Consequences

- Rapid adoption using existing Redis deployment.
- Straightforward scaling for moderate workloads.
- If throughput or ordering guarantees exceed Redis capabilities, migrate queueing to a dedicated broker without changing the API-facing contract.
