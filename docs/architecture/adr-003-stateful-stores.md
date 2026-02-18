# ADR 003: Postgres as System of Record with Object and Vector Stores

Status: Accepted
Date: 2026-02-10

## Context

ThreatSimGPT requires durable storage for jobs, simulations, outputs, and audit trails. It also needs a vector store for RAG embeddings and an object store for large artifacts. The deployment must work in both cloud and on-prem environments.

## Decision

- Use Postgres as the system of record for metadata, job state, and audit logs.
- Use an object store for generated artifacts and large outputs (S3 or S3-compatible on-prem).
- Use a configurable vector store for embeddings (Chroma, FAISS, or Neo4j).

## Consequences

- Clear separation between metadata and large artifacts.
- RAG storage can be tuned per deployment needs.
- Storage interfaces must remain pluggable to support on-prem and cloud deployments.
