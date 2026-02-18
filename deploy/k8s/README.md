# Kubernetes Deployment

This directory provides Kubernetes manifests for the ThreatSimGPT platform.

## Base Deployment

Apply the base stack with Postgres, Redis, and the API service:

```
kubectl apply -k deploy/k8s/base
```

This applies API, Postgres, Redis, workers, and HPA manifests.

## Secrets

The API expects a secret named threatsimgpt-secrets with these keys:

- DATABASE_URL
- REDIS_URL
- OPENAI_API_KEY
- ANTHROPIC_API_KEY
- OPENROUTER_API_KEY
- API_KEY
- POSTGRES_USER
- POSTGRES_PASSWORD
- POSTGRES_DB
- NEO4J_PASSWORD

Create the secret using your organization values:

```
kubectl -n threatsimgpt create secret generic threatsimgpt-secrets \
  --from-env-file=/path/to/threatsimgpt.secrets.env
```

## Optional Services

Ollama (local LLM server):

```
kubectl apply -f deploy/k8s/optional/ollama.yaml
```

## Worker Queues

Workers consume Redis queues by name:

- simulation
- manuals
- feedback
- rag_ingest
- rag_generate
- deployment

## Notes

- The base deployment mounts config.yaml from the repository using Kustomize.
- For production, store configuration in a dedicated config repository or secure config store.
