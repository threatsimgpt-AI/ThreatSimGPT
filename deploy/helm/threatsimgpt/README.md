# ThreatSimGPT Helm Chart

This Helm chart deploys ThreatSimGPT with API and worker services, plus optional Postgres and Redis.

## Install

```
helm install threatsimgpt deploy/helm/threatsimgpt \
  --namespace threatsimgpt --create-namespace
```

## Required Secrets

Create the secret referenced by values.yaml (default: threatsimgpt-secrets):

```
kubectl -n threatsimgpt create secret generic threatsimgpt-secrets \
  --from-env-file=/path/to/threatsimgpt.secrets.env
```

Required keys:

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

## Configuration

- To use an existing config map, set `config.existingConfigMap`.
- To disable Postgres or Redis, set `postgres.enabled=false` or `redis.enabled=false`.
- To adjust worker queues and resources, edit `workers` in values.yaml.

## External Services with TLS

Set external endpoints in values.yaml:

```
external:
  postgres:
    enabled: true
    url: "postgresql://user:pass@host:5432/db?sslmode=require"
    tls:
      secretName: "postgres-tls"
      rootCertKey: "ca.crt"
      certKey: "client.crt"
      keyKey: "client.key"
  redis:
    enabled: true
    url: "rediss://:pass@host:6379/0"
    tls:
      secretName: "redis-tls"
      caKey: "ca.crt"
      certKey: "client.crt"
      keyKey: "client.key"
  neo4j:
    enabled: true
    uri: "neo4j+s://host:7687"
    user: "neo4j"
    password: "password"
```
Create the TLS secrets with the keys referenced above:

```
kubectl -n threatsimgpt create secret generic postgres-tls \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=client.crt=/path/to/client.crt \
  --from-file=client.key=/path/to/client.key

kubectl -n threatsimgpt create secret generic redis-tls \
  --from-file=ca.crt=/path/to/ca.crt \
  --from-file=client.crt=/path/to/client.crt \
  --from-file=client.key=/path/to/client.key
```

## Prometheus ServiceMonitor

Enable ServiceMonitor resources if you run Prometheus Operator:

```
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

## Autoscaling

HPA is enabled by default. Tune thresholds in `hpa` values.
