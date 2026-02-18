"""Redis-backed job status store."""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)


class RedisJobStore:
    """Job status storage using Redis hashes."""

    def __init__(self, redis_url: str, namespace: str = "threatsimgpt") -> None:
        self.redis_url = redis_url
        self.namespace = namespace
        self._client: Optional[redis.Redis] = None

    @classmethod
    def from_env(cls) -> Optional["RedisJobStore"]:
        redis_url = os.getenv("REDIS_URL")
        if not redis_url:
            return None
        return cls(redis_url)

    async def connect(self) -> None:
        if self._client is None:
            self._client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                **_redis_tls_kwargs(),
            )
            await self._client.ping()

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    def _job_key(self, job_id: str) -> str:
        return f"{self.namespace}:jobs:{job_id}"

    def _index_key(self) -> str:
        return f"{self.namespace}:jobs:index"

    def _job_ttl_seconds(self) -> int:
        return int(os.getenv("JOB_TTL_SECONDS", "86400"))

    async def create_job(self, job_id: str, job_type: str, payload: Dict[str, Any]) -> None:
        if not self._client:
            raise RuntimeError("Job store is not connected")

        now = datetime.now(timezone.utc).isoformat()
        ttl_seconds = self._job_ttl_seconds()
        await self._client.hset(
            self._job_key(job_id),
            mapping={
                "job_id": job_id,
                "job_type": job_type,
                "status": "queued",
                "payload": json.dumps(payload),
                "created_at": now,
                "updated_at": now,
            },
        )
        await self._client.expire(self._job_key(job_id), ttl_seconds)
        await self._client.zadd(self._index_key(), {job_id: datetime.now(timezone.utc).timestamp()})

    async def update_job(self, job_id: str, **fields: Any) -> None:
        if not self._client:
            raise RuntimeError("Job store is not connected")

        fields["updated_at"] = datetime.now(timezone.utc).isoformat()
        ttl_seconds = self._job_ttl_seconds()
        mapping = {}
        for key, value in fields.items():
            if isinstance(value, (dict, list)):
                mapping[key] = json.dumps(value)
            else:
                mapping[key] = value
        await self._client.hset(self._job_key(job_id), mapping=mapping)
        await self._client.expire(self._job_key(job_id), ttl_seconds)

    async def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        if not self._client:
            raise RuntimeError("Job store is not connected")

        data = await self._client.hgetall(self._job_key(job_id))
        if not data:
            return None

        for key in ["payload", "result", "error"]:
            if key in data and data[key]:
                try:
                    data[key] = json.loads(data[key])
                except json.JSONDecodeError:
                    pass
        return data

    async def list_jobs(self, offset: int = 0, limit: int = 50) -> Dict[str, Any]:
        if not self._client:
            raise RuntimeError("Job store is not connected")

        ttl_seconds = self._job_ttl_seconds()
        cutoff = datetime.now(timezone.utc).timestamp() - ttl_seconds
        await self._client.zremrangebyscore(self._index_key(), 0, cutoff)

        total = await self._client.zcard(self._index_key())
        job_ids = await self._client.zrevrange(self._index_key(), offset, offset + limit - 1)

        jobs = []
        for job_id in job_ids:
            job = await self.get_job(job_id)
            if job:
                jobs.append(job)

        return {
            "total": total,
            "offset": offset,
            "limit": limit,
            "jobs": jobs,
        }


def _redis_tls_kwargs() -> Dict[str, Any]:
    ca_path = os.getenv("REDIS_SSL_CA")
    cert_path = os.getenv("REDIS_SSL_CERT")
    key_path = os.getenv("REDIS_SSL_KEY")

    if not any([ca_path, cert_path, key_path]):
        return {}

    return {
        "ssl_cert_reqs": "required",
        "ssl_ca_certs": ca_path,
        "ssl_certfile": cert_path,
        "ssl_keyfile": key_path,
    }
