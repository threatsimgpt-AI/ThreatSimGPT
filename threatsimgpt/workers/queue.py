"""Redis-backed queue utilities for distributed workers."""

import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import redis.asyncio as redis

logger = logging.getLogger(__name__)


@dataclass
class QueueMessage:
    """Queue message envelope."""
    message_id: str
    message_type: str
    payload: Dict[str, Any]
    created_at: str


class RedisQueue:
    """Minimal Redis-backed queue with JSON payloads."""

    def __init__(self, redis_url: str, namespace: str = "threatsimgpt"):
        self.redis_url = redis_url
        self.namespace = namespace
        self._client: Optional[redis.Redis] = None

    @classmethod
    def from_env(cls) -> Optional["RedisQueue"]:
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
            logger.info("Connected to Redis queue at %s", self.redis_url)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()
            self._client = None

    def _queue_key(self, name: str) -> str:
        return f"{self.namespace}:{name}"

    async def enqueue(self, queue_name: str, message_type: str, payload: Dict[str, Any], message_id: str) -> None:
        if not self._client:
            raise RuntimeError("Redis queue is not connected")

        message = QueueMessage(
            message_id=message_id,
            message_type=message_type,
            payload=payload,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        serialized = json.dumps(message.__dict__)
        await self._client.rpush(self._queue_key(queue_name), serialized)

    async def dequeue(self, queue_name: str, timeout_seconds: int = 5) -> Optional[QueueMessage]:
        if not self._client:
            raise RuntimeError("Redis queue is not connected")

        result = await self._client.blpop(self._queue_key(queue_name), timeout=timeout_seconds)
        if not result:
            return None

        _, raw_message = result
        data = json.loads(raw_message)
        return QueueMessage(
            message_id=data["message_id"],
            message_type=data["message_type"],
            payload=data.get("payload", {}),
            created_at=data.get("created_at", ""),
        )

    async def length(self, queue_name: str) -> int:
        if not self._client:
            raise RuntimeError("Redis queue is not connected")

        return int(await self._client.llen(self._queue_key(queue_name)))


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
