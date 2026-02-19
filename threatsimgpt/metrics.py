"""Prometheus metrics for ThreatSimGPT."""

from __future__ import annotations

import logging
from typing import Iterable, Optional

import redis.asyncio as redis
from prometheus_client import CONTENT_TYPE_LATEST, Gauge, Histogram, generate_latest

logger = logging.getLogger(__name__)


QUEUE_DEPTH = Gauge(
    "threatsimgpt_queue_depth",
    "Queue depth by queue name",
    ["queue"],
)

JOB_LATENCY = Histogram(
    "threatsimgpt_job_latency_seconds",
    "Job processing latency in seconds",
    ["job_type"],
    buckets=(0.1, 0.25, 0.5, 1, 2, 5, 10, 20, 30, 60, 120),
)


def render_metrics() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST


async def update_queue_depths(redis_url: Optional[str], queues: Iterable[str]) -> None:
    if not redis_url:
        return

    client = redis.from_url(redis_url, decode_responses=True)
    try:
        for queue_name in queues:
            depth = await client.llen(f"threatsimgpt:{queue_name}")
            QUEUE_DEPTH.labels(queue=queue_name).set(depth)
    except Exception as exc:
        logger.error("Failed to update queue depth metrics: %s", exc)
    finally:
        await client.close()
