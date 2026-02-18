"""Redis-backed worker consumer for ThreatSimGPT."""

import asyncio
import logging
import os
import signal
import time
from typing import Callable, Dict

from prometheus_client import start_http_server

from .handlers import HANDLERS
from .queue import RedisQueue, QueueMessage
from threatsimgpt.metrics import JOB_LATENCY

logger = logging.getLogger(__name__)


def _configure_logging() -> None:
    log_level = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=getattr(logging, log_level, logging.INFO))


def _get_queue_names() -> list[str]:
    raw = os.getenv("WORKER_QUEUES", "manuals,feedback,rag_ingest,rag_generate,deployment")
    return [name.strip() for name in raw.split(",") if name.strip()]


def _get_handler(message_type: str) -> Callable:
    handler = HANDLERS.get(message_type)
    if not handler:
        raise ValueError(f"No handler registered for message type: {message_type}")
    return handler


async def _process_message(message: QueueMessage) -> None:
    handler = _get_handler(message.message_type)
    start_time = time.perf_counter()
    result = await handler(message.payload)
    duration = time.perf_counter() - start_time
    JOB_LATENCY.labels(job_type=message.message_type).observe(duration)
    logger.info("Processed message %s (%s): %s", message.message_id, message.message_type, result)


async def _consumer_loop(queue: RedisQueue, queue_name: str, semaphore: asyncio.Semaphore) -> None:
    while True:
        message = await queue.dequeue(queue_name)
        if not message:
            continue

        async with semaphore:
            try:
                await _process_message(message)
            except Exception as exc:
                logger.exception("Failed processing message %s: %s", message.message_id, exc)


async def main() -> None:
    _configure_logging()

    redis_queue = RedisQueue.from_env()
    if not redis_queue:
        raise RuntimeError("REDIS_URL is required to run worker")

    metrics_port = int(os.getenv("METRICS_PORT", "9102"))
    if os.getenv("ENABLE_METRICS", "true").lower() in ("true", "1", "yes"):
        start_http_server(metrics_port)
        logger.info("Worker metrics server listening on %s", metrics_port)

    await redis_queue.connect()

    queue_names = _get_queue_names()
    concurrency = int(os.getenv("WORKER_CONCURRENCY", "4"))
    semaphore = asyncio.Semaphore(concurrency)

    tasks = [asyncio.create_task(_consumer_loop(redis_queue, name, semaphore)) for name in queue_names]

    stop_event = asyncio.Event()

    def _stop(*_args):
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, _stop)

    await stop_event.wait()

    for task in tasks:
        task.cancel()
    await redis_queue.close()


if __name__ == "__main__":
    asyncio.run(main())
