"""Batch Processing Engine for ThreatSimGPT Simulations.

This module provides high-performance batch execution of threat simulations
with configurable concurrency, progress tracking, and graceful shutdown.

Features:
- Async queue-based processing with configurable concurrency
- Real-time progress tracking with callbacks and ETA calculation
- Graceful shutdown completing in-flight simulations
- Error isolation (one failure does not stop batch)
- Memory-efficient for large batches (1000+ scenarios)
- Throughput metrics and performance monitoring
- Retry logic with exponential backoff
- Hook points for future caching integration

Issue: #109
Author: Ajibola Olajide-Shokunbi (@jiboo2022)
"""

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import (
    Any,
    AsyncIterator,
    Callable,
    Dict,
    List,
    Optional,
    Protocol,
    Sequence,
    TypeVar,
    Union,
)
from uuid import uuid4

from threatsimgpt.core.models import (
    SimulationResult,
    SimulationStatus,
    ThreatScenario,
)
from threatsimgpt.core.simulator import ThreatSimulator

logger = logging.getLogger(__name__)


class BatchStatus(str, Enum):
    """Status of a batch processing job."""
    
    PENDING = "pending"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETING = "completing"  # Graceful shutdown in progress
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobStatus(str, Enum):
    """Status of an individual job within a batch."""
    
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    RETRYING = "retrying"
    SKIPPED = "skipped"


@dataclass
class JobResult:
    """Result of a single simulation job within a batch."""
    
    job_id: str
    scenario_id: str
    scenario_name: str
    status: JobStatus
    result: Optional[SimulationResult] = None
    error_message: Optional[str] = None
    error_type: Optional[str] = None
    attempt_count: int = 1
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    duration_ms: Optional[float] = None
    
    def __post_init__(self):
        if self.start_time and self.end_time:
            self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000


@dataclass
class BatchProgress:
    """Real-time progress information for a batch job."""
    
    batch_id: str
    status: BatchStatus
    total_jobs: int
    completed_jobs: int
    failed_jobs: int
    running_jobs: int
    pending_jobs: int
    start_time: datetime
    current_time: datetime
    elapsed_seconds: float
    estimated_remaining_seconds: Optional[float] = None
    estimated_completion_time: Optional[datetime] = None
    throughput_per_second: float = 0.0
    success_rate: float = 0.0
    
    @property
    def progress_percent(self) -> float:
        """Calculate completion percentage."""
        if self.total_jobs == 0:
            return 100.0
        return (self.completed_jobs + self.failed_jobs) / self.total_jobs * 100
    
    @property
    def is_complete(self) -> bool:
        """Check if batch processing is complete."""
        return self.status in (
            BatchStatus.COMPLETED,
            BatchStatus.FAILED,
            BatchStatus.CANCELLED,
        )


@dataclass
class BatchMetrics:
    """Performance metrics for a completed batch."""
    
    batch_id: str
    total_jobs: int
    successful_jobs: int
    failed_jobs: int
    skipped_jobs: int
    total_duration_seconds: float
    avg_job_duration_ms: float
    min_job_duration_ms: float
    max_job_duration_ms: float
    p50_job_duration_ms: float
    p95_job_duration_ms: float
    p99_job_duration_ms: float
    throughput_per_second: float
    success_rate: float
    retry_count: int
    concurrency_used: int
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        return {
            "batch_id": self.batch_id,
            "total_jobs": self.total_jobs,
            "successful_jobs": self.successful_jobs,
            "failed_jobs": self.failed_jobs,
            "skipped_jobs": self.skipped_jobs,
            "total_duration_seconds": round(self.total_duration_seconds, 3),
            "avg_job_duration_ms": round(self.avg_job_duration_ms, 2),
            "min_job_duration_ms": round(self.min_job_duration_ms, 2),
            "max_job_duration_ms": round(self.max_job_duration_ms, 2),
            "p50_job_duration_ms": round(self.p50_job_duration_ms, 2),
            "p95_job_duration_ms": round(self.p95_job_duration_ms, 2),
            "p99_job_duration_ms": round(self.p99_job_duration_ms, 2),
            "throughput_per_second": round(self.throughput_per_second, 3),
            "success_rate": round(self.success_rate, 4),
            "retry_count": self.retry_count,
            "concurrency_used": self.concurrency_used,
        }


@dataclass
class BatchResult:
    """Complete result of a batch processing job."""
    
    batch_id: str
    status: BatchStatus
    job_results: List[JobResult]
    metrics: BatchMetrics
    start_time: datetime
    end_time: datetime
    error_message: Optional[str] = None
    
    @property
    def successful_results(self) -> List[JobResult]:
        """Get all successful job results."""
        return [j for j in self.job_results if j.status == JobStatus.COMPLETED]
    
    @property
    def failed_results(self) -> List[JobResult]:
        """Get all failed job results."""
        return [j for j in self.job_results if j.status == JobStatus.FAILED]
    
    def get_simulation_results(self) -> List[SimulationResult]:
        """Extract simulation results from successful jobs."""
        return [j.result for j in self.successful_results if j.result is not None]


# Type for progress callbacks
ProgressCallback = Callable[[BatchProgress], None]
AsyncProgressCallback = Callable[[BatchProgress], Any]


class CacheProvider(Protocol):
    """Protocol for optional caching integration.
    
    This allows future caching layer to be plugged in without
    modifying the batch processor.
    """
    
    async def get_cached_result(
        self, scenario: ThreatScenario
    ) -> Optional[SimulationResult]:
        """Retrieve cached simulation result if available."""
        ...
    
    async def cache_result(
        self, scenario: ThreatScenario, result: SimulationResult
    ) -> None:
        """Cache a simulation result for future use."""
        ...
    
    def get_cache_key(self, scenario: ThreatScenario) -> str:
        """Generate cache key for a scenario."""
        ...


@dataclass
class BatchConfig:
    """Configuration for batch processing."""
    
    max_concurrency: int = 10
    max_retries: int = 3
    retry_base_delay_seconds: float = 1.0
    retry_max_delay_seconds: float = 30.0
    job_timeout_seconds: float = 300.0  # 5 minutes per job
    progress_update_interval_seconds: float = 1.0
    enable_caching: bool = True
    fail_fast: bool = False  # Stop on first failure
    preserve_order: bool = False  # Return results in input order
    
    def __post_init__(self):
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be at least 1")
        if self.max_retries < 0:
            raise ValueError("max_retries cannot be negative")
        if self.job_timeout_seconds <= 0:
            raise ValueError("job_timeout_seconds must be positive")


class BatchProcessor:
    """High-performance batch processor for threat simulations.
    
    Provides efficient parallel execution of multiple threat simulations
    with progress tracking, error isolation, and graceful shutdown.
    
    Usage:
        processor = BatchProcessor(simulator, config=BatchConfig(max_concurrency=20))
        
        # With progress callback
        async def on_progress(progress: BatchProgress):
            print(f"Progress: {progress.progress_percent:.1f}%")
        
        result = await processor.process_batch(scenarios, on_progress=on_progress)
        print(f"Completed {result.metrics.successful_jobs} simulations")
    
    Features:
        - Configurable concurrency with asyncio.Semaphore
        - Real-time progress tracking with ETA
        - Graceful shutdown completing in-flight work
        - Retry with exponential backoff
        - Error isolation (failures don't stop batch)
        - Memory-efficient streaming for large batches
        - Optional caching integration hook
    """
    
    def __init__(
        self,
        simulator: Optional[ThreatSimulator] = None,
        config: Optional[BatchConfig] = None,
        cache_provider: Optional[CacheProvider] = None,
    ):
        """Initialize the batch processor.
        
        Args:
            simulator: ThreatSimulator instance for executing simulations.
                      Creates default instance if not provided.
            config: Batch processing configuration. Uses defaults if not provided.
            cache_provider: Optional cache provider for result caching.
        """
        self.simulator = simulator or ThreatSimulator()
        self.config = config or BatchConfig()
        self.cache_provider = cache_provider
        
        # Internal state
        self._semaphore: Optional[asyncio.Semaphore] = None
        self._shutdown_event: Optional[asyncio.Event] = None
        self._pause_event: Optional[asyncio.Event] = None
        self._active_batch_id: Optional[str] = None
        self._job_results: Dict[str, JobResult] = {}
        self._running_jobs: int = 0
        self._total_retries: int = 0
        self._lock = asyncio.Lock()
    
    async def process_batch(
        self,
        scenarios: Sequence[ThreatScenario],
        on_progress: Optional[Union[ProgressCallback, AsyncProgressCallback]] = None,
        batch_id: Optional[str] = None,
    ) -> BatchResult:
        """Process a batch of scenarios with parallel execution.
        
        Args:
            scenarios: Sequence of ThreatScenario objects to process.
            on_progress: Optional callback for progress updates.
            batch_id: Optional batch identifier. Auto-generated if not provided.
            
        Returns:
            BatchResult containing all job results and metrics.
            
        Raises:
            RuntimeError: If another batch is already running on this processor.
        """
        if self._active_batch_id is not None:
            raise RuntimeError(
                f"Batch {self._active_batch_id} is already running. "
                "Create a new BatchProcessor or wait for completion."
            )
        
        batch_id = batch_id or f"batch_{uuid4().hex[:12]}"
        self._active_batch_id = batch_id
        
        logger.info(
            f"Starting batch {batch_id} with {len(scenarios)} scenarios, "
            f"concurrency={self.config.max_concurrency}"
        )
        
        # Initialize state
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._shutdown_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Not paused initially
        self._job_results = {}
        self._running_jobs = 0
        self._total_retries = 0
        
        start_time = datetime.now(timezone.utc)
        batch_status = BatchStatus.RUNNING
        error_message = None
        
        try:
            # Create jobs for all scenarios
            jobs = [
                self._create_job(scenario, i)
                for i, scenario in enumerate(scenarios)
            ]
            
            # Start progress reporting task
            progress_task = None
            if on_progress:
                progress_task = asyncio.create_task(
                    self._report_progress(
                        batch_id, jobs, start_time, on_progress
                    )
                )
            
            # Process all jobs concurrently with controlled parallelism
            await asyncio.gather(
                *[self._execute_job(job) for job in jobs],
                return_exceptions=True,
            )
            
            # Determine final status
            failed_count = sum(
                1 for j in self._job_results.values()
                if j.status == JobStatus.FAILED
            )
            
            if self._shutdown_event.is_set():
                batch_status = BatchStatus.CANCELLED
            elif failed_count == len(scenarios):
                batch_status = BatchStatus.FAILED
                error_message = "All jobs failed"
            else:
                batch_status = BatchStatus.COMPLETED
            
            # Stop progress reporting
            if progress_task:
                progress_task.cancel()
                try:
                    await progress_task
                except asyncio.CancelledError:
                    pass
            
        except Exception as e:
            logger.exception(f"Batch {batch_id} failed with unexpected error: {e}")
            batch_status = BatchStatus.FAILED
            error_message = str(e)
        
        finally:
            self._active_batch_id = None
        
        end_time = datetime.now(timezone.utc)
        
        # Collect results in order if requested
        job_results = list(self._job_results.values())
        if self.config.preserve_order:
            job_results.sort(key=lambda j: int(j.job_id.split("_")[-1]))
        
        # Calculate metrics
        metrics = self._calculate_metrics(batch_id, job_results, start_time, end_time)
        
        logger.info(
            f"Batch {batch_id} {batch_status.value}: "
            f"{metrics.successful_jobs}/{metrics.total_jobs} successful, "
            f"throughput={metrics.throughput_per_second:.2f}/s"
        )
        
        return BatchResult(
            batch_id=batch_id,
            status=batch_status,
            job_results=job_results,
            metrics=metrics,
            start_time=start_time,
            end_time=end_time,
            error_message=error_message,
        )
    
    async def process_batch_streaming(
        self,
        scenarios: Sequence[ThreatScenario],
        batch_id: Optional[str] = None,
    ) -> AsyncIterator[JobResult]:
        """Process batch and yield results as they complete.
        
        Memory-efficient alternative for very large batches where
        you want to process results incrementally.
        
        Args:
            scenarios: Sequence of scenarios to process.
            batch_id: Optional batch identifier.
            
        Yields:
            JobResult for each completed job as it finishes.
        """
        batch_id = batch_id or f"batch_{uuid4().hex[:12]}"
        
        if self._active_batch_id is not None:
            raise RuntimeError(f"Batch {self._active_batch_id} is already running.")
        
        self._active_batch_id = batch_id
        self._semaphore = asyncio.Semaphore(self.config.max_concurrency)
        self._shutdown_event = asyncio.Event()
        self._pause_event = asyncio.Event()
        self._pause_event.set()
        
        result_queue: asyncio.Queue[Optional[JobResult]] = asyncio.Queue()
        
        async def execute_and_queue(job: Dict[str, Any]) -> None:
            """Execute job and put result in queue."""
            await self._execute_job(job)
            result = self._job_results.get(job["job_id"])
            if result:
                await result_queue.put(result)
        
        try:
            jobs = [self._create_job(scenario, i) for i, scenario in enumerate(scenarios)]
            
            # Start all jobs
            tasks = [
                asyncio.create_task(execute_and_queue(job))
                for job in jobs
            ]
            
            # Yield results as they arrive
            completed = 0
            while completed < len(scenarios):
                if self._shutdown_event.is_set():
                    break
                
                result = await result_queue.get()
                if result:
                    completed += 1
                    yield result
            
            # Wait for any remaining tasks
            await asyncio.gather(*tasks, return_exceptions=True)
            
        finally:
            self._active_batch_id = None
    
    def request_shutdown(self) -> None:
        """Request graceful shutdown of the current batch.
        
        In-flight jobs will complete, but no new jobs will start.
        """
        if self._shutdown_event:
            logger.info(f"Shutdown requested for batch {self._active_batch_id}")
            self._shutdown_event.set()
    
    def pause(self) -> None:
        """Pause batch processing.
        
        In-flight jobs will complete, new jobs wait until resumed.
        """
        if self._pause_event:
            logger.info(f"Pausing batch {self._active_batch_id}")
            self._pause_event.clear()
    
    def resume(self) -> None:
        """Resume paused batch processing."""
        if self._pause_event:
            logger.info(f"Resuming batch {self._active_batch_id}")
            self._pause_event.set()
    
    def get_active_batch_id(self) -> Optional[str]:
        """Get the ID of the currently running batch, if any."""
        return self._active_batch_id
    
    def _create_job(self, scenario: ThreatScenario, index: int) -> Dict[str, Any]:
        """Create a job dictionary for a scenario."""
        return {
            "job_id": f"job_{index:06d}",
            "scenario": scenario,
            "index": index,
        }
    
    async def _execute_job(self, job: Dict[str, Any]) -> None:
        """Execute a single job with retry logic.
        
        Args:
            job: Job dictionary containing scenario and metadata.
        """
        job_id = job["job_id"]
        scenario = job["scenario"]
        
        # Check for shutdown before starting
        if self._shutdown_event and self._shutdown_event.is_set():
            self._job_results[job_id] = JobResult(
                job_id=job_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                status=JobStatus.SKIPPED,
                error_message="Batch shutdown requested",
            )
            return
        
        # Wait if paused
        if self._pause_event:
            await self._pause_event.wait()
        
        # Check cache first
        if self.cache_provider and self.config.enable_caching:
            try:
                cached = await self.cache_provider.get_cached_result(scenario)
                if cached:
                    logger.debug(f"Cache hit for job {job_id}")
                    self._job_results[job_id] = JobResult(
                        job_id=job_id,
                        scenario_id=scenario.scenario_id,
                        scenario_name=scenario.name,
                        status=JobStatus.COMPLETED,
                        result=cached,
                        start_time=datetime.now(timezone.utc),
                        end_time=datetime.now(timezone.utc),
                    )
                    return
            except Exception as e:
                logger.warning(f"Cache lookup failed for job {job_id}: {e}")
        
        # Execute with semaphore for concurrency control
        async with self._semaphore:
            await self._execute_with_retry(job_id, scenario)
    
    async def _execute_with_retry(
        self, job_id: str, scenario: ThreatScenario
    ) -> None:
        """Execute simulation with retry logic.
        
        Uses exponential backoff with jitter for retries.
        """
        attempt = 0
        last_error: Optional[Exception] = None
        start_time = datetime.now(timezone.utc)
        
        async with self._lock:
            self._running_jobs += 1
        
        try:
            while attempt <= self.config.max_retries:
                attempt += 1
                
                # Check for shutdown between retries
                if self._shutdown_event and self._shutdown_event.is_set():
                    self._job_results[job_id] = JobResult(
                        job_id=job_id,
                        scenario_id=scenario.scenario_id,
                        scenario_name=scenario.name,
                        status=JobStatus.SKIPPED,
                        error_message="Shutdown during retry",
                        attempt_count=attempt,
                        start_time=start_time,
                        end_time=datetime.now(timezone.utc),
                    )
                    return
                
                try:
                    # Execute with timeout
                    result = await asyncio.wait_for(
                        self.simulator.execute_simulation(scenario),
                        timeout=self.config.job_timeout_seconds,
                    )
                    
                    end_time = datetime.now(timezone.utc)
                    
                    # Cache successful result
                    if self.cache_provider and self.config.enable_caching:
                        try:
                            await self.cache_provider.cache_result(scenario, result)
                        except Exception as e:
                            logger.warning(f"Failed to cache result for {job_id}: {e}")
                    
                    self._job_results[job_id] = JobResult(
                        job_id=job_id,
                        scenario_id=scenario.scenario_id,
                        scenario_name=scenario.name,
                        status=JobStatus.COMPLETED,
                        result=result,
                        attempt_count=attempt,
                        start_time=start_time,
                        end_time=end_time,
                    )
                    
                    logger.debug(
                        f"Job {job_id} completed in "
                        f"{(end_time - start_time).total_seconds():.2f}s"
                    )
                    return
                    
                except asyncio.TimeoutError:
                    last_error = TimeoutError(
                        f"Job timed out after {self.config.job_timeout_seconds}s"
                    )
                    logger.warning(
                        f"Job {job_id} timed out on attempt {attempt}"
                    )
                    
                except Exception as e:
                    last_error = e
                    logger.warning(
                        f"Job {job_id} failed on attempt {attempt}: {e}"
                    )
                
                # Retry with exponential backoff
                if attempt <= self.config.max_retries:
                    async with self._lock:
                        self._total_retries += 1
                    
                    delay = min(
                        self.config.retry_base_delay_seconds * (2 ** (attempt - 1)),
                        self.config.retry_max_delay_seconds,
                    )
                    # Add jitter (10-30% of delay)
                    jitter = delay * (0.1 + 0.2 * random.random())
                    delay += jitter
                    
                    logger.debug(
                        f"Retrying job {job_id} in {delay:.2f}s "
                        f"(attempt {attempt + 1}/{self.config.max_retries + 1})"
                    )
                    await asyncio.sleep(delay)
            
            # All retries exhausted
            end_time = datetime.now(timezone.utc)
            self._job_results[job_id] = JobResult(
                job_id=job_id,
                scenario_id=scenario.scenario_id,
                scenario_name=scenario.name,
                status=JobStatus.FAILED,
                error_message=str(last_error) if last_error else "Unknown error",
                error_type=type(last_error).__name__ if last_error else None,
                attempt_count=attempt,
                start_time=start_time,
                end_time=end_time,
            )
            
            logger.error(
                f"Job {job_id} failed after {attempt} attempts: {last_error}"
            )
            
            # Fail fast if configured
            if self.config.fail_fast and self._shutdown_event:
                self._shutdown_event.set()
                
        finally:
            async with self._lock:
                self._running_jobs -= 1
    
    async def _report_progress(
        self,
        batch_id: str,
        jobs: List[Dict[str, Any]],
        start_time: datetime,
        callback: Union[ProgressCallback, AsyncProgressCallback],
    ) -> None:
        """Periodically report progress to callback."""
        total_jobs = len(jobs)
        
        while True:
            await asyncio.sleep(self.config.progress_update_interval_seconds)
            
            current_time = datetime.now(timezone.utc)
            elapsed = (current_time - start_time).total_seconds()
            
            completed = sum(
                1 for j in self._job_results.values()
                if j.status == JobStatus.COMPLETED
            )
            failed = sum(
                1 for j in self._job_results.values()
                if j.status == JobStatus.FAILED
            )
            
            processed = completed + failed
            pending = total_jobs - processed - self._running_jobs
            
            # Calculate throughput and ETA
            throughput = processed / elapsed if elapsed > 0 else 0
            remaining = total_jobs - processed
            eta_seconds = remaining / throughput if throughput > 0 else None
            eta_time = (
                datetime.now(timezone.utc) + 
                timedelta(seconds=eta_seconds)
            ) if eta_seconds else None
            
            progress = BatchProgress(
                batch_id=batch_id,
                status=BatchStatus.RUNNING,
                total_jobs=total_jobs,
                completed_jobs=completed,
                failed_jobs=failed,
                running_jobs=self._running_jobs,
                pending_jobs=pending,
                start_time=start_time,
                current_time=current_time,
                elapsed_seconds=elapsed,
                estimated_remaining_seconds=eta_seconds,
                estimated_completion_time=eta_time,
                throughput_per_second=throughput,
                success_rate=completed / processed if processed > 0 else 0.0,
            )
            
            # Call callback (handle both sync and async)
            try:
                result = callback(progress)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.warning(f"Progress callback error: {e}")
    
    def _calculate_metrics(
        self,
        batch_id: str,
        job_results: List[JobResult],
        start_time: datetime,
        end_time: datetime,
    ) -> BatchMetrics:
        """Calculate comprehensive batch metrics."""
        total = len(job_results)
        successful = sum(1 for j in job_results if j.status == JobStatus.COMPLETED)
        failed = sum(1 for j in job_results if j.status == JobStatus.FAILED)
        skipped = sum(1 for j in job_results if j.status == JobStatus.SKIPPED)
        
        total_duration = (end_time - start_time).total_seconds()
        
        # Calculate duration statistics
        durations = [
            j.duration_ms for j in job_results
            if j.duration_ms is not None and j.status == JobStatus.COMPLETED
        ]
        
        if durations:
            durations_sorted = sorted(durations)
            avg_duration = sum(durations) / len(durations)
            min_duration = durations_sorted[0]
            max_duration = durations_sorted[-1]
            p50_duration = durations_sorted[len(durations) // 2]
            p95_duration = durations_sorted[int(len(durations) * 0.95)]
            p99_duration = durations_sorted[int(len(durations) * 0.99)]
        else:
            avg_duration = min_duration = max_duration = 0.0
            p50_duration = p95_duration = p99_duration = 0.0
        
        throughput = total / total_duration if total_duration > 0 else 0.0
        success_rate = successful / total if total > 0 else 0.0
        
        return BatchMetrics(
            batch_id=batch_id,
            total_jobs=total,
            successful_jobs=successful,
            failed_jobs=failed,
            skipped_jobs=skipped,
            total_duration_seconds=total_duration,
            avg_job_duration_ms=avg_duration,
            min_job_duration_ms=min_duration,
            max_job_duration_ms=max_duration,
            p50_job_duration_ms=p50_duration,
            p95_job_duration_ms=p95_duration,
            p99_job_duration_ms=p99_duration,
            throughput_per_second=throughput,
            success_rate=success_rate,
            retry_count=self._total_retries,
            concurrency_used=self.config.max_concurrency,
        )


async def process_scenarios_batch(
    scenarios: Sequence[ThreatScenario],
    max_concurrency: int = 10,
    on_progress: Optional[ProgressCallback] = None,
    **config_kwargs: Any,
) -> BatchResult:
    """Convenience function for batch processing scenarios.
    
    Args:
        scenarios: Scenarios to process.
        max_concurrency: Maximum parallel simulations.
        on_progress: Optional progress callback.
        **config_kwargs: Additional BatchConfig parameters.
        
    Returns:
        BatchResult with all simulation results.
        
    Example:
        result = await process_scenarios_batch(
            scenarios,
            max_concurrency=20,
            on_progress=lambda p: print(f"{p.progress_percent:.1f}%"),
        )
    """
    config = BatchConfig(max_concurrency=max_concurrency, **config_kwargs)
    processor = BatchProcessor(config=config)
    return await processor.process_batch(scenarios, on_progress=on_progress)


def process_scenarios_batch_sync(
    scenarios: Sequence[ThreatScenario],
    max_concurrency: int = 10,
    on_progress: Optional[ProgressCallback] = None,
    **config_kwargs: Any,
) -> BatchResult:
    """Synchronous wrapper for batch processing.
    
    Runs the async batch processor in a new event loop.
    Use this when calling from synchronous code.
    
    Args:
        scenarios: Scenarios to process.
        max_concurrency: Maximum parallel simulations.
        on_progress: Optional progress callback.
        **config_kwargs: Additional BatchConfig parameters.
        
    Returns:
        BatchResult with all simulation results.
    """
    return asyncio.run(
        process_scenarios_batch(
            scenarios,
            max_concurrency=max_concurrency,
            on_progress=on_progress,
            **config_kwargs,
        )
    )
