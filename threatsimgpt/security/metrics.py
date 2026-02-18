"""
Metrics collection for Template Security Validator.

Provides structured metrics collection for monitoring
and observability in production environments.
"""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, Any, Optional
from collections import defaultdict, deque


@dataclass
class ValidationMetrics:
    """Metrics for template validation operations."""
    
    # Counters
    total_validations: int = 0
    successful_validations: int = 0
    failed_validations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    
    # Timing
    total_duration_ms: float = 0.0
    min_duration_ms: float = float('inf')
    max_duration_ms: float = 0.0
    
    # Security findings
    total_findings: int = 0
    critical_findings: int = 0
    high_findings: int = 0
    medium_findings: int = 0
    low_findings: int = 0
    info_findings: int = 0
    
    # Errors
    rate_limit_exceeded: int = 0
    circuit_breaker_open: int = 0
    audit_log_failures: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary for serialization."""
        total = max(1, self.total_validations)
        
        return {
            'counters': {
                'total_validations': self.total_validations,
                'successful_validations': self.successful_validations,
                'failed_validations': self.failed_validations,
                'cache_hits': self.cache_hits,
                'cache_misses': self.cache_misses,
                'cache_hit_rate': self.cache_hits / total,
                'success_rate': self.successful_validations / total,
            },
            'timing': {
                'avg_duration_ms': self.total_duration_ms / total,
                'min_duration_ms': self.min_duration_ms,
                'max_duration_ms': self.max_duration_ms,
                'total_duration_ms': self.total_duration_ms,
            },
            'findings': {
                'total_findings': self.total_findings,
                'critical_findings': self.critical_findings,
                'high_findings': self.high_findings,
                'medium_findings': self.medium_findings,
                'low_findings': self.low_findings,
                'info_findings': self.info_findings,
                'avg_findings_per_validation': self.total_findings / total,
            },
            'errors': {
                'rate_limit_exceeded': self.rate_limit_exceeded,
                'circuit_breaker_open': self.circuit_breaker_open,
                'audit_log_failures': self.audit_log_failures,
                'error_rate': self.failed_validations / total,
            },
        }


class MetricsCollector:
    """Thread-safe metrics collector."""
    
    def __init__(self, history_size: int = 1000):
        """
        Initialize metrics collector.
        
        Args:
            history_size: Number of recent data points to keep
        """
        self.metrics = ValidationMetrics()
        self.history = deque(maxlen=history_size)
        self.lock = threading.Lock()
        self.start_time = time.time()
    
    def record_validation_start(self) -> None:
        """Record start of validation."""
        with self.lock:
            self.metrics.total_validations += 1
    
    def record_validation_success(
        self,
        duration_ms: float,
        cache_hit: bool,
        findings_count: int = 0,
        findings_by_severity: Optional[Dict[str, int]] = None
    ) -> None:
        """Record successful validation."""
        with self.lock:
            self.metrics.successful_validations += 1
            self.metrics.total_duration_ms += duration_ms
            self.metrics.min_duration_ms = min(self.metrics.min_duration_ms, duration_ms)
            self.metrics.max_duration_ms = max(self.metrics.max_duration_ms, duration_ms)
            
            if cache_hit:
                self.metrics.cache_hits += 1
            else:
                self.metrics.cache_misses += 1
            
            if findings_count > 0 and findings_by_severity:
                self.metrics.total_findings += findings_count
                self.metrics.critical_findings += findings_by_severity.get('critical', 0)
                self.metrics.high_findings += findings_by_severity.get('high', 0)
                self.metrics.medium_findings += findings_by_severity.get('medium', 0)
                self.metrics.low_findings += findings_by_severity.get('low', 0)
                self.metrics.info_findings += findings_by_severity.get('info', 0)
            
            # Add to history
            self.history.append({
                'timestamp': time.time(),
                'duration_ms': duration_ms,
                'cache_hit': cache_hit,
                'findings_count': findings_count,
                'success': True,
            })
    
    def record_validation_failure(self, duration_ms: float, error_type: str) -> None:
        """Record failed validation."""
        with self.lock:
            self.metrics.failed_validations += 1
            self.metrics.total_duration_ms += duration_ms
            
            # Categorize error
            if error_type == 'rate_limit':
                self.metrics.rate_limit_exceeded += 1
            elif error_type == 'circuit_breaker':
                self.metrics.circuit_breaker_open += 1
            elif error_type == 'audit_log':
                self.metrics.audit_log_failures += 1
            
            # Add to history
            self.history.append({
                'timestamp': time.time(),
                'duration_ms': duration_ms,
                'error_type': error_type,
                'success': False,
            })
    
    def get_metrics(self) -> ValidationMetrics:
        """Get current metrics snapshot."""
        with self.lock:
            return ValidationMetrics(**self.metrics.__dict__)
    
    def get_recent_metrics(self, minutes: int = 5) -> Dict[str, Any]:
        """Get metrics from recent time window."""
        with self.lock:
            cutoff_time = time.time() - (minutes * 60)
            recent = [
                point for point in self.history 
                if point['timestamp'] > cutoff_time
            ]
            
            if not recent:
                return {'error': 'No recent data'}
            
            successful = [p for p in recent if p['success']]
            failed = [p for p in recent if not p['success']]
            
            return {
                'time_window_minutes': minutes,
                'total_requests': len(recent),
                'successful_requests': len(successful),
                'failed_requests': len(failed),
                'success_rate': len(successful) / len(recent),
                'avg_duration_ms': sum(p['duration_ms'] for p in recent) / len(recent),
                'cache_hit_rate': sum(1 for p in successful if p['cache_hit']) / max(1, len(successful)),
                'requests_per_minute': len(recent) / minutes,
            }
    
    def reset(self) -> None:
        """Reset all metrics."""
        with self.lock:
            self.metrics = ValidationMetrics()
            self.history.clear()
            self.start_time = time.time()
    
    def get_uptime_seconds(self) -> float:
        """Get collector uptime in seconds."""
        return time.time() - self.start_time


class HealthChecker:
    """Health check for validation system."""
    
    def __init__(
        self,
        metrics_collector: MetricsCollector,
        cache,
        audit_logger,
        rate_limiter
    ):
        """Initialize health checker."""
        self.metrics = metrics_collector
        self.cache = cache
        self.audit_logger = audit_logger
        self.rate_limiter = rate_limiter
    
    def check_health(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        health = {
            'status': 'healthy',
            'timestamp': time.time(),
            'uptime_seconds': self.metrics.get_uptime_seconds(),
            'checks': {},
        }
        
        # Check metrics collection
        try:
            metrics = self.metrics.get_metrics()
            health['checks']['metrics'] = {
                'status': 'pass',
                'total_validations': metrics.total_validations,
                'success_rate': metrics.successful_validations / max(1, metrics.total_validations),
            }
        except Exception as e:
            health['checks']['metrics'] = {'status': f'fail: {e}'}
            health['status'] = 'unhealthy'
        
        # Check cache
        try:
            test_key = "health_check_" + str(int(time.time()))
            self.cache.put(test_key, "test_value")
            cached_value = self.cache.get(test_key)
            if cached_value == "test_value":
                health['checks']['cache'] = {'status': 'pass'}
            else:
                health['checks']['cache'] = {'status': 'fail: value mismatch'}
                health['status'] = 'unhealthy'
        except Exception as e:
            health['checks']['cache'] = {'status': f'fail: {e}'}
            health['status'] = 'unhealthy'
        
        # Check audit logger (if available)
        if self.audit_logger:
            try:
                # Try to log a test event
                self.audit_logger.log_validation_attempt(
                    "test_hash", "health_check", "health_checker", 
                    0, 0, True
                )
                health['checks']['audit'] = {'status': 'pass'}
            except Exception as e:
                health['checks']['audit'] = {'status': f'fail: {e}'}
                health['status'] = 'unhealthy'
        
        # Check rate limiter
        try:
            stats = self.rate_limiter.get_stats()
            health['checks']['rate_limiter'] = {
                'status': 'pass',
                'utilization_percent': stats.get('utilization_percent', 0),
            }
        except Exception as e:
            health['checks']['rate_limiter'] = {'status': f'fail: {e}'}
            health['status'] = 'unhealthy'
        
        return health
