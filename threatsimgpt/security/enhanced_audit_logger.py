"""
Enhanced audit logger with circuit breaker protection.

Provides structured logging with fault tolerance and
performance optimizations for production use.
"""

import json
import logging
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any

from .circuit_breaker import CircuitBreaker, CircuitBreakerError
from .config import SecurityValidatorConfig


class EnhancedAuditLogger:
    """Enhanced audit logger with circuit breaker protection."""
    
    def __init__(self, config: SecurityValidatorConfig):
        """
        Initialize enhanced audit logger.
        
        Args:
            config: Security validator configuration
        """
        self.config = config
        self.log_file = config.audit_log_file or Path("logs/template_validation_audit.log")
        self.log_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Configure audit logger with structured logging
        self.logger = logging.getLogger(f"{__name__}.audit")
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # Circuit breaker for audit logging failures
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=config.audit_circuit_breaker_threshold,
            timeout=config.audit_circuit_breaker_timeout,
            expected_exception=(IOError, OSError)
        )
        
        # In-memory buffer for when circuit is open
        self.buffer = []
        self.buffer_lock = threading.Lock()
        self.max_buffer_size = 1000
    
    def log_validation_attempt(
        self,
        template_hash: str,
        template_name: str,
        validator_name: str,
        findings_count: int,
        duration_ms: int,
        success: bool
    ) -> None:
        """Log validation attempt with structured data."""
        audit_data = {
            "event_type": "template_validation",
            "template_hash": template_hash[:16],  # First 16 chars for privacy
            "template_name": template_name,
            "validator": validator_name,
            "findings_count": findings_count,
            "duration_ms": duration_ms,
            "success": success,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "user": "system"  # Will be overridden with actual user
        }
        
        log_message = (
            f"{'PASS' if success else 'FAIL'} - "
            f"Template: {template_name} - "
            f"Hash: {template_hash[:16]} - "
            f"Findings: {findings_count} - "
            f"Duration: {duration_ms}ms"
        )
        
        self._write_log(log_message, audit_data, success)
    
    def log_validation(
        self,
        template_hash: str,
        validation_id: str,
        result: 'SecurityValidationResult',
        source: str = "unknown",
        user_id: Optional[str] = None
    ) -> None:
        """Log a template validation event."""
        audit_data = {
            "event_type": "template_validation",
            "template_hash": template_hash[:16],
            "validation_id": validation_id,
            "is_secure": result.is_secure,
            "findings_count": len(result.findings),
            "source": source,
            "user_id": user_id or "system",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        log_message = (
            f"{'PASS' if result.is_secure else 'FAIL'} - "
            f"Validation: {validation_id} - "
            f"Hash: {template_hash[:16]} - "
            f"Findings: {len(result.findings)}"
        )
        
        self._write_log(log_message, audit_data, result.is_secure)
    
    def log_security_finding(
        self,
        template_hash: str,
        template_name: str,
        finding: 'SecurityFinding'
    ) -> None:
        """Log security finding with structured data."""
        audit_data = {
            "event_type": "security_finding",
            "template_hash": template_hash[:16],
            "template_name": template_name,
            "severity": finding.severity.value,
            "category": finding.category.value,
            "title": finding.title,
            "location": finding.location,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        log_message = (
            f"[{finding.severity.value.upper()}] "
            f"{finding.category.value} - "
            f"{finding.title} - "
            f"Location: {finding.location}"
        )
        
        # Security findings are always important
        self._write_log(log_message, audit_data, False)
    
    def log_rate_limit_exceeded(
        self,
        tenant_id: str,
        retry_after: int
    ) -> None:
        """Log rate limit exceeded event."""
        audit_data = {
            "event_type": "rate_limit_exceeded",
            "tenant_id": tenant_id,
            "retry_after_seconds": retry_after,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        log_message = (
            f"RATE_LIMIT - "
            f"Tenant: {tenant_id} - "
            f"Retry after: {retry_after}s"
        )
        
        self._write_log(log_message, audit_data, False)
    
    def log_circuit_breaker_open(
        self,
        service: str,
        failure_count: int
    ) -> None:
        """Log circuit breaker opening event."""
        audit_data = {
            "event_type": "circuit_breaker_open",
            "service": service,
            "failure_count": failure_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        
        log_message = (
            f"CIRCUIT_BREAKER - "
            f"Service: {service} - "
            f"Failures: {failure_count}"
        )
        
        self._write_log(log_message, audit_data, False)
    
    def _write_log(
        self,
        log_message: str,
        audit_data: Dict[str, Any],
        is_success: bool
    ) -> None:
        """Write log with circuit breaker protection."""
        try:
            # Try to write through circuit breaker
            self.circuit_breaker.call(
                self._write_to_file, log_message, audit_data, is_success
            )
        except CircuitBreakerError:
            # Circuit is open - buffer the log
            self._buffer_log(log_message, audit_data, is_success)
            
            # Log the circuit breaker event
            self._log_circuit_breaker_event()
    
    def _write_to_file(
        self,
        log_message: str,
        audit_data: Dict[str, Any],
        is_success: bool
    ) -> None:
        """Actually write to file."""
        # Write structured log
        self.logger.info(log_message, extra=audit_data)
        
        # Also write JSON line for machine processing
        with open(self.log_file.with_suffix('.jsonl'), 'a') as f:
            f.write(json.dumps(audit_data) + '\n')
    
    def _buffer_log(
        self,
        log_message: str,
        audit_data: Dict[str, Any],
        is_success: bool
    ) -> None:
        """Buffer log when circuit is open."""
        with self.buffer_lock:
            if len(self.buffer) < self.max_buffer_size:
                self.buffer.append({
                    'message': log_message,
                    'data': audit_data,
                    'success': is_success,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
    
    def _log_circuit_breaker_event(self) -> None:
        """Log that circuit breaker is open."""
        stats = self.circuit_breaker.get_stats()
        self.logger.warning(
            f"Audit circuit breaker is OPEN: {stats}"
        )
    
    def flush_buffer(self) -> int:
        """
        Attempt to flush buffered logs.
        
        Returns:
            Number of logs flushed
        """
        if self.circuit_breaker.get_state().value != 'CLOSED':
            return 0
        
        with self.buffer_lock:
            if not self.buffer:
                return 0
            
            flushed_count = 0
            remaining_buffer = []
            
            for log_entry in self.buffer:
                try:
                    self.circuit_breaker.call(
                        self._write_to_file,
                        log_entry['message'],
                        log_entry['data'],
                        log_entry['success']
                    )
                    flushed_count += 1
                except CircuitBreakerError:
                    # Circuit opened again - keep remaining in buffer
                    remaining_buffer.append(log_entry)
                    break
            
            self.buffer = remaining_buffer
            return flushed_count
    
    def get_stats(self) -> Dict[str, Any]:
        """Get audit logger statistics."""
        return {
            'circuit_breaker': self.circuit_breaker.get_stats(),
            'buffer_size': len(self.buffer),
            'max_buffer_size': self.max_buffer_size,
            'log_file': str(self.log_file),
        }
