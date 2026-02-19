"""Template Security Validator for ThreatSimGPT.

This module provides comprehensive security validation for threat scenario templates,
detecting injection attacks, malicious content, path traversal, and other security
issues that could compromise the system or enable abuse.

Security Categories Validated:
- Injection Attacks: YAML injection, command injection, code injection
- Path Traversal: Directory traversal, symlink attacks
- Malicious Content: Harmful URLs, credential patterns, PII exposure
- Resource Abuse: DoS patterns, excessive resource consumption
- Compliance: Ethical boundaries, content policy violations

Security Hardening (Issue #106 Review Fixes):
- ReDoS protection via regex timeout
- Unicode normalization (NFKC) for bypass prevention
- Path validation for storage operations
- Proper error handling (no silent failures)
- File locking for concurrent access
- Audit log sanitization
"""

import base64
import fcntl
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import signal
import threading
import time
import unicodedata
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, unquote

import yaml
from pydantic import BaseModel, Field

# Configure module logger
logger = logging.getLogger(__name__)

# ==================== Security Models ====================
class SecuritySeverity(Enum):
    """Security severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityCategory(Enum):
    """Security finding categories."""
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    MALICIOUS_CONTENT = "malicious_content"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    PII_EXPOSURE = "pii_exposure"
    RESOURCE_ABUSE = "resource_abuse"
    CONTENT_POLICY = "content_policy"
    ENCODING_ATTACK = "encoding_attack"
    SCHEMA_VIOLATION = "schema_violation"

@dataclass
class SecurityFinding:
    """Security finding with full context."""
    severity: SecuritySeverity
    category: SecurityCategory
    title: str
    description: str
    location: Optional[str] = None
    evidence: Optional[str] = None
    pattern_matched: Optional[str] = None
    recommendation: Optional[str] = None
    value_preview: Optional[str] = None
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "severity": self.severity.value,
            "category": self.category.value,
            "title": self.title,
            "description": self.description,
            "location": self.location,
            "evidence": self.evidence,
            "pattern_matched": self.pattern_matched,
            "recommendation": self.recommendation,
            "value_preview": self.value_preview,
            "remediation": self.remediation,
            "cwe_id": self.cwe_id,
            "mitre_technique": self.mitre_technique,
        }

@dataclass
class SecurityValidationResult:
    """Result of template security validation."""
    is_secure: bool
    findings: List[SecurityFinding] = field(default_factory=list)
    template_hash: str = field(default="")
    validation_id: str = field(default="")
    validated_at: Optional[datetime] = None
    validation_duration_ms: int = field(default=0)
    metadata: Dict[str, Any] = field(default_factory=dict)
    scan_timestamp: Optional[datetime] = None
    scan_duration_ms: Optional[float] = None
    
    # Aggregated statistics
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    def __post_init__(self):
        """Initialize aggregated statistics."""
        for finding in self.findings:
            if finding.severity == SecuritySeverity.CRITICAL:
                self.critical_count += 1
            elif finding.severity == SecuritySeverity.HIGH:
                self.high_count += 1
            elif finding.severity == SecuritySeverity.MEDIUM:
                self.medium_count += 1
            elif finding.severity == SecuritySeverity.LOW:
                self.low_count += 1
            else:
                self.info_count += 1
    
    @property
    def blocking_findings(self) -> List[SecurityFinding]:
        """Return findings that should block template usage."""
        return [f for f in self.findings 
                if f.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH)]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary for serialization."""
        return {
            "is_secure": self.is_secure,
            "findings": [finding.to_dict() for finding in self.findings],
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "info_count": self.info_count,
            "scan_timestamp": self.scan_timestamp.isoformat() if self.scan_timestamp else None,
            "scan_duration_ms": self.scan_duration_ms,
            "template_hash": self.template_hash,
            "validation_id": self.validation_id,
        }

# ==================== Caching System ====================

class ValidationCache:
    """Thread-safe cache for template validation results."""
    
    def __init__(self, max_size: int = 100, ttl_seconds: int = 300):
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._cache: Dict[str, Tuple[SecurityValidationResult, float]] = {}
        self._lock = threading.RLock()
    
    def get(self, template_hash: str) -> Optional[SecurityValidationResult]:
        """Get cached validation result if still valid."""
        with self._lock:
            if template_hash in self._cache:
                result, timestamp = self._cache[template_hash]
                if time.time() - timestamp < self.ttl_seconds:
                    return result
                else:
                    # Expired, remove from cache
                    del self._cache[template_hash]
        return None
    
    def put(self, template_hash: str, result: SecurityValidationResult) -> None:
        """Cache validation result with timestamp."""
        with self._lock:
            self._cache[template_hash] = (result, time.time())
            
            # Implement LRU eviction
            if len(self._cache) > self.max_size:
                # Remove oldest entry
                oldest_hash = min(self._cache.keys(), 
                                   key=lambda k: self._cache[k][1])
                del self._cache[oldest_hash]

# ==================== Enhanced Audit Logging ====================

class SecurityAuditLogger:
    """Enhanced audit logger for template validation."""
    
    def __init__(self, log_file: Optional[Path] = None):
        self.log_file = log_file or Path("logs/template_validation_audit.log")
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
    
    def log_validation_attempt(self, 
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
        
        if success:
            self.logger.info(log_message, extra=audit_data)
        else:
            self.logger.warning(log_message, extra=audit_data)
    
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
        
        if result.is_secure:
            self.logger.info(log_message, extra=audit_data)
        else:
            self.logger.warning(log_message, extra=audit_data)
    
    def log_security_finding(self, 
                              template_hash: str,
                              template_name: str,
                              finding: SecurityFinding
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
        
        if finding.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
            self.logger.error(log_message, extra=audit_data)
        else:
            self.logger.warning(log_message, extra=audit_data)

# ==================== Security Utility Functions ====================
# Added as part of Issue #106 review fixes

# Constants
MAX_REGEX_TIMEOUT_SECONDS = 2
MAX_AUDIT_LOG_SIZE = 5000
MAX_BLOCKLIST_PATTERNS = 100  # Limit to prevent DoS
MAX_TRAVERSAL_DEPTH = 50  # Prevent stack overflow
MAX_TEMPLATE_SIZE_BYTES = 1_000_000  # 1MB max template size
MAX_TEMPLATE_STRING_SIZE = 500_000  # 500KB for string templates (to allow for encoding overhead)
ALLOWED_STORAGE_BASE_DIRS = [
    Path("/var/lib/threatsimgpt"),
    Path.home() / ".threatsimgpt",
    Path.cwd() / "data",
]

# Pre-compiled regex patterns for performance
# These patterns are used repeatedly and benefit from pre-compilation
_COMPILED_PATTERNS = {
    # URL extraction patterns
    'url_http': re.compile(r'https?://[^\s<>"\']+', re.IGNORECASE),
    'url_http_strict': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    'data_uri': re.compile(r'data:[^,\s]+', re.IGNORECASE),
    
    # Validation patterns
    'base64_check': re.compile(r'^[A-Za-z0-9+/]+=*$'),
    'data_uri_mime': re.compile(r'data:([^;,]+)'),
    
    # Detection patterns
    'email': re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    'ipv4': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
    
    # Dangerous protocol patterns
    'javascript_proto': re.compile(r'javascript:', re.IGNORECASE),
    'vbscript_proto': re.compile(r'vbscript:', re.IGNORECASE),
}


class RegexTimeoutError(TimeoutError):
    """Raised when regex execution exceeds timeout."""
    pass


class SecurityConfigError(ValueError):
    """Raised when security configuration is invalid."""
    pass


class PatternLimitExceededError(SecurityConfigError):
    """Raised when blocklist pattern limit is exceeded."""
    pass


def _thread_safe_regex_match(
    pattern: Union[str, re.Pattern], 
    value: str, 
    timeout: float = MAX_REGEX_TIMEOUT_SECONDS,
    flags: int = 0
) -> Optional[re.Match]:
    """Thread-pool based regex timeout that works in threads/async.
    
    This is the preferred method for regex matching with timeout protection
    as it works in all execution contexts (main thread, worker threads, async).
    
    Args:
        pattern: Regex pattern (string or compiled)
        value: String to match against
        timeout: Maximum execution time in seconds
        flags: Regex flags (only used if pattern is string)
        
    Returns:
        Match object if found, None otherwise
        
    Raises:
        RegexTimeoutError: If regex execution exceeds timeout
    """
    import concurrent.futures
    
    # Compile pattern if string
    if isinstance(pattern, str):
        try:
            compiled = re.compile(pattern, flags)
        except re.error as e:
            logger.warning(f"Invalid regex pattern: {e}")
            return None
    else:
        compiled = pattern
    
    def do_match():
        return compiled.search(value)
    
    # Use thread pool for timeout - works everywhere
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(do_match)
        try:
            return future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            # Note: Cannot actually cancel the thread, but we raise immediately
            raise RegexTimeoutError(f"Regex execution timed out after {timeout}s")


@contextmanager
def regex_timeout(seconds: int = MAX_REGEX_TIMEOUT_SECONDS):
    """Context manager for regex execution with timeout protection against ReDoS.
    
    WARNING: This uses SIGALRM which only works in the main thread on Unix.
    For thread-safe timeout, use _thread_safe_regex_match() instead.
    
    Args:
        seconds: Maximum execution time for regex operations
        
    Raises:
        RegexTimeoutError: If regex execution exceeds timeout
        
    Note:
        Only works on Unix systems in main thread.
        On Windows or worker threads, regex executes without timeout.
        Prefer _thread_safe_regex_match() for production use.
    """
    def handler(signum, frame):
        raise RegexTimeoutError(f"Regex execution timed out after {seconds}s")
    
    # signal.SIGALRM only available on Unix
    if hasattr(signal, 'SIGALRM'):
        # Check if we're in the main thread
        if threading.current_thread() is threading.main_thread():
            old_handler = signal.signal(signal.SIGALRM, handler)
            signal.alarm(seconds)
            try:
                yield
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)
        else:
            # In worker thread - signal won't work, just yield
            logger.debug("regex_timeout in worker thread - no protection available")
            yield
    else:
        # Windows fallback - no timeout protection
        logger.debug("regex_timeout on non-Unix - no protection available")
        yield


def normalize_for_security(value: str) -> str:
    """Normalize a string for security comparison using NFKC.
    
    This prevents Unicode bypass attacks using confusable characters.
    
    Args:
        value: String to normalize
        
    Returns:
        NFKC normalized, lowercased, stripped string
    """
    # NFKC normalization converts fullwidth characters, compatibility chars, etc.
    normalized = unicodedata.normalize('NFKC', value)
    return normalized.lower().strip()


def validate_storage_path(path: Path, allowed_bases: Optional[List[Path]] = None) -> Path:
    """Validate that a storage path is within allowed directories.
    
    Prevents path traversal attacks in storage operations.
    
    Args:
        path: Path to validate
        allowed_bases: List of allowed base directories (defaults to ALLOWED_STORAGE_BASE_DIRS)
        
    Returns:
        Resolved absolute path
        
    Raises:
        SecurityConfigError: If path is outside allowed directories
    """
    if allowed_bases is None:
        allowed_bases = ALLOWED_STORAGE_BASE_DIRS
    
    resolved = path.resolve()
    
    for base in allowed_bases:
        try:
            base_resolved = base.resolve()
            # Check if path is under this base directory
            resolved.relative_to(base_resolved)
            return resolved
        except ValueError:
            continue
    
    raise SecurityConfigError(
        f"Storage path '{resolved}' is not within allowed directories. "
        f"Allowed bases: {[str(b) for b in allowed_bases]}"
    )


def sanitize_for_log(value: str, max_length: int = 100) -> str:
    """Sanitize a value for safe inclusion in logs.
    
    Prevents log injection attacks by escaping control characters.
    
    Args:
        value: Value to sanitize
        max_length: Maximum length of output
        
    Returns:
        Sanitized string safe for logging
    """
    # Replace control characters that could inject log entries
    sanitized = value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
    # Remove other control characters
    sanitized = ''.join(c if ord(c) >= 32 or c in ' ' else f'\\x{ord(c):02x}' for c in sanitized)
    # Truncate if needed
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + '...'
    return sanitized


def decode_if_base64(value: str) -> Tuple[str, bool]:
    """Attempt to decode a base64 string for credential detection.
    
    Args:
        value: Potentially base64-encoded string
        
    Returns:
        Tuple of (decoded string or original, was_decoded)
    """
    # Check if it looks like base64 (use pre-compiled pattern)
    if not _COMPILED_PATTERNS['base64_check'].match(value) or len(value) < 20:
        return value, False
    
    try:
        decoded = base64.b64decode(value, validate=True).decode('utf-8', errors='ignore')
        # Only return if it produced printable ASCII
        if decoded.isprintable() and len(decoded) > 10:
            return decoded, True
    except Exception:
        pass
    
    return value, False



def is_safe_data_uri(uri: str) -> bool:
    """Check if a data URI is safe (only allows specific image types).
    
    Args:
        uri: Data URI to check
        
    Returns:
        True if URI is a safe image type, False otherwise
    """
    safe_mime_types = {
        'image/png',
        'image/jpeg',
        'image/gif',
        'image/webp',
        'image/svg+xml',  # Note: SVG can be dangerous, but we check separately
    }
    
    # Extract MIME type from data URI (use pre-compiled pattern)
    match = _COMPILED_PATTERNS['data_uri_mime'].match(uri.lower())
    if not match:
        return False
    
    mime_type = match.group(1)
    
    # SVG needs special handling - reject if it contains script patterns
    if mime_type == 'image/svg+xml':
        # Check for XSS patterns in SVG
        dangerous_patterns = ['<script', 'onload=', 'onerror=', 'onclick=', 'javascript:']
        uri_lower = uri.lower()
        return not any(p in uri_lower for p in dangerous_patterns)
    
    return mime_type in safe_mime_types


# ==================== Circuit Breaker Pattern ====================
# Prevents cascading failures under heavy load


class CircuitBreakerState(str, Enum):
    """State of the circuit breaker."""
    CLOSED = "closed"      # Normal operation, requests allowed
    OPEN = "open"          # Failures detected, requests blocked
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class CircuitBreaker:
    """Circuit breaker pattern for protecting against cascading failures.
    
    This prevents repeated failures from consuming resources and provides
    automatic recovery after a cooldown period.
    
    Attributes:
        name: Identifier for this circuit breaker
        failure_threshold: Number of failures before opening circuit
        recovery_timeout: Seconds to wait before trying again
        success_threshold: Successes needed to close half-open circuit
    
    Usage:
        cb = CircuitBreaker("regex_validation", failure_threshold=5)
        if cb.allow_request():
            try:
                result = risky_operation()
                cb.record_success()
            except Exception as e:
                cb.record_failure(e)
                raise
    """
    name: str
    failure_threshold: int = 5
    recovery_timeout: float = 30.0  # seconds
    success_threshold: int = 2
    
    # Internal state
    _state: CircuitBreakerState = field(default=CircuitBreakerState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _success_count: int = field(default=0, init=False)
    _last_failure_time: Optional[float] = field(default=None, init=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False)
    _recent_failures: deque = field(default_factory=lambda: deque(maxlen=10), init=False)
    
    def allow_request(self) -> bool:
        """Check if a request should be allowed through.
        
        Returns:
            True if request is allowed, False if circuit is open
        """
        import time
        
        with self._lock:
            if self._state == CircuitBreakerState.CLOSED:
                return True
            
            if self._state == CircuitBreakerState.OPEN:
                # Check if recovery timeout has elapsed
                if self._last_failure_time is not None:
                    elapsed = time.time() - self._last_failure_time
                    if elapsed >= self.recovery_timeout:
                        self._state = CircuitBreakerState.HALF_OPEN
                        self._success_count = 0
                        logger.info(f"Circuit breaker '{self.name}' entering half-open state")
                        return True
                return False
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Allow limited requests in half-open state
                return True
            
            return True
    
    def record_success(self) -> None:
        """Record a successful operation."""
        with self._lock:
            if self._state == CircuitBreakerState.HALF_OPEN:
                self._success_count += 1
                if self._success_count >= self.success_threshold:
                    self._state = CircuitBreakerState.CLOSED
                    self._failure_count = 0
                    logger.info(f"Circuit breaker '{self.name}' closed after recovery")
            elif self._state == CircuitBreakerState.CLOSED:
                # Decay failure count on success (bounded recovery)
                if self._failure_count > 0:
                    self._failure_count = max(0, self._failure_count - 1)
    
    def record_failure(self, error: Optional[Exception] = None) -> None:
        """Record a failed operation."""
        import time
        
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            
            # Track recent failures for debugging
            if error:
                self._recent_failures.append({
                    "time": datetime.now(timezone.utc).isoformat(),
                    "error_type": type(error).__name__,
                    "message": str(error)[:100]
                })
            
            if self._state == CircuitBreakerState.HALF_OPEN:
                # Any failure in half-open reopens the circuit
                self._state = CircuitBreakerState.OPEN
                logger.warning(f"Circuit breaker '{self.name}' reopened after failure in half-open state")
            elif self._state == CircuitBreakerState.CLOSED:
                if self._failure_count >= self.failure_threshold:
                    self._state = CircuitBreakerState.OPEN
                    logger.warning(
                        f"Circuit breaker '{self.name}' opened after {self._failure_count} failures. "
                        f"Recovery timeout: {self.recovery_timeout}s"
                    )
    
    def is_open(self) -> bool:
        """Check if circuit is currently open."""
        with self._lock:
            return self._state == CircuitBreakerState.OPEN
    
    def get_status(self) -> Dict[str, Any]:
        """Get current circuit breaker status for monitoring."""
        with self._lock:
            return {
                "name": self.name,
                "state": self._state.value,
                "failure_count": self._failure_count,
                "success_count": self._success_count,
                "last_failure_time": self._last_failure_time,
                "recent_failures": list(self._recent_failures),
            }
    
    def reset(self) -> None:
        """Manually reset the circuit breaker."""
        with self._lock:
            self._state = CircuitBreakerState.CLOSED
            self._failure_count = 0
            self._success_count = 0
            self._last_failure_time = None
            self._recent_failures.clear()
            logger.info(f"Circuit breaker '{self.name}' manually reset")


# Global circuit breakers for critical operations
_circuit_breakers: Dict[str, CircuitBreaker] = {}
_circuit_breaker_lock = threading.Lock()


def get_circuit_breaker(name: str, **kwargs) -> CircuitBreaker:
    """Get or create a circuit breaker by name.
    
    Args:
        name: Unique identifier for the circuit breaker
        **kwargs: Arguments to pass to CircuitBreaker if creating new
        
    Returns:
        CircuitBreaker instance
    """
    with _circuit_breaker_lock:
        if name not in _circuit_breakers:
            _circuit_breakers[name] = CircuitBreaker(name, **kwargs)
        return _circuit_breakers[name]


# ==================== Metrics and Observability ====================


@dataclass
class ValidationMetrics:
    """Metrics for monitoring template validation performance.
    
    Thread-safe metrics collection for observability and performance monitoring.
    Can be used with Prometheus, StatsD, or other metrics backends.
    """
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)
    
    # Counters
    _total_validations: int = field(default=0, init=False)
    _successful_validations: int = field(default=0, init=False)
    _failed_validations: int = field(default=0, init=False)
    _blocked_validations: int = field(default=0, init=False)  # Circuit breaker blocks
    
    # Timing (stored as list for percentile calculation)
    _validation_times: deque = field(default_factory=lambda: deque(maxlen=1000), init=False)
    
    # Finding counters by severity
    _findings_by_severity: Dict[str, int] = field(default_factory=dict, init=False)
    _findings_by_category: Dict[str, int] = field(default_factory=dict, init=False)
    
    # Error tracking
    _timeout_count: int = field(default=0, init=False)
    _error_count: int = field(default=0, init=False)
    
    def record_validation(
        self, 
        success: bool, 
        duration_ms: float,
        findings: Optional[List["SecurityFinding"]] = None,
        blocked: bool = False
    ) -> None:
        """Record a validation attempt with its results.
        
        Args:
            success: Whether validation passed (no critical findings)
            duration_ms: Time taken in milliseconds
            findings: List of security findings if any
            blocked: Whether request was blocked by circuit breaker
        """
        with self._lock:
            self._total_validations += 1
            
            if blocked:
                self._blocked_validations += 1
            elif success:
                self._successful_validations += 1
            else:
                self._failed_validations += 1
            
            self._validation_times.append(duration_ms)
            
            if findings:
                for finding in findings:
                    sev_key = finding.severity.value
                    cat_key = finding.category.value
                    self._findings_by_severity[sev_key] = self._findings_by_severity.get(sev_key, 0) + 1
                    self._findings_by_category[cat_key] = self._findings_by_category.get(cat_key, 0) + 1
    
    def record_timeout(self) -> None:
        """Record a timeout event."""
        with self._lock:
            self._timeout_count += 1
    
    def record_error(self) -> None:
        """Record an error event."""
        with self._lock:
            self._error_count += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Get current metrics snapshot for monitoring."""
        import statistics
        
        with self._lock:
            times = list(self._validation_times)
            
            stats = {
                "total_validations": self._total_validations,
                "successful_validations": self._successful_validations,
                "failed_validations": self._failed_validations,
                "blocked_validations": self._blocked_validations,
                "timeout_count": self._timeout_count,
                "error_count": self._error_count,
                "findings_by_severity": dict(self._findings_by_severity),
                "findings_by_category": dict(self._findings_by_category),
            }
            
            if times:
                stats.update({
                    "validation_time_avg_ms": statistics.mean(times),
                    "validation_time_p50_ms": statistics.median(times),
                    "validation_time_p95_ms": sorted(times)[int(len(times) * 0.95)] if len(times) >= 20 else None,
                    "validation_time_p99_ms": sorted(times)[int(len(times) * 0.99)] if len(times) >= 100 else None,
                    "validation_time_max_ms": max(times),
                })
            
            return stats
    
    def reset(self) -> None:
        """Reset all metrics (useful for testing)."""
        with self._lock:
            self._total_validations = 0
            self._successful_validations = 0
            self._failed_validations = 0
            self._blocked_validations = 0
            self._timeout_count = 0
            self._error_count = 0
            self._validation_times.clear()
            self._findings_by_severity.clear()
            self._findings_by_category.clear()


# Global metrics instance
_validation_metrics: Optional[ValidationMetrics] = None
_metrics_lock = threading.Lock()


def get_validation_metrics() -> ValidationMetrics:
    """Get the global validation metrics instance."""
    global _validation_metrics
    with _metrics_lock:
        if _validation_metrics is None:
            _validation_metrics = ValidationMetrics()
        return _validation_metrics


@contextmanager
def timed_validation():
    """Context manager to time validation operations.
    
    Yields the start time and records duration to metrics on exit.
    
    Usage:
        with timed_validation() as timer:
            # do validation
            timer["success"] = True
            timer["findings"] = findings
    """
    import time
    
    result = {"success": False, "findings": None, "blocked": False}
    start = time.perf_counter()
    
    try:
        yield result
    finally:
        duration_ms = (time.perf_counter() - start) * 1000
        get_validation_metrics().record_validation(
            success=result.get("success", False),
            duration_ms=duration_ms,
            findings=result.get("findings"),
            blocked=result.get("blocked", False)
        )


# ==================== Security Enums and Models ====================

class SecuritySeverity(str, Enum):
    """Security finding severity levels aligned with CVSS."""
    
    CRITICAL = "critical"  # 9.0-10.0: Immediate action required
    HIGH = "high"          # 7.0-8.9: Should be fixed urgently
    MEDIUM = "medium"      # 4.0-6.9: Should be addressed
    LOW = "low"            # 0.1-3.9: Minor issue
    INFO = "info"          # Informational finding


class SecurityCategory(str, Enum):
    """Categories of security findings."""
    
    INJECTION = "injection"
    PATH_TRAVERSAL = "path_traversal"
    CREDENTIAL_EXPOSURE = "credential_exposure"
    MALICIOUS_URL = "malicious_url"
    PII_EXPOSURE = "pii_exposure"
    RESOURCE_ABUSE = "resource_abuse"
    YAML_SECURITY = "yaml_security"
    CONTENT_POLICY = "content_policy"
    ENCODING_ATTACK = "encoding_attack"
    SCHEMA_VIOLATION = "schema_violation"


class BlocklistManager:
    """Manages blocklists for prohibited content in templates.
    
    Provides functionality to:
    - Add/remove entries from blocklists
    - Check content against blocklists
    - Persist blocklists to storage with file locking
    - Support multiple blocklist categories
    
    Security Hardening (Review Fixes):
    - Thread-safe operations with RLock
    - ReDoS protection with regex timeout
    - Path validation for storage
    - Proper error handling with logging
    - Unicode normalization for bypass prevention
    
    Author: Olabisi Olajide (bayulus)
    Issue: #106 - Implement Template Security Validation
    """
    
    # Valid blocklist categories
    VALID_CATEGORIES = frozenset({'domains', 'keywords', 'patterns', 'emails', 'ips', 'hashes'})
    
    def __init__(
        self, 
        storage_path: Optional[Path] = None,
        allowed_storage_bases: Optional[List[Path]] = None
    ):
        """Initialize blocklist manager.
        
        Args:
            storage_path: Path to persist blocklists. If None, uses in-memory only.
            allowed_storage_bases: Allowed base directories for storage path validation.
            
        Raises:
            SecurityConfigError: If storage_path is outside allowed directories.
        """
        self._lock = threading.RLock()
        self._blocklists: Dict[str, Set[str]] = {cat: set() for cat in self.VALID_CATEGORIES}
        self._audit_log: deque = deque(maxlen=MAX_AUDIT_LOG_SIZE)
        
        # Validate and set storage path
        if storage_path:
            self.storage_path = validate_storage_path(storage_path, allowed_storage_bases)
        else:
            self.storage_path = None
        
        # Load from storage if available
        if self.storage_path and self.storage_path.exists():
            self._load_from_storage()
    
    def add_to_blocklist(
        self, 
        category: str, 
        value: str, 
        reason: str = "",
        added_by: str = "system"
    ) -> bool:
        """Add an entry to a blocklist.
        
        Args:
            category: Blocklist category (domains, keywords, patterns, emails, ips, hashes)
            value: Value to block
            reason: Reason for blocking
            added_by: Who added this entry
            
        Returns:
            True if added, False if already exists
            
        Raises:
            ValueError: If category is invalid
            SecurityConfigError: If pattern is potentially malicious (ReDoS)
        """
        if category not in self.VALID_CATEGORIES:
            raise ValueError(f"Invalid blocklist category: {category}. Valid: {self.VALID_CATEGORIES}")
        
        # Use secure normalization
        normalized_value = normalize_for_security(value)
        
        # Validate patterns for ReDoS before adding
        if category == 'patterns':
            self._validate_pattern_safety(normalized_value)
        
        with self._lock:
            if normalized_value in self._blocklists[category]:
                return False
            
            self._blocklists[category].add(normalized_value)
            
            # Audit log entry with sanitization
            self._log_audit_event(
                action="add",
                category=category,
                value=normalized_value,
                reason=reason,
                performed_by=added_by
            )
            
            # Persist if storage configured
            if self.storage_path:
                self._save_to_storage()
            
            return True
    
    def _validate_pattern_safety(self, pattern: str) -> None:
        """Validate that a regex pattern is safe from ReDoS.
        
        Uses thread-safe timeout for pattern testing.
        
        Args:
            pattern: Regex pattern to validate
            
        Raises:
            SecurityConfigError: If pattern fails safety checks
            PatternLimitExceededError: If blocklist pattern limit exceeded
        """
        # Check pattern count limit
        with self._lock:
            pattern_count = len(self._blocklists.get('patterns', set()))
            if pattern_count >= MAX_BLOCKLIST_PATTERNS:
                raise PatternLimitExceededError(
                    f"Maximum blocklist pattern limit ({MAX_BLOCKLIST_PATTERNS}) exceeded"
                )
        
        # Check for common ReDoS patterns
        dangerous_patterns = [
            r'\(.+\)\+\+',      # Nested quantifiers
            r'\(.+\)\*\+',      # Nested quantifiers variant
            r'\(.+\)\+\*',      # Nested quantifiers variant
            r'\(.+\)\{\d+,\}\+', # Nested quantifiers with braces
            r'(?:[^)]+\|[^)]+)\+', # Alternation with quantifier
        ]
        
        for danger in dangerous_patterns:
            if re.search(danger, pattern):
                raise SecurityConfigError(
                    f"Pattern contains potentially dangerous ReDoS construct: {pattern[:50]}"
                )
        
        # Test execution with thread-safe timeout on sample input
        try:
            test_input = 'a' * 25
            # Use thread-safe regex matching for safety test
            _thread_safe_regex_match(pattern, test_input, timeout=1)
        except RegexTimeoutError:
            raise SecurityConfigError(
                f"Pattern execution timed out during safety test: {pattern[:50]}"
            )
        except re.error as e:
            raise SecurityConfigError(f"Invalid regex pattern: {e}")

    
    def remove_from_blocklist(
        self, 
        category: str, 
        value: str,
        reason: str = "",
        removed_by: str = "system"
    ) -> bool:
        """Remove an entry from a blocklist.
        
        Args:
            category: Blocklist category
            value: Value to unblock
            reason: Reason for removal
            removed_by: Who removed this entry
            
        Returns:
            True if removed, False if not found
            
        Raises:
            ValueError: If category is invalid
        """
        if category not in self.VALID_CATEGORIES:
            raise ValueError(f"Invalid blocklist category: {category}. Valid: {self.VALID_CATEGORIES}")
        
        normalized_value = normalize_for_security(value)
        
        with self._lock:
            if normalized_value not in self._blocklists[category]:
                return False
            
            self._blocklists[category].discard(normalized_value)
            
            # Audit log entry
            self._log_audit_event(
                action="remove",
                category=category,
                value=normalized_value,
                reason=reason,
                performed_by=removed_by
            )
            
            # Persist if storage configured
            if self.storage_path:
                self._save_to_storage()
            
            return True
    
    def is_blocked(self, category: str, value: str) -> bool:
        """Check if a value is in a blocklist.
        
        Args:
            category: Blocklist category to check
            value: Value to check
            
        Returns:
            True if blocked, False otherwise
            
        Raises:
            ValueError: If category is invalid
        """
        if category not in self.VALID_CATEGORIES:
            raise ValueError(f"Invalid blocklist category: {category}. Valid: {self.VALID_CATEGORIES}")
        
        normalized_value = normalize_for_security(value)
        
        with self._lock:
            return normalized_value in self._blocklists[category]
    
    def check_all_blocklists(self, value: str) -> Optional[str]:
        """Check a value against all blocklists.
        
        Uses Unicode normalization and URL decoding for bypass prevention.
        Uses thread-safe regex matching with circuit breaker protection.
        
        Args:
            value: Value to check
            
        Returns:
            Category name if blocked, None if not blocked
        """
        # Get circuit breaker for blocklist operations
        cb = get_circuit_breaker("blocklist_check", failure_threshold=10, recovery_timeout=30)
        
        if not cb.allow_request():
            logger.warning("Blocklist check blocked by circuit breaker")
            get_validation_metrics().record_error()
            return None  # Fail open - allow content when circuit is open
        
        # Apply multiple normalization layers to prevent bypasses
        normalized_value = normalize_for_security(value)
        
        # Also check URL-decoded version
        try:
            url_decoded = unquote(value)
            url_decoded_normalized = normalize_for_security(url_decoded)
        except Exception:
            url_decoded_normalized = normalized_value
        
        # Check base64 decoded version for credential detection
        base64_decoded, was_decoded = decode_if_base64(value)
        base64_normalized = normalize_for_security(base64_decoded) if was_decoded else None
        
        values_to_check = [normalized_value, url_decoded_normalized]
        if base64_normalized:
            values_to_check.append(base64_normalized)
        
        try:
            with self._lock:
                for check_value in values_to_check:
                    for category, blocklist in self._blocklists.items():
                        if check_value in blocklist:
                            cb.record_success()
                            return category
                        
                        # For patterns, check regex match with thread-safe timeout
                        if category == 'patterns':
                            for pattern in blocklist:
                                try:
                                    # Use thread-safe regex matching
                                    match = _thread_safe_regex_match(
                                        pattern, 
                                        check_value, 
                                        timeout=MAX_REGEX_TIMEOUT_SECONDS
                                    )
                                    if match:
                                        cb.record_success()
                                        return category
                                except RegexTimeoutError as e:
                                    logger.warning(f"Pattern check timed out for '{pattern[:30]}': {e}")
                                    get_validation_metrics().record_timeout()
                                    cb.record_failure(e)
                                    continue
                                except re.error as e:
                                    logger.warning(f"Pattern check failed for '{pattern[:30]}': {e}")
                                    continue
            
            cb.record_success()
            return None
            
        except Exception as e:
            logger.error(f"Blocklist check failed: {e}")
            cb.record_failure(e)
            get_validation_metrics().record_error()
            return None  # Fail open on unexpected errors

    
    def get_blocklist(self, category: str) -> Set[str]:
        """Get all entries in a blocklist category.
        
        Args:
            category: Blocklist category
            
        Returns:
            Set of blocked values
            
        Raises:
            ValueError: If category is invalid
        """
        if category not in self.VALID_CATEGORIES:
            raise ValueError(f"Invalid blocklist category: {category}. Valid: {self.VALID_CATEGORIES}")
        
        with self._lock:
            return self._blocklists.get(category, set()).copy()
    
    def get_all_blocklists(self) -> Dict[str, Set[str]]:
        """Get all blocklists.
        
        Returns:
            Dictionary of all blocklists (thread-safe copies)
        """
        with self._lock:
            return {k: v.copy() for k, v in self._blocklists.items()}
    
    def get_audit_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent audit log entries.
        
        Args:
            limit: Maximum number of entries to return
            
        Returns:
            List of audit log entries
        """
        with self._lock:
            return list(self._audit_log)[-limit:]
    
    def _log_audit_event(
        self,
        action: str,
        category: str,
        value: str,
        reason: str,
        performed_by: str
    ) -> None:
        """Log an audit event with sanitization."""
        # Sanitize all user-provided values to prevent log injection
        self._audit_log.append({
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'action': sanitize_for_log(action, 50),
            'category': sanitize_for_log(category, 50),
            'value': sanitize_for_log(value, 100),
            'reason': sanitize_for_log(reason, 200),
            'performed_by': sanitize_for_log(performed_by, 100),
        })
        # Note: deque with maxlen handles bounding automatically
    
    def _load_from_storage(self) -> None:
        """Load blocklists from storage with file locking."""
        try:
            with open(self.storage_path, 'r') as f:
                # Acquire shared lock for reading
                fcntl.flock(f.fileno(), fcntl.LOCK_SH)
                try:
                    data = json.load(f)
                    for category, values in data.get('blocklists', {}).items():
                        if category in self._blocklists:
                            self._blocklists[category] = set(values)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse blocklist storage: {e}")
        except IOError as e:
            logger.warning(f"Failed to load blocklist from storage: {e}")
    
    def _save_to_storage(self, timeout: float = 5.0) -> None:
        """Save blocklists to storage with non-blocking file locking.
        
        Uses LOCK_NB with retry to prevent deadlocks under heavy load.
        
        Args:
            timeout: Maximum time to wait for lock in seconds
        """
        import time
        
        start_time = time.time()
        retry_delay = 0.1
        
        try:
            self.storage_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.storage_path, 'w') as f:
                # Try to acquire lock with timeout using non-blocking attempts
                while True:
                    try:
                        fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break  # Lock acquired
                    except BlockingIOError:
                        elapsed = time.time() - start_time
                        if elapsed >= timeout:
                            logger.error(f"Failed to acquire lock for blocklist storage after {timeout}s")
                            raise IOError(f"Lock acquisition timeout after {timeout}s")
                        
                        # Exponential backoff with jitter
                        time.sleep(retry_delay + secrets.randbelow(100) / 1000)
                        retry_delay = min(retry_delay * 1.5, 1.0)
                
                try:
                    json.dump({
                        'blocklists': {k: list(v) for k, v in self._blocklists.items()},
                        'updated_at': datetime.now(timezone.utc).isoformat(),
                    }, f, indent=2)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except IOError as e:
            logger.error(f"Failed to save blocklist to storage: {e}")
            raise  # Propagate error - storage failure should not be silent



class TemplateSecurityValidator:
    """Enhanced security validator for threat scenario templates.
    
    This validator implements defense-in-depth with multiple security checks:
    1. Input sanitization and encoding validation
    2. Injection attack detection (YAML, command, code, SQL)
    3. Path traversal and file inclusion prevention
    4. Credential and secret detection
    5. Malicious URL and domain detection
    6. PII exposure detection
    7. Resource abuse prevention
    8. Content policy enforcement
    
    REDesign Features (Issue #129):
    - Enhanced audit logging with structured data
    - Thread-safe caching for performance
    - Proper integration with template manager state
    - Follows established security validation patterns
    
    Usage:
        validator = TemplateSecurityValidator()
        result = validator.validate_template(template_data)
        if not result.is_secure:
            for finding in result.blocking_findings:
                print(f"[{finding.severity}] {finding.title}: {finding.description}")
    """
    
    # ==================== Pattern Definitions ====================
    
    # YAML/Command Injection patterns
    YAML_INJECTION_PATTERNS = [
        # YAML directives and anchors that could be exploited
        (r'!!python/', "Python object deserialization"),
        (r'!!ruby/', "Ruby object deserialization"),
        (r'!!perl/', "Perl object deserialization"),
        (r'!!java/', "Java object deserialization"),
        (r'!!\w+/\w+', "Generic YAML tag injection"),
        (r'<<:\s*\*', "YAML merge key with anchor reference"),
        (r'\*[a-zA-Z_]\w*', "YAML anchor reference"),
        (r'&[a-zA-Z_]\w*', "YAML anchor definition"),
        # YAML multi-document exploits
        (r'^---\s*$', "YAML document separator"),
        (r'^\.\.\.\s*$', "YAML document end marker"),
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        # Shell command injection
        (r'[;&|`$]\s*\w+', "Shell metacharacter sequence"),
        (r'\$\([^)]+\)', "Command substitution $(...)"),
        (r'`[^`]+`', "Backtick command substitution"),
        (r'\|\s*\w+', "Pipe to command"),
        (r'>\s*[/\w]', "Output redirection"),
        (r'<\s*[/\w]', "Input redirection"),
        # Common dangerous commands
        (r'\b(rm|chmod|chown|wget|curl|nc|netcat|bash|sh|python|perl|ruby)\s+-?[a-zA-Z]', 
         "Dangerous command pattern"),
        (r'/bin/sh', "Direct shell reference"),
        (r'/bin/bash', "Direct bash reference"),
    ]
    
    CODE_INJECTION_PATTERNS = [
        # Python code injection
        (r'__import__\s*\(', "Python __import__() call"),
        (r'eval\s*\(', "Python eval() call"),
        (r'exec\s*\(', "Python exec() call"),
        (r'compile\s*\(', "Python compile() call"),
        (r'getattr\s*\([^,]+,\s*[\'"][^\'"]+[\'"]\s*\)', "Python getattr() with string"),
        (r'setattr\s*\(', "Python setattr() call"),
        (r'globals\s*\(\s*\)', "Python globals() access"),
        (r'locals\s*\(\s*\)', "Python locals() access"),
        (r'__builtins__', "Python builtins access"),
        (r'__class__', "Python class dunder access"),
        (r'__mro__', "Python MRO access"),
        (r'__subclasses__', "Python subclasses access"),
        # JavaScript/Node.js patterns
        (r'require\s*\([\'"]', "Node.js require()"),
        (r'process\.env', "Node.js process.env access"),
        (r'child_process', "Node.js child_process"),
        # Template injection
        (r'\{\{\s*.*\s*\}\}', "Template expression {{}}"),
        (r'\{%\s*.*\s*%\}', "Jinja/Template tag"),
        (r'\$\{[^}]+\}', "Template variable ${...}"),
    ]
    
    SQL_INJECTION_PATTERNS = [
        (r"'\s*OR\s+'?1'?\s*=\s*'?1", "SQL OR injection"),
        (r"'\s*;\s*(DROP|DELETE|UPDATE|INSERT)", "SQL statement injection"),
        (r"UNION\s+(ALL\s+)?SELECT", "SQL UNION injection"),
        (r"--\s*$", "SQL comment injection"),
        (r"/\*.*\*/", "SQL block comment"),
    ]
    
    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        (r'\.\./', "Parent directory traversal"),
        (r'\.\.\\', "Windows parent directory traversal"),
        (r'%2e%2e[/\\]', "URL-encoded traversal"),
        (r'%252e%252e', "Double URL-encoded traversal"),
        (r'\.\.%00', "Null byte injection with traversal"),
        (r'/etc/passwd', "Unix password file access"),
        (r'/etc/shadow', "Unix shadow file access"),
        (r'C:\\Windows', "Windows system directory"),
        (r'\\\\[a-zA-Z0-9]+\\', "UNC path"),
        (r'file://', "File protocol URL"),
    ]
    
    # Credential patterns (must be case-insensitive)
    CREDENTIAL_PATTERNS = [
        # API Keys and tokens
        (r'(?:api[_-]?key|apikey)\s*[:=]\s*[\'"]?[\w-]{20,}', "API key exposure"),
        (r'(?:secret[_-]?key|secretkey)\s*[:=]\s*[\'"]?[\w-]{20,}', "Secret key exposure"),
        (r'(?:access[_-]?token|accesstoken)\s*[:=]\s*[\'"]?[\w-]{20,}', "Access token exposure"),
        (r'(?:auth[_-]?token|authtoken)\s*[:=]\s*[\'"]?[\w-]{20,}', "Auth token exposure"),
        (r'bearer\s+[\w-]+\.[\w-]+\.[\w-]+', "JWT Bearer token"),
        # Cloud provider patterns
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*[\w/+=]{40}', "AWS Secret Key"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI API Key"),
        (r'sk-proj-[a-zA-Z0-9]{20,}', "OpenAI Project API Key"),
        (r'sk-ant-api\d{2}-[\w-]{40,}', "Anthropic API Key"),
        (r'AIza[0-9A-Za-z_-]{35}', "Google API Key"),
        (r'ghp_[0-9a-zA-Z]{36}', "GitHub Personal Access Token"),
        (r'gho_[0-9a-zA-Z]{36}', "GitHub OAuth Token"),
        (r'glpat-[\w-]{20}', "GitLab Personal Access Token"),
        # Database connection strings
        (r'(?:postgres|mysql|mongodb)://[^\s]+:[^\s]+@', "Database connection string"),
        (r'(?:redis|amqp)://[^\s]*:[^\s]*@', "Message queue connection string"),
        # Password patterns
        (r'(?:password|passwd|pwd)\s*[:=]\s*[\'"]?[^\s\'"]{8,}', "Hardcoded password"),
        (r'(?:private[_-]?key)\s*[:=]', "Private key reference"),
    ]
    
    # PII patterns
    PII_PATTERNS = [
        # Email addresses (real, not templated)
        (r'[a-zA-Z0-9._%+-]+@(?!example\.|test\.|placeholder\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 
         "Real email address"),
        # Social Security Numbers
        (r'\b\d{3}-\d{2}-\d{4}\b', "SSN format"),
        # Credit card numbers
        (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', 
         "Credit card number"),
        # Phone numbers (US format with area code)
        (r'\b(?:\+1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b', "US phone number"),
        # IP addresses (private ranges are OK)
        (r'\b(?!10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)'
         r'(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', "Public IP address"),
    ]
    
    # Malicious URL patterns
    MALICIOUS_URL_PATTERNS = [
        # Known malicious TLDs
        (r'https?://[^\s]+\.(?:xyz|top|click|gq|ml|ga|cf|tk|work|date|racing)(?:/|$)', 
         "Suspicious TLD"),
        # URL shorteners (can hide malicious URLs)
        (r'https?://(?:bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|j\.mp)', 
         "URL shortener"),
        # Data URLs with scripts
        (r'data:text/html', "Data URL with HTML"),
        (r'javascript:', "JavaScript URL"),
        (r'vbscript:', "VBScript URL"),
        # Suspicious URL patterns
        (r'https?://[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', "IP-based URL"),
        (r'@[^\s/]+\.[a-z]+/', "URL with embedded credentials"),
        # Phishing indicators
        (r'login.*\.(?!example\.|test\.)[a-z]+\.[a-z]+', "Potential phishing domain"),
        (r'secure.*bank', "Potential phishing keyword"),
        (r'verify.*account', "Potential phishing keyword"),
    ]
    
    # Resource abuse patterns
    RESOURCE_ABUSE_PATTERNS = [
        # Extremely long strings
        (r'.{10000,}', "Excessively long string (potential DoS)"),
        # Nested structures (potential YAML bomb)
        (r'(\w+:\s*\n\s+){20,}', "Deeply nested structure"),
        # Large numeric values
        (r'\b\d{15,}\b', "Extremely large number"),
        # Repeated patterns (potential ReDoS)
        (r'(.+)\1{100,}', "Excessive repetition"),
    ]
    
    # Content policy violations
    CONTENT_POLICY_PATTERNS = [
        # Actual malicious payloads (not simulated)
        (r'<script[^>]*>.*</script>', "Embedded script tag"),
        (r'<iframe[^>]*>', "Embedded iframe"),
        (r'on\w+\s*=\s*[\'"]', "Event handler attribute"),
        # Potentially harmful content indicators
        (r'\b(ransomware|malware)\s+(?:download|execute|deploy)', 
         "Actual malware reference"),
        (r'\b(exploit|vulnerability)\s+(?:code|payload)', "Exploit code reference"),
    ]
    
    # Encoding attack patterns
    ENCODING_ATTACK_PATTERNS = [
        # Unicode attacks
        (r'[\x00-\x08\x0b\x0c\x0e-\x1f]', "Control character"),
        (r'\\u0000', "Null character escape"),
        (r'%00', "URL-encoded null"),
        # UTF-7 attacks
        (r'\+ADw-', "UTF-7 encoded <"),
        (r'\+AD4-', "UTF-7 encoded >"),
        # Overlong UTF-8
        (r'%c0%ae', "Overlong UTF-8 dot"),
    ]
    
    # Allowed domains for URLs in templates
    ALLOWED_URL_DOMAINS = {
        'attack.mitre.org',
        'cve.mitre.org',
        'd3fend.mitre.org',
        'nvd.nist.gov',
        'cwe.mitre.org',
        'owasp.org',
        'sans.org',
        'nist.gov',
        'github.com',
        'docs.microsoft.com',
        'learn.microsoft.com',
        'cloud.google.com',
        'docs.aws.amazon.com',
        'wikipedia.org',
        'example.com',
        'example.org',
        'example.net',
        'test.com',
        'localhost',
    }
    
    # Fields that should never contain executable content
    RESTRICTED_FIELDS = {
        'metadata.name',
        'metadata.author',
        'metadata.version',
        'target_profile.role',
        'target_profile.department',
        'target_profile.company_name',
        'simulation_parameters.language',
        'simulation_parameters.tone',
    }
    
    # Maximum allowed values for numeric fields
    MAX_VALUES = {
        'simulation_parameters.max_iterations': 10,
        'simulation_parameters.max_duration_minutes': 480,
        'simulation_parameters.urgency_level': 10,
        'difficulty_level': 10,
        'estimated_duration': 480,
        'target_profile.security_awareness_level': 10,
    }
    
    # String length limits
    MAX_STRING_LENGTHS = {
        'metadata.name': 200,
        'metadata.description': 2000,
        'metadata.author': 100,
        'target_profile.role': 100,
        'target_profile.department': 100,
        'default': 5000,
    }
    
    def __init__(
        self,
        strict_mode: bool = True,
        allow_url_shorteners: bool = False,
        allow_ip_urls: bool = False,
        custom_allowed_domains: Optional[Set[str]] = None,
        enable_pii_detection: bool = True,
        enable_credential_detection: bool = True,
        blocklist_manager: Optional[BlocklistManager] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        enable_caching: bool = True,
        cache_ttl_seconds: int = 300,
        max_cache_size: int = 100,
    ):
        """Initialize the enhanced security validator.
        
        Args:
            strict_mode: If True, treat warnings as errors
            allow_url_shorteners: Allow URL shortener links
            allow_ip_urls: Allow IP-based URLs
            custom_allowed_domains: Additional allowed domains for URLs
            enable_pii_detection: Enable PII detection checks
            enable_credential_detection: Enable credential/secret detection
            blocklist_manager: Optional blocklist manager for prohibited content
            audit_logger: Optional audit logger for validation events
            enable_caching: Enable validation result caching
            cache_ttl_seconds: Cache time-to-live in seconds
            max_cache_size: Maximum number of cached results
        """
        self.strict_mode = strict_mode
        self.allow_url_shorteners = allow_url_shorteners
        self.allow_ip_urls = allow_ip_urls
        self.enable_pii_detection = enable_pii_detection
        self.enable_credential_detection = enable_credential_detection
        self.blocklist_manager = blocklist_manager or BlocklistManager()
        
        # Initialize enhanced audit logging
        self.audit_logger = audit_logger or SecurityAuditLogger()
        
        # Initialize caching system
        self.enable_caching = enable_caching
        self.cache = ValidationCache(max_size=max_cache_size, ttl_seconds=cache_ttl_seconds) if enable_caching else None
        
        # Merge custom allowed domains
        self.allowed_domains = self.ALLOWED_URL_DOMAINS.copy()
        if custom_allowed_domains:
            self.allowed_domains.update(custom_allowed_domains)
        
        # Compile all patterns for performance
        self._compile_patterns()
    
    def _extract_template_name(self, template_data: Union[Dict[str, Any], str, Path]) -> str:
        """Extract template name from template data."""
        if isinstance(template_data, Path):
            return template_data.name
        elif isinstance(template_data, str):
            # Try to extract name from YAML content
            try:
                parsed = yaml.safe_load(template_data)
                return parsed.get('metadata', {}).get('name', 'unnamed')
            except:
                return 'unnamed'
        elif isinstance(template_data, dict):
            return template_data.get('metadata', {}).get('name', 'unnamed')
        else:
            return 'unnamed'
    
    def _compile_patterns(self) -> None:
        """Compile regex patterns for better performance."""
        self._compiled_patterns: Dict[str, List[Tuple[re.Pattern, str]]] = {}
        
        pattern_groups = [
            ('yaml_injection', self.YAML_INJECTION_PATTERNS),
            ('command_injection', self.COMMAND_INJECTION_PATTERNS),
            ('code_injection', self.CODE_INJECTION_PATTERNS),
            ('sql_injection', self.SQL_INJECTION_PATTERNS),
            ('path_traversal', self.PATH_TRAVERSAL_PATTERNS),
            ('credential', self.CREDENTIAL_PATTERNS),
            ('pii', self.PII_PATTERNS),
            ('malicious_url', self.MALICIOUS_URL_PATTERNS),
            ('resource_abuse', self.RESOURCE_ABUSE_PATTERNS),
            ('content_policy', self.CONTENT_POLICY_PATTERNS),
            ('encoding_attack', self.ENCODING_ATTACK_PATTERNS),
        ]
        
        for group_name, patterns in pattern_groups:
            compiled = []
            for pattern, description in patterns:
                try:
                    flags = re.IGNORECASE if group_name in ('credential', 'sql_injection') else 0
                    compiled.append((re.compile(pattern, flags), description))
                except re.error as e:
                    # Log compilation error but continue
                    logger.warning(f"Failed to compile pattern '{pattern}': {e}")
            self._compiled_patterns[group_name] = compiled
    
    def validate_template(
        self,
        template_data: Union[Dict[str, Any], str, Path],
        user_context: Optional[Dict[str, str]] = None,
    ) -> SecurityValidationResult:
        """Validate a template for security issues with enhanced features.
        
        Integrates with caching, audit logging, and proper state management.
        
        Args:
            template_data: Template as dict, YAML string, or file path
            user_context: Optional user context for audit logging (user, role, etc.)
            
        Returns:
            SecurityValidationResult with all findings and metadata
        """
        import time
        
        # Extract user context for audit logging
        user = user_context.get('user', 'system') if user_context else 'system'
        role = user_context.get('role', 'unknown') if user_context else 'unknown'
        
        # Check cache first if enabled
        template_hash = self._calculate_hash(template_data)
        template_name = self._extract_template_name(template_data)
        
        if self.enable_caching and self.cache:
            cached_result = self.cache.get(template_hash)
            if cached_result:
                # Log cache hit
                self.audit_logger.log_validation_attempt(
                    template_hash=template_hash,
                    template_name=template_name,
                    validator_name="TemplateSecurityValidator",
                    findings_count=len(cached_result.findings),
                    duration_ms=0,  # Cache hit = 0ms
                    success=cached_result.is_secure
                )
                return cached_result
        
        start_time_perf = time.perf_counter()
        start_time = datetime.now(timezone.utc)
        findings: List[SecurityFinding] = []
        
        try:
            # Parse template if needed
            if isinstance(template_data, (str, Path)):
                template_data, parse_findings = self._parse_template(template_data)
                findings.extend(parse_findings)
                if template_data is None:
                    # Parsing failed completely
                    result = self._create_result(
                        findings=findings,
                        template_hash="PARSE_FAILED",
                        start_time=start_time,
                    )
                    self.audit_logger.log_validation_attempt(
                        template_hash=template_hash,
                        template_name=template_name,
                        validator_name="TemplateSecurityValidator",
                        findings_count=len(findings),
                        duration_ms=0,
                        success=False,
                    )
                    return result
            
            # Calculate template hash for tracking
            template_hash = self._calculate_hash(template_data)
            
            # Run all security checks
            findings.extend(self._check_injection_attacks(template_data))
            findings.extend(self._check_path_traversal(template_data))
            
            if self.enable_credential_detection:
                findings.extend(self._check_credential_exposure(template_data))
            
            findings.extend(self._check_malicious_urls(template_data))
            
            if self.enable_pii_detection:
                findings.extend(self._check_pii_exposure(template_data))
            
            findings.extend(self._check_resource_abuse(template_data))
            findings.extend(self._check_encoding_attacks(template_data))
            findings.extend(self._check_content_policy(template_data))
            findings.extend(self._check_schema_security(template_data))
            
            # Check against blocklists
            findings.extend(self._check_blocklist(template_data))
            
            # Create result
            result = self._create_result(
                findings=findings,
                template_hash=template_hash,
                start_time=start_time,
            )
            
            # Cache result if enabled
            if self.enable_caching and self.cache:
                self.cache.put(template_hash, result)
            
            # Log validation attempt
            duration_ms = (time.perf_counter() - start_time_perf) * 1000
            self.audit_logger.log_validation_attempt(
                template_hash=template_hash,
                template_name=template_name,
                validator_name="TemplateSecurityValidator",
                findings_count=len(findings),
                duration_ms=duration_ms,
                success=result.is_secure,
            )
            
            # Log individual findings if any
            for finding in findings:
                if finding.severity in [SecuritySeverity.CRITICAL, SecuritySeverity.HIGH]:
                    self.audit_logger.log_security_finding(
                        template_hash=template_hash,
                        template_name=template_name,
                        finding=finding,
                    )
            
            return result
            
        except Exception as e:
            # Log unexpected errors
            duration_ms = (time.perf_counter() - start_time_perf) * 1000
            get_validation_metrics().record_validation(
                success=False, duration_ms=duration_ms, findings=findings
            )
            findings.append(SecurityFinding(
                severity=SecuritySeverity.HIGH,
                category=SecurityCategory.RESOURCE_ABUSE,
                title="Validation Error",
                description=f"Unexpected error during validation: {type(e).__name__}",
                location="system",
            ))
            return self._create_result(
                findings=findings,
                template_hash="ERROR",
                start_time=start_time,
            )

    
    def validate_template_file(self, file_path: Path) -> SecurityValidationResult:
        """Validate a template file for security issues.
        
        Args:
            file_path: Path to the template file
            
        Returns:
            SecurityValidationResult with all findings
        """
        return self.validate_template(file_path)
    
    def _parse_template(
        self, 
        template_source: Union[str, Path]
    ) -> Tuple[Optional[Dict[str, Any]], List[SecurityFinding]]:
        """Safely parse a template from string or file.
        
        Args:
            template_source: YAML string or file path
            
        Returns:
            Tuple of (parsed dict or None, list of findings)
        """
        findings: List[SecurityFinding] = []
        
        try:
            if isinstance(template_source, Path):
                if not template_source.exists():
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.SCHEMA_VIOLATION,
                        title="Template file not found",
                        description=f"The specified template file does not exist: {template_source}",
                        location="file_path",
                        value_preview=str(template_source),
                        remediation="Verify the file path is correct and the file exists",
                    ))
                    return None, findings
                
                # Check file size before reading
                file_size = template_source.stat().st_size
                if file_size > MAX_TEMPLATE_SIZE_BYTES:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="Template file too large",
                        description=f"Template file exceeds maximum size limit: {file_size:,} bytes (limit: {MAX_TEMPLATE_SIZE_BYTES:,})",
                        location="file_path",
                        value_preview=str(template_source),
                        remediation=f"Reduce template file size to under {MAX_TEMPLATE_SIZE_BYTES // 1_000_000}MB",
                        cwe_id="CWE-400",
                    ))
                    return None, findings
                
                with open(template_source, 'r', encoding='utf-8') as f:
                    yaml_content = f.read()
            else:
                yaml_content = template_source
                # Check string template size
                if len(yaml_content) > MAX_TEMPLATE_STRING_SIZE:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="Template string too large",
                        description=f"Template string exceeds maximum size limit: {len(yaml_content):,} chars (limit: {MAX_TEMPLATE_STRING_SIZE:,})",
                        location="input",
                        value_preview=yaml_content[:100] + "...",
                        remediation=f"Reduce template size to under {MAX_TEMPLATE_STRING_SIZE // 1000}KB",
                        cwe_id="CWE-400",
                    ))
                    return None, findings

            
            # Use safe_load to prevent arbitrary code execution
            template_data = yaml.safe_load(yaml_content)
            
            if template_data is None:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.MEDIUM,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Empty template",
                    description="Template parsed to empty/null content",
                    location="root",
                    value_preview="null",
                    remediation="Provide valid template content",
                ))
                return {}, findings
            
            if not isinstance(template_data, dict):
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.HIGH,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Invalid template structure",
                    description=f"Template root must be a dictionary, got {type(template_data).__name__}",
                    location="root",
                    value_preview=str(type(template_data)),
                    remediation="Ensure template root is a YAML mapping/dictionary",
                ))
                return None, findings
            
            return template_data, findings
            
        except yaml.YAMLError as e:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.HIGH,
                category=SecurityCategory.YAML_SECURITY,
                title="YAML parsing error",
                description=f"Failed to parse YAML: {str(e)[:200]}",
                location="root",
                value_preview=str(e)[:100],
                remediation="Fix YAML syntax errors",
                cwe_id="CWE-20",
            ))
            return None, findings
        except Exception as e:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.HIGH,
                category=SecurityCategory.SCHEMA_VIOLATION,
                title="Template parsing error",
                description=f"Unexpected error parsing template: {str(e)[:200]}",
                location="root",
                value_preview=str(e)[:100],
                remediation="Review template format and content",
            ))
            return None, findings
    
    def _calculate_hash(self, template_data: Dict[str, Any]) -> str:
        """Calculate SHA-256 hash of template content.
        
        Uses 32 hex chars (128 bits) for better collision resistance.
        """
        content = yaml.dump(template_data, default_flow_style=False, sort_keys=True)
        return hashlib.sha256(content.encode('utf-8')).hexdigest()[:32]
    
    def _create_result(
        self,
        findings: List[SecurityFinding],
        template_hash: str,
        start_time: datetime,
        source: str = "api",
        user_id: Optional[str] = None,
    ) -> SecurityValidationResult:
        """Create a SecurityValidationResult from findings."""
        end_time = datetime.now(timezone.utc)
        duration_ms = (end_time - start_time).total_seconds() * 1000
        
        # Determine if template is secure
        blocking_severities = {SecuritySeverity.CRITICAL, SecuritySeverity.HIGH}
        if self.strict_mode:
            blocking_severities.add(SecuritySeverity.MEDIUM)
        
        is_secure = not any(
            f.severity in blocking_severities for f in findings
        )
        
        validation_id = secrets.token_hex(8)
        
        result = SecurityValidationResult(
            is_secure=is_secure,
            findings=findings,
            validated_at=start_time,
            validation_duration_ms=int(duration_ms),
            template_hash=template_hash,
            validation_id=validation_id,
        )
        
        # Audit logging
        if self.audit_logger:
            self.audit_logger.log_validation(
                template_hash=template_hash,
                validation_id=validation_id,
                result=result,
                source=source,
                user_id=user_id
            )
            
            # Log individual findings for critical/high severity
            for finding in findings:
                if finding.severity in (SecuritySeverity.CRITICAL, SecuritySeverity.HIGH):
                    self.audit_logger.log_security_finding(
                        template_hash=template_hash,
                        template_name="unknown",
                        finding=finding
                    )
        
        return result
    
    def _check_value_against_patterns(
        self,
        value: str,
        patterns: List[Tuple[re.Pattern, str]],
        location: str,
        category: SecurityCategory,
        severity: SecuritySeverity,
        cwe_id: Optional[str] = None,
        mitre_technique: Optional[str] = None,
    ) -> List[SecurityFinding]:
        """Check a value against a list of patterns.
        
        Applies NFKC normalization to prevent Unicode bypass attacks.
        """
        findings: List[SecurityFinding] = []
        
        # Normalize value to prevent Unicode bypass attacks
        normalized_value = unicodedata.normalize('NFKC', value)
        
        for pattern, description in patterns:
            # Check both original and normalized values
            if pattern.search(value) or pattern.search(normalized_value):
                # Truncate and sanitize the value preview
                preview = sanitize_for_log(value, 100)
                
                findings.append(SecurityFinding(
                    severity=severity,
                    category=category,
                    title=f"Potential {description}",
                    description=f"Detected pattern indicating {description} at '{location}'",
                    location=location,
                    value_preview=preview,
                    remediation=self._get_remediation(category),
                    cwe_id=cwe_id,
                    mitre_technique=mitre_technique,
                ))
        
        return findings
    
    def _get_remediation(self, category: SecurityCategory) -> str:
        """Get remediation advice for a security category."""
        remediations = {
            SecurityCategory.INJECTION: "Remove or escape special characters that could be interpreted as code or commands",
            SecurityCategory.PATH_TRAVERSAL: "Use absolute paths or validate path components; remove '..' sequences",
            SecurityCategory.CREDENTIAL_EXPOSURE: "Remove hardcoded credentials; use environment variables or secret management",
            SecurityCategory.MALICIOUS_URL: "Verify URL legitimacy; use only known-good domains from the allowlist",
            SecurityCategory.PII_EXPOSURE: "Remove or anonymize personally identifiable information",
            SecurityCategory.RESOURCE_ABUSE: "Reduce resource consumption; limit string lengths and nesting depth",
            SecurityCategory.YAML_SECURITY: "Use safe YAML features; avoid custom tags and anchors",
            SecurityCategory.CONTENT_POLICY: "Remove content that violates security policies",
            SecurityCategory.ENCODING_ATTACK: "Use standard UTF-8 encoding; remove control characters",
            SecurityCategory.SCHEMA_VIOLATION: "Ensure template conforms to the expected schema",
        }
        return remediations.get(category, "Review and fix the security issue")
    
    def _traverse_dict(
        self,
        data: Dict[str, Any],
        path: str = "",
    ) -> List[Tuple[str, Any]]:
        """Recursively traverse a dictionary and yield (path, value) tuples."""
        items: List[Tuple[str, Any]] = []
        
        for key, value in data.items():
            current_path = f"{path}.{key}" if path else key
            
            if isinstance(value, dict):
                items.extend(self._traverse_dict(value, current_path))
            elif isinstance(value, list):
                for i, item in enumerate(value):
                    item_path = f"{current_path}[{i}]"
                    if isinstance(item, dict):
                        items.extend(self._traverse_dict(item, item_path))
                    else:
                        items.append((item_path, item))
            else:
                items.append((current_path, value))
        
        return items
    
    def _check_injection_attacks(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for various injection attack patterns."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # YAML injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['yaml_injection'],
                location=location,
                category=SecurityCategory.YAML_SECURITY,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-502",  # Deserialization of Untrusted Data
                mitre_technique="T1059",  # Command and Scripting Interpreter
            ))
            
            # Command injection (higher severity for certain fields)
            severity = SecuritySeverity.CRITICAL if location in self.RESTRICTED_FIELDS else SecuritySeverity.HIGH
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['command_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=severity,
                cwe_id="CWE-78",  # OS Command Injection
                mitre_technique="T1059",
            ))
            
            # Code injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['code_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=SecuritySeverity.CRITICAL,
                cwe_id="CWE-94",  # Improper Control of Generation of Code
                mitre_technique="T1059",
            ))
            
            # SQL injection
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['sql_injection'],
                location=location,
                category=SecurityCategory.INJECTION,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-89",  # SQL Injection
            ))
        
        return findings
    
    def _check_path_traversal(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for path traversal attempts."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['path_traversal'],
                location=location,
                category=SecurityCategory.PATH_TRAVERSAL,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-22",  # Path Traversal
                mitre_technique="T1083",  # File and Directory Discovery
            ))
        
        return findings
    
    def _check_credential_exposure(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for exposed credentials and secrets.
        
        Security Hardening (Review Fixes):
        - Base64 decoding to detect obfuscated credentials
        - Unicode normalization for pattern matching
        """
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # Check original value
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['credential'],
                location=location,
                category=SecurityCategory.CREDENTIAL_EXPOSURE,
                severity=SecuritySeverity.CRITICAL,
                cwe_id="CWE-798",  # Use of Hard-coded Credentials
                mitre_technique="T1552",  # Unsecured Credentials
            ))
            
            # Also check base64-decoded version to detect obfuscated credentials
            decoded_value, was_decoded = decode_if_base64(value)
            if was_decoded:
                decoded_findings = self._check_value_against_patterns(
                    value=decoded_value,
                    patterns=self._compiled_patterns['credential'],
                    location=f"{location} (base64 decoded)",
                    category=SecurityCategory.CREDENTIAL_EXPOSURE,
                    severity=SecuritySeverity.CRITICAL,
                    cwe_id="CWE-798",
                    mitre_technique="T1552",
                )
                findings.extend(decoded_findings)
        
        return findings
    
    def _check_malicious_urls(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for potentially malicious URLs.
        
        Security Hardening (Review Fixes):
        - URL decoding before validation to prevent bypass
        - Comprehensive data URI validation
        - Unicode normalization for domain checks
        - Pre-compiled regex patterns for performance
        """
        findings: List[SecurityFinding] = []
        
        # Use pre-compiled patterns for performance
        url_pattern = _COMPILED_PATTERNS['url_http']
        data_uri_pattern = _COMPILED_PATTERNS['data_uri']
        
        # Dangerous protocol patterns (pre-compiled)
        dangerous_protocols = [
            (_COMPILED_PATTERNS['javascript_proto'], "JavaScript URL protocol"),
            (_COMPILED_PATTERNS['vbscript_proto'], "VBScript URL protocol"),
        ]
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # Check for dangerous protocols first (use pre-compiled patterns)
            for compiled_pattern, description in dangerous_protocols:
                if compiled_pattern.search(value):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.MALICIOUS_URL,
                        title=f"Dangerous URL protocol: {description}",
                        description=f"Detected {description} which can be used for XSS attacks",
                        location=location,
                        value_preview=sanitize_for_log(value, 100),
                        remediation="Remove dangerous URL protocols; use only https:// URLs",
                        cwe_id="CWE-79",  # Cross-site Scripting (XSS)
                        mitre_technique="T1059.007",  # JavaScript

                    ))
            
            # Check data URIs for safety
            data_uris = data_uri_pattern.findall(value)
            for data_uri in data_uris:
                if not is_safe_data_uri(data_uri):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="Potentially dangerous data URI",
                        description="Data URI may contain executable content or unsafe MIME type",
                        location=location,
                        value_preview=sanitize_for_log(data_uri, 100),
                        remediation="Only use data URIs with safe image MIME types (png, jpeg, gif, webp)",
                        cwe_id="CWE-79",
                        mitre_technique="T1059.007",
                    ))
            
            # URL decode before checking to prevent bypass
            decoded_value = unquote(value)
            
            # Find all HTTP/HTTPS URLs in the value (check both original and decoded)
            urls = set(url_pattern.findall(value))
            urls.update(url_pattern.findall(decoded_value))
            
            for url in urls:
                url_findings = self._validate_url(url, location)
                findings.extend(url_findings)
            
            # Check against malicious URL patterns
            if not self.allow_url_shorteners:
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=[p for p in self._compiled_patterns['malicious_url'] 
                              if 'shortener' in p[1].lower()],
                    location=location,
                    category=SecurityCategory.MALICIOUS_URL,
                    severity=SecuritySeverity.MEDIUM,
                    cwe_id="CWE-601",  # URL Redirection
                ))
            
            if not self.allow_ip_urls:
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=[p for p in self._compiled_patterns['malicious_url'] 
                              if 'IP-based' in p[1]],
                    location=location,
                    category=SecurityCategory.MALICIOUS_URL,
                    severity=SecuritySeverity.MEDIUM,
                ))
        
        return findings
    
    def _validate_url(self, url: str, location: str) -> List[SecurityFinding]:
        """Validate a specific URL for security issues.
        
        Security Hardening (Review Fixes):
        - URL decoding before domain extraction
        - Unicode normalization for domain comparison
        - Proper exception handling with logging
        """
        findings: List[SecurityFinding] = []
        
        try:
            # URL decode before parsing to prevent bypass
            decoded_url = unquote(url)
            parsed = urlparse(decoded_url)
            
            # Check domain against allowlist
            domain = parsed.netloc.lower().strip()
            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Apply Unicode normalization to prevent confusable character bypass
            normalized_domain = normalize_for_security(domain)
            
            # Check if domain is in allowlist (including subdomains)
            domain_allowed = False
            for allowed in self.allowed_domains:
                allowed_normalized = normalize_for_security(allowed)
                if normalized_domain == allowed_normalized or normalized_domain.endswith(f'.{allowed_normalized}'):
                    domain_allowed = True
                    break
            
            if not domain_allowed and normalized_domain and not normalized_domain.startswith('localhost'):
                # Check if it's a suspicious TLD
                suspicious_tlds = {'.xyz', '.top', '.click', '.gq', '.ml', '.ga', '.cf', '.tk'}
                has_suspicious_tld = any(normalized_domain.endswith(tld) for tld in suspicious_tlds)
                
                if has_suspicious_tld:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="URL with suspicious TLD",
                        description=f"URL uses a TLD commonly associated with malicious sites",
                        location=location,
                        value_preview=sanitize_for_log(url, 100),
                        remediation="Use domains from the allowed list or known legitimate sources",
                        cwe_id="CWE-601",
                    ))
                elif not self._is_known_legitimate_domain(normalized_domain):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.LOW,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="URL domain not in allowlist",
                        description=f"URL domain '{domain}' is not in the approved allowlist",
                        location=location,
                        value_preview=sanitize_for_log(url, 100),
                        remediation="Add domain to allowlist if legitimate, or use approved domains",
                    ))
            
            # Check for IP-based URLs
            if not self.allow_ip_urls:
                try:
                    ipaddress.ip_address(domain)
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.MALICIOUS_URL,
                        title="IP-based URL",
                        description="URLs should use domain names, not IP addresses",
                        location=location,
                        value_preview=sanitize_for_log(url, 100),
                        remediation="Use a domain name instead of an IP address",
                    ))
                except ValueError:
                    pass  # Not an IP address
            
            # Check for credential in URL
            if '@' in parsed.netloc:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.HIGH,
                    category=SecurityCategory.CREDENTIAL_EXPOSURE,
                    title="Credentials in URL",
                    description="URL contains embedded credentials",
                    location=location,
                    value_preview=sanitize_for_log(url[:50], 50),
                    remediation="Remove credentials from URL; use proper authentication",
                    cwe_id="CWE-522",
                ))
                
        except (ValueError, AttributeError, TypeError) as e:
            # Log parsing errors for debugging but don't expose to user
            logger.debug(f"URL parsing failed for '{url[:50]}': {e}")
        
        return findings
    
    def _is_known_legitimate_domain(self, domain: str) -> bool:
        """Check if domain is a known legitimate domain."""
        legitimate_patterns = [
            r'\.gov$',
            r'\.edu$',
            r'\.mil$',
            r'microsoft\.com$',
            r'google\.com$',
            r'amazon\.com$',
            r'cloudflare\.com$',
        ]
        return any(re.search(p, domain) for p in legitimate_patterns)
    
    def _check_pii_exposure(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for exposed personally identifiable information."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['pii'],
                location=location,
                category=SecurityCategory.PII_EXPOSURE,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-359",  # Exposure of Private Personal Information
            ))
        
        return findings
    
    def _check_resource_abuse(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for resource abuse patterns."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            # Check string lengths
            if isinstance(value, str):
                max_length = self.MAX_STRING_LENGTHS.get(
                    location, 
                    self.MAX_STRING_LENGTHS['default']
                )
                if len(value) > max_length:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="String exceeds maximum length",
                        description=f"String at '{location}' is {len(value):,} characters (max: {max_length:,})",
                        location=location,
                        value_preview=value[:50] + "...",
                        remediation=f"Reduce string length to under {max_length:,} characters",
                        cwe_id="CWE-400",  # Uncontrolled Resource Consumption
                    ))
                
                # Check for resource abuse patterns
                findings.extend(self._check_value_against_patterns(
                    value=value,
                    patterns=self._compiled_patterns['resource_abuse'],
                    location=location,
                    category=SecurityCategory.RESOURCE_ABUSE,
                    severity=SecuritySeverity.MEDIUM,
                    cwe_id="CWE-400",
                ))
            
            # Check numeric values
            elif isinstance(value, (int, float)):
                max_value = self.MAX_VALUES.get(location)
                if max_value is not None and value > max_value:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.MEDIUM,
                        category=SecurityCategory.RESOURCE_ABUSE,
                        title="Numeric value exceeds maximum",
                        description=f"Value {value} at '{location}' exceeds maximum {max_value}",
                        location=location,
                        value_preview=str(value),
                        remediation=f"Reduce value to {max_value} or less",
                        cwe_id="CWE-400",
                    ))
        
        # Check nesting depth
        depth = self._get_max_depth(template_data)
        if depth > 15:
            findings.append(SecurityFinding(
                severity=SecuritySeverity.MEDIUM,
                category=SecurityCategory.RESOURCE_ABUSE,
                title="Excessive nesting depth",
                description=f"Template has nesting depth of {depth} (max recommended: 15)",
                location="root",
                value_preview=f"depth={depth}",
                remediation="Reduce nesting depth to prevent stack overflow",
                cwe_id="CWE-674",  # Uncontrolled Recursion
            ))
        
        return findings
    
    def _get_max_depth(self, data: Any, current_depth: int = 0) -> int:
        """Calculate maximum nesting depth of a data structure."""
        if current_depth > 50:  # Safety limit
            return current_depth
        
        if isinstance(data, dict):
            if not data:
                return current_depth
            return max(self._get_max_depth(v, current_depth + 1) for v in data.values())
        elif isinstance(data, list):
            if not data:
                return current_depth
            return max(self._get_max_depth(item, current_depth + 1) for item in data)
        else:
            return current_depth
    
    def _check_encoding_attacks(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for encoding-based attacks."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['encoding_attack'],
                location=location,
                category=SecurityCategory.ENCODING_ATTACK,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-838",  # Inappropriate Encoding for Output Context
            ))
        
        return findings
    
    def _check_content_policy(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for content policy violations."""
        findings: List[SecurityFinding] = []
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            findings.extend(self._check_value_against_patterns(
                value=value,
                patterns=self._compiled_patterns['content_policy'],
                location=location,
                category=SecurityCategory.CONTENT_POLICY,
                severity=SecuritySeverity.HIGH,
                cwe_id="CWE-79",  # XSS
            ))
        
        return findings
    
    def _check_schema_security(
        self, 
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check for schema-related security issues."""
        findings: List[SecurityFinding] = []
        
        # Check for unexpected top-level keys
        expected_keys = {
            'metadata', 'threat_type', 'delivery_vector', 'target_profile',
            'behavioral_pattern', 'difficulty_level', 'estimated_duration',
            'simulation_parameters', 'custom_parameters'
        }
        
        for key in template_data.keys():
            if key not in expected_keys:
                findings.append(SecurityFinding(
                    severity=SecuritySeverity.LOW,
                    category=SecurityCategory.SCHEMA_VIOLATION,
                    title="Unexpected top-level key",
                    description=f"Key '{key}' is not part of the expected schema",
                    location=key,
                    value_preview=str(key),
                    remediation="Remove unexpected keys or move to custom_parameters",
                ))
        
        # Check custom_parameters for suspicious keys
        custom_params = template_data.get('custom_parameters', {})
        if isinstance(custom_params, dict):
            suspicious_keys = {'__', 'eval', 'exec', 'import', 'system', 'shell', 'cmd'}
            for key in custom_params.keys():
                key_lower = key.lower()
                if any(sus in key_lower for sus in suspicious_keys):
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.HIGH,
                        category=SecurityCategory.INJECTION,
                        title="Suspicious custom parameter key",
                        description=f"Custom parameter key '{key}' contains suspicious pattern",
                        location=f"custom_parameters.{key}",
                        value_preview=key,
                        remediation="Rename the key to not include suspicious patterns",
                        cwe_id="CWE-94",
                    ))
        
        return findings
    
    def _check_blocklist(
        self,
        template_data: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """Check template content against blocklists.
        
        Checks all string values against:
        - Blocked domains
        - Blocked keywords
        - Blocked patterns
        - Blocked emails
        - Blocked IPs
        
        Security Hardening (Review Fixes):
        - URL decoding before domain extraction
        - Unicode normalization for matching
        - Proper exception handling with logging
        
        Author: Olabisi Olajide (bayulus)
        Issue: #106 - Implement Template Security Validation
        """
        findings: List[SecurityFinding] = []
        
        if not self.blocklist_manager:
            return findings
        
        for location, value in self._traverse_dict(template_data):
            if not isinstance(value, str):
                continue
            
            # Check against all blocklists (already handles normalization internally)
            try:
                blocked_category = self.blocklist_manager.check_all_blocklists(value)
                
                if blocked_category:
                    findings.append(SecurityFinding(
                        severity=SecuritySeverity.CRITICAL,
                        category=SecurityCategory.CONTENT_POLICY,
                        title=f"Blocklisted content detected ({blocked_category})",
                        description=f"Value matches entry in {blocked_category} blocklist",
                        location=location,
                        value_preview=sanitize_for_log(value, 50),
                        remediation=f"Remove or replace blocklisted {blocked_category} content",
                        cwe_id="CWE-1188",  # Initialization with Hard-Coded Network Resource Configuration
                    ))
                    continue
            except (ValueError, RegexTimeoutError) as e:
                logger.warning(f"Blocklist check failed for location '{location}': {e}")
            
            # Extract and check URLs (with URL decoding)
            url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            decoded_value = unquote(value)
            urls = set(url_pattern.findall(value))
            urls.update(url_pattern.findall(decoded_value))
            
            for url in urls:
                try:
                    decoded_url = unquote(url)
                    parsed = urlparse(decoded_url)
                    domain = normalize_for_security(parsed.netloc)
                    
                    # Check if domain is blocklisted
                    if self.blocklist_manager.is_blocked('domains', domain):
                        findings.append(SecurityFinding(
                            severity=SecuritySeverity.CRITICAL,
                            category=SecurityCategory.MALICIOUS_URL,
                            title="Blocklisted domain detected",
                            description=f"URL contains blocklisted domain",
                            location=location,
                            value_preview=sanitize_for_log(url, 50),
                            remediation="Remove or replace URL with blocklisted domain",
                            cwe_id="CWE-601",
                        ))
                except (ValueError, TypeError) as e:
                    logger.debug(f"URL parsing in blocklist check failed: {e}")
            
            # Extract and check email addresses
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            emails = email_pattern.findall(value)
            
            for email in emails:
                try:
                    if self.blocklist_manager.is_blocked('emails', email):
                        findings.append(SecurityFinding(
                            severity=SecuritySeverity.HIGH,
                            category=SecurityCategory.CONTENT_POLICY,
                            title="Blocklisted email detected",
                            description=f"Email address is blocklisted",
                            location=location,
                            value_preview=sanitize_for_log(email, 50),
                            remediation="Remove or replace blocklisted email address",
                            cwe_id="CWE-359",
                        ))
                except ValueError as e:
                    logger.debug(f"Email blocklist check failed: {e}")
            
            # Extract and check IP addresses
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            ips = ip_pattern.findall(value)
            
            for ip in ips:
                try:
                    if self.blocklist_manager.is_blocked('ips', ip):
                        findings.append(SecurityFinding(
                            severity=SecuritySeverity.HIGH,
                            category=SecurityCategory.MALICIOUS_URL,
                            title="Blocklisted IP address detected",
                            description=f"IP address is blocklisted",
                            location=location,
                            value_preview=sanitize_for_log(ip, 20),
                            remediation="Remove or replace blocklisted IP address",
                            cwe_id="CWE-1188",
                        ))
                except ValueError as e:
                    logger.debug(f"IP blocklist check failed: {e}")
        
        return findings
    
    def sanitize_template(
        self,
        template_data: Dict[str, Any],
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Sanitize a template by removing or escaping dangerous content.
        
        Args:
            template_data: Template to sanitize
            
        Returns:
            Tuple of (sanitized template, list of modifications made)
        """
        import copy
        sanitized = copy.deepcopy(template_data)
        modifications: List[str] = []
        
        def sanitize_value(value: Any, path: str) -> Any:
            if isinstance(value, str):
                original = value
                
                # Remove null bytes
                value = value.replace('\x00', '')
                
                # Remove control characters
                value = ''.join(c for c in value if ord(c) >= 32 or c in '\n\r\t')
                
                # Escape YAML special characters in restricted fields
                if path in self.RESTRICTED_FIELDS:
                    value = value.replace('{{', '{ {').replace('}}', '} }')
                    value = value.replace('${', '$ {')
                
                if value != original:
                    modifications.append(f"Sanitized value at {path}")
                
                return value
            
            elif isinstance(value, dict):
                return {k: sanitize_value(v, f"{path}.{k}") for k, v in value.items()}
            
            elif isinstance(value, list):
                return [sanitize_value(item, f"{path}[{i}]") for i, item in enumerate(value)]
            
            return value
        
        for key, value in sanitized.items():
            sanitized[key] = sanitize_value(value, key)
        
        return sanitized, modifications


def validate_template_security(
    template_data: Union[Dict[str, Any], str, Path],
    strict: bool = True,
) -> SecurityValidationResult:
    """Convenience function to validate template security.
    
    Args:
        template_data: Template as dict, YAML string, or file path
        strict: Use strict validation mode
        
    Returns:
        SecurityValidationResult with all findings
    """
    validator = TemplateSecurityValidator(strict_mode=strict)
    return validator.validate_template(template_data)
