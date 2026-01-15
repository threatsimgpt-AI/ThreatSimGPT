"""Safety Guardrails for LLM Output Validation.

This module implements a comprehensive safety guardrails system for validating
LLM-generated content against security, compliance, and ethical policies.

Issue: #55 - Implement Safety Guardrails
Owner: Lanre Shittu (AI/ML Software Engineer)
Track: ML/AI
"""

from __future__ import annotations

import re
import time
import logging
import asyncio
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Pattern, Tuple, Any
from datetime import datetime, timezone
from enum import Enum
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
import signal

logger = logging.getLogger(__name__)

# ============================================================================
# Configuration Constants
# ============================================================================

MAX_TEXT_LENGTH = 50_000  # 50KB input limit
MAX_MATCHES_PER_RULE = 100  # Prevent DoS from excessive matches
REGEX_TIMEOUT_SECONDS = 0.1  # 100ms timeout for regex operations (P0 Fix: ReDoS protection)
MAX_VALIDATOR_FAILURES = 5  # Circuit breaker threshold
CIRCUIT_BREAKER_TIMEOUT = 60  # Seconds before retry
MAX_TRACKED_VALIDATORS = 1000  # P0 Fix: Prevent memory leak in circuit breaker

# Rate limiting constants (P0 Fix: Per-user rate limiting)
DEFAULT_RATE_LIMIT_PER_USER = 100  # requests per minute
DEFAULT_RATE_LIMIT_BURST = 10  # burst allowance
DEFAULT_GLOBAL_RATE_LIMIT = 10000  # global requests per minute

# ============================================================================
# Constants
# ============================================================================

class Severity(str, Enum):
    """Severity levels for guardrail violations."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    """Actions to take when a rule is violated."""
    ALLOW = "allow"
    BLOCK = "block"
    DEFANG = "defang"
    ESCALATE = "escalate"
    LOG = "log"


class ViolationType(str, Enum):
    """Types of content violations."""
    PII = "pii"  # Personal Identifiable Information
    CREDENTIALS = "credentials"
    TOXIC = "toxic"
    BIAS = "bias"
    MALICIOUS_CODE = "malicious_code"
    POLICY_VIOLATION = "policy_violation"
    INJECTION_ATTACK = "injection_attack"
    CUSTOM = "custom"


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded. (P0 Fix)"""
    def __init__(self, user_id: str, message: str = "Rate limit exceeded"):
        self.user_id = user_id
        self.message = message
        super().__init__(f"{message} for user {user_id}")

# ============================================================================
# Helper Classes
# ============================================================================

class CircuitBreaker:
    """Circuit breaker for failing validators to prevent cascading failures."""
    
    def __init__(
        self, 
        failure_threshold: int = MAX_VALIDATOR_FAILURES, 
        timeout: int = CIRCUIT_BREAKER_TIMEOUT,
        max_tracked: int = MAX_TRACKED_VALIDATORS  # P0 Fix: Prevent memory leak
    ):
        self.failure_threshold = failure_threshold
        self.timeout = timeout
        self.max_tracked = max_tracked
        self.failures: Dict[str, Tuple[int, float]] = {}  # validator_id -> (count, last_failure_time)
        self._lock = asyncio.Lock()
    
    async def should_execute(self, validator_id: str) -> bool:
        """Check if validator should be executed based on failure history."""
        async with self._lock:
            if validator_id not in self.failures:
                return True
            
            count, last_failure = self.failures[validator_id]
            
            # Reset if timeout has passed
            if time.time() - last_failure > self.timeout:
                del self.failures[validator_id]
                return True
            
            # Block if threshold exceeded
            return count < self.failure_threshold
    
    async def record_failure(self, validator_id: str) -> None:
        """Record a validator failure."""
        async with self._lock:
            # P0 Fix: LRU eviction to prevent memory leak
            if validator_id not in self.failures and len(self.failures) >= self.max_tracked:
                # Evict oldest entry
                oldest = min(self.failures, key=lambda k: self.failures[k][1])
                del self.failures[oldest]
                logger.debug(f"Circuit breaker evicted oldest entry: {oldest}")
            
            if validator_id in self.failures:
                count, _ = self.failures[validator_id]
                self.failures[validator_id] = (count + 1, time.time())
            else:
                self.failures[validator_id] = (1, time.time())
            
            count, _ = self.failures[validator_id]
            if count >= self.failure_threshold:
                logger.warning(f"Circuit breaker OPEN for validator {validator_id} (failures: {count})")
    
    async def record_success(self, validator_id: str) -> None:
        """Record a validator success and reset failure count."""
        async with self._lock:
            if validator_id in self.failures:
                del self.failures[validator_id]


class RateLimiter:
    """Token bucket rate limiter for per-user rate limiting. (P0 Fix)
    
    Implements a sliding window rate limiter with burst support.
    Thread-safe for async operations.
    """
    
    def __init__(
        self,
        per_user_rpm: int = DEFAULT_RATE_LIMIT_PER_USER,
        burst: int = DEFAULT_RATE_LIMIT_BURST,
        global_rpm: int = DEFAULT_GLOBAL_RATE_LIMIT
    ):
        self.per_user_rpm = per_user_rpm
        self.burst = burst
        self.global_rpm = global_rpm
        self._user_requests: Dict[str, List[float]] = {}  # user_id -> list of timestamps
        self._global_requests: List[float] = []
        self._lock = asyncio.Lock()
        self._max_tracked_users = 10000  # Prevent memory exhaustion
    
    async def allow(self, user_id: str) -> bool:
        """Check if a request from user_id should be allowed.
        
        Returns:
            True if request is allowed, False if rate limited
        """
        now = time.time()
        window_start = now - 60  # 1 minute window
        
        async with self._lock:
            # Clean old entries and check global rate
            self._global_requests = [t for t in self._global_requests if t > window_start]
            if len(self._global_requests) >= self.global_rpm:
                logger.warning(f"Global rate limit exceeded: {len(self._global_requests)} requests/min")
                return False
            
            # Check per-user rate
            if user_id not in self._user_requests:
                # LRU eviction if too many users tracked
                if len(self._user_requests) >= self._max_tracked_users:
                    oldest_user = min(self._user_requests, 
                                     key=lambda u: max(self._user_requests[u]) if self._user_requests[u] else 0)
                    del self._user_requests[oldest_user]
                self._user_requests[user_id] = []
            
            # Clean old entries for this user
            self._user_requests[user_id] = [t for t in self._user_requests[user_id] if t > window_start]
            
            # Check if under limit (with burst allowance)
            user_request_count = len(self._user_requests[user_id])
            if user_request_count >= self.per_user_rpm + self.burst:
                logger.warning(f"Rate limit exceeded for user {user_id}: {user_request_count} requests/min")
                return False
            
            # Record this request
            self._user_requests[user_id].append(now)
            self._global_requests.append(now)
            return True
    
    def get_user_usage(self, user_id: str) -> Dict[str, Any]:
        """Get current usage stats for a user."""
        now = time.time()
        window_start = now - 60
        
        if user_id not in self._user_requests:
            return {"requests": 0, "limit": self.per_user_rpm, "remaining": self.per_user_rpm}
        
        current = len([t for t in self._user_requests[user_id] if t > window_start])
        return {
            "requests": current,
            "limit": self.per_user_rpm,
            "remaining": max(0, self.per_user_rpm - current),
            "burst_remaining": max(0, self.per_user_rpm + self.burst - current)
        }


@dataclass
class DefangResult:
    """Result of defanging operation with preserved entities."""
    defanged_text: str
    entities: Dict[str, List[str]] = field(default_factory=dict)
    
    def __post_init__(self):
        """Initialize entities dict if not provided."""
        if not self.entities:
            object.__setattr__(self, 'entities', {
                "urls": [],
                "ips": [],
                "emails": [],
                "phone_numbers": [],
                "api_keys": [],
                "tags": []
            })


# ============================================================================
# Data Models
# ============================================================================

@dataclass(frozen=True)
class Rule:
    """Immutable guardrail rule definition.
    
    Attributes:
        id: Unique identifier for the rule
        description: Human-readable description
        pattern: Compiled regex pattern (optional for ML-based rules)
        severity: Severity level of violations
        action: Action to take on violation
        violation_type: Category of violation
        enabled: Whether the rule is active
        meta: Additional metadata
    """
    id: str
    description: str
    pattern: Optional[Pattern] = None
    severity: Severity = Severity.MEDIUM
    action: Action = Action.BLOCK
    violation_type: ViolationType = ViolationType.CUSTOM
    enabled: bool = True
    meta: Dict[str, Any] = field(default_factory=dict)
    
    def __post_init__(self):
        """Validate rule after creation."""
        if not self.id or not self.id.strip():
            raise ValueError("Rule ID cannot be empty")
        if not self.description or not self.description.strip():
            raise ValueError("Rule description cannot be empty")

    @classmethod
    def from_regex(
        cls,
        id: str,
        description: str,
        regex: str,
        severity: Severity = Severity.MEDIUM,
        action: Action = Action.BLOCK,
        violation_type: ViolationType = ViolationType.CUSTOM,
        flags: int = 0
    ) -> Rule:
        """Create a rule from a regex pattern.
        
        Raises:
            ValueError: If regex is invalid
        """
        try:
            pattern = re.compile(regex, flags)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern '{regex}': {e}")
        
        return cls(
            id=id,
            description=description,
            pattern=pattern,
            severity=severity,
            action=action,
            violation_type=violation_type
        )


# Action priority for conflict resolution (higher = more restrictive)
ACTION_PRIORITY = {
    Action.ALLOW: 0,
    Action.LOG: 1,
    Action.ESCALATE: 2,
    Action.DEFANG: 3,
    Action.BLOCK: 4,
}


@dataclass
class RuleMatch:
    """Represents a rule violation match."""
    rule: Rule
    span: Tuple[int, int]
    excerpt: str
    confidence: float = 1.0  # For ML-based checks
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class ValidationResult:
    """Result of a guardrail validation check.
    
    Attributes:
        safe: Whether the content passed all checks
        action: Recommended action to take
        matches: List of rule violations found
        messages: Human-readable violation messages
        output: Processed output (defanged if applicable)
        metadata: Additional validation metadata
        latency_ms: Time taken for validation
    """
    safe: bool
    action: Action
    matches: List[RuleMatch]
    messages: List[str]
    output: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "safe": self.safe,
            "action": self.action.value,
            "matches": [
                {
                    "rule_id": m.rule.id,
                    "description": m.rule.description,
                    "severity": m.rule.severity.value,
                    "violation_type": m.rule.violation_type.value,
                    "span": m.span,
                    "excerpt": m.excerpt,
                    "confidence": m.confidence,
                    "timestamp": m.timestamp.isoformat()
                }
                for m in self.matches
            ],
            "messages": self.messages,
            "output": self.output,
            "metadata": self.metadata,
            "latency_ms": self.latency_ms
        }


# ============================================================================
# Metrics Tracking
# ============================================================================

@dataclass
class GuardrailMetrics:
    """Metrics for guardrail performance monitoring."""
    total_validations: int = 0
    total_violations: int = 0
    total_blocks: int = 0
    total_defangs: int = 0
    total_escalations: int = 0
    violations_by_type: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    violations_by_severity: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    avg_latency_ms: float = 0.0
    max_latency_ms: float = 0.0
    
    def record_validation(self, result: ValidationResult) -> None:
        """Record a validation result for metrics."""
        self.total_validations += 1
        
        if not result.safe:
            self.total_violations += 1
            
            if result.action == Action.BLOCK:
                self.total_blocks += 1
            elif result.action == Action.DEFANG:
                self.total_defangs += 1
            elif result.action == Action.ESCALATE:
                self.total_escalations += 1
            
            for match in result.matches:
                self.violations_by_type[match.rule.violation_type.value] += 1
                self.violations_by_severity[match.rule.severity.value] += 1
        
        # Update latency metrics
        self.max_latency_ms = max(self.max_latency_ms, result.latency_ms)
        self.avg_latency_ms = (
            (self.avg_latency_ms * (self.total_validations - 1) + result.latency_ms)
            / self.total_validations
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_validations": self.total_validations,
            "total_violations": self.total_violations,
            "total_blocks": self.total_blocks,
            "total_defangs": self.total_defangs,
            "total_escalations": self.total_escalations,
            "violations_by_type": dict(self.violations_by_type),
            "violations_by_severity": dict(self.violations_by_severity),
            "avg_latency_ms": round(self.avg_latency_ms, 2),
            "max_latency_ms": round(self.max_latency_ms, 2),
            "block_rate": round(self.total_blocks / max(self.total_validations, 1) * 100, 2)
        }


# ============================================================================
# Guardrails Engine
# ============================================================================

class GuardrailsEngine:
    """Comprehensive guardrails engine for LLM output validation.
    
    Supports:
    - Deterministic rule-based validation (regex patterns)
    - Custom validator plugins (extensible)
    - Allowlist/Denylist with short-circuit logic (P0 Fix: no longer bypasses critical rules)
    - True async batch validation with parallel processing
    - Metrics and telemetry
    - Thread-safe operations
    - DoS protection (input size limits, match limits, timeouts)
    - Circuit breakers for failing validators
    - Per-user rate limiting (P0 Fix)
    """

    def __init__(
        self, 
        rules: Optional[List[Rule]] = None, 
        max_workers: int = 4,
        enable_rate_limiting: bool = True,
        rate_limit_per_user: int = DEFAULT_RATE_LIMIT_PER_USER,
        rate_limit_burst: int = DEFAULT_RATE_LIMIT_BURST,
        global_rate_limit: int = DEFAULT_GLOBAL_RATE_LIMIT
    ):
        """Initialize the guardrails engine.
        
        Args:
            rules: Initial list of rules (optional)
            max_workers: Thread pool size for CPU-bound regex operations
            enable_rate_limiting: Whether to enforce rate limits (P0 Fix)
            rate_limit_per_user: Max requests per user per minute
            rate_limit_burst: Burst allowance for rate limiting
            global_rate_limit: Max global requests per minute
        """
        self._lock = asyncio.Lock()
        self.rules: List[Rule] = list(rules or [])
        self.custom_validators: List[Callable[[str, Dict], Tuple[bool, Optional[str], float]]] = []
        self.allowlist: List[Pattern] = []
        self.denylist: List[Pattern] = []
        self.metrics = GuardrailMetrics()
        self.circuit_breaker = CircuitBreaker()
        self._executor = ThreadPoolExecutor(max_workers=max_workers)
        
        # P0 Fix: Add rate limiter
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limiter = RateLimiter(
            per_user_rpm=rate_limit_per_user,
            burst=rate_limit_burst,
            global_rpm=global_rate_limit
        )
        
        self._add_default_rules()
    
    def __del__(self):
        """Cleanup thread pool on deletion."""
        if hasattr(self, '_executor'):
            self._executor.shutdown(wait=False)

    def _add_default_rules(self) -> None:
        """Add default security-focused rules."""
        # PII Detection Rules
        self.rules.extend([
            Rule.from_regex(
                "pii-ssn",
                "Detect US Social Security Numbers",
                r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.PII
            ),
            Rule.from_regex(
                "pii-credit-card",
                "Detect credit card numbers",
                r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.PII
            ),
            Rule.from_regex(
                "pii-email",
                "Detect email addresses",
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                severity=Severity.HIGH,
                action=Action.DEFANG,
                violation_type=ViolationType.PII
            ),
            Rule.from_regex(
                "pii-phone",
                "Detect phone numbers",
                r"\b(?:\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b",
                severity=Severity.HIGH,
                action=Action.DEFANG,
                violation_type=ViolationType.PII
            ),
        ])
        
        # Credentials Detection
        self.rules.extend([
            Rule.from_regex(
                "cred-api-key",
                "Detect API keys",
                r"(?i)(api[_-]?key|apikey|access[_-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{20,})['\"]?",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-password",
                "Detect exposed passwords",
                r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{8,})['\"]?",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-aws-key",
                "Detect AWS access keys",
                r"(?i)(AKIA[0-9A-Z]{16})",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            # P0 FIX: Additional secret patterns (RED Team Security Review)
            Rule.from_regex(
                "cred-github-token",
                "Detect GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)",
                r"\b(gh[pousr]_[a-zA-Z0-9]{36,255})\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-github-pat-fine",
                "Detect GitHub fine-grained PAT",
                r"\bgithub_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-jwt-token",
                "Detect JWT tokens",
                r"\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-private-key",
                "Detect private keys (RSA, DSA, EC, PGP)",
                r"-----BEGIN\s+(RSA|DSA|EC|PGP|OPENSSH)\s+PRIVATE\s+KEY-----",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-aws-secret",
                "Detect AWS secret access keys",
                r"(?i)(aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-gcp-service-account",
                "Detect GCP service account keys",
                r'"type"\s*:\s*"service_account"',
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-azure-connection",
                "Detect Azure connection strings",
                r"(?i)(DefaultEndpointsProtocol|AccountKey|SharedAccessSignature)\s*=\s*[^;\s]+",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-slack-token",
                "Detect Slack tokens (xox[baprs])",
                r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-stripe-key",
                "Detect Stripe API keys (sk_live_, sk_test_, pk_live_, pk_test_)",
                r"\b[sr]k_(live|test)_[a-zA-Z0-9]{24,}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-twilio",
                "Detect Twilio API keys and SIDs",
                r"\b(SK[a-f0-9]{32}|AC[a-f0-9]{32})\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-sendgrid",
                "Detect SendGrid API keys",
                r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-db-connection",
                "Detect database connection strings with credentials",
                r"(?i)(mongodb|postgresql|mysql|redis|amqp)://[^:]+:[^@]+@[^\s]+",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-openai-key",
                "Detect OpenAI API keys",
                r"\bsk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-npm-token",
                "Detect npm tokens",
                r"\bnpm_[a-zA-Z0-9]{36}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
            Rule.from_regex(
                "cred-pypi-token",
                "Detect PyPI API tokens",
                r"\bpypi-AgEIcHlwaS5vcmc[a-zA-Z0-9_-]{50,}\b",
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                violation_type=ViolationType.CREDENTIALS
            ),
        ])
        
        # Injection Attack Detection
        self.rules.extend([
            Rule.from_regex(
                "injection-sql",
                "Detect SQL injection patterns",
                r"(?i)(union\s+select|select\s+.*\s+from|insert\s+into|delete\s+from|drop\s+table|exec\s*\()",
                severity=Severity.HIGH,
                action=Action.BLOCK,
                violation_type=ViolationType.INJECTION_ATTACK
            ),
            Rule.from_regex(
                "injection-command",
                "Detect command injection patterns",
                r"(?i)(`|;|\||&&|\$\(|>\s*/dev/|nc\s+-|bash\s+-i)",
                severity=Severity.HIGH,
                action=Action.BLOCK,
                violation_type=ViolationType.INJECTION_ATTACK
            ),
        ])
        
        # Malicious Code Detection
        self.rules.extend([
            Rule.from_regex(
                "malicious-obfuscated",
                "Detect obfuscated code patterns",
                r"(?i)(eval\s*\(|exec\s*\(|base64\.decode|fromCharCode|unescape\()",
                severity=Severity.MEDIUM,
                action=Action.ESCALATE,
                violation_type=ViolationType.MALICIOUS_CODE
            ),
        ])

    # ========================================================================
    # Rule Management
    # ========================================================================

    async def add_rule(self, rule: Rule) -> None:
        """Add a rule to the engine.
        
        Raises:
            ValueError: If rule with same ID already exists
        """
        async with self._lock:
            # Check for duplicate IDs
            if any(r.id == rule.id for r in self.rules):
                raise ValueError(f"Rule with ID '{rule.id}' already exists")
            
            self.rules.append(rule)
            logger.info(f"Added rule: {rule.id}")

    async def remove_rule(self, rule_id: str) -> bool:
        """Remove a rule by ID. Returns True if removed."""
        async with self._lock:
            initial_count = len(self.rules)
            self.rules = [r for r in self.rules if r.id != rule_id]
            removed = len(self.rules) < initial_count
            if removed:
                logger.info(f"Removed rule: {rule_id}")
            return removed

    async def get_rule(self, rule_id: str) -> Optional[Rule]:
        """Get a rule by ID."""
        async with self._lock:
            return next((r for r in self.rules if r.id == rule_id), None)

    async def list_rules(self, enabled_only: bool = False) -> List[Rule]:
        """List all rules, optionally filtered by enabled status."""
        async with self._lock:
            if enabled_only:
                return [r for r in self.rules if r.enabled]
            return list(self.rules)

    async def toggle_rule(self, rule_id: str, enabled: bool) -> bool:
        """Enable or disable a rule. Returns True if found."""
        async with self._lock:
            for i, rule in enumerate(self.rules):
                if rule.id == rule_id:
                    # Create new rule with updated enabled status
                    updated_rule = Rule(
                        id=rule.id,
                        description=rule.description,
                        pattern=rule.pattern,
                        severity=rule.severity,
                        action=rule.action,
                        violation_type=rule.violation_type,
                        enabled=enabled,
                        meta=rule.meta
                    )
                    self.rules[i] = updated_rule
                    logger.info(f"Toggled rule {rule_id}: enabled={enabled}")
                    return True
            return False

    def add_custom_validator(
        self,
        validator: Callable[[str, Dict], Tuple[bool, Optional[str], float]]
    ) -> None:
        """Add a custom validator function.
        
        Validator signature: (text: str, context: Dict) -> (is_safe: bool, message: Optional[str], confidence: float)
        """
        self.custom_validators.append(validator)
        logger.info(f"Added custom validator: {validator.__name__}")

    def add_allow_pattern(self, regex: str) -> None:
        """Add an allowlist regex pattern."""
        self.allowlist.append(re.compile(regex))
        logger.info(f"Added allowlist pattern: {regex}")

    def add_deny_pattern(self, regex: str) -> None:
        """Add a denylist regex pattern."""
        self.denylist.append(re.compile(regex))
        logger.info(f"Added denylist pattern: {regex}")

    # ========================================================================
    # Content Processing
    # ========================================================================

    @staticmethod
    def _defang_text(text: str) -> DefangResult:
        """Defang potentially harmful content while preserving extracted entities.
        
        Sanitizes and extracts:
        - URLs (http/https, including obfuscated hxxp)
        - IP addresses (IPv4 and IPv6)
        - Email addresses
        - Phone numbers
        - API keys
        - HTML/XML tags
        
        Returns:
            DefangResult with sanitized text and extracted entities
        """
        entities = {
            "urls": [],
            "ips": [],
            "emails": [],
            "phone_numbers": [],
            "api_keys": [],
            "tags": []
        }
        
        # Extract and defang URLs
        def replace_url(match):
            entities["urls"].append(match.group(0))
            return f"[URL_REMOVED_{len(entities['urls'])}]"
        
        text = re.sub(r"h[tx]{2}ps?://\S+", replace_url, text)  # Handles hxxp obfuscation
        
        # Extract and defang IPv4
        def replace_ipv4(match):
            entities["ips"].append(match.group(0))
            return f"[IP_REMOVED_{len(entities['ips'])}]"
        
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b", replace_ipv4, text)  # Includes port
        
        # Extract and defang IPv6
        def replace_ipv6(match):
            entities["ips"].append(match.group(0))
            return f"[IPV6_REMOVED_{len(entities['ips'])}]"
        
        text = re.sub(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b", replace_ipv6, text)
        
        # Extract and defang emails
        def replace_email(match):
            entities["emails"].append(match.group(0))
            return f"[EMAIL_REMOVED_{len(entities['emails'])}]"
        
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", replace_email, text)
        
        # Extract and defang phone numbers
        def replace_phone(match):
            entities["phone_numbers"].append(match.group(0))
            return f"[PHONE_REMOVED_{len(entities['phone_numbers'])}]"
        
        text = re.sub(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b", replace_phone, text)
        
        # Extract and defang API keys
        def replace_api_key(match):
            entities["api_keys"].append(match.group(0))
            return f"[API_KEY_REMOVED_{len(entities['api_keys'])}]"
        
        text = re.sub(r"\b[s|a]k[-_][a-zA-Z0-9]{20,}\b", replace_api_key, text)
        
        # Extract and defang HTML/XML tags
        def replace_tag(match):
            entities["tags"].append(match.group(0))
            return f"[TAG_REMOVED_{len(entities['tags'])}]"
        
        text = re.sub(r"<[^>]+>", replace_tag, text)
        
        return DefangResult(defanged_text=text, entities=entities)

    async def _is_allowlisted(self, text: str) -> bool:
        """Check if text matches allowlist patterns (thread-safe)."""
        async with self._lock:
            patterns = list(self.allowlist)
        
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False

    async def _is_denylisted(self, text: str) -> bool:
        """Check if text matches denylist patterns (thread-safe)."""
        async with self._lock:
            patterns = list(self.denylist)
        
        for pattern in patterns:
            if pattern.search(text):
                return True
        return False

    # ========================================================================
    # Validation
    # ========================================================================
    
    async def _check_rule_async(self, rule: Rule, text: str) -> List[RuleMatch]:
        """Check a single rule against text (async to not block event loop)."""
        if rule.pattern is None or not rule.enabled:
            return []
        
        # Run CPU-bound regex in thread pool
        loop = asyncio.get_event_loop()
        
        def check_pattern():
            matches = []
            match_count = 0
            for match in rule.pattern.finditer(text):
                if match_count >= MAX_MATCHES_PER_RULE:
                    logger.warning(f"Rule {rule.id} exceeded max matches ({MAX_MATCHES_PER_RULE})")
                    break
                
                matches.append(RuleMatch(
                    rule=rule,
                    span=match.span(),
                    excerpt=match.group(0)[:200],
                    confidence=1.0
                ))
                match_count += 1
            return matches
        
        try:
            # Run with timeout to prevent catastrophic backtracking
            return await asyncio.wait_for(
                loop.run_in_executor(self._executor, check_pattern),
                timeout=REGEX_TIMEOUT_SECONDS
            )
        except asyncio.TimeoutError:
            logger.error(f"Rule {rule.id} timed out after {REGEX_TIMEOUT_SECONDS}s - possible ReDoS")
            # Return empty list but log the issue
            return []

    async def validate(
        self,
        text: str,
        context: Optional[Dict[str, Any]] = None
    ) -> ValidationResult:
        """Validate text against all guardrails with DoS protection.
        
        Args:
            text: Text to validate
            context: Optional context for validation (user_id, simulation_id, etc.)
            
        Returns:
            ValidationResult with safety status and recommended action
            
        Raises:
            ValueError: If input exceeds size limits
            RateLimitExceeded: If user has exceeded rate limit (P0 Fix)
        """
        start_time = time.perf_counter()
        context = context or {}
        
        # P0 Fix: Rate limiting check
        if self.enable_rate_limiting:
            user_id = context.get("user_id", "anonymous")
            if not await self.rate_limiter.allow(user_id):
                raise RateLimitExceeded(
                    user_id=user_id,
                    message=f"Rate limit exceeded: {self.rate_limiter.per_user_rpm} requests/min"
                )
        
        # DoS Protection: Input size limit
        if len(text) > MAX_TEXT_LENGTH:
            logger.warning(f"Input too large: {len(text)} bytes > {MAX_TEXT_LENGTH} bytes")
            result = ValidationResult(
                safe=False,
                action=Action.BLOCK,
                matches=[],
                messages=[f"Input too large: {len(text)} > {MAX_TEXT_LENGTH} bytes"],
                output="",
                metadata={"context": context, "input_size": len(text)},
                latency_ms=(time.perf_counter() - start_time) * 1000
            )
            self.metrics.record_validation(result)
            return result
        
        result = ValidationResult(
            safe=True,
            action=Action.ALLOW,
            matches=[],
            messages=[],
            output=text,
            metadata={"context": context}
        )

        # P0 FIX: Allowlist now only skips LOW/MEDIUM severity rules, NOT critical security checks
        # This prevents allowlist bypass attacks where malicious content is prepended with allowlisted pattern
        is_allowlisted = await self._is_allowlisted(text)
        if is_allowlisted:
            logger.debug("Text allowlisted - will skip LOW/MEDIUM severity rules only")
            result.metadata["allowlisted"] = True

        # Short-circuit: Denylist (async) - ALWAYS checked, even for allowlisted content
        if await self._is_denylisted(text):
            logger.warning("Text denylisted")
            result.safe = False
            result.action = Action.BLOCK
            result.messages.append("Content matched denylist pattern")
            result.latency_ms = (time.perf_counter() - start_time) * 1000
            self.metrics.record_validation(result)
            return result

        # Deterministic Rule Checks (parallel async)
        async with self._lock:
            enabled_rules = [r for r in self.rules if r.enabled]
        
        # P0 FIX: If allowlisted, only run CRITICAL and HIGH severity rules
        if is_allowlisted:
            enabled_rules = [r for r in enabled_rules if r.severity in (Severity.CRITICAL, Severity.HIGH)]
            logger.debug(f"Allowlisted content: running {len(enabled_rules)} critical/high severity rules only")
        
        # Check all rules in parallel
        rule_tasks = [self._check_rule_async(rule, text) for rule in enabled_rules]
        rule_results = await asyncio.gather(*rule_tasks, return_exceptions=True)
        
        # Process results
        for rule, matches in zip(enabled_rules, rule_results):
            if isinstance(matches, Exception):
                logger.error(f"Rule {rule.id} failed: {matches}", exc_info=matches)
                continue
            
            for rule_match in matches:
                result.matches.append(rule_match)
                result.safe = False
                
                # Use priority mapping instead of if-else chain
                current_priority = ACTION_PRIORITY[result.action]
                rule_priority = ACTION_PRIORITY[rule.action]
                
                if rule_priority > current_priority:
                    result.action = rule.action
                
                result.messages.append(f"{rule.id}: {rule.description}")
                logger.warning(f"Rule violation: {rule.id} - {rule.description}")

        # Custom Validators (async with circuit breaker)
        async with self._lock:
            validators = list(self.custom_validators)
        
        for validator in validators:
            validator_id = getattr(validator, '__name__', str(validator))
            
            # Circuit breaker check
            if not await self.circuit_breaker.should_execute(validator_id):
                logger.warning(f"Validator {validator_id} circuit breaker OPEN, skipping")
                continue
            
            try:
                # Run validator in thread pool (might be CPU-bound)
                loop = asyncio.get_event_loop()
                is_safe, message, confidence = await loop.run_in_executor(
                    self._executor,
                    validator,
                    text,
                    context
                )
                
                if not is_safe:
                    result.safe = False
                    current_priority = ACTION_PRIORITY[result.action]
                    escalate_priority = ACTION_PRIORITY[Action.ESCALATE]
                    
                    if escalate_priority > current_priority:
                        result.action = Action.ESCALATE
                    
                    if message:
                        result.messages.append(message)
                    logger.warning(f"Custom validator failed: {validator_id}")
                
                # Record success
                await self.circuit_breaker.record_success(validator_id)
                
            except (KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                # Fail-safe: Escalate on validator errors
                logger.error(f"Validator error ({validator_id}): {exc}", exc_info=True)
                result.safe = False
                result.action = Action.ESCALATE
                result.messages.append(f"Validator error: {validator_id}")
                
                # Record failure for circuit breaker
                await self.circuit_breaker.record_failure(validator_id)

        # Apply action transformations
        if result.action == Action.DEFANG:
            defang_result = self._defang_text(text)
            result.output = defang_result.defanged_text
            result.metadata["extracted_entities"] = defang_result.entities
            logger.info(f"Content defanged: {len(defang_result.entities)} entity types extracted")
        elif result.action == Action.BLOCK:
            result.output = ""
            logger.warning("Content blocked")
        # ESCALATE/LOG keep original output for review

        result.latency_ms = (time.perf_counter() - start_time) * 1000
        self.metrics.record_validation(result)
        
        return result

    async def validate_batch(
        self,
        texts: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> List[ValidationResult]:
        """Validate multiple texts concurrently.
        
        Args:
            texts: List of texts to validate
            context: Optional shared context
            
        Returns:
            List of ValidationResults in same order as input
        """
        tasks = [self.validate(text, context) for text in texts]
        return await asyncio.gather(*tasks)

    async def validate_stream(
        self,
        text_stream: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> List[ValidationResult]:
        """Validate streaming text chunks.
        
        Useful for real-time LLM output validation.
        
        Args:
            text_stream: List of text chunks (streaming tokens)
            context: Optional context
            
        Returns:
            List of ValidationResults for each chunk
        """
        results = []
        accumulated_text = ""
        
        for chunk in text_stream:
            accumulated_text += chunk
            result = await self.validate(accumulated_text, context)
            results.append(result)
            
            # Early stop if blocked
            if result.action == Action.BLOCK:
                logger.warning("Stream validation blocked")
                break
        
        return results

    # ========================================================================
    # Metrics & Monitoring
    # ========================================================================

    def get_metrics(self) -> Dict[str, Any]:
        """Get current guardrail metrics."""
        return self.metrics.to_dict()

    def reset_metrics(self) -> None:
        """Reset metrics counters."""
        self.metrics = GuardrailMetrics()
        logger.info("Metrics reset")

    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on guardrails engine.
        
        Returns:
            Health status with diagnostics
        """
        async with self._lock:
            total_rules = len(self.rules)
            enabled_rules = len([r for r in self.rules if r.enabled])
        
        return {
            "status": "healthy",
            "total_rules": total_rules,
            "enabled_rules": enabled_rules,
            "custom_validators": len(self.custom_validators),
            "allowlist_patterns": len(self.allowlist),
            "denylist_patterns": len(self.denylist),
            "metrics": self.get_metrics(),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
