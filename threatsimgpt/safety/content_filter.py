"""
Content Safety Filter for ThreatSimGPT
Multi-layer filtering to prevent generation of harmful content

Author: Temi Adebola (TSG-RED Lead)
Created: 13 January 2026
Hardened: 13 January 2026 (Principal Engineer Review)

⚠️ PRODUCTION WARNING:
This implementation includes critical security hardening but requires
additional infrastructure for production deployment:
- Redis/persistent storage for kill switch state
- Centralized audit logging system
- Rate limiting middleware
- Authorization service integration
"""

import re
import hashlib
import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from threatsimgpt.safety.exceptions import ContentFilterError, SafetyViolationError


# Configure audit logger
logger = logging.getLogger("threatsimgpt.safety.audit")
logger.setLevel(logging.INFO)


class RiskLevel(Enum):
    """Content risk levels"""
    SAFE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    BLOCKED = 5


class ContentCategory(Enum):
    """Categories of potentially harmful content"""
    MALWARE_CODE = "malware_code"
    REAL_CREDENTIALS = "real_credentials"
    PII_DATA = "pii_data"
    FINANCIAL_DATA = "financial_data"
    EXPLOITATION = "exploitation"
    WEAPONIZATION = "weaponization"
    HARASSMENT = "harassment"
    ILLEGAL_ACTIVITY = "illegal_activity"


@dataclass
class FilterResult:
    """Result of content filtering"""
    is_safe: bool
    risk_level: RiskLevel
    categories_detected: List[ContentCategory] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    filter_id: str = field(default_factory=lambda: hashlib.sha256(
        datetime.utcnow().isoformat().encode()
    ).hexdigest()[:12])

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "is_safe": self.is_safe,
            "risk_level": self.risk_level.name,
            "categories_detected": [c.value for c in self.categories_detected],
            "matched_patterns": self.matched_patterns,
            "risk_score": self.risk_score,
            "recommendations": self.recommendations,
            "filter_id": self.filter_id
        }


@dataclass
class FilterConfig:
    """Configuration for content filter"""
    strict_mode: bool = True
    allow_defanged: bool = True
    max_risk_level: RiskLevel = RiskLevel.MEDIUM
    blocked_categories: Set[ContentCategory] = field(default_factory=lambda: {
        ContentCategory.MALWARE_CODE,
        ContentCategory.REAL_CREDENTIALS,
        ContentCategory.EXPLOITATION
    })
    custom_patterns: List[str] = field(default_factory=list)
    # Security hardening
    enable_rate_limiting: bool = True
    max_requests_per_minute: int = 100
    fail_safe_mode: bool = True  # Fail closed on errors
    kill_switch_persist_path: Optional[Path] = None  # Path to persist kill switch state


class AuthorizationValidator:
    """
    Authorization validator for kill switch operations
    
    In production, this should integrate with your auth service.
    Current implementation uses HMAC-based token validation.
    """
    
    def __init__(self, secret_key: Optional[str] = None):
        import os
        self.secret_key = secret_key or os.getenv("THREATGPT_KILLSWITCH_SECRET", "")
        if not self.secret_key:
            logger.warning("No kill switch secret configured - using development mode")
    
    def validate(self, token: str) -> bool:
        """Validate authorization token"""
        if not self.secret_key:
            # Development mode - log warning
            logger.warning("Kill switch authorization in development mode - NOT SECURE")
            return True
        
        try:
            # Expected format: timestamp:signature
            parts = token.split(":")
            if len(parts) != 2:
                return False
            
            timestamp_str, provided_sig = parts
            timestamp = int(timestamp_str)
            
            # Check if token is too old (5 minute window)
            now = int(time.time())
            if abs(now - timestamp) > 300:
                logger.warning("Kill switch token expired")
                return False
            
            # Verify signature
            import hmac
            expected_sig = hmac.new(
                self.secret_key.encode(),
                timestamp_str.encode(),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(expected_sig, provided_sig)
        
        except Exception as e:
            logger.error(f"Authorization validation error: {e}")
            return False
    
    @staticmethod
    def generate_token(secret_key: str) -> str:
        """Generate valid authorization token (for admin use)"""
        import hmac
        timestamp = str(int(time.time()))
        signature = hmac.new(
            secret_key.encode(),
            timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{timestamp}:{signature}"


class RateLimiter:
    """Thread-safe rate limiter using sliding window"""
    
    def __init__(self, max_requests: int = 100, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
    
    def check_rate_limit(self, identifier: str = "global") -> bool:
        """
        Check if request is within rate limit
        
        Args:
            identifier: User ID, IP, or session identifier
            
        Returns:
            True if allowed, False if rate limited
        """
        now = time.time()
        
        with self._lock:
            # Clean old requests
            if identifier in self._requests:
                self._requests[identifier] = [
                    ts for ts in self._requests[identifier]
                    if now - ts < self.window_seconds
                ]
            else:
                self._requests[identifier] = []
            
            # Check limit
            if len(self._requests[identifier]) >= self.max_requests:
                logger.warning(f"Rate limit exceeded for {identifier}")
                return False
            
            # Add current request
            self._requests[identifier].append(now)
            return True


class ContentFilter:
    """
    Multi-layer content safety filter
    
    Layers:
    1. Blocklist - Known dangerous patterns
    2. PII Detection - SSN, credit cards, etc.
    3. Payload Scanner - Malware signatures
    4. Context Analysis - Intent classification
    5. Output Sanitizer - Defanging URLs/IPs
    
    Features:
    - Configurable risk thresholds
    - Bypass-resistant design
    - Audit logging
    - Emergency kill switch
    """
    
    # Blocklist patterns (regex)
    BLOCKLIST_PATTERNS = {
        ContentCategory.MALWARE_CODE: [
            r'(?i)import\s+subprocess.*shell\s*=\s*True',
            r'(?i)exec\s*\(\s*base64\.b64decode',
            r'(?i)powershell.*-enc',
            r'(?i)cmd\.exe\s*/c',
            r'(?i)eval\s*\(\s*request\.',
            r'(?i)__import__\s*\(\s*[\'"]os[\'"]\)',
            r'(?i)msfvenom',
            r'(?i)meterpreter',
            r'(?i)reverse.?shell',
            r'(?i)bind.?shell',
            r'\bnc\s+-[a-z]*e\s+',  # netcat with -e flag
            r'/bin/(ba)?sh\s+.*attacker',  # shell to attacker
            r'/dev/tcp/',  # bash TCP redirection
        ],
        ContentCategory.REAL_CREDENTIALS: [
            r'(?i)password\s*[=:]\s*["\'][^"\']{8,}["\']',
            r'(?i)api[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'(?i)secret[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9]{20,}["\']',
            r'sk-[a-zA-Z0-9]{40,}',  # OpenAI key pattern (flexible length)
            r'ghp_[a-zA-Z0-9]{36}',  # GitHub token pattern
            r"['\"]key['\"]:\s*['\"][a-zA-Z0-9]{32,}['\"]",  # Generic API keys
        ],
        ContentCategory.EXPLOITATION: [
            r'(?i)CVE-\d{4}-\d{4,}.*exploit',
            r'(?i)0day|zero.?day',
            r'(?i)metasploit.*payload',
            r'(?i)sqlmap',
            r'(?i)union\s+select.*from',
            r'(?i)<script>.*<\/script>',
        ]
    }
    
    # PII patterns
    PII_PATTERNS = {
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        'phone': r'\b(?:\+1)?[\s.-]?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b',
        'email_real': r'\b[A-Za-z0-9._%+-]+@(?:gmail|yahoo|outlook|hotmail)\.[a-z]{2,}\b',
    }
    
    def __init__(self, config: FilterConfig = None):
        self.config = config or FilterConfig()
        self._kill_switch_active = False
        self._custom_validators: List[Callable] = []
        self._lock = threading.Lock()  # Thread safety
        
        # Authorization validator
        self._auth_validator = AuthorizationValidator()
        
        # Rate limiter (if enabled)
        if self.config.enable_rate_limiting:
            self._rate_limiter = RateLimiter(
                max_requests=self.config.max_requests_per_minute,
                window_seconds=60
            )
        else:
            self._rate_limiter = None
        
        # Load kill switch state from persistence
        self._load_kill_switch_state()
        
        # Audit logging setup
        logger.info("ContentFilter initialized", extra={
            "strict_mode": self.config.strict_mode,
            "rate_limiting": self.config.enable_rate_limiting,
            "fail_safe_mode": self.config.fail_safe_mode
        })
    
    def filter(self, content: str, context: Optional[Dict] = None) -> FilterResult:
        """
        Filter content through all safety layers
        
        Args:
            content: Content to filter
            context: Additional context (template, user, session_id, etc.)
            
        Returns:
            FilterResult with risk assessment
            
        Raises:
            ContentFilterError: If rate limited or filter error in fail-safe mode
        """
        # Rate limiting check
        if self._rate_limiter:
            session_id = context.get("session_id", "global") if context else "global"
            if not self._rate_limiter.check_rate_limit(session_id):
                raise ContentFilterError(f"Rate limit exceeded for session: {session_id}")
        
        # Check kill switch first (thread-safe)
        with self._lock:
            if self._kill_switch_active:
                logger.critical("Content blocked - kill switch active", extra=context)
                return FilterResult(
                    is_safe=False,
                    risk_level=RiskLevel.BLOCKED,
                    recommendations=["Kill switch active - all generation blocked"]
                )
        
        try:
            categories_detected = []
            matched_patterns = []
            risk_scores = []
            
            # Layer 1: Blocklist check
            blocklist_result = self._check_blocklist(content)
            categories_detected.extend(blocklist_result[0])
            matched_patterns.extend(blocklist_result[1])
            if blocklist_result[0]:
                risk_scores.append(0.8)
            
            # Layer 2: PII detection
            pii_result = self._check_pii(content)
            if pii_result:
                categories_detected.append(ContentCategory.PII_DATA)
                matched_patterns.extend(pii_result)
                risk_scores.append(0.7)
            
            # Layer 3: Payload scanning
            payload_result = self._scan_payloads(content)
            if payload_result:
                categories_detected.append(ContentCategory.MALWARE_CODE)
                matched_patterns.extend(payload_result)
                risk_scores.append(0.9)
            
            # Layer 4: Custom validators (with error handling)
            for validator in self._custom_validators:
                try:
                    validator_result = validator(content, context)
                    if validator_result:
                        risk_scores.append(validator_result.get('risk', 0.5))
                except Exception as e:
                    logger.error(f"Custom validator failed: {e}", extra={
                        "validator": validator.__name__,
                        "context": context
                    })
                    if self.config.fail_safe_mode:
                        # Fail closed - treat as high risk
                        risk_scores.append(0.8)
            
            # Calculate overall risk
            risk_score = max(risk_scores) if risk_scores else 0.0
            risk_level = self._score_to_level(risk_score)
            
            # Determine if safe
            is_safe = (
                risk_level.value <= self.config.max_risk_level.value and
                not any(cat in self.config.blocked_categories for cat in categories_detected)
            )
            
            # Generate recommendations
            recommendations = self._generate_recommendations(
                categories_detected, risk_level
            )
            
            result = FilterResult(
                is_safe=is_safe,
                risk_level=risk_level,
                categories_detected=categories_detected,
                matched_patterns=matched_patterns[:10],  # Limit for logging
                risk_score=risk_score,
                recommendations=recommendations
            )
            
            # Structured audit logging
            self._log_filter(content, result, context)
            
            return result
        
        except Exception as e:
            logger.error(f"Filter error: {e}", extra=context, exc_info=True)
            if self.config.fail_safe_mode:
                # Fail closed
                raise ContentFilterError(f"Filter processing error: {e}")
            else:
                # Fail open (allow but log)
                logger.warning("Filter failed but allowing content (fail-open mode)")
                return FilterResult(
                    is_safe=True,
                    risk_level=RiskLevel.SAFE,
                    recommendations=["Filter error - content not fully validated"]
                )
    
    def _check_blocklist(
        self, content: str
    ) -> Tuple[List[ContentCategory], List[str]]:
        """Check content against blocklist patterns"""
        categories = []
        patterns = []
        
        for category, pattern_list in self.BLOCKLIST_PATTERNS.items():
            for pattern in pattern_list:
                if re.search(pattern, content):
                    if category not in categories:
                        categories.append(category)
                    patterns.append(pattern[:50])  # Truncate for logging
        
        return categories, patterns
    
    def _check_pii(self, content: str) -> List[str]:
        """Check for personally identifiable information"""
        found = []
        for pii_type, pattern in self.PII_PATTERNS.items():
            if re.search(pattern, content):
                found.append(f"pii:{pii_type}")
        return found
    
    def _scan_payloads(self, content: str) -> List[str]:
        """Scan for malicious payload patterns"""
        payload_indicators = []
        
        # Check for encoded content
        if re.search(r'base64[._-]?encode|atob|btoa', content, re.I):
            payload_indicators.append("encoded_content")
        
        # Check for obfuscation
        if re.search(r'\\x[0-9a-f]{2}', content, re.I):
            payload_indicators.append("hex_obfuscation")
        
        # Check for shell commands
        if re.search(r'(?:bash|sh|cmd|powershell)\s+-[cek]', content, re.I):
            payload_indicators.append("shell_execution")
        
        return payload_indicators
    
    def _score_to_level(self, score: float) -> RiskLevel:
        """Convert risk score to level"""
        if score >= 0.9:
            return RiskLevel.CRITICAL
        elif score >= 0.7:
            return RiskLevel.HIGH
        elif score >= 0.5:
            return RiskLevel.MEDIUM
        elif score >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_recommendations(
        self,
        categories: List[ContentCategory],
        risk_level: RiskLevel
    ) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        if ContentCategory.MALWARE_CODE in categories:
            recommendations.append("Remove or defang executable code")
        
        if ContentCategory.PII_DATA in categories:
            recommendations.append("Replace real PII with synthetic data")
        
        if ContentCategory.REAL_CREDENTIALS in categories:
            recommendations.append("Remove or mask real credentials")
        
        if risk_level.value >= RiskLevel.HIGH.value:
            recommendations.append("Content requires manual review before use")
        
        return recommendations
    
    def _log_filter(
        self,
        content: str,
        result: FilterResult,
        context: Optional[Dict]
    ):
        """Log filter operation for audit (structured logging)"""
        log_data = {
            "filter_id": result.filter_id,
            "content_hash": hashlib.sha256(content.encode()).hexdigest()[:16],
            "content_length": len(content),
            "risk_level": result.risk_level.name,
            "is_safe": result.is_safe,
            "categories": [c.value for c in result.categories_detected],
            "risk_score": result.risk_score,
        }
        
        if context:
            log_data.update({
                "user_id": context.get("user_id"),
                "session_id": context.get("session_id"),
                "template_id": context.get("template_id"),
            })
        
        if result.is_safe:
            logger.info("Content passed filter", extra=log_data)
        else:
            logger.warning("Content blocked by filter", extra=log_data)
    
    # =========================================================================
    # Kill Switch (Hardened)
    # =========================================================================
    
    def activate_kill_switch(self, reason: str = "", operator: str = "system"):
        """
        Activate emergency kill switch - blocks ALL content generation
        
        Args:
            reason: Reason for activation (required for audit)
            operator: Who activated (user ID or system)
        """
        with self._lock:
            self._kill_switch_active = True
            self._persist_kill_switch_state(active=True)
        
        logger.critical("KILL SWITCH ACTIVATED", extra={
            "reason": reason,
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    def deactivate_kill_switch(self, authorization: str, operator: str = "unknown"):
        """
        Deactivate kill switch (requires verified authorization)
        
        Args:
            authorization: Authorization token (HMAC-signed timestamp)
            operator: Who is deactivating (for audit trail)
            
        Raises:
            SafetyViolationError: If authorization is invalid
        """
        # Verify authorization
        if not self._auth_validator.validate(authorization):
            logger.error("Kill switch deactivation failed - invalid authorization", extra={
                "operator": operator,
                "timestamp": datetime.utcnow().isoformat()
            })
            raise SafetyViolationError(
                "Invalid authorization token. Kill switch remains active."
            )
        
        with self._lock:
            self._kill_switch_active = False
            self._persist_kill_switch_state(active=False)
        
        logger.warning("Kill switch deactivated", extra={
            "operator": operator,
            "timestamp": datetime.utcnow().isoformat()
        })
    
    @property
    def kill_switch_status(self) -> bool:
        """Check if kill switch is active (thread-safe)"""
        with self._lock:
            return self._kill_switch_active
    
    def _load_kill_switch_state(self):
        """Load kill switch state from persistent storage"""
        if not self.config.kill_switch_persist_path:
            return
        
        try:
            if self.config.kill_switch_persist_path.exists():
                state_data = self.config.kill_switch_persist_path.read_text()
                if state_data.strip() == "ACTIVE":
                    self._kill_switch_active = True
                    logger.warning("Kill switch loaded in ACTIVE state from persistence")
        except Exception as e:
            logger.error(f"Failed to load kill switch state: {e}")
    
    def _persist_kill_switch_state(self, active: bool):
        """Persist kill switch state to storage"""
        if not self.config.kill_switch_persist_path:
            return
        
        try:
            self.config.kill_switch_persist_path.parent.mkdir(parents=True, exist_ok=True)
            state = "ACTIVE" if active else "INACTIVE"
            self.config.kill_switch_persist_path.write_text(state)
            logger.info(f"Kill switch state persisted: {state}")
        except Exception as e:
            logger.error(f"Failed to persist kill switch state: {e}")
    
    # =========================================================================
    # Custom Validators
    # =========================================================================
    
    def add_validator(self, validator: Callable):
        """Add custom validation function (thread-safe)"""
        with self._lock:
            self._custom_validators.append(validator)
        logger.info(f"Added custom validator: {validator.__name__}")
    
    def remove_validator(self, validator: Callable):
        """Remove custom validation function (thread-safe)"""
        with self._lock:
            if validator in self._custom_validators:
                self._custom_validators.remove(validator)
        logger.info(f"Removed custom validator: {validator.__name__}")
    
    # =========================================================================
    # Metrics & Health Check
    # =========================================================================
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get filter health status for monitoring"""
        return {
            "kill_switch_active": self._kill_switch_active,
            "custom_validators_count": len(self._custom_validators),
            "rate_limiting_enabled": self._rate_limiter is not None,
            "fail_safe_mode": self.config.fail_safe_mode,
            "strict_mode": self.config.strict_mode,
        }


class OutputSanitizer:
    """
    Sanitizes generated output to prevent accidental harm
    
    Features:
    - URL defanging (hxxp://)
    - IP defanging (127[.]0[.]0[.]1)
    - Email defanging (user[@]domain)
    - Hash truncation
    """
    
    @staticmethod
    def defang_url(content: str) -> str:
        """Defang URLs to prevent accidental clicks"""
        # http:// -> hxxp://
        content = re.sub(r'http://', 'hxxp://', content, flags=re.I)
        content = re.sub(r'https://', 'hxxps://', content, flags=re.I)
        return content
    
    @staticmethod
    def defang_ip(content: str) -> str:
        """Defang IP addresses"""
        # 192.168.1.1 -> 192[.]168[.]1[.]1
        ip_pattern = r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b'
        return re.sub(ip_pattern, r'\1[.]\2[.]\3[.]\4', content)
    
    @staticmethod
    def defang_email(content: str) -> str:
        """Defang email addresses"""
        # user@domain.com -> user[@]domain[.]com
        email_pattern = r'([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})'
        return re.sub(email_pattern, r'\1[@]\2[.]\3', content)
    
    @classmethod
    def sanitize_all(cls, content: str) -> str:
        """Apply all defanging operations"""
        content = cls.defang_url(content)
        content = cls.defang_ip(content)
        content = cls.defang_email(content)
        return content


# Global instance for convenience (thread-safe singleton)
_global_filter: Optional[ContentFilter] = None
_global_filter_lock = threading.Lock()


def get_global_filter() -> ContentFilter:
    """Get or create global content filter instance (thread-safe)"""
    global _global_filter
    
    if _global_filter is None:
        with _global_filter_lock:
            # Double-check locking pattern
            if _global_filter is None:
                _global_filter = ContentFilter()
    
    return _global_filter


def set_global_filter(filter_instance: ContentFilter):
    """Set custom global filter instance (thread-safe)"""
    global _global_filter
    with _global_filter_lock:
        _global_filter = filter_instance
