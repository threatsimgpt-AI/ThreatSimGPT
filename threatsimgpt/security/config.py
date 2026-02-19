"""
Configuration management for Template Security Validator.

Provides centralized configuration with environment variable support
and validation of configuration values.
"""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class SecurityValidatorConfig:
    """Configuration for Template Security Validator."""
    
    # Core validation settings
    max_template_size: int = field(default=1_000_000)
    strict_mode: bool = field(default=True)
    enable_caching: bool = field(default=True)
    
    # Cache configuration
    cache_ttl_seconds: int = field(default=300)  # 5 minutes
    cache_max_size: int = field(default=100)
    cache_shards: int = field(default=16)  # For sharded caching
    
    # Audit logging configuration
    max_audit_log_size: int = field(default=5000)
    audit_log_file: Optional[Path] = field(default=None)
    audit_circuit_breaker_threshold: int = field(default=5)
    audit_circuit_breaker_timeout: int = field(default=60)
    
    # Rate limiting
    rate_limit_requests_per_minute: int = field(default=100)
    rate_limit_enabled: bool = field(default=True)
    
    # Performance settings
    max_regex_timeout_seconds: int = field(default=2)
    max_traversal_depth: int = field(default=50)
    
    # Security settings
    hash_length: int = field(default=32)  # For template hashing
    
    @classmethod
    def from_env(cls) -> 'SecurityValidatorConfig':
        """Create configuration from environment variables."""
        return cls(
            max_template_size=int(os.getenv('MAX_TEMPLATE_SIZE', str(cls.max_template_size))),
            strict_mode=os.getenv('STRICT_MODE', 'true').lower() == 'true',
            enable_caching=os.getenv('ENABLE_CACHING', 'true').lower() == 'true',
            cache_ttl_seconds=int(os.getenv('CACHE_TTL_SECONDS', str(cls.cache_ttl_seconds))),
            cache_max_size=int(os.getenv('CACHE_MAX_SIZE', str(cls.cache_max_size))),
            cache_shards=int(os.getenv('CACHE_SHARDS', str(cls.cache_shards))),
            max_audit_log_size=int(os.getenv('MAX_AUDIT_LOG_SIZE', str(cls.max_audit_log_size))),
            audit_log_file=Path(os.getenv('AUDIT_LOG_FILE', 'logs/template_validation_audit.log')) if os.getenv('AUDIT_LOG_FILE') else None,
            audit_circuit_breaker_threshold=int(os.getenv('AUDIT_CIRCUIT_BREAKER_THRESHOLD', str(cls.audit_circuit_breaker_threshold))),
            audit_circuit_breaker_timeout=int(os.getenv('AUDIT_CIRCUIT_BREAKER_TIMEOUT', str(cls.audit_circuit_breaker_timeout))),
            rate_limit_requests_per_minute=int(os.getenv('RATE_LIMIT_REQUESTS_PER_MINUTE', str(cls.rate_limit_requests_per_minute))),
            rate_limit_enabled=os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true',
            max_regex_timeout_seconds=int(os.getenv('MAX_REGEX_TIMEOUT_SECONDS', str(cls.max_regex_timeout_seconds))),
            max_traversal_depth=int(os.getenv('MAX_TRAVERSAL_DEPTH', str(cls.max_traversal_depth))),
            hash_length=int(os.getenv('HASH_LENGTH', str(cls.hash_length))),
        )
    
    def validate(self) -> None:
        """Validate configuration values."""
        if self.max_template_size <= 0:
            raise ValueError("max_template_size must be positive")
        if self.cache_ttl_seconds <= 0:
            raise ValueError("cache_ttl_seconds must be positive")
        if self.cache_max_size <= 0:
            raise ValueError("cache_max_size must be positive")
        if self.rate_limit_requests_per_minute <= 0:
            raise ValueError("rate_limit_requests_per_minute must be positive")
        if self.hash_length < 16 or self.hash_length > 64:
            raise ValueError("hash_length must be between 16 and 64")
    
    def to_dict(self) -> dict:
        """Convert configuration to dictionary for logging."""
        return {
            'max_template_size': self.max_template_size,
            'strict_mode': self.strict_mode,
            'enable_caching': self.enable_caching,
            'cache_ttl_seconds': self.cache_ttl_seconds,
            'cache_max_size': self.cache_max_size,
            'cache_shards': self.cache_shards,
            'max_audit_log_size': self.max_audit_log_size,
            'audit_log_file': str(self.audit_log_file) if self.audit_log_file else None,
            'rate_limit_requests_per_minute': self.rate_limit_requests_per_minute,
            'rate_limit_enabled': self.rate_limit_enabled,
            'max_regex_timeout_seconds': self.max_regex_timeout_seconds,
            'max_traversal_depth': self.max_traversal_depth,
            'hash_length': self.hash_length,
        }
