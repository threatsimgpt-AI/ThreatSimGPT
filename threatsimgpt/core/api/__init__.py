"""
ThreatSimGPT API Gateway Module

This module provides enterprise-grade API gateway functionality with
focus on security, performance, and reliability.

Core Components:
- Gateway Service: Main orchestration with linear control flow
- Authentication: Multi-method security validation
- Rate Limiting: Multi-algorithm traffic management
- Monitoring: Comprehensive observability and metrics
"""

from .gateway_service import APIGatewayService
from .authentication import APIAuthenticator
from .rate_limiter import AdvancedRateLimiter
from .request_router import RequestRouter
from .api_monitoring import APIMonitoring
from .circuit_breaker import CircuitBreaker
from .middleware import APIGatewayMiddleware
from .config import GatewayConfigManager
from .models import (
    GatewayConfig, AuthMethod, RateLimitAlgorithm, 
    GatewayState, AuthResult, RateLimitResult
)

__version__ = "1.0.0"
__author__ = "ThreatSimGPT Development Team"
__description__ = "Enterprise-grade API gateway with security, performance, and reliability"

# Enterprise standards constants
ENTERPRISE_STANDARDS = {
    "fixed_bounds": True,
    "high_assertion_density": True,
    "linear_control_flow": True,
    "zero_warnings_policy": True
}

# Fixed bounds constants
MAX_REQUEST_SIZE = 10_485_760  # 10MB
MAX_PROCESSING_TIME = 30.0  # 30 seconds
MAX_RETRY_ATTEMPTS = 3

# Performance targets
PERFORMANCE_TARGETS = {
    "max_overhead_ms": 5,
    "max_throughput_rps": 10_000,
    "max_memory_mb": 512,
    "max_cpu_percent": 50
}

__all__ = [
    "APIGatewayService",
    "APIAuthenticator",
    "AdvancedRateLimiter",
    "RequestRouter",
    "APIMonitoring",
    "CircuitBreaker",
    "APIGatewayMiddleware",
    "GatewayConfigManager",
    "GatewayConfig",
    "AuthMethod",
    "RateLimitAlgorithm",
    "GatewayState",
    "AuthResult",
    "RateLimitResult",
    "ENTERPRISE_STANDARDS",
    "MAX_REQUEST_SIZE",
    "MAX_PROCESSING_TIME",
    "MAX_RETRY_ATTEMPTS",
    "PERFORMANCE_TARGETS"
]
