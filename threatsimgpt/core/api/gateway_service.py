"""
API Gateway Service

This module implements the core API gateway service with
focus on security, performance, and reliability.

Author: ThreatSimGPT Development Team
"""

import time
import asyncio
import logging
from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import Request, Response, HTTPException
from fastapi.responses import JSONResponse

from .models import (
    GatewayConfig, AuthResult, RateLimitResult, RequestMetrics,
    HealthCheck, GatewayState, CircuitBreakerState, GatewayError
)
from .authentication import APIAuthenticator
from .rate_limiter import AdvancedRateLimiter
from .request_router import RequestRouter
from .api_monitoring import APIMonitoring
from .circuit_breaker import CircuitBreaker


logger = logging.getLogger(__name__)


class APIGatewayService:
    """"Core API gateway service with enterprise standards"""
    
    # Fixed bounds for safety and performance
    MAX_REQUEST_SIZE_BYTES = 10_485_760  # 10MB
    MAX_PROCESSING_TIME_SECONDS = 30.0   # 30 seconds
    MAX_RETRY_ATTEMPTS = 3                # Fixed retry bound
    
    def __init__(self, config: GatewayConfig):
        """Initialize gateway service with validated configuration"""
        assert config is not None, "Configuration cannot be None"
        assert isinstance(config, GatewayConfig), "Invalid configuration type"
        
        self.config = config
        self.start_time = time.time()
        
        # Initialize components with dependency injection
        self.authenticator = APIAuthenticator(config)
        self.rate_limiter = AdvancedRateLimiter(config)
        self.router = RequestRouter(config)
        self.monitoring = APIMonitoring(config)
        self.circuit_breaker = CircuitBreaker(config)
        
        # Metrics tracking
        self.requests_processed = 0
        self.active_connections = 0
        
        logger.info("API Gateway Service initialized successfully")
    
    async def process_request(self, request: Request) -> Response:
        """
        Process request with linear control flow
        
        Args:
            request: Incoming HTTP request
            
        Returns:
            Response: Processed HTTP response
            
        Raises:
            HTTPException: For processing failures
        """
        start_time = time.time()
        request_id = self._generate_request_id()
        
        try:
            # Step 1: Request validation with fixed bounds
            await self._validate_request(request)
            
            # Step 2: Authentication with high assertion density
            auth_result = await self._authenticate_request(request, request_id)
            assert auth_result is not None, "Authentication result cannot be None"
            
            # Step 3: Rate limiting check
            rate_result = await self._check_rate_limit(request, auth_result, request_id)
            assert rate_result is not None, "Rate limit result cannot be None"
            
            # Step 4: Circuit breaker protection
            circuit_state = await self._check_circuit_breaker(request_id)
            assert circuit_state is not None, "Circuit breaker state cannot be None"
            
            # Step 5: Request routing with fixed timeout
            response = await self._route_request(request, auth_result, request_id)
            assert response is not None, "Response cannot be None"
            
            # Step 6: Metrics recording with error handling
            await self._record_metrics(request, response, auth_result, rate_result, start_time, request_id)
            
            return response
            
        except Exception as e:
            logger.error(f"Request processing failed: {str(e)}", extra={"request_id": request_id})
            return await self._handle_error(e, request_id)
    
    async def _validate_request(self, request: Request) -> None:
        """Validate request with fixed bounds and assertions"""
        # Check request size
        content_length = request.headers.get("content-length")
        if content_length:
            assert int(content_length) <= self.MAX_REQUEST_SIZE_BYTES, "Request too large"
        
        # Validate required headers
        assert request.method is not None, "HTTP method cannot be None"
        assert request.url is not None, "Request URL cannot be None"
        
        # Check for malicious patterns
        path = str(request.url.path)
        assert len(path) <= 2048, "Request path too long"
        assert ".." not in path, "Path traversal detected"
        
        logger.debug("Request validation passed", extra={"path": path})
    
    async def _authenticate_request(self, request: Request, request_id: str) -> AuthResult:
        """Authenticate request with comprehensive validation"""
        try:
            auth_result = await self.authenticator.authenticate(request)
            
            # Validate authentication result
            assert isinstance(auth_result, AuthResult), "Invalid authentication result type"
            assert auth_result.method is not None, "Authentication method cannot be None"
            
            if not auth_result.is_valid:
                logger.warning(
                    "Authentication failed",
                    extra={
                        "request_id": request_id,
                        "method": auth_result.method.value,
                        "reason": "Invalid credentials"
                    }
                )
                raise HTTPException(status_code=401, detail="Authentication failed")
            
            logger.info(
                "Authentication successful",
                extra={
                    "request_id": request_id,
                    "user_id": auth_result.user_id,
                    "method": auth_result.method.value
                }
            )
            
            return auth_result
            
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}", extra={"request_id": request_id})
            raise HTTPException(status_code=401, detail="Authentication error")
    
    async def _check_rate_limit(self, request: Request, auth_result: AuthResult, request_id: str) -> RateLimitResult:
        """Check rate limits with algorithm validation"""
        try:
            rate_result = await self.rate_limiter.check_limit(request, auth_result)
            
            # Validate rate limit result
            assert isinstance(rate_result, RateLimitResult), "Invalid rate limit result type"
            assert rate_result.limit > 0, "Rate limit must be positive"
            assert rate_result.current_usage >= 0, "Current usage cannot be negative"
            
            if not rate_result.allowed:
                logger.warning(
                    "Rate limit exceeded",
                    extra={
                        "request_id": request_id,
                        "user_id": auth_result.user_id,
                        "limit": rate_result.limit,
                        "current_usage": rate_result.current_usage,
                        "retry_after": rate_result.retry_after
                    }
                )
                
                raise HTTPException(
                    status_code=429,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(rate_result.retry_after or 60)}
                )
            
            return rate_result
            
        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            logger.error(f"Rate limiting error: {str(e)}", extra={"request_id": request_id})
            # Continue processing if rate limiting fails
            return RateLimitResult(
                allowed=True,
                algorithm="token_bucket",
                current_usage=0,
                limit=1000,
                window_seconds=60
            )
    
    async def _check_circuit_breaker(self, request_id: str) -> CircuitBreakerState:
        """Check circuit breaker state with safety validation"""
        try:
            circuit_state = self.circuit_breaker.get_state()
            
            # Validate circuit breaker state
            assert isinstance(circuit_state, CircuitBreakerState), "Invalid circuit breaker state"
            assert circuit_state.state in ["CLOSED", "OPEN", "HALF_OPEN"], "Invalid circuit breaker state value"
            
            if circuit_state.state == "OPEN":
                logger.warning(
                    "Circuit breaker is OPEN",
                    extra={
                        "request_id": request_id,
                        "failure_count": circuit_state.failure_count,
                        "next_attempt_time": circuit_state.next_attempt_time
                    }
                )
                raise HTTPException(status_code=503, detail="Service temporarily unavailable")
            
            return circuit_state
            
        except HTTPException:
            raise  # Re-raise HTTP exceptions
        except Exception as e:
            logger.error(f"Circuit breaker error: {str(e)}", extra={"request_id": request_id})
            # Continue processing if circuit breaker fails
            return CircuitBreakerState(state="CLOSED", failure_count=0, success_count=0)
    
    async def _route_request(self, request: Request, auth_result: AuthResult, request_id: str) -> Response:
        """Route request with timeout protection"""
        try:
            # Route with fixed timeout
            response = await asyncio.wait_for(
                self.router.route(request, auth_result),
                timeout=self.MAX_PROCESSING_TIME_SECONDS
            )
            
            # Validate response
            assert response is not None, "Router returned None response"
            assert hasattr(response, 'status_code'), "Response missing status code"
            
            logger.info(
                "Request routed successfully",
                extra={
                    "request_id": request_id,
                    "status_code": response.status_code,
                    "user_id": auth_result.user_id
                }
            )
            
            return response
            
        except asyncio.TimeoutError:
            logger.error("Request routing timeout", extra={"request_id": request_id})
            raise HTTPException(status_code=504, detail="Request timeout")
        except Exception as e:
            logger.error(f"Request routing error: {str(e)}", extra={"request_id": request_id})
            raise HTTPException(status_code=502, detail="Routing error")
    
    async def _record_metrics(
        self,
        request: Request,
        response: Response,
        auth_result: AuthResult,
        rate_result: RateLimitResult,
        start_time: float,
        request_id: str
    ) -> None:
        """Record metrics with error handling"""
        try:
            duration_ms = (time.time() - start_time) * 1000
            
            metrics = RequestMetrics(
                request_id=request_id,
                method=request.method,
                path=str(request.url.path),
                user_id=auth_result.user_id,
                status_code=response.status_code,
                duration_ms=duration_ms,
                auth_method=auth_result.method,
                rate_limited=not rate_result.allowed
            )
            
            await self.monitoring.record_request(metrics)
            
            # Update gateway metrics
            self.requests_processed += 1
            
            logger.debug(
                "Metrics recorded",
                extra={
                    "request_id": request_id,
                    "duration_ms": duration_ms,
                    "status_code": response.status_code
                }
            )
            
        except Exception as e:
            logger.error(f"Metrics recording failed: {str(e)}", extra={"request_id": request_id})
            # Don't fail the request if metrics recording fails
    
    async def _handle_error(self, error: Exception, request_id: str) -> Response:
        """Handle errors with consistent response format"""
        if isinstance(error, HTTPException):
            return JSONResponse(
                status_code=error.status_code,
                content={
                    "error": error.detail,
                    "request_id": request_id,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
        
        # Handle unexpected errors
        logger.error(f"Unexpected error: {str(error)}", extra={"request_id": request_id})
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "request_id": request_id,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID with fixed format"""
        import uuid
        return f"req_{int(time.time())}_{uuid.uuid4().hex[:8]}"
    
    async def health_check(self) -> HealthCheck:
        """Perform comprehensive health check"""
        try:
            components = {}
            
            # Check authentication
            try:
                await self.authenticator.health_check()
                components["authentication"] = "healthy"
            except Exception as e:
                components["authentication"] = f"unhealthy: {str(e)}"
            
            # Check rate limiting
            try:
                await self.rate_limiter.health_check()
                components["rate_limiting"] = "healthy"
            except Exception as e:
                components["rate_limiting"] = f"unhealthy: {str(e)}"
            
            # Check router
            try:
                await self.router.health_check()
                components["router"] = "healthy"
            except Exception as e:
                components["router"] = f"unhealthy: {str(e)}"
            
            # Check monitoring
            try:
                await self.monitoring.health_check()
                components["monitoring"] = "healthy"
            except Exception as e:
                components["monitoring"] = f"unhealthy: {str(e)}"
            
            # Determine overall status
            all_healthy = all(status == "healthy" for status in components.values())
            status = GatewayState.HEALTHY if all_healthy else GatewayState.DEGRADED
            
            return HealthCheck(
                status=status,
                components=components,
                uptime_seconds=time.time() - self.start_time,
                active_connections=self.active_connections,
                requests_processed=self.requests_processed
            )
            
        except Exception as e:
            logger.error(f"Health check failed: {str(e)}")
            return HealthCheck(
                status=GatewayState.UNHEALTHY,
                components={"gateway": f"unhealthy: {str(e)}"},
                uptime_seconds=time.time() - self.start_time,
                active_connections=self.active_connections,
                requests_processed=self.requests_processed
            )
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get gateway metrics with fixed bounds"""
        return {
            "uptime_seconds": time.time() - self.start_time,
            "requests_processed": self.requests_processed,
            "active_connections": self.active_connections,
            "config": {
                "max_request_size_bytes": self.MAX_REQUEST_SIZE_BYTES,
                "max_processing_time_seconds": self.MAX_PROCESSING_TIME_SECONDS,
                "max_retry_attempts": self.MAX_RETRY_ATTEMPTS
            }
        }
