"""
Rate limiting implementation for DoS protection.

Implements token bucket algorithm for smooth rate limiting
with thread-safe operations.
"""

import time
import threading
from collections import deque
from typing import Optional


class RateLimitExceeded(Exception):
    """Raised when rate limit is exceeded."""
    pass


class TokenBucket:
    """Token bucket for rate limiting."""
    
    def __init__(self, capacity: int, refill_rate: float):
        """
        Initialize token bucket.
        
        Args:
            capacity: Maximum number of tokens
            refill_rate: Tokens per second refill rate
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = capacity
        self.last_refill = time.time()
        self.lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """
        Consume tokens if available.
        
        Args:
            tokens: Number of tokens to consume
            
        Returns:
            True if tokens were consumed, False otherwise
        """
        with self.lock:
            self._refill()
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False
    
    def _refill(self) -> None:
        """Refill tokens based on elapsed time."""
        now = time.time()
        elapsed = now - self.last_refill
        tokens_to_add = elapsed * self.refill_rate
        
        self.tokens = min(self.capacity, self.tokens + tokens_to_add)
        self.last_refill = now


class RateLimiter:
    """Rate limiter using sliding window algorithm."""
    
    def __init__(self, requests_per_minute: int = 100):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_minute: Maximum requests per minute
        """
        self.requests_per_minute = requests_per_minute
        self.requests = deque()
        self.lock = threading.Lock()
    
    def is_allowed(self, burst: int = 1) -> bool:
        """
        Check if request is allowed.
        
        Args:
            burst: Number of requests in this burst
            
        Returns:
            True if request is allowed
            
        Raises:
            RateLimitExceeded: If rate limit is exceeded
        """
        with self.lock:
            now = time.time()
            
            # Remove old requests (older than 1 minute)
            while self.requests and self.requests[0] < now - 60:
                self.requests.popleft()
            
            # Check if adding burst would exceed limit
            if len(self.requests) + burst > self.requests_per_minute:
                # Calculate retry after
                oldest_request = self.requests[0] if self.requests else now
                retry_after = int(60 - (now - oldest_request))
                
                raise RateLimitExceeded(
                    f"Rate limit exceeded. "
                    f"Current: {len(self.requests)}, "
                    f"Limit: {self.requests_per_minute}, "
                    f"Retry after: {retry_after}s"
                )
            
            # Record this request
            for _ in range(burst):
                self.requests.append(now)
            
            return True
    
    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        with self.lock:
            now = time.time()
            
            # Count requests in last minute
            recent_requests = sum(1 for req_time in self.requests 
                              if req_time > now - 60)
            
            return {
                'requests_last_minute': recent_requests,
                'requests_per_minute': self.requests_per_minute,
                'utilization_percent': (recent_requests / self.requests_per_minute) * 100,
            }


class MultiTenantRateLimiter:
    """Rate limiter for multiple tenants/clients."""
    
    def __init__(self, requests_per_minute: int = 100, max_tenants: int = 1000):
        """
        Initialize multi-tenant rate limiter.
        
        Args:
            requests_per_minute: Requests per minute per tenant
            max_tenants: Maximum number of tenants to track
        """
        self.requests_per_minute = requests_per_minute
        self.max_tenants = max_tenants
        self.limiters = {}
        self.lock = threading.Lock()
    
    def is_allowed(self, tenant_id: str, burst: int = 1) -> bool:
        """
        Check if request is allowed for specific tenant.
        
        Args:
            tenant_id: Unique identifier for tenant
            burst: Number of requests in this burst
            
        Returns:
            True if request is allowed
        """
        with self.lock:
            # Create limiter for new tenant
            if tenant_id not in self.limiters:
                if len(self.limiters) >= self.max_tenants:
                    # Evict oldest tenant
                    oldest_tenant = next(iter(self.limiters))
                    del self.limiters[oldest_tenant]
                
                self.limiters[tenant_id] = RateLimiter(self.requests_per_minute)
            
            return self.limiters[tenant_id].is_allowed(burst)
    
    def get_stats(self, tenant_id: Optional[str] = None) -> dict:
        """Get rate limiter statistics."""
        with self.lock:
            if tenant_id:
                if tenant_id in self.limiters:
                    return {
                        'tenant_id': tenant_id,
                        **self.limiters[tenant_id].get_stats()
                    }
                return {'tenant_id': tenant_id, 'error': 'Tenant not found'}
            
            # Return aggregate stats
            total_requests = sum(
                limiter.get_stats()['requests_last_minute'] 
                for limiter in self.limiters.values()
            )
            
            return {
                'total_tenants': len(self.limiters),
                'total_requests_last_minute': total_requests,
                'average_requests_per_tenant': total_requests / max(1, len(self.limiters)),
            }
