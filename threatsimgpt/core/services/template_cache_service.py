"""Template Cache Service with proper bounds and security.

Provides thread-safe caching for template validation results with:
- Size limits and LRU eviction
- Secure cache key generation
- TTL-based expiration
- Memory leak prevention
"""

import hashlib
import secrets
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional, Tuple

from threatsimgpt.security.template_validator import SecurityValidationResult


class CacheEntry:
    """Individual cache entry with metadata."""
    
    def __init__(self, result: SecurityValidationResult, timestamp: datetime):
        self.result = result
        self.timestamp = timestamp
        self.access_count = 1
        self.last_accessed = timestamp
    
    def is_expired(self, ttl_seconds: int) -> bool:
        """Check if entry has expired."""
        return datetime.now(timezone.utc) - self.timestamp > timedelta(seconds=ttl_seconds)
    
    def touch(self):
        """Update access statistics."""
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc)


class TemplateCacheService:
    """Thread-safe caching service with proper bounds and security."""
    
    def __init__(
        self,
        ttl_seconds: int = 300,
        max_size: int = 1000,
        enable_lru: bool = True
    ):
        """Initialize cache service with security bounds.
        
        Args:
            ttl_seconds: Time-to-live for cache entries
            max_size: Maximum number of entries (prevents memory leaks)
            enable_lru: Enable LRU eviction when cache is full
        """
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self.enable_lru = enable_lru
        
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = Lock()
        
        # Statistics
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'expirations': 0,
            'total_requests': 0
        }
    
    def _generate_secure_cache_key(
        self, 
        template_path: Path, 
        user_id: Optional[str] = None
    ) -> str:
        """Generate secure cache key to prevent collisions.
        
        Uses cryptographic hashing instead of string concatenation
        to prevent path traversal and collision attacks.
        
        Args:
            template_path: Path to template file
            user_id: Optional user identifier
            
        Returns:
            Cryptographically secure cache key
        """
        # Get file modification time for cache invalidation
        try:
            mtime = template_path.stat().st_mtime
        except OSError:
            mtime = 0
        
        # Create deterministic but secure hash
        key_data = f"{template_path}:{mtime}:{user_id or 'anonymous'}"
        return hashlib.sha256(key_data.encode('utf-8')).hexdigest()
    
    def get(self, template_path: Path, user_id: Optional[str] = None) -> Optional[SecurityValidationResult]:
        """Get cached validation result if available and not expired.
        
        Args:
            template_path: Path to template file
            user_id: Optional user identifier
            
        Returns:
            Cached validation result or None
        """
        with self._lock:
            self._stats['total_requests'] += 1
            
            cache_key = self._generate_secure_cache_key(template_path, user_id)
            
            if cache_key not in self._cache:
                self._stats['misses'] += 1
                return None
            
            entry = self._cache[cache_key]
            
            # Check expiration
            if entry.is_expired(self.ttl_seconds):
                del self._cache[cache_key]
                self._stats['expirations'] += 1
                self._stats['misses'] += 1
                return None
            
            # Update access statistics
            entry.touch()
            self._stats['hits'] += 1
            
            return entry.result
    
    def put(
        self, 
        template_path: Path, 
        result: SecurityValidationResult, 
        user_id: Optional[str] = None
    ) -> None:
        """Cache validation result with proper bounds checking.
        
        Args:
            template_path: Path to template file
            result: Validation result to cache
            user_id: Optional user identifier
        """
        with self._lock:
            cache_key = self._generate_secure_cache_key(template_path, user_id)
            
            # Check if we need to evict entries
            if len(self._cache) >= self.max_size:
                if cache_key in self._cache:
                    # Replace existing entry
                    del self._cache[cache_key]
                elif self.enable_lru:
                    # Evict least recently used entry
                    self._evict_lru()
                else:
                    # Don't cache if full and LRU disabled
                    return
            
            # Create new entry
            entry = CacheEntry(result, datetime.now(timezone.utc))
            self._cache[cache_key] = entry
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry from cache."""
        if not self._cache:
            return
        
        # Find entry with oldest last_accessed time
        lru_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].last_accessed
        )
        
        del self._cache[lru_key]
        self._stats['evictions'] += 1
    
    def clear(self) -> int:
        """Clear all cached entries.
        
        Returns:
            Number of entries cleared
        """
        with self._lock:
            old_size = len(self._cache)
            self._cache.clear()
            return old_size
    
    def size(self) -> int:
        """Get current cache size."""
        with self._lock:
            return len(self._cache)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get cache performance statistics.
        
        Returns:
            Dictionary with cache statistics
        """
        with self._lock:
            total = self._stats['total_requests']
            hit_rate = self._stats['hits'] / total if total > 0 else 0.0
            
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'ttl_seconds': self.ttl_seconds,
                'hits': self._stats['hits'],
                'misses': self._stats['misses'],
                'evictions': self._stats['evictions'],
                'expirations': self._stats['expirations'],
                'total_requests': total,
                'hit_rate': hit_rate,
                'utilization': len(self._cache) / self.max_size if self.max_size > 0 else 0.0
            }
    
    def cleanup_expired(self) -> int:
        """Remove expired entries from cache.
        
        Returns:
            Number of entries removed
        """
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired(self.ttl_seconds)
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            self._stats['expirations'] += len(expired_keys)
            return len(expired_keys)
