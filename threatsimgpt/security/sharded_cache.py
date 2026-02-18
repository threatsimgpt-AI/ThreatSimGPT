"""
Sharded cache implementation for improved concurrent performance.

Uses multiple cache shards to reduce lock contention
and improve throughput under high load.
"""

import hashlib
import threading
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional, List

from .config import SecurityValidatorConfig


class CacheEntry:
    """Single cache entry with expiration."""
    
    def __init__(self, value: Any, ttl_seconds: int):
        """Initialize cache entry."""
        self.value = value
        self.created_at = time.time()
        self.expires_at = self.created_at + ttl_seconds
    
    def is_expired(self) -> bool:
        """Check if entry has expired."""
        return time.time() > self.expires_at
    
    def get_age_seconds(self) -> float:
        """Get age of entry in seconds."""
        return time.time() - self.created_at


class ValidationCache:
    """Thread-safe validation cache."""
    
    def __init__(self, config: SecurityValidatorConfig):
        """
        Initialize validation cache.
        
        Args:
            config: Security validator configuration
        """
        self.config = config
        self.cache: Dict[str, CacheEntry] = {}
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0
    
    def put(self, key: str, value: Any) -> None:
        """Store value in cache."""
        with self.lock:
            # Enforce size limit
            if len(self.cache) >= self.config.cache_max_size:
                self._evict_lru()
            
            self.cache[key] = CacheEntry(value, self.config.cache_ttl_seconds)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache."""
        with self.lock:
            if key not in self.cache:
                self.misses += 1
                return None
            
            entry = self.cache[key]
            if entry.is_expired():
                # Remove expired entry
                del self.cache[key]
                self.misses += 1
                return None
            
            self.hits += 1
            return entry.value
    
    def clear(self) -> None:
        """Clear all entries from cache."""
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0
    
    def _evict_lru(self) -> None:
        """Evict least recently used entry."""
        if not self.cache:
            return
        
        # Find LRU entry
        lru_key = min(
            self.cache.keys(),
            key=lambda k: self.cache[k].get_age_seconds()
        )
        del self.cache[lru_key]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self.lock:
            total_requests = self.hits + self.misses
            return {
                'size': len(self.cache),
                'max_size': self.config.cache_max_size,
                'hits': self.hits,
                'misses': self.misses,
                'hit_rate': self.hits / max(1, total_requests),
                'total_requests': total_requests,
            }


class ShardedValidationCache:
    """Sharded validation cache for high concurrency."""
    
    def __init__(self, config: SecurityValidatorConfig):
        """
        Initialize sharded cache.
        
        Args:
            config: Security validator configuration
        """
        self.config = config
        self.num_shards = config.cache_shards
        self.shards = [
            ValidationCache(config) 
            for _ in range(self.num_shards)
        ]
        self.global_lock = threading.Lock()
        self.global_hits = 0
        self.global_misses = 0
    
    def _get_shard(self, key: str) -> ValidationCache:
        """Get cache shard for a key."""
        # Use hash to distribute keys evenly
        shard_index = int(hashlib.sha256(key.encode()).hexdigest(), 16) % self.num_shards
        return self.shards[shard_index]
    
    def put(self, key: str, value: Any) -> None:
        """Store value in appropriate shard."""
        shard = self._get_shard(key)
        shard.put(key, value)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from appropriate shard."""
        shard = self._get_shard(key)
        result = shard.get(key)
        
        # Update global statistics
        with self.global_lock:
            if result is not None:
                self.global_hits += 1
            else:
                self.global_misses += 1
        
        return result
    
    def clear(self) -> None:
        """Clear all shards."""
        for shard in self.shards:
            shard.clear()
        
        with self.global_lock:
            self.global_hits = 0
            self.global_misses = 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get comprehensive cache statistics."""
        shard_stats = [shard.get_stats() for shard in self.shards]
        
        with self.global_lock:
            total_requests = self.global_hits + self.global_misses
            
            return {
                'num_shards': self.num_shards,
                'global_stats': {
                    'hits': self.global_hits,
                    'misses': self.global_misses,
                    'hit_rate': self.global_hits / max(1, total_requests),
                    'total_requests': total_requests,
                },
                'shard_stats': shard_stats,
                'aggregate': {
                    'total_size': sum(stats['size'] for stats in shard_stats),
                    'total_max_size': sum(stats['max_size'] for stats in shard_stats),
                    'total_hits': sum(stats['hits'] for stats in shard_stats),
                    'total_misses': sum(stats['misses'] for stats in shard_stats),
                },
            }
    
    def optimize_shards(self) -> Dict[str, Any]:
        """Optimize shard distribution based on usage patterns."""
        shard_stats = [shard.get_stats() for shard in self.shards]
        
        # Calculate load imbalance
        total_requests = sum(stats['total_requests'] for stats in shard_stats)
        avg_requests_per_shard = total_requests / self.num_shards
        
        imbalanced_shards = []
        for i, stats in enumerate(shard_stats):
            load_ratio = stats['total_requests'] / avg_requests_per_shard
            if load_ratio > 1.5 or load_ratio < 0.5:  # 50% imbalance threshold
                imbalanced_shards.append({
                    'shard_index': i,
                    'load_ratio': load_ratio,
                    'requests': stats['total_requests'],
                })
        
        return {
            'avg_requests_per_shard': avg_requests_per_shard,
            'imbalanced_shards': imbalanced_shards,
            'recommendation': (
                "Consider increasing num_shards" if imbalanced_shards 
                else "Shard distribution is balanced"
            ),
        }


class CacheWarmer:
    """Cache warming utility for common templates."""
    
    def __init__(self, cache: ShardedValidationCache):
        """Initialize cache warmer."""
        self.cache = cache
    
    def warm_common_templates(self, common_templates: List[Dict[str, Any]]) -> int:
        """
        Warm cache with commonly used templates.
        
        Args:
            common_templates: List of common template data
            
        Returns:
            Number of templates warmed
        """
        warmed_count = 0
        
        for template in common_templates:
            try:
                # This would need to be integrated with validation engine
                # For now, just simulate warming
                key = f"template_{template.get('id', 'unknown')}"
                self.cache.put(key, {"warmed": True})
                warmed_count += 1
            except Exception as e:
                # Log error but continue warming others
                print(f"Failed to warm template {template.get('id')}: {e}")
        
        return warmed_count
