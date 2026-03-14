"""
Debug rate limiter test.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'threatsimgpt'))

from threatsimgpt.security.rate_limiter import MultiTenantRateLimiter, RateLimitExceeded

def test_rate_limiter_debug():
    """Debug rate limiter test."""
    print("Testing rate limiter with debug...")
    
    limiter = MultiTenantRateLimiter(requests_per_minute=5)
    
    # Should allow first 5 requests
    for i in range(5):
        try:
            result = limiter.is_allowed(f"tenant{i}")
            print(f"Request {i}: {result}")
        except Exception as e:
            print(f"Request {i} failed: {e}")
            print(f"Exception type: {type(e)}")
    
    # 6th request should fail
    print("\nTesting 6th request...")
    try:
        result = limiter.is_allowed("tenant0")
        print(f"6th request: {result}")
        print("ERROR: Should have raised exception!")
    except RateLimitExceeded as e:
        print(f"✓ 6th request correctly blocked: {e}")
    except Exception as e:
        print(f"❌ 6th request raised unexpected exception: {type(e).__name__}: {e}")
    
    stats = limiter.get_stats()
    print(f"Stats: {stats}")

if __name__ == "__main__":
    test_rate_limiter_debug()
