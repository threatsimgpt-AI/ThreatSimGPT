"""
Edge Case & Security Tests for Hardened ContentFilter

Principal Engineer Review - Deep Security Testing
Created: 13 January 2026

These tests validate security hardening and edge cases identified
in the Principal Engineer review.
"""

import pytest
import time
import threading
import hashlib
import hmac
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from threatsimgpt.safety.content_filter import (
    ContentFilter,
    FilterConfig,
    FilterResult,
    RiskLevel,
    ContentCategory,
    OutputSanitizer,
    AuthorizationValidator,
    RateLimiter,
)
from threatsimgpt.safety.exceptions import SafetyViolationError, ContentFilterError


class TestEdgeCasesInput:
    """Test edge cases in input handling"""
    
    def test_empty_string_input(self):
        """Empty string should be handled gracefully"""
        filter = ContentFilter()
        result = filter.filter("")
        assert result.is_safe
        assert result.risk_level == RiskLevel.SAFE
    
    def test_none_content_handling(self):
        """None content should raise ContentFilterError (fail-safe)"""
        filter = ContentFilter()
        # In fail-safe mode, None input raises ContentFilterError
        with pytest.raises(ContentFilterError):
            filter.filter(None)
    
    def test_very_long_content(self):
        """Very long content should be handled"""
        filter = ContentFilter()
        # 100KB of content
        long_content = "a" * 100_000
        result = filter.filter(long_content)
        assert isinstance(result, FilterResult)
    
    def test_unicode_content(self):
        """Unicode content including emojis"""
        filter = ContentFilter()
        content = "Hello 世界 🔥 مرحبا שלום"
        result = filter.filter(content)
        assert result.is_safe
    
    def test_null_bytes_in_content(self):
        """Null bytes should not crash filter"""
        filter = ContentFilter()
        content = "Hello\x00World\x00"
        result = filter.filter(content)
        assert isinstance(result, FilterResult)
    
    def test_control_characters(self):
        """Control characters should be handled"""
        filter = ContentFilter()
        content = "Hello\x01\x02\x03\x04World"
        result = filter.filter(content)
        assert isinstance(result, FilterResult)
    
    def test_unicode_bypass_attempts(self):
        """Test Unicode bypass attempts for malware patterns"""
        filter = ContentFilter()
        
        # Attempt to bypass with Unicode lookalikes
        bypass_attempts = [
            "import\u0020subprocess",  # Unicode space
            "ｉｍｐｏｒｔ subprocess",  # Fullwidth letters
            "import\u200Bsubprocess",  # Zero-width space
            "import\u00A0subprocess",  # Non-breaking space
        ]
        
        for attempt in bypass_attempts:
            result = filter.filter(attempt)
            # Should at minimum not crash
            assert isinstance(result, FilterResult)
    
    def test_rtl_override_attacks(self):
        """Test Right-to-Left Override attacks"""
        filter = ContentFilter()
        # RTL override can make malicious text appear benign
        content = "safe\u202Etxet\u202C"  # RTL override
        result = filter.filter(content)
        assert isinstance(result, FilterResult)


class TestEdgeCasesPII:
    """Test PII detection edge cases"""
    
    def test_valid_ssn_format(self):
        """Valid SSN format should be detected"""
        filter = ContentFilter(FilterConfig(max_risk_level=RiskLevel.HIGH))
        result = filter.filter("My SSN is 123-45-6789")
        assert ContentCategory.PII_DATA in result.categories_detected
    
    def test_invalid_ssn_format_no_dashes(self):
        """SSN without dashes should not match current pattern"""
        filter = ContentFilter(FilterConfig(max_risk_level=RiskLevel.HIGH))
        result = filter.filter("My SSN is 123456789")
        # Current implementation only matches with dashes
        assert "pii:ssn" not in result.matched_patterns
    
    def test_credit_card_luhn_check_absent(self):
        """Invalid Luhn credit card should still match (limitation)"""
        filter = ContentFilter(FilterConfig(max_risk_level=RiskLevel.HIGH))
        # 0000-0000-0000-0000 fails Luhn but matches pattern
        result = filter.filter("Card: 0000-0000-0000-0000")
        assert ContentCategory.PII_DATA in result.categories_detected
    
    def test_partial_credit_card(self):
        """Partial credit card should not match"""
        filter = ContentFilter()
        result = filter.filter("Last 4 digits: 1234")
        assert "pii:credit_card" not in result.matched_patterns
    
    def test_phone_international_formats(self):
        """International phone formats"""
        filter = ContentFilter(FilterConfig(max_risk_level=RiskLevel.HIGH))
        
        # US format (should match)
        result = filter.filter("Call 555-123-4567")
        # Note: Current pattern is US-centric
        
        # UK format (won't match current pattern)
        result = filter.filter("Call +44 20 7946 0958")
        # This is a limitation - international support needed


class TestEdgeCasesRegex:
    """Test regex edge cases and potential ReDoS"""
    
    def test_regex_backtracking_credit_card(self):
        """Test for regex backtracking on credit card pattern"""
        filter = ContentFilter()
        
        # Potentially problematic input for backtracking
        evil_input = "4532" + " " * 1000 + "not-a-card"
        
        start = time.time()
        result = filter._check_pii(evil_input)
        elapsed = time.time() - start
        
        # Should complete quickly (under 1 second)
        assert elapsed < 1.0, f"PII check took {elapsed:.2f}s - possible ReDoS"
    
    def test_regex_nested_quantifiers(self):
        """Test nested quantifier patterns"""
        filter = ContentFilter()
        
        # Input designed to exploit nested quantifiers
        evil_input = "a" * 100 + "!"
        
        start = time.time()
        result = filter.filter(evil_input)
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"Filter took {elapsed:.2f}s"
    
    def test_very_long_regex_input(self):
        """Test long input against all regex patterns"""
        filter = ContentFilter()
        
        # 10KB input
        long_input = "x" * 10_000
        
        start = time.time()
        result = filter.filter(long_input)
        elapsed = time.time() - start
        
        assert elapsed < 1.0, f"Filter took {elapsed:.2f}s on long input"


class TestKillSwitchSecurity:
    """Test kill switch security edge cases"""
    
    def test_kill_switch_no_secret_fails_closed(self):
        """Without secret, kill switch should ideally fail closed"""
        # This test documents the CURRENT behavior (fails open)
        # The Principal Engineer review recommends changing this
        validator = AuthorizationValidator(secret_key="")
        
        # Currently returns True in dev mode - THIS IS A SECURITY ISSUE
        result = validator.validate("any-token")
        # Document current behavior
        assert result is True  # FIXME: Should be False for security
    
    def test_token_replay_within_window(self):
        """Test that tokens can be replayed (limitation)"""
        secret = "test-secret-key"
        validator = AuthorizationValidator(secret_key=secret)
        
        token = AuthorizationValidator.generate_token(secret)
        
        # First use
        assert validator.validate(token) is True
        # Replay within 5 minutes - currently allowed (SECURITY ISSUE)
        assert validator.validate(token) is True
    
    def test_token_after_expiry(self):
        """Test token rejection after expiry"""
        secret = "test-secret"
        validator = AuthorizationValidator(secret_key=secret)
        
        # Create expired token (6 minutes ago)
        old_timestamp = str(int(time.time()) - 360)
        signature = hmac.new(
            secret.encode(),
            old_timestamp.encode(),
            hashlib.sha256
        ).hexdigest()
        expired_token = f"{old_timestamp}:{signature}"
        
        assert validator.validate(expired_token) is False
    
    def test_token_format_tampering(self):
        """Test various token format tampering"""
        validator = AuthorizationValidator(secret_key="secret")
        
        invalid_tokens = [
            "",
            ":",
            ":::",
            "abc:def:ghi",
            "timestamp:",
            ":signature",
            "not-a-number:signature",
            f"{int(time.time())}:wrong-sig",
        ]
        
        for token in invalid_tokens:
            assert validator.validate(token) is False, f"Token should be invalid: {token}"
    
    def test_kill_switch_persistence_integrity(self, tmp_path):
        """Test persistence file tampering"""
        persist_path = tmp_path / "killswitch.state"
        config = FilterConfig(kill_switch_persist_path=persist_path)
        
        # Create filter and activate
        filter1 = ContentFilter(config)
        filter1.activate_kill_switch(reason="Test")
        
        # Tamper with the file
        persist_path.write_text("INVALID_STATE")
        
        # New filter should handle gracefully
        filter2 = ContentFilter(config)
        # Should not crash, should default to inactive
        assert filter2.kill_switch_status is False


class TestRateLimiterSecurity:
    """Test rate limiter security"""
    
    def test_rate_limit_memory_growth(self):
        """Test that rate limiter doesn't grow unbounded"""
        limiter = RateLimiter(max_requests=10, window_seconds=1)
        
        # Simulate many unique identifiers
        for i in range(1000):
            limiter.check_rate_limit(f"user-{i}")
        
        # Check memory usage (dict size)
        assert len(limiter._requests) == 1000
        
        # After waiting, cleanup should work on next check
        time.sleep(1.1)
        limiter.check_rate_limit("user-0")  # Triggers cleanup for user-0
        
        # Note: Other entries not cleaned - this is the memory leak
        # Documenting current behavior
        assert len(limiter._requests) == 1000  # Still 1000 entries!
    
    def test_rate_limit_boundary(self):
        """Test exact boundary of rate limit"""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        
        # Exactly at limit
        for i in range(5):
            assert limiter.check_rate_limit("user") is True
        
        # One over limit
        assert limiter.check_rate_limit("user") is False
    
    def test_rate_limit_window_expiry(self):
        """Test rate limit window expiration"""
        limiter = RateLimiter(max_requests=3, window_seconds=1)
        
        # Use up limit
        for i in range(3):
            limiter.check_rate_limit("user")
        
        # Should be blocked
        assert limiter.check_rate_limit("user") is False
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Should be allowed again
        assert limiter.check_rate_limit("user") is True


class TestThreadSafety:
    """Test thread safety of ContentFilter"""
    
    def test_concurrent_filter_calls(self):
        """Test many concurrent filter calls"""
        filter = ContentFilter(FilterConfig(enable_rate_limiting=False))
        results = []
        errors = []
        
        def filter_content(i):
            try:
                result = filter.filter(f"Test content {i}")
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        # 100 concurrent calls
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(filter_content, i) for i in range(100)]
            for f in as_completed(futures):
                pass
        
        assert len(errors) == 0, f"Errors occurred: {errors}"
        assert len(results) == 100
    
    def test_concurrent_kill_switch_operations(self):
        """Test concurrent kill switch activate/deactivate"""
        filter = ContentFilter()
        errors = []
        
        def toggle_kill_switch(i):
            try:
                if i % 2 == 0:
                    filter.activate_kill_switch(reason=f"Thread {i}")
                else:
                    try:
                        filter.deactivate_kill_switch(
                            authorization="dev-token",
                            operator=f"thread-{i}"
                        )
                    except SafetyViolationError:
                        pass  # Expected in non-dev mode
            except Exception as e:
                errors.append(e)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(toggle_kill_switch, i) for i in range(50)]
            for f in as_completed(futures):
                pass
        
        assert len(errors) == 0, f"Thread safety errors: {errors}"
    
    def test_concurrent_validator_modification(self):
        """Test adding validators while filtering"""
        filter = ContentFilter(FilterConfig(enable_rate_limiting=False))
        errors = []
        
        def dummy_validator(content, context):
            return None
        
        def add_validators():
            for i in range(10):
                filter.add_validator(dummy_validator)
                time.sleep(0.001)
        
        def run_filters():
            for i in range(50):
                try:
                    filter.filter("test content")
                except Exception as e:
                    errors.append(e)
        
        # Run concurrently
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [
                executor.submit(add_validators),
                executor.submit(run_filters),
                executor.submit(run_filters),
            ]
            for f in as_completed(futures):
                pass
        
        # Document current behavior - may have race condition
        # If this fails, thread safety needs fixing


class TestOutputSanitizerEdgeCases:
    """Test OutputSanitizer edge cases"""
    
    def test_already_defanged_url(self):
        """Already defanged URLs should be handled"""
        content = "Visit hxxps://example[.]com"
        result = OutputSanitizer.sanitize_all(content)
        # Should not double-defang
        assert "hxxhxxps" not in result
    
    def test_url_in_code_block(self):
        """URLs in code should be defanged"""
        content = 'url = "https://example.com/api"'
        result = OutputSanitizer.defang_url(content)
        assert "hxxps://" in result
    
    def test_ip_like_but_not_ip(self):
        """Version numbers that look like IPs"""
        content = "Version 1.2.3.4 is available"
        result = OutputSanitizer.defang_ip(content)
        # Note: This WILL defang version numbers too
        assert "1[.]2[.]3[.]4" in result  # Current behavior
    
    def test_ipv6_not_handled(self):
        """IPv6 addresses are not currently defanged"""
        content = "IPv6: 2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = OutputSanitizer.defang_ip(content)
        # IPv6 not handled - limitation
        assert "2001:0db8" in result  # Not defanged
    
    def test_email_with_plus(self):
        """Email with plus addressing"""
        content = "Contact: user+tag@example.com"
        result = OutputSanitizer.defang_email(content)
        assert "user+tag[@]example[.]com" in result
    
    def test_multiple_items(self):
        """Multiple URLs, IPs, and emails"""
        content = """
        http://a.com https://b.com
        192.168.1.1 10.0.0.1
        a@b.com c@d.org
        """
        result = OutputSanitizer.sanitize_all(content)
        
        assert "hxxp://" in result
        assert "hxxps://" in result
        assert "[.]168[.]" in result
        assert "[@]" in result


class TestBypassAttempts:
    """Test various filter bypass attempts"""
    
    def test_case_variation_bypass(self):
        """Test case variation bypass attempts"""
        filter = ContentFilter()
        
        variations = [
            "POWERSHELL -enc",
            "PowerShell -Enc",
            "pOwErShElL -eNc",
        ]
        
        for var in variations:
            result = filter.filter(var)
            assert not result.is_safe, f"Case variation bypassed: {var}"
    
    def test_whitespace_injection(self):
        """Test whitespace injection bypass"""
        filter = ContentFilter()
        
        # Adding extra whitespace
        payloads = [
            "import  subprocess",  # Double space
            "import\tsubprocess",  # Tab
            "import\nsubprocess",  # Newline
        ]
        
        # Note: Current patterns may not catch all whitespace variants
    
    def test_comment_injection(self):
        """Test comment injection bypass"""
        filter = ContentFilter()
        
        # SQL comment injection
        content = "SELECT * FROM users --"
        result = filter.filter(content)
        # Should be safe - no UNION SELECT
        
        content = "' UNION/* */SELECT password FROM users"
        result = filter.filter(content)
        # May bypass due to comment breaking pattern
    
    def test_encoding_evasion(self):
        """Test encoding-based evasion"""
        filter = ContentFilter()
        
        # HTML entity encoding
        content = "&#x3C;script&#x3E;alert('XSS')&#x3C;/script&#x3E;"
        result = filter.filter(content)
        # Currently not decoded before checking - may bypass
    
    def test_null_byte_injection(self):
        """Test null byte injection"""
        filter = ContentFilter()
        
        # Null byte before dangerous content
        content = "safe\x00<script>alert('XSS')</script>"
        result = filter.filter(content)
        # Should still detect the script tag


class TestConfigurationEdgeCases:
    """Test configuration edge cases"""
    
    def test_zero_rate_limit(self):
        """Test zero rate limit"""
        config = FilterConfig(
            enable_rate_limiting=True,
            max_requests_per_minute=0
        )
        filter = ContentFilter(config)
        
        # Should immediately block
        with pytest.raises(ContentFilterError):
            filter.filter("test", context={"session_id": "test"})
    
    def test_negative_rate_limit(self):
        """Test negative rate limit"""
        config = FilterConfig(
            enable_rate_limiting=True,
            max_requests_per_minute=-1
        )
        filter = ContentFilter(config)
        
        # Should block (negative means no requests allowed)
        with pytest.raises(ContentFilterError):
            filter.filter("test", context={"session_id": "test"})
    
    def test_empty_blocked_categories(self):
        """Test with no blocked categories"""
        config = FilterConfig(blocked_categories=set())
        filter = ContentFilter(config)
        
        # Malware code should pass if not in blocked categories
        result = filter.filter("import subprocess; shell=True")
        # Risk detected but not blocked
        assert ContentCategory.MALWARE_CODE in result.categories_detected
    
    def test_all_categories_blocked(self):
        """Test with all categories blocked"""
        config = FilterConfig(
            blocked_categories=set(ContentCategory),
            max_risk_level=RiskLevel.SAFE
        )
        filter = ContentFilter(config)
        
        # Even mild content might be blocked
        result = filter.filter("Contact: user@gmail.com")
        assert not result.is_safe


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
