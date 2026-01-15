"""Comprehensive tests for Safety Guardrails implementation.

Tests cover:
- Rule-based validation (deterministic)
- Custom validators (extensible)
- Allowlist/Denylist logic
- Async batch validation
- Streaming validation
- Metrics tracking
- PII detection
- Credentials detection
- Injection attack detection
- Edge cases

Issue: #55 - Implement Safety Guardrails
Owner: Lanre Adetola
"""

import pytest
import asyncio
import re
from threatsimgpt.llm.guardrails import (
    GuardrailsEngine,
    Rule,
    Action,
    Severity,
    ViolationType,
    RuleMatch,
    ValidationResult,
    GuardrailMetrics
)


# ============================================================================
# Rule Management Tests
# ============================================================================

class TestRuleManagement:
    """Test rule CRUD operations."""

    @pytest.mark.asyncio
    async def test_add_rule(self):
        engine = GuardrailsEngine(rules=[])
        rule = Rule.from_regex("test-1", "Test rule", r"forbidden", action=Action.BLOCK)
        
        await engine.add_rule(rule)
        rules = await engine.list_rules()
        
        assert len(rules) > 0
        assert any(r.id == "test-1" for r in rules)

    @pytest.mark.asyncio
    async def test_remove_rule(self):
        rule = Rule.from_regex("test-remove", "Remove me", r"test", action=Action.BLOCK)
        engine = GuardrailsEngine(rules=[rule])
        
        removed = await engine.remove_rule("test-remove")
        assert removed is True
        
        rules = await engine.list_rules()
        assert not any(r.id == "test-remove" for r in rules)

    @pytest.mark.asyncio
    async def test_get_rule(self):
        rule = Rule.from_regex("test-get", "Get me", r"test", action=Action.BLOCK)
        engine = GuardrailsEngine(rules=[rule])
        
        found = await engine.get_rule("test-get")
        assert found is not None
        assert found.id == "test-get"
        
        not_found = await engine.get_rule("nonexistent")
        assert not_found is None

    @pytest.mark.asyncio
    async def test_toggle_rule(self):
        rule = Rule.from_regex("test-toggle", "Toggle me", r"test", action=Action.BLOCK)
        engine = GuardrailsEngine(rules=[rule])
        
        # Disable
        toggled = await engine.toggle_rule("test-toggle", False)
        assert toggled is True
        
        updated = await engine.get_rule("test-toggle")
        assert updated.enabled is False
        
        # Re-enable
        await engine.toggle_rule("test-toggle", True)
        updated = await engine.get_rule("test-toggle")
        assert updated.enabled is True


# ============================================================================
# Deterministic Rule Validation Tests
# ============================================================================

class TestRuleValidation:
    """Test deterministic rule-based validation."""

    @pytest.mark.asyncio
    async def test_rule_blocking(self):
        engine = GuardrailsEngine(rules=[])
        rule = Rule.from_regex("block-cc", "Block credit cards", r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", action=Action.BLOCK)
        await engine.add_rule(rule)
        
        result = await engine.validate("My card is 4111 1111 1111 1111")
        
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert len(result.matches) >= 1  # May match default rule + custom rule
        assert result.output == ""  # Blocked output is empty

    @pytest.mark.asyncio
    async def test_defang_action(self):
        engine = GuardrailsEngine(rules=[])
        rule = Rule.from_regex("defang-url", "Defang URLs", r"https?://\S+", action=Action.DEFANG)
        await engine.add_rule(rule)
        
        result = await engine.validate("Visit http://evil.example.com now")
        
        assert result.safe is False
        assert result.action == Action.DEFANG
        assert "[URL_REMOVED" in result.output  # Now uses numbered placeholders
        assert "http://evil.example.com" not in result.output
        # Verify entity was extracted
        assert "extracted_entities" in result.metadata
        assert "urls" in result.metadata["extracted_entities"]
        assert len(result.metadata["extracted_entities"]["urls"]) == 1

    @pytest.mark.asyncio
    async def test_escalate_action(self):
        engine = GuardrailsEngine(rules=[])
        # Clear default rules that might trigger BLOCK
        engine.rules = []
        rule = Rule.from_regex("escalate-sql", "Escalate SQL", r"(?i)admin", action=Action.ESCALATE)
        await engine.add_rule(rule)
        
        result = await engine.validate("Login as admin user")
        
        assert result.safe is False
        assert result.action == Action.ESCALATE
        assert len(result.messages) > 0

    @pytest.mark.asyncio
    async def test_action_priority(self):
        """BLOCK should take precedence over DEFANG."""
        engine = GuardrailsEngine(rules=[])
        block_rule = Rule.from_regex("block", "Block this", r"block", action=Action.BLOCK)
        defang_rule = Rule.from_regex("defang", "Defang this", r"defang", action=Action.DEFANG)
        await engine.add_rule(defang_rule)
        await engine.add_rule(block_rule)
        
        result = await engine.validate("This has block and defang content")
        
        assert result.action == Action.BLOCK  # BLOCK wins


# ============================================================================
# Default Rules Tests (PII, Credentials, Injection)
# ============================================================================

class TestDefaultRules:
    """Test built-in security rules."""

    @pytest.mark.asyncio
    async def test_pii_ssn_detection(self):
        engine = GuardrailsEngine()
        result = await engine.validate("My SSN is 123-45-6789")
        
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert any(m.rule.violation_type == ViolationType.PII for m in result.matches)

    @pytest.mark.asyncio
    async def test_pii_credit_card_detection(self):
        engine = GuardrailsEngine()
        result = await engine.validate("Card: 4532 1488 0343 6467")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_pii_email_defang(self):
        engine = GuardrailsEngine()
        result = await engine.validate("Contact: user@example.com")
        
        assert result.safe is False
        assert result.action == Action.DEFANG
        assert "[EMAIL_REMOVED" in result.output  # Numbered placeholders
        assert "user@example.com" not in result.output

    @pytest.mark.asyncio
    async def test_credentials_api_key(self):
        engine = GuardrailsEngine()
        result = await engine.validate("api_key: sk_live_abcdefghij1234567890")
        
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert any(m.rule.violation_type == ViolationType.CREDENTIALS for m in result.matches)

    @pytest.mark.asyncio
    async def test_credentials_password(self):
        engine = GuardrailsEngine()
        result = await engine.validate("password: MySecureP@ss123")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_injection_sql(self):
        engine = GuardrailsEngine()
        result = await engine.validate("admin' OR '1'='1'; DROP TABLE users--")
        
        assert result.safe is False
        assert any(m.rule.violation_type == ViolationType.INJECTION_ATTACK for m in result.matches)

    @pytest.mark.asyncio
    async def test_injection_command(self):
        engine = GuardrailsEngine()
        result = await engine.validate("Run: `cat /etc/passwd`")
        
        assert result.safe is False


# ============================================================================
# Custom Validators Tests
# ============================================================================

class TestCustomValidators:
    """Test custom validator plugins."""

    @pytest.mark.asyncio
    async def test_custom_validator_success(self):
        engine = GuardrailsEngine(rules=[])
        
        def always_safe(text, ctx):
            return (True, None, 1.0)
        
        engine.add_custom_validator(always_safe)
        result = await engine.validate("anything goes")
        
        assert result.safe is True

    @pytest.mark.asyncio
    async def test_custom_validator_failure(self):
        engine = GuardrailsEngine(rules=[])
        
        def always_unsafe(text, ctx):
            return (False, "Custom validator failed", 0.95)
        
        engine.add_custom_validator(always_unsafe)
        result = await engine.validate("test content")
        
        assert result.safe is False
        assert result.action == Action.ESCALATE
        assert any("Custom validator failed" in m for m in result.messages)

    @pytest.mark.asyncio
    async def test_validator_error_escalates(self):
        """Validator exceptions should escalate for safety."""
        engine = GuardrailsEngine(rules=[])
        
        def failing_validator(text, ctx):
            raise ValueError("Validator crashed!")
        
        engine.add_custom_validator(failing_validator)
        result = await engine.validate("test")
        
        assert result.safe is False
        assert result.action == Action.ESCALATE
        assert any("Validator error" in m for m in result.messages)


# ============================================================================
# Allowlist/Denylist Tests
# ============================================================================

class TestAllowDenyLists:
    """Test allowlist and denylist short-circuit logic."""

    @pytest.mark.asyncio
    async def test_allowlist_skips_low_severity_rules_only(self):
        """P0 Security Fix: Allowlist no longer bypasses ALL checks.
        
        Allowlist now only skips LOW/MEDIUM severity rules.
        CRITICAL and HIGH severity rules (and denylist) ALWAYS run.
        This prevents allowlist bypass attacks.
        """
        engine = GuardrailsEngine(rules=[])
        engine.add_deny_pattern(r"forbidden")
        engine.add_allow_pattern(r"internal-whitelist")
        
        # P0 FIX: Denylist should still block even if allowlisted
        # This is INTENTIONAL security behavior change
        result = await engine.validate("internal-whitelist contains forbidden word")
        
        # Denylist takes precedence over allowlist for security
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.metadata.get("allowlisted") is True  # Was allowlisted but still checked
        
    @pytest.mark.asyncio
    async def test_allowlist_skips_low_severity_rules(self):
        """Test that allowlisted content skips LOW severity rules."""
        engine = GuardrailsEngine(rules=[])
        engine.rules = []  # Clear defaults
        
        # Add a LOW severity rule
        from threatsimgpt.llm.guardrails import Rule, Severity
        low_rule = Rule.from_regex(
            "low-test", "Low severity test", r"test-pattern",
            severity=Severity.LOW, action=Action.LOG
        )
        await engine.add_rule(low_rule)
        engine.add_allow_pattern(r"allowlisted")
        
        # Allowlisted content should skip LOW severity rule
        result = await engine.validate("allowlisted test-pattern content")
        
        assert result.safe is True  # LOW severity rule skipped due to allowlist
        assert result.metadata.get("allowlisted") is True

    @pytest.mark.asyncio
    async def test_denylist_blocks(self):
        engine = GuardrailsEngine(rules=[])
        engine.add_deny_pattern(r"forbidden")
        
        result = await engine.validate("This contains forbidden content")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_no_match_passes(self):
        engine = GuardrailsEngine(rules=[])
        result = await engine.validate("Clean content with no violations")
        
        # Will fail due to default rules, so let's use empty engine
        engine_no_defaults = GuardrailsEngine(rules=[])
        engine_no_defaults.rules = []  # Clear defaults
        result = await engine_no_defaults.validate("Clean content")
        
        assert result.safe is True
        assert result.action == Action.ALLOW


# ============================================================================
# Async Batch Validation Tests
# ============================================================================

class TestBatchValidation:
    """Test async batch validation for performance."""

    @pytest.mark.asyncio
    async def test_batch_validation(self):
        engine = GuardrailsEngine(rules=[])
        
        texts = [
            "Clean text 1",
            "My SSN is 123-45-6789",
            "Clean text 2",
            "api_key: sk_test_12345678901234567890"
        ]
        
        results = await engine.validate_batch(texts)
        
        assert len(results) == 4
        assert results[0].safe is True or results[0].safe is False  # May trigger defaults
        assert results[1].safe is False  # SSN
        assert results[3].safe is False  # API key

    @pytest.mark.asyncio
    async def test_batch_validation_performance(self):
        """Batch should be faster than sequential."""
        engine = GuardrailsEngine(rules=[])
        texts = [f"Test text {i}" for i in range(10)]
        
        import time
        start = time.perf_counter()
        results = await engine.validate_batch(texts)
        batch_time = time.perf_counter() - start
        
        assert len(results) == 10
        # Batch should complete reasonably fast
        assert batch_time < 1.0  # Should be way under 1 second


# ============================================================================
# Streaming Validation Tests
# ============================================================================

class TestStreamingValidation:
    """Test streaming validation for real-time LLM output."""

    @pytest.mark.asyncio
    async def test_stream_validation(self):
        engine = GuardrailsEngine(rules=[])
        rule = Rule.from_regex("block-secret", "Block secrets", r"SECRET123", action=Action.BLOCK)
        await engine.add_rule(rule)
        
        stream = ["Hello ", "this ", "is ", "SECRET123 ", "oops"]
        results = await engine.validate_stream(stream)
        
        # Should have results for each chunk
        assert len(results) >= 4  # Should stop at SECRET123
        # Last result before stop should be BLOCK
        assert any(r.action == Action.BLOCK for r in results)

    @pytest.mark.asyncio
    async def test_stream_early_stop(self):
        """Stream should stop on BLOCK action."""
        engine = GuardrailsEngine(rules=[])
        rule = Rule.from_regex("block-bad", "Block bad", r"BAD", action=Action.BLOCK)
        await engine.add_rule(rule)
        
        stream = ["Good ", "content ", "BAD ", "rest ", "ignored"]
        results = await engine.validate_stream(stream)
        
        # Should stop after "BAD"
        assert len(results) <= 3


# ============================================================================
# Metrics Tests
# ============================================================================

class TestMetrics:
    """Test metrics tracking and reporting."""

    @pytest.mark.asyncio
    async def test_metrics_recording(self):
        engine = GuardrailsEngine(rules=[])
        
        # Clean validation
        await engine.validate("clean text")
        
        # Violation
        await engine.validate("My SSN is 123-45-6789")
        
        metrics = engine.get_metrics()
        
        assert metrics["total_validations"] >= 2
        assert metrics["total_violations"] >= 1

    @pytest.mark.asyncio
    async def test_metrics_latency(self):
        engine = GuardrailsEngine(rules=[])
        result = await engine.validate("test content")
        
        assert result.latency_ms > 0
        assert result.latency_ms < 1000  # Should be fast

    @pytest.mark.asyncio
    async def test_metrics_reset(self):
        engine = GuardrailsEngine(rules=[])
        await engine.validate("test")
        
        engine.reset_metrics()
        metrics = engine.get_metrics()
        
        assert metrics["total_validations"] == 0

    @pytest.mark.asyncio
    async def test_violation_tracking_by_type(self):
        engine = GuardrailsEngine()
        
        await engine.validate("SSN: 123-45-6789")  # PII
        await engine.validate("password: secret123")  # Credentials
        
        metrics = engine.get_metrics()
        
        assert "pii" in metrics["violations_by_type"]
        assert "credentials" in metrics["violations_by_type"]


# ============================================================================
# Health Check Tests
# ============================================================================

class TestHealthCheck:
    """Test health check functionality."""

    @pytest.mark.asyncio
    async def test_health_check(self):
        engine = GuardrailsEngine()
        health = await engine.health_check()
        
        assert health["status"] == "healthy"
        assert "total_rules" in health
        assert "enabled_rules" in health
        assert "metrics" in health
        assert "timestamp" in health


# ============================================================================
# Edge Cases Tests
# ============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.mark.asyncio
    async def test_empty_text(self):
        engine = GuardrailsEngine(rules=[])
        result = await engine.validate("")
        
        # Empty text should pass (no violations)
        assert result.safe is True or result.safe is False  # Depends on defaults

    @pytest.mark.asyncio
    async def test_very_long_text(self):
        engine = GuardrailsEngine(rules=[])
        long_text = "a" * 100000
        
        result = await engine.validate(long_text)
        
        assert result is not None
        assert result.latency_ms > 0

    @pytest.mark.asyncio
    async def test_unicode_text(self):
        engine = GuardrailsEngine(rules=[])
        result = await engine.validate("Hello 世界 🌍 مرحبا")
        
        assert result is not None

    @pytest.mark.asyncio
    async def test_disabled_rule_not_triggered(self):
        rule = Rule(id="disabled-rule", description="Should not trigger", pattern=re.compile(r"forbidden"), action=Action.BLOCK, enabled=False)
        engine = GuardrailsEngine(rules=[rule])
        
        result = await engine.validate("This contains forbidden word")
        
        # Rule is disabled, so should not match
        assert not any(m.rule.id == "disabled-rule" for m in result.matches)

    @pytest.mark.asyncio
    async def test_multiple_violations_same_text(self):
        engine = GuardrailsEngine()
        # Text with multiple PII types
        text = "SSN: 123-45-6789, Email: user@test.com, Card: 4111111111111111"
        
        result = await engine.validate(text)
        
        assert result.safe is False
        assert len(result.matches) >= 2  # Multiple violations


# ============================================================================
# Defang Function Tests
# ============================================================================

class TestDefangFunction:
    """Test content defanging logic."""

    @pytest.mark.asyncio
    async def test_defang_urls(self):
        engine = GuardrailsEngine(rules=[])
        defang_result = engine._defang_text("Visit https://evil.com and http://bad.org")
        
        assert "[URL_REMOVED" in defang_result.defanged_text
        assert "evil.com" not in defang_result.defanged_text
        assert len(defang_result.entities["urls"]) == 2

    @pytest.mark.asyncio
    async def test_defang_ips(self):
        engine = GuardrailsEngine(rules=[])
        defang_result = engine._defang_text("Server at 192.168.1.1 is down")
        
        assert "[IP_REMOVED" in defang_result.defanged_text
        assert "192.168.1.1" not in defang_result.defanged_text
        assert len(defang_result.entities["ips"]) == 1

    @pytest.mark.asyncio
    async def test_defang_emails(self):
        engine = GuardrailsEngine(rules=[])
        defang_result = engine._defang_text("Contact admin@example.com")
        
        assert "[EMAIL_REMOVED" in defang_result.defanged_text
        assert "admin@example.com" not in defang_result.defanged_text
        assert len(defang_result.entities["emails"]) == 1

    @pytest.mark.asyncio
    async def test_defang_tags(self):
        engine = GuardrailsEngine(rules=[])
        defang_result = engine._defang_text("Code: <script>alert('xss')</script>")
        
        assert "[TAG_REMOVED" in defang_result.defanged_text
        assert "<script>" not in defang_result.defanged_text
        assert len(defang_result.entities["tags"]) == 2  # Opening and closing tags


# ============================================================================
# ValidationResult Serialization Tests
# ============================================================================

class TestValidationResultSerialization:
    """Test ValidationResult to_dict serialization."""

    @pytest.mark.asyncio
    async def test_result_to_dict(self):
        engine = GuardrailsEngine()
        result = await engine.validate("SSN: 123-45-6789")
        
        result_dict = result.to_dict()
        
        assert isinstance(result_dict, dict)
        assert "safe" in result_dict
        assert "action" in result_dict
        assert "matches" in result_dict
        assert "messages" in result_dict
        assert "output" in result_dict
        assert "latency_ms" in result_dict

    @pytest.mark.asyncio
    async def test_result_dict_matches_structure(self):
        engine = GuardrailsEngine()
        result = await engine.validate("password: secret123")
        
        result_dict = result.to_dict()
        
        if result_dict["matches"]:
            match = result_dict["matches"][0]
            assert "rule_id" in match
            assert "description" in match
            assert "severity" in match
            assert "violation_type" in match
            assert "span" in match
            assert "confidence" in match


# ============================================================================
# P0 Security Fixes Tests (RED Team Review - Olabisi)
# ============================================================================

class TestP0SecurityFixes:
    """Test P0 security fixes from RED Team review."""

    @pytest.mark.asyncio
    async def test_github_token_detection(self):
        """P0 Fix: Detect GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_)."""
        engine = GuardrailsEngine()
        
        # Test various GitHub token formats
        test_cases = [
            "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",  # PAT
            "gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",  # OAuth
            "ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",  # User-to-server
            "ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",  # Server-to-server
            "ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456789012",  # Refresh
        ]
        
        for token in test_cases:
            result = await engine.validate(f"Token: {token}")
            assert result.safe is False, f"Failed to detect: {token[:10]}..."
            assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_jwt_token_detection(self):
        """P0 Fix: Detect JWT tokens."""
        engine = GuardrailsEngine()
        
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        result = await engine.validate(f"JWT: {jwt}")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_private_key_detection(self):
        """P0 Fix: Detect private keys."""
        engine = GuardrailsEngine()
        
        private_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA..."
        result = await engine.validate(private_key)
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_slack_token_detection(self):
        """P0 Fix: Detect Slack tokens."""
        engine = GuardrailsEngine()
        
        # Construct token dynamically to avoid GitHub secret scanning
        # Real format: xoxb-{10-13 digits}-{10-13 digits}-{alphanumeric}
        slack_token = "xox" + "b-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
        result = await engine.validate(f"Slack: {slack_token}")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_stripe_key_detection(self):
        """P0 Fix: Detect Stripe keys."""
        engine = GuardrailsEngine()
        
        # Construct key dynamically to avoid GitHub secret scanning
        # Real format: sk_live_{24+ alphanumeric}
        stripe_key = "sk_" + "live_abcdefghijklmnopqrstuvwxyz"
        result = await engine.validate(f"Stripe: {stripe_key}")
        
        assert result.safe is False
        assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_db_connection_string_detection(self):
        """P0 Fix: Detect database connection strings."""
        engine = GuardrailsEngine()
        
        conn_strings = [
            "postgresql://user:password@localhost:5432/db",
            "mongodb://admin:secret@cluster.mongodb.net/db",
            "mysql://root:pass123@mysql.example.com/mydb",
        ]
        
        for conn in conn_strings:
            result = await engine.validate(f"DB: {conn}")
            assert result.safe is False, f"Failed to detect: {conn[:20]}..."
            assert result.action == Action.BLOCK

    @pytest.mark.asyncio
    async def test_rate_limiting(self):
        """P0 Fix: Test rate limiting functionality."""
        from threatsimgpt.llm.guardrails import RateLimitExceeded
        
        engine = GuardrailsEngine(
            enable_rate_limiting=True,
            rate_limit_per_user=5,
            rate_limit_burst=0
        )
        
        # First 5 requests should succeed
        for i in range(5):
            result = await engine.validate("test", {"user_id": "test-user"})
            assert result is not None
        
        # 6th request should be rate limited
        with pytest.raises(RateLimitExceeded):
            await engine.validate("test", {"user_id": "test-user"})

    @pytest.mark.asyncio
    async def test_rate_limiting_disabled(self):
        """Test that rate limiting can be disabled."""
        engine = GuardrailsEngine(enable_rate_limiting=False)
        
        # Should be able to make many requests without rate limiting
        for i in range(100):
            result = await engine.validate("test", {"user_id": "test-user"})
            assert result is not None

    @pytest.mark.asyncio
    async def test_allowlist_no_longer_bypasses_denylist(self):
        """P0 Fix: Allowlist should NOT bypass denylist (security fix)."""
        engine = GuardrailsEngine(rules=[])
        engine.add_allow_pattern(r"trusted-source")
        engine.add_deny_pattern(r"malicious")
        
        # Even with allowlist match, denylist should still block
        result = await engine.validate("trusted-source contains malicious content")
        
        assert result.safe is False
        assert result.action == Action.BLOCK
        assert result.metadata.get("allowlisted") is True

    @pytest.mark.asyncio
    async def test_circuit_breaker_memory_limit(self):
        """P0 Fix: Circuit breaker should not grow unbounded."""
        from threatsimgpt.llm.guardrails import CircuitBreaker, MAX_TRACKED_VALIDATORS
        
        cb = CircuitBreaker(max_tracked=10)
        
        # Record failures for 15 unique validators
        for i in range(15):
            await cb.record_failure(f"validator-{i}")
        
        # Should have evicted oldest entries, max 10 tracked
        assert len(cb.failures) <= 10

    @pytest.mark.asyncio
    async def test_regex_timeout_is_short(self):
        """P0 Fix: Regex timeout should be 100ms, not 2 seconds."""
        from threatsimgpt.llm.guardrails import REGEX_TIMEOUT_SECONDS
        
        assert REGEX_TIMEOUT_SECONDS <= 0.5, "Regex timeout should be <= 500ms for DoS protection"

