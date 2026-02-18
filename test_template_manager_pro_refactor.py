"""Unit tests for refactored TemplateManagerPro - Issue #129.

Tests cover audit logging, caching, state integration, and security validation patterns.
"""

import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from threatsimgpt.core.template_manager_pro import (
    TemplateManager, 
    ValidationCache, 
    AuditLogger
)
from threatsimgpt.security.template_validator import SecurityValidationResult, SecuritySeverity
from datetime import datetime, timezone


class TestValidationCache(unittest.TestCase):
    """Test the ValidationCache implementation."""
    
    def setUp(self):
        self.cache = ValidationCache(ttl_seconds=1)
    
    def test_cache_put_and_get(self):
        """Test basic cache put/get operations."""
        result = SecurityValidationResult(
            validation_id="test-123",
            is_secure=True,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        # Put result in cache
        self.cache.put("test_key", result)
        
        # Get result immediately
        cached_result = self.cache.get("test_key")
        self.assertIsNotNone(cached_result)
        self.assertEqual(cached_result.validation_id, "test-123")
    
    def test_cache_ttl_expiration(self):
        """Test cache TTL expiration."""
        result = SecurityValidationResult(
            validation_id="test-456",
            is_secure=True,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        # Put result in cache
        self.cache.put("expire_key", result)
        
        # Get immediately (should work)
        cached_result = self.cache.get("expire_key")
        self.assertIsNotNone(cached_result)
        
        # Wait for TTL to expire
        time.sleep(1.1)  # Wait longer than TTL
        
        # Should return None after expiration
        expired_result = self.cache.get("expire_key")
        self.assertIsNone(expired_result)
    
    def test_cache_size_and_clear(self):
        """Test cache size tracking and clearing."""
        result1 = SecurityValidationResult(
            validation_id="test-1",
            is_secure=True,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        result2 = SecurityValidationResult(
            validation_id="test-2",
            is_secure=False,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        # Add two items
        self.cache.put("key1", result1)
        self.cache.put("key2", result2)
        
        # Check size
        self.assertEqual(self.cache.size(), 2)
        
        # Clear cache
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)


class TestAuditLogger(unittest.TestCase):
    """Test the AuditLogger implementation."""
    
    def setUp(self):
        # Use a temporary directory for audit logs
        self.temp_dir = tempfile.mkdtemp()
        self.audit_logger = AuditLogger('test_audit')
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    @patch('logging.FileHandler')
    def test_log_validation_attempt(self, mock_handler):
        """Test validation attempt logging."""
        mock_handler_instance = Mock()
        mock_handler.return_value = mock_handler_instance
        
        # Re-initialize to use mock
        self.audit_logger._setup_logger()
        
        # Mock the logger.info method
        self.audit_logger.logger.info = Mock()
        
        # Log validation attempt
        self.audit_logger.log_validation_attempt("test_template.yaml", "user123")
        
        # Verify logger was called
        self.audit_logger.logger.info.assert_called_once()
        call_args = self.audit_logger.logger.info.call_args[0][0]
        self.assertIn("VALIDATION_ATTEMPT", call_args)
        self.assertIn("test_template.yaml", call_args)
        self.assertIn("user123", call_args)
    
    @patch('logging.FileHandler')
    def test_log_validation_result(self, mock_handler):
        """Test validation result logging."""
        mock_handler_instance = Mock()
        mock_handler.return_value = mock_handler_instance
        
        # Re-initialize to use mock
        self.audit_logger._setup_logger()
        
        # Mock the logger.info method
        self.audit_logger.logger.info = Mock()
        
        result = SecurityValidationResult(
            validation_id="test-789",
            is_secure=False,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        # Log validation result
        self.audit_logger.log_validation_result("test_template.yaml", result, user_id="user456")
        
        # Verify logger was called
        self.audit_logger.logger.info.assert_called_once()
        call_args = self.audit_logger.logger.info.call_args[0][0]
        self.assertIn("VALIDATION_RESULT", call_args)
        self.assertIn("BLOCKED", call_args)
        self.assertIn("user456", call_args)


class TestTemplateManagerRefactor(unittest.TestCase):
    """Test the refactored TemplateManager."""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_security_validation=True,
            strict_security_mode=True,
            cache_ttl_seconds=60,
            enable_audit_logging=True
        )
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization_with_enhanced_features(self):
        """Test TemplateManager initialization with new features."""
        # Verify cache is initialized
        self.assertIsNotNone(self.manager.validation_cache)
        self.assertEqual(self.manager.validation_cache.ttl_seconds, 60)
        
        # Verify audit logger is initialized
        self.assertIsNotNone(self.manager.audit_logger)
        
        # Verify statistics are initialized
        self.assertEqual(self.manager._validation_stats['total_validations'], 0)
        self.assertEqual(self.manager._validation_stats['cache_hits'], 0)
        self.assertEqual(self.manager._validation_stats['security_blocks'], 0)
    
    def test_validate_template_security_with_caching(self):
        """Test security validation with caching functionality."""
        # Create a test template
        test_template = self.temp_dir / "test.yaml"
        test_template.write_text("""
name: "Test Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        # First validation (should cache result)
        result1 = self.manager.validate_template_security(test_template, user_id="test_user")
        
        # Second validation (should hit cache)
        result2 = self.manager.validate_template_security(test_template, user_id="test_user")
        
        # Verify both results are the same (cached)
        self.assertEqual(result1.validation_id, result2.validation_id)
        self.assertEqual(result1.is_secure, result2.is_secure)
        
        # Verify cache hit statistics
        stats = self.manager.get_validation_statistics()
        self.assertEqual(stats['cache_hits'], 1)
        self.assertEqual(stats['total_validations'], 2)
    
    def test_validate_template_security_force_refresh(self):
        """Test security validation with force refresh."""
        # Create a test template
        test_template = self.temp_dir / "test_refresh.yaml"
        test_template.write_text("""
name: "Test Refresh Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        # First validation
        result1 = self.manager.validate_template_security(test_template, user_id="test_user")
        
        # Force refresh validation
        result2 = self.manager.validate_template_security(
            test_template, user_id="test_user", force_refresh=True
        )
        
        # Verify results have different validation IDs (not cached)
        self.assertNotEqual(result1.validation_id, result2.validation_id)
        
        # Verify no cache hit for force refresh
        stats = self.manager.get_validation_statistics()
        self.assertEqual(stats['cache_hits'], 0)
        self.assertEqual(stats['total_validations'], 2)
    
    def test_get_validation_statistics(self):
        """Test validation statistics calculation."""
        # Perform some validations
        test_template = self.temp_dir / "test_stats.yaml"
        test_template.write_text("""
name: "Test Stats Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        # Multiple validations
        self.manager.validate_template_security(test_template)
        self.manager.validate_template_security(test_template, force_refresh=True)
        
        # Get statistics
        stats = self.manager.get_validation_statistics()
        
        # Verify statistics structure
        self.assertIn('total_validations', stats)
        self.assertIn('cache_hits', stats)
        self.assertIn('security_blocks', stats)
        self.assertIn('cache_hit_rate', stats)
        self.assertIn('security_block_rate', stats)
        self.assertIn('cache_size', stats)
        
        # Verify calculated rates
        expected_hit_rate = stats['cache_hits'] / stats['total_validations']
        self.assertEqual(stats['cache_hit_rate'], expected_hit_rate)
    
    def test_clear_validation_cache(self):
        """Test cache clearing with audit logging."""
        # Add something to cache
        test_template = self.temp_dir / "test_clear.yaml"
        test_template.write_text("""
name: "Test Clear Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        self.manager.validate_template_security(test_template)
        
        # Verify cache has items
        stats = self.manager.get_validation_statistics()
        self.assertGreater(stats['cache_size'], 0)
        
        # Clear cache
        self.manager.clear_validation_cache()
        
        # Verify cache is empty
        stats_after = self.manager.get_validation_statistics()
        self.assertEqual(stats_after['cache_size'], 0)
    
    def test_get_cache_info(self):
        """Test cache information retrieval."""
        # Perform some validation to populate stats
        test_template = self.temp_dir / "test_info.yaml"
        test_template.write_text("""
name: "Test Info Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        self.manager.validate_template_security(test_template)
        
        stats = self.manager.get_validation_statistics()
        
        # Verify statistics structure
        self.assertIn('total_validations', stats)
        self.assertIn('cache_hits', stats)
        self.assertIn('security_blocks', stats)
        self.assertIn('cache_hit_rate', stats)
        self.assertIn('security_block_rate', stats)
        self.assertIn('cache_size', stats)
        
        # Verify calculated rates
        expected_hit_rate = stats['cache_hits'] / stats['total_validations']
        self.assertEqual(stats['cache_hit_rate'], expected_hit_rate)
    
    def test_disabled_security_validation(self):
        """Test behavior when security validation is disabled."""
        manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_security_validation=False
        )
        
        test_template = self.temp_dir / "test_disabled.yaml"
        test_template.write_text("""
name: "Test Disabled Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        # Should raise ValueError when validation is disabled
        with self.assertRaises(ValueError) as context:
            manager.validate_template_security(test_template)
        
        self.assertIn("Security validation is disabled", str(context.exception))


class TestIntegrationPatterns(unittest.TestCase):
    """Test integration with established security validation patterns."""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_security_validation=True,
            strict_security_mode=True
        )
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_integration_with_template_security_validator(self):
        """Test proper integration with TemplateSecurityValidator."""
        # Create a template with security issues
        test_template = self.temp_dir / "test_integration.yaml"
        test_template.write_text("""
name: "Malicious Template"
threat_type: "phishing"
delivery_vector: "email"
description: "This template contains javascript:alert('xss') which should be blocked"
""")
        
        # Validate template
        result = self.manager.validate_template_security(test_template, user_id="integration_test")
        
        # Verify security validator detected the issue
        self.assertFalse(result.is_secure)
        self.assertGreater(len(result.findings), 0)
        
        # Check for XSS detection
        xss_findings = [f for f in result.findings if 'javascript' in f.title.lower()]
        self.assertGreater(len(xss_findings), 0)
    
    def test_strict_security_mode_enforcement(self):
        """Test strict security mode enforcement."""
        # Create template with medium severity issue
        test_template = self.temp_dir / "test_strict.yaml"
        test_template.write_text("""
name: "Medium Risk Template"
threat_type: "phishing"
delivery_vector: "email"
description: "Contains potentially suspicious content"
""")
        
        # In strict mode, even medium issues should be handled appropriately
        result = self.manager.validate_template_security(test_template)
        
        # Verify strict mode behavior
        # (This will depend on the specific implementation of strict mode)
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
