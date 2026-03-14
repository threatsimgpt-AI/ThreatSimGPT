"""Unit tests for refactored TemplateManager - Service-based architecture.

Tests cover the new service-based architecture while maintaining
compatibility with existing test expectations.
"""

import tempfile
import time
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

import pytest

from threatsimgpt.core.template_manager_refactored import TemplateManager
from threatsimgpt.core.services import (
    TemplateCacheService,
    TemplateAuditService,
    TemplateSecurityService,
    TemplateValidationService
)
from threatsimgpt.security.template_validator import SecurityValidationResult, SecuritySeverity


class TestTemplateManagerRefactored(unittest.TestCase):
    """Test the refactored TemplateManager with service architecture."""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
        self.manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_security_validation=True,
            strict_security_mode=True,
            cache_ttl_seconds=60,
            cache_max_size=100,
            enable_audit_logging=True,
            enable_performance_monitoring=True
        )
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_initialization_with_services(self):
        """Test TemplateManager initialization with all services."""
        # Verify all services are initialized
        self.assertIsNotNone(self.manager.validation_service)
        self.assertIsNotNone(self.manager.security_service)
        self.assertIsNotNone(self.manager.cache_service)
        self.assertIsNotNone(self.manager.audit_service)
        
        # Verify service configuration
        self.assertEqual(self.manager.cache_service.ttl_seconds, 60)
        self.assertEqual(self.manager.cache_service.max_size, 100)
        self.assertTrue(self.manager.security_service.enable_performance_monitoring)
    
    def test_initialization_without_security_validation(self):
        """Test TemplateManager initialization without security validation."""
        manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_security_validation=False
        )
        
        # Verify security service is disabled
        self.assertIsNone(manager.security_service)
        self.assertIsNone(manager.security_validator)
        
        # Other services should still be initialized
        self.assertIsNotNone(manager.validation_service)
        self.assertIsNotNone(manager.cache_service)
        self.assertIsNotNone(manager.audit_service)
    
    def test_initialization_without_audit_logging(self):
        """Test TemplateManager initialization without audit logging."""
        manager = TemplateManager(
            templates_dir=self.temp_dir,
            enable_audit_logging=False
        )
        
        # Verify audit service is disabled
        self.assertIsNone(manager.audit_service)
        self.assertIsNone(manager.audit_logger)
        
        # Other services should still be initialized
        self.assertIsNotNone(manager.validation_service)
        self.assertIsNotNone(manager.security_service)
        self.assertIsNotNone(manager.cache_service)
    
    def test_validate_template_security_with_services(self):
        """Test security validation using service architecture."""
        # Create a test template
        test_template = self.temp_dir / "test.yaml"
        test_template.write_text("""
name: "Test Template"
threat_type: "phishing"
delivery_vector: "email"
description: "This is a test template"
""")
        
        # Test validation
        result = self.manager.validate_template_security(test_template, user_id="test_user")
        
        # Verify result structure
        self.assertIsInstance(result, SecurityValidationResult)
        self.assertIsNotNone(result.validation_id)
        self.assertIsInstance(result.is_secure, bool)
        self.assertIsInstance(result.findings, list)
        
        # Verify audit logging
        if self.manager.audit_service:
            # Check that audit entries were created
            # (This would require checking log files or mocking)
            pass
    
    def test_validate_template_security_with_caching(self):
        """Test security validation with caching functionality."""
        # Create a test template
        test_template = self.temp_dir / "test_cache.yaml"
        test_template.write_text("""
name: "Test Cache Template"
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
        self.assertGreater(stats['cache_hit_rate'], 0)
    
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
    
    def test_get_validation_statistics_from_services(self):
        """Test comprehensive statistics from all services."""
        # Perform some operations to generate statistics
        test_template = self.temp_dir / "test_stats.yaml"
        test_template.write_text("""
name: "Test Stats Template"
threat_type: "phishing"
delivery_vector: "email"
""")
        
        # Multiple validations
        self.manager.validate_template_security(test_template)
        self.manager.validate_template_security(test_template, force_refresh=True)
        
        # Get comprehensive statistics
        stats = self.manager.get_validation_statistics()
        
        # Verify statistics structure
        expected_keys = [
            'total_validations', 'cache_hits', 'security_blocks',
            'cache_size', 'cache_hit_rate', 'cache_utilization',
            'schema_success_rate', 'templates_fixed'
        ]
        
        for key in expected_keys:
            self.assertIn(key, stats)
        
        # Verify calculated rates
        self.assertIsInstance(stats['cache_hit_rate'], float)
        self.assertIsInstance(stats['schema_success_rate'], float)
        self.assertIsInstance(stats['cache_utilization'], float)
    
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
        stats_before = self.manager.get_validation_statistics()
        self.assertGreater(stats_before['cache_size'], 0)
        
        # Clear cache
        self.manager.clear_validation_cache()
        
        # Verify cache is empty
        stats_after = self.manager.get_validation_statistics()
        self.assertEqual(stats_after['cache_size'], 0)
    
    def test_validate_all_templates_with_services(self):
        """Test comprehensive template validation using services."""
        # Create multiple test templates
        templates = [
            ("valid1.yaml", """
name: "Valid Template 1"
threat_type: "phishing"
delivery_vector: "email"
description: "A valid template"
"""),
            ("invalid.yaml", """
name: "Invalid Template"
threat_type: "invalid_threat"
delivery_vector: "email"
"""),
            ("secure.yaml", """
name: "Secure Template"
threat_type: "phishing"
delivery_vector: "email"
description: "A secure template"
""")
        ]
        
        for filename, content in templates:
            (self.temp_dir / filename).write_text(content)
        
        # Validate all templates
        results = self.manager.validate_all_templates()
        
        # Verify results structure
        self.assertIn('valid', results)
        self.assertIn('invalid', results)
        self.assertIn('security_issues', results)
        self.assertIn('statistics', results)
        
        # Verify statistics
        stats = results['statistics']
        self.assertEqual(stats['total'], 3)
        self.assertGreater(stats['valid_count'] + stats['invalid_count'], 0)
        self.assertIsInstance(stats['success_rate'], float)
    
    def test_fix_template_issues_with_service(self):
        """Test template fixing using validation service."""
        # Create a template with issues
        test_template = self.temp_dir / "test_fix.yaml"
        test_template.write_text("""
name: "Template with Issues"
threat_type: "invalid_threat_type"
delivery_vector: "multi_channel"
simulation_parameters:
  max_iterations: "3"  # String instead of int
  max_duration_minutes: "60"  # String instead of int
""")
        
        # Fix template
        result = self.manager.fix_template_issues(test_template)
        
        # Verify fix was attempted
        self.assertIsInstance(result, bool)
        
        # Check if backup was created
        backup_files = list(self.temp_dir.glob("*.backup_*.yaml"))
        if result:  # If fixes were applied
            self.assertGreater(len(backup_files), 0)
    
    def test_create_from_template_with_service(self):
        """Test template creation using validation service."""
        # Create source template
        source_template = self.temp_dir / "source.yaml"
        source_template.write_text("""
name: "Source Template"
threat_type: "phishing"
delivery_vector: "email"
description: "Source template for cloning"
""")
        
        # Create new template from source
        new_path = self.manager.create_from_template("source", "Cloned Template")
        
        # Verify new template was created
        self.assertTrue(new_path.exists())
        self.assertEqual(new_path.name, "cloned_template.yaml")
        
        # Verify content was copied and modified
        with open(new_path, 'r') as f:
            content = f.read()
            self.assertIn("Cloned Template", content)
            self.assertIn("Cloned from source", content)
    
    def test_service_access_methods(self):
        """Test access to underlying services."""
        # Test service access methods
        self.assertIsInstance(self.manager.get_security_service(), TemplateSecurityService)
        self.assertIsInstance(self.manager.get_cache_service(), TemplateCacheService)
        self.assertIsInstance(self.manager.get_audit_service(), TemplateAuditService)
        self.assertIsInstance(self.manager.get_validation_service(), TemplateValidationService)
    
    def test_health_check(self):
        """Test comprehensive health check."""
        # Perform health check
        health = self.manager.check_health()
        
        # Verify health structure
        self.assertIn('status', health)
        self.assertIn('services', health)
        self.assertIn('issues', health)
        
        # Verify service health
        services = health['services']
        self.assertIn('validation', services)
        self.assertIn('security', services)
        self.assertIn('cache', services)
        self.assertIn('audit', services)
        
        # Verify each service has status
        for service_name, service_health in services.items():
            self.assertIn('status', service_health)
            self.assertIn(service_health['status'], ['healthy', 'degraded', 'unhealthy'])
    
    def test_backward_compatibility(self):
        """Test that legacy API still works."""
        # Test legacy cache access
        self.assertIsNotNone(self.manager.validation_cache)
        self.assertEqual(self.manager.validation_cache.ttl_seconds, 60)
        
        # Test legacy audit logger access
        if self.manager.audit_logger:
            self.assertIsNotNone(self.manager.audit_logger)
        
        # Test legacy security validator access
        if self.manager.security_validator:
            self.assertIsNotNone(self.manager.security_validator)
        
        # Test legacy statistics
        self.assertIsInstance(self.manager._validation_stats, dict)
        self.assertIn('total_validations', self.manager._validation_stats)


class TestServiceIntegration(unittest.TestCase):
    """Test integration between services."""
    
    def setUp(self):
        self.temp_dir = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_cache_service_integration(self):
        """Test cache service in isolation."""
        cache_service = TemplateCacheService(ttl_seconds=1, max_size=10)
        
        # Create test result
        result = SecurityValidationResult(
            validation_id="test-123",
            is_secure=True,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=0.0,
            template_hash="test_hash"
        )
        
        # Test cache operations
        test_path = self.temp_dir / "test.yaml"
        test_path.write_text("test")
        
        # Put and get
        cache_service.put(test_path, result)
        cached_result = cache_service.get(test_path)
        
        self.assertIsNotNone(cached_result)
        self.assertEqual(cached_result.validation_id, "test-123")
        
        # Test statistics
        stats = cache_service.get_statistics()
        self.assertEqual(stats['size'], 1)
        self.assertEqual(stats['hits'], 1)
        self.assertEqual(stats['total_requests'], 1)
    
    def test_audit_service_integration(self):
        """Test audit service in isolation."""
        audit_service = TemplateAuditService(
            log_dir=self.temp_dir,
            enable_console=False
        )
        
        # Test logging operations
        audit_service.log_validation_attempt("test.yaml", "test_user")
        
        result = SecurityValidationResult(
            validation_id="test-456",
            is_secure=False,
            findings=[],
            scan_timestamp=datetime.now(timezone.utc),
            scan_duration_ms=100.0,
            template_hash="test_hash"
        )
        
        audit_service.log_validation_result("test.yaml", result, user_id="test_user")
        
        # Test statistics
        stats = audit_service.get_log_statistics()
        self.assertEqual(stats['log_dir'], str(self.temp_dir))
        self.assertIn('file_count', stats)
    
    def test_security_service_integration(self):
        """Test security service in isolation."""
        security_service = TemplateSecurityService(strict_mode=True)
        
        # Create test template
        test_template = self.temp_dir / "test_security.yaml"
        test_template.write_text("""
name: "Security Test Template"
threat_type: "phishing"
delivery_vector: "email"
description: "Template for security testing"
""")
        
        # Test validation
        result = security_service.validate_template_file(test_template)
        
        self.assertIsInstance(result, SecurityValidationResult)
        self.assertIsNotNone(result.validation_id)
        
        # Test statistics
        stats = security_service.get_security_statistics()
        self.assertEqual(stats['total_validations'], 1)
        self.assertGreater(stats['average_duration_ms'], 0)
    
    def test_validation_service_integration(self):
        """Test validation service in isolation."""
        validation_service = TemplateValidationService(self.temp_dir)
        
        # Create test template
        test_template = self.temp_dir / "test_validation.yaml"
        test_template.write_text("""
name: "Validation Test Template"
threat_type: "phishing"
delivery_vector: "email"
description: "Template for validation testing"
metadata:
  name: "Test Template"
  author: "Test Author"
  version: "1.0.0"
  created_at: "2023-01-01T00:00:00Z"
  updated_at: "2023-01-01T00:00:00Z"
  tags: []
  references: []
""")
        
        # Test validation
        is_valid, scenario, error = validation_service.validate_template_schema(test_template)
        
        self.assertIsInstance(is_valid, bool)
        if is_valid:
            self.assertIsNotNone(scenario)
            self.assertIsNone(error)
        else:
            self.assertIsNone(scenario)
            self.assertIsNotNone(error)
        
        # Test statistics
        stats = validation_service.get_validation_statistics()
        self.assertEqual(stats['total_validations'], 1)


if __name__ == '__main__':
    unittest.main()
