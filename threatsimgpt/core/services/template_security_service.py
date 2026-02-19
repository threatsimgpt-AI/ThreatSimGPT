"""Template Security Service with enhanced security validation.

Provides comprehensive security scanning for templates with:
- Integration with TemplateSecurityValidator
- Performance monitoring
- Batch validation capabilities
- Enhanced error handling
"""

import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threatsimgpt.security.template_validator import (
    TemplateSecurityValidator,
    SecurityValidationResult,
    SecuritySeverity,
)


class SecurityValidationError(Exception):
    """Raised when security validation fails unexpectedly."""
    pass


class TemplateSecurityService:
    """Service for template security validation and monitoring.
    
    Wraps TemplateSecurityValidator with additional features:
    - Performance monitoring
    - Batch operations
    - Enhanced error handling
    - Statistics tracking
    """
    
    def __init__(
        self,
        strict_mode: bool = True,
        enable_performance_monitoring: bool = True,
        max_concurrent_validations: int = 10
    ):
        """Initialize security service.
        
        Args:
            strict_mode: Enable strict security validation
            enable_performance_monitoring: Track validation performance
            max_concurrent_validations: Maximum concurrent validations
        """
        self.strict_mode = strict_mode
        self.enable_performance_monitoring = enable_performance_monitoring
        self.max_concurrent_validations = max_concurrent_validations
        
        # Initialize the underlying validator
        self.validator = TemplateSecurityValidator(strict_mode=strict_mode)
        
        # Performance statistics
        self._stats = {
            'total_validations': 0,
            'total_duration_ms': 0.0,
            'cache_hits': 0,  # Will be updated by cache service
            'security_blocks': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'average_duration_ms': 0.0,
            'slowest_validation_ms': 0.0,
            'fastest_validation_ms': float('inf')
        }
        
        # Validation history for trend analysis (keep last 1000)
        self._validation_history: List[Dict[str, Any]] = []
        self._max_history_size = 1000
    
    @contextmanager
    def _performance_monitor(self, template_path: Path):
        """Context manager for monitoring validation performance.
        
        Args:
            template_path: Path to template being validated
            
        Yields:
            Dictionary to store performance metrics
        """
        start_time = time.time()
        metrics = {
            'template_path': str(template_path),
            'start_time': datetime.now(timezone.utc),
            'duration_ms': 0.0,
            'success': False,
            'error': None
        }
        
        try:
            yield metrics
            metrics['success'] = True
        except Exception as e:
            metrics['error'] = str(e)
            raise
        finally:
            end_time = time.time()
            metrics['duration_ms'] = (end_time - start_time) * 1000
            metrics['end_time'] = datetime.now(timezone.utc)
            
            # Update statistics
            if self.enable_performance_monitoring:
                self._update_performance_stats(metrics)
            
            # Add to history
            self._add_to_history(metrics)
    
    def _update_performance_stats(self, metrics: Dict[str, Any]) -> None:
        """Update performance statistics.
        
        Args:
            metrics: Performance metrics from validation
        """
        duration = metrics['duration_ms']
        
        self._stats['total_validations'] += 1
        self._stats['total_duration_ms'] += duration
        
        # Update min/max
        if duration > self._stats['slowest_validation_ms']:
            self._stats['slowest_validation_ms'] = duration
        
        if duration < self._stats['fastest_validation_ms']:
            self._stats['fastest_validation_ms'] = duration
        
        # Calculate average
        self._stats['average_duration_ms'] = (
            self._stats['total_duration_ms'] / self._stats['total_validations']
        )
    
    def _add_to_history(self, metrics: Dict[str, Any]) -> None:
        """Add validation metrics to history.
        
        Args:
            metrics: Performance metrics to add
        """
        self._validation_history.append(metrics)
        
        # Maintain history size
        if len(self._validation_history) > self._max_history_size:
            self._validation_history.pop(0)
    
    def validate_template_file(
        self,
        template_path: Path,
        user_id: Optional[str] = None
    ) -> SecurityValidationResult:
        """Validate a single template file for security issues.
        
        Args:
            template_path: Path to template file
            user_id: Optional user identifier for tracking
            
        Returns:
            SecurityValidationResult with all findings
            
        Raises:
            SecurityValidationError: If validation fails unexpectedly
        """
        if not template_path.exists():
            raise SecurityValidationError(f"Template file not found: {template_path}")
        
        if not template_path.is_file():
            raise SecurityValidationError(f"Template path is not a file: {template_path}")
        
        # Monitor performance
        with self._performance_monitor(template_path) as metrics:
            try:
                result = self.validator.validate_template_file(template_path)
                
                # Update security statistics
                self._update_security_stats(result)
                
                # Add user context to metrics
                if user_id:
                    metrics['user_id'] = user_id
                
                return result
                
            except Exception as e:
                # Convert to SecurityValidationError with context
                raise SecurityValidationError(
                    f"Security validation failed for {template_path}: {e}"
                ) from e
    
    def validate_template_content(
        self,
        content: str,
        template_name: str = "unknown",
        user_id: Optional[str] = None
    ) -> SecurityValidationResult:
        """Validate template content directly from string.
        
        Args:
            content: Template content as string
            template_name: Name for identification
            user_id: Optional user identifier for tracking
            
        Returns:
            SecurityValidationResult with all findings
            
        Raises:
            SecurityValidationError: If validation fails unexpectedly
        """
        # Create a temporary path for monitoring
        temp_path = Path(f"<string:{template_name}>")
        
        with self._performance_monitor(temp_path) as metrics:
            try:
                result = self.validator.validate_template_content(content, template_name)
                
                # Update security statistics
                self._update_security_stats(result)
                
                # Add context to metrics
                metrics['template_name'] = template_name
                if user_id:
                    metrics['user_id'] = user_id
                
                return result
                
            except Exception as e:
                raise SecurityValidationError(
                    f"Security validation failed for content '{template_name}': {e}"
                ) from e
    
    def validate_templates_batch(
        self,
        template_paths: List[Path],
        user_id: Optional[str] = None,
        fail_fast: bool = False
    ) -> Dict[str, SecurityValidationResult]:
        """Validate multiple template files in batch.
        
        Args:
            template_paths: List of template file paths
            user_id: Optional user identifier for tracking
            fail_fast: Stop on first validation error
            
        Returns:
            Dictionary mapping template paths to validation results
            
        Raises:
            SecurityValidationError: If validation fails and fail_fast=True
        """
        results = {}
        
        for template_path in template_paths:
            try:
                result = self.validate_template_file(template_path, user_id)
                results[str(template_path)] = result
                
                if fail_fast and not result.is_secure:
                    raise SecurityValidationError(
                        f"Security validation failed for {template_path}: "
                        f"{result.critical_count} critical, {result.high_count} high severity issues"
                    )
                    
            except Exception as e:
                if fail_fast:
                    raise
                # Create error result for failed validation
                error_result = SecurityValidationResult(
                    validation_id=f"error_{datetime.now(timezone.utc).timestamp()}",
                    is_secure=False,
                    findings=[],
                    scan_timestamp=datetime.now(timezone.utc),
                    scan_duration_ms=0.0,
                    template_hash="error"
                )
                results[str(template_path)] = error_result
        
        return results
    
    def _update_security_stats(self, result: SecurityValidationResult) -> None:
        """Update security statistics based on validation result.
        
        Args:
            result: Security validation result
        """
        if not result.is_secure:
            self._stats['security_blocks'] += 1
        
        self._stats['critical_findings'] += result.critical_count
        self._stats['high_findings'] += result.high_count
        self._stats['medium_findings'] += result.medium_count
        self._stats['low_findings'] += result.low_count
    
    def get_security_statistics(self) -> Dict[str, Any]:
        """Get comprehensive security validation statistics.
        
        Returns:
            Dictionary with security statistics
        """
        stats = self._stats.copy()
        
        # Calculate derived metrics
        if stats['total_validations'] > 0:
            stats['security_block_rate'] = (
                stats['security_blocks'] / stats['total_validations']
            )
            stats['average_findings_per_validation'] = (
                (stats['critical_findings'] + stats['high_findings'] + 
                 stats['medium_findings'] + stats['low_findings']) / 
                stats['total_validations']
            )
        else:
            stats['security_block_rate'] = 0.0
            stats['average_findings_per_validation'] = 0.0
        
        # Fix infinite value for fastest validation
        if stats['fastest_validation_ms'] == float('inf'):
            stats['fastest_validation_ms'] = 0.0
        
        # Add recent performance trends (last 100 validations)
        recent_history = self._validation_history[-100:]
        if recent_history:
            recent_durations = [h['duration_ms'] for h in recent_history if h['success']]
            if recent_durations:
                stats['recent_average_duration_ms'] = sum(recent_durations) / len(recent_durations)
                stats['recent_success_rate'] = (
                    sum(1 for h in recent_history if h['success']) / len(recent_history)
                )
            else:
                stats['recent_average_duration_ms'] = 0.0
                stats['recent_success_rate'] = 0.0
        else:
            stats['recent_average_duration_ms'] = 0.0
            stats['recent_success_rate'] = 0.0
        
        return stats
    
    def get_validation_history(
        self,
        limit: int = 100,
        include_successful: bool = True,
        include_failures: bool = True
    ) -> List[Dict[str, Any]]:
        """Get validation history with filtering options.
        
        Args:
            limit: Maximum number of entries to return
            include_successful: Include successful validations
            include_failures: Include failed validations
            
        Returns:
            List of validation history entries
        """
        history = self._validation_history.copy()
        
        # Filter by success/failure
        if not include_successful:
            history = [h for h in history if not h['success']]
        
        if not include_failures:
            history = [h for h in history if h['success']]
        
        # Return most recent entries
        return history[-limit:] if limit > 0 else history
    
    def reset_statistics(self) -> None:
        """Reset all statistics and history."""
        self._stats = {
            'total_validations': 0,
            'total_duration_ms': 0.0,
            'cache_hits': 0,
            'security_blocks': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'average_duration_ms': 0.0,
            'slowest_validation_ms': 0.0,
            'fastest_validation_ms': float('inf')
        }
        
        self._validation_history.clear()
    
    def check_validator_health(self) -> Dict[str, Any]:
        """Check the health of the security validator.
        
        Returns:
            Health check results
        """
        health_status = {
            'status': 'healthy',
            'issues': [],
            'validator_available': True,
            'statistics': self.get_security_statistics()
        }
        
        try:
            # Test validator with safe content
            test_result = self.validate_template_content(
                "name: test\nthreat_type: phishing",
                "health_check"
            )
            
            if not test_result.is_secure:
                health_status['issues'].append(
                    "Validator incorrectly flags safe content as insecure"
                )
                health_status['status'] = 'degraded'
        
        except Exception as e:
            health_status['validator_available'] = False
            health_status['issues'].append(f"Validator error: {e}")
            health_status['status'] = 'unhealthy'
        
        # Check for performance issues
        stats = self.get_security_statistics()
        if stats.get('average_duration_ms', 0) > 5000:  # 5 seconds
            health_status['issues'].append(
                "Average validation duration exceeds 5 seconds"
            )
            health_status['status'] = 'degraded'
        
        # Check for high failure rate
        if stats.get('security_block_rate', 0) > 0.5:  # 50%
            health_status['issues'].append(
                "Security block rate exceeds 50%"
            )
            health_status['status'] = 'degraded'
        
        return health_status
