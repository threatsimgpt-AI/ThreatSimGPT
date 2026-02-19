"""Simplified Template Manager with reduced wrapper complexity.

This version reduces temporary complexity by:
- Eliminating dual statistics tracking
- Using service statistics as source of truth
- Simplifying audit logging to single path
- Maintaining backward compatibility through delegation
"""

import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from threatsimgpt.config.models import ThreatScenario
from threatsimgpt.core.services import (
    TemplateCacheService,
    TemplateAuditService,
    TemplateSecurityService,
    TemplateValidationService,
    SecurityValidationError,
    ValidationError,
    TemplateFixResult
)
from threatsimgpt.security.template_validator import SecurityValidationResult

console = Console()


class TemplateManager:
    """Simplified Template Manager with reduced complexity.

    Uses services directly with minimal wrapper layer for backward compatibility.
    Eliminates dual statistics tracking and redundant audit logging.
    """

    def __init__(
        self,
        templates_dir: Optional[Path] = None,
        enable_security_validation: bool = True,
        strict_security_mode: bool = True,
        cache_ttl_seconds: int = 300,
        cache_max_size: int = 1000,
        enable_audit_logging: bool = True,
        audit_log_dir: Optional[Path] = None,
        enable_performance_monitoring: bool = True
    ):
        """Initialize template manager with simplified architecture."""
        self.templates_dir = templates_dir or Path("templates")
        self.enable_security_validation = enable_security_validation
        
        # Initialize services
        self.validation_service = TemplateValidationService(self.templates_dir)
        
        if self.enable_security_validation:
            self.security_service = TemplateSecurityService(
                strict_mode=strict_security_mode,
                enable_performance_monitoring=enable_performance_monitoring
            )
        else:
            self.security_service = None
        
        self.cache_service = TemplateCacheService(
            ttl_seconds=cache_ttl_seconds,
            max_size=cache_max_size,
            enable_lru=True
        )
        
        if enable_audit_logging:
            self.audit_service = TemplateAuditService(
                log_dir=audit_log_dir,
                retention_days=30
            )
        else:
            self.audit_service = None

    # Simplified legacy properties (delegation only)
    @property
    def validation_cache(self):
        """Legacy cache property - delegates to cache service."""
        return _SimpleCacheWrapper(self.cache_service)
    
    @property
    def audit_logger(self):
        """Legacy audit logger - delegates to audit service."""
        return _SimpleAuditWrapper(self.audit_service) if self.audit_service else None
    
    @property
    def security_validator(self):
        """Legacy security validator - delegates to security service."""
        return _SimpleSecurityWrapper(self.security_service) if self.security_service else None

    # Main API methods (using services directly)
    def validate_template_security(
        self,
        template_file: Path,
        user_id: Optional[str] = None,
        force_refresh: bool = False,
    ) -> SecurityValidationResult:
        """Validate template security using services directly."""
        if not self.security_service:
            raise ValueError("Security validation is disabled")
        
        # Single audit logging path
        if self.audit_service:
            self.audit_service.log_validation_attempt(str(template_file), user_id)
        
        # Check cache
        if not force_refresh:
            cached_result = self.cache_service.get(template_file, user_id)
            if cached_result:
                if self.audit_service:
                    self.audit_service.log_validation_result(
                        str(template_file), cached_result, 
                        cache_hit=True, user_id=user_id
                    )
                return cached_result
        
        # Perform validation
        result = self.security_service.validate_template_file(template_file, user_id)
        
        # Cache result
        self.cache_service.put(template_file, result, user_id)
        
        # Single audit logging path
        if self.audit_service:
            self.audit_service.log_validation_result(
                str(template_file), result, 
                cache_hit=False, user_id=user_id
            )
        
        return result

    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get statistics from services (single source of truth)."""
        stats = {}
        
        # Get statistics from each service
        cache_stats = self.cache_service.get_statistics()
        stats.update({
            'cache_size': cache_stats['size'],
            'cache_hit_rate': cache_stats['hit_rate'],
            'cache_utilization': cache_stats['utilization'],
            'total_validations': cache_stats['total_requests'],
            'cache_hits': cache_stats['hits']
        })
        
        if self.security_service:
            security_stats = self.security_service.get_security_statistics()
            stats.update({
                'security_block_rate': security_stats['security_block_rate'],
                'average_validation_duration_ms': security_stats['average_duration_ms'],
                'total_security_findings': (
                    security_stats['critical_findings'] +
                    security_stats['high_findings'] +
                    security_stats['medium_findings'] +
                    security_stats['low_findings']
                ),
                'security_blocks': security_stats['security_blocks']
            })
        
        validation_stats = self.validation_service.get_validation_statistics()
        stats.update({
            'schema_success_rate': validation_stats['success_rate'],
            'templates_fixed': validation_stats['templates_fixed']
        })
        
        if self.audit_service:
            audit_stats = self.audit_service.get_log_statistics()
            stats.update({
                'audit_log_size_mb': audit_stats['total_size_mb'],
                'audit_log_files': audit_stats['file_count']
            })
        
        # Add legacy compatibility fields
        stats['last_validation'] = datetime.now(timezone.utc)
        
        return stats

    def clear_validation_cache(self) -> None:
        """Clear cache using service directly."""
        old_size = self.cache_service.clear()
        
        if self.audit_service:
            self.audit_service.log_service_event(
                'CACHE_CLEAR', 
                {'old_size': old_size, 'timestamp': datetime.now(timezone.utc).isoformat()}
            )

    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache info from service."""
        return self.cache_service.get_statistics()

    def validate_all_templates_security(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Validate all templates using services."""
        if not self.security_service:
            return {"error": "Security validation is disabled"}
        
        results = {
            "secure": [],
            "insecure": [],
            "statistics": {
                "total": 0,
                "secure_count": 0,
                "insecure_count": 0,
                "critical_findings": 0,
                "high_findings": 0,
                "medium_findings": 0,
                "low_findings": 0,
            }
        }
        
        if not self.templates_dir.exists():
            return results
        
        template_files = list(self.templates_dir.glob("*.yaml")) + list(self.templates_dir.glob("*.yml"))
        results["statistics"]["total"] = len(template_files)
        
        for template_file in template_files:
            try:
                security_result = self.security_service.validate_template_file(template_file, user_id)
                
                template_info = {
                    "file": template_file.name,
                    "validation_id": security_result.validation_id,
                    "findings_count": len(security_result.findings),
                    "critical": security_result.critical_count,
                    "high": security_result.high_count,
                    "medium": security_result.medium_count,
                    "low": security_result.low_count,
                }
                
                if security_result.is_secure:
                    results["secure"].append(template_info)
                    results["statistics"]["secure_count"] += 1
                else:
                    template_info["findings"] = [
                        {
                            "severity": f.severity.value,
                            "category": f.category.value,
                            "title": f.title,
                            "location": f.location,
                        }
                        for f in security_result.blocking_findings
                    ]
                    results["insecure"].append(template_info)
                    results["statistics"]["insecure_count"] += 1
                
                # Aggregate findings
                results["statistics"]["critical_findings"] += security_result.critical_count
                results["statistics"]["high_findings"] += security_result.high_count
                results["statistics"]["medium_findings"] += security_result.medium_count
                results["statistics"]["low_findings"] += security_result.low_count
                
            except Exception as e:
                results["insecure"].append({
                    "file": template_file.name,
                    "error": str(e)
                })
                results["statistics"]["insecure_count"] += 1
        
        return results

    def validate_all_templates(self) -> Dict[str, Any]:
        """Validate all templates using services."""
        results = {
            "valid": [],
            "invalid": [],
            "security_issues": [],
            "statistics": {
                "total": 0,
                "valid_count": 0,
                "invalid_count": 0,
                "security_issues_count": 0,
                "success_rate": 0.0
            }
        }

        if not self.templates_dir.exists():
            return results

        template_files = list(self.templates_dir.glob("*.yaml")) + list(self.templates_dir.glob("*.yml"))
        results["statistics"]["total"] = len(template_files)

        for template_file in template_files:
            # Schema validation
            is_valid, scenario, schema_error = self.validation_service.validate_template_schema(template_file)
            
            if not is_valid:
                results["invalid"].append({
                    "file": template_file.name,
                    "error": schema_error
                })
                results["statistics"]["invalid_count"] += 1
                continue
            
            # Security validation
            if self.security_service:
                try:
                    security_result = self.security_service.validate_template_file(template_file)
                    if not security_result.is_secure:
                        results["security_issues"].append({
                            "file": template_file.name,
                            "findings": [
                                {
                                    "severity": f.severity.value,
                                    "category": f.category.value,
                                    "title": f.title,
                                    "remediation": f.remediation,
                                }
                                for f in security_result.blocking_findings[:5]
                            ]
                        })
                        results["statistics"]["security_issues_count"] += 1
                        results["invalid"].append({
                            "file": template_file.name,
                            "error": f"Security validation failed: {security_result.critical_count} critical, {security_result.high_count} high severity issues"
                        })
                        results["statistics"]["invalid_count"] += 1
                        continue
                except Exception as e:
                    results["invalid"].append({
                        "file": template_file.name,
                        "error": f"Security validation error: {str(e)}"
                    })
                    results["statistics"]["invalid_count"] += 1
                    continue

            # Extract enum values properly
            threat_type_value = scenario.threat_type.value if hasattr(scenario.threat_type, 'value') else str(scenario.threat_type)
            difficulty_value = scenario.difficulty_level.value if hasattr(scenario.difficulty_level, 'value') else scenario.difficulty_level

            results["valid"].append({
                "file": template_file.name,
                "name": scenario.metadata.name,
                "threat_type": threat_type_value,
                "difficulty": difficulty_value,
                "security_validated": self.security_service is not None,
            })
            results["statistics"]["valid_count"] += 1

        if results["statistics"]["total"] > 0:
            results["statistics"]["success_rate"] = results["statistics"]["valid_count"] / results["statistics"]["total"]

        return results

    def fix_template_issues(self, template_file: Path) -> bool:
        """Fix template issues using validation service."""
        try:
            fix_result = self.validation_service.fix_template_issues(template_file)
            
            if self.audit_service:
                self.audit_service.log_template_operation(
                    "TEMPLATE_FIX",
                    str(template_file),
                    success=fix_result.success,
                    details={
                        "fixes_applied": fix_result.fixes_applied,
                        "backup_created": fix_result.backup_path is not None
                    }
                )
            
            if fix_result.success and fix_result.backup_path:
                console.print(f"[green]Fixed {template_file.name}:[/green]")
                for fix in fix_result.fixes_applied:
                    console.print(f"  - {fix}")
                console.print(f"[dim]Backup saved: {fix_result.backup_path.name}[/dim]")
            
            return fix_result.success
            
        except Exception as e:
            if self.audit_service:
                self.audit_service.log_template_operation(
                    "TEMPLATE_FIX_ERROR",
                    str(template_file),
                    success=False,
                    details={"error": str(e)}
                )
            
            console.print(f"[red]Failed to fix {template_file.name}: {e}[/red]")
            return False

    def create_from_template(self, source_template: str, new_name: str) -> Path:
        """Create template from source using validation service."""
        try:
            success, new_path, error = self.validation_service.clone_template(
                source_template, 
                new_name
            )
            
            if self.audit_service:
                self.audit_service.log_template_operation(
                    "TEMPLATE_CLONE",
                    str(new_path) if new_path else source_template,
                    success=success,
                    details={"source": source_template, "new_name": new_name}
                )
            
            if success:
                console.print(f"[green]Template created: {new_path}[/green]")
                return new_path
            else:
                raise FileNotFoundError(f"Failed to clone template: {error}")
                
        except Exception as e:
            if self.audit_service:
                self.audit_service.log_template_operation(
                    "TEMPLATE_CLONE_ERROR",
                    source_template,
                    success=False,
                    details={"error": str(e), "new_name": new_name}
                )
            raise

    # Service access methods
    def get_security_service(self) -> Optional[TemplateSecurityService]:
        return self.security_service
    
    def get_cache_service(self) -> TemplateCacheService:
        return self.cache_service
    
    def get_audit_service(self) -> Optional[TemplateAuditService]:
        return self.audit_service
    
    def get_validation_service(self) -> TemplateValidationService:
        return self.validation_service

    def check_health(self) -> Dict[str, Any]:
        """Check health of all services."""
        health = {
            "status": "healthy",
            "services": {},
            "issues": []
        }
        
        # Check validation service
        try:
            validation_stats = self.validation_service.get_validation_statistics()
            health["services"]["validation"] = {
                "status": "healthy",
                "statistics": validation_stats
            }
        except Exception as e:
            health["services"]["validation"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health["status"] = "degraded"
            health["issues"].append(f"Validation service error: {e}")
        
        # Check security service
        if self.security_service:
            try:
                security_health = self.security_service.check_validator_health()
                health["services"]["security"] = security_health
                if security_health["status"] != "healthy":
                    health["status"] = "degraded"
                    health["issues"].extend(security_health["issues"])
            except Exception as e:
                health["services"]["security"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health["status"] = "degraded"
                health["issues"].append(f"Security service error: {e}")
        
        # Check cache service
        try:
            cache_stats = self.cache_service.get_statistics()
            cache_health = "healthy"
            if cache_stats["utilization"] > 0.9:
                cache_health = "degraded"
                health["issues"].append("Cache utilization above 90%")
            elif cache_stats["hit_rate"] < 0.5 and cache_stats["total_requests"] > 100:
                cache_health = "degraded"
                health["issues"].append("Cache hit rate below 50%")
            
            health["services"]["cache"] = {
                "status": cache_health,
                "statistics": cache_stats
            }
            
            if cache_health != "healthy" and health["status"] == "healthy":
                health["status"] = "degraded"
        except Exception as e:
            health["services"]["cache"] = {
                "status": "unhealthy",
                "error": str(e)
            }
            health["status"] = "degraded"
            health["issues"].append(f"Cache service error: {e}")
        
        # Check audit service
        if self.audit_service:
            try:
                audit_stats = self.audit_service.get_log_statistics()
                health["services"]["audit"] = {
                    "status": "healthy",
                    "statistics": audit_stats
                }
            except Exception as e:
                health["services"]["audit"] = {
                    "status": "unhealthy",
                    "error": str(e)
                }
                health["status"] = "degraded"
                health["issues"].append(f"Audit service error: {e}")
        
        return health


# Simplified wrapper classes (minimal delegation)
class _SimpleCacheWrapper:
    """Minimal cache wrapper for backward compatibility."""
    
    def __init__(self, cache_service: TemplateCacheService):
        self._cache_service = cache_service
        self.ttl_seconds = cache_service.ttl_seconds
    
    def get(self, key: str):
        if isinstance(key, str) and '|' in key:
            return None  # Force refresh for legacy keys
        return self._cache_service.get(Path(key))
    
    def put(self, key: str, result: SecurityValidationResult):
        self._cache_service.put(Path(key), result)
    
    def clear(self):
        self._cache_service.clear()
    
    def size(self):
        return self._cache_service.size()


class _SimpleAuditWrapper:
    """Minimal audit wrapper for backward compatibility."""
    
    def __init__(self, audit_service: TemplateAuditService):
        self._audit_service = audit_service
    
    def log_validation_attempt(self, template_file: str, user_id: Optional[str] = None):
        self._audit_service.log_validation_attempt(template_file, user_id)
    
    def log_validation_result(
        self, 
        template_file: str, 
        result: SecurityValidationResult,
        cache_hit: bool = False, 
        user_id: Optional[str] = None
    ):
        self._audit_service.log_validation_result(
            template_file, result, cache_hit, user_id
        )
    
    def log_cache_operation(self, operation: str, details: Dict[str, Any]):
        self._audit_service.log_service_event(f"CACHE_{operation.upper()}", details)


class _SimpleSecurityWrapper:
    """Minimal security wrapper for backward compatibility."""
    
    def __init__(self, security_service: TemplateSecurityService):
        self._security_service = security_service
        self.strict_mode = security_service.strict_mode
    
    def validate_template_file(self, template_path: Path):
        return self._security_service.validate_template_file(template_path)
