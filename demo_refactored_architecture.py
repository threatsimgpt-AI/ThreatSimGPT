#!/usr/bin/env python3
"""Demo script for the refactored Template Manager.

This script demonstrates the new service-based architecture
and shows the improvements over the original implementation.
"""

import sys
import tempfile
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent))

from threatsimgpt.core.template_manager_refactored import TemplateManager

console = Console()


def demo_simplified_architecture():
    """Demonstrate the simplified service-based architecture."""
    
    console.print(Panel.fit(
        "[bold blue]Simplified Template Manager Demo[/bold blue]\n"
        "Clean service-based architecture with eliminated complexity",
        border_style="blue"
    ))
    
    # Create temporary directory for demo
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Initialize refactored TemplateManager
        console.print("\n[bold cyan]1. Initializing Services[/bold cyan]")
        manager = TemplateManager(
            templates_dir=temp_path,
            enable_security_validation=True,
            strict_security_mode=True,
            cache_ttl_seconds=60,
            cache_max_size=100,
            enable_audit_logging=True,
            enable_performance_monitoring=True
        )
        
        # Show service initialization
        console.print("✓ TemplateValidationService initialized")
        console.print("✓ TemplateSecurityService initialized")
        console.print("✓ TemplateCacheService initialized")
        console.print("✓ TemplateAuditService initialized")
        
        # Create sample templates
        console.print("\n[bold cyan]2. Creating Sample Templates[/bold cyan]")
        
        templates = [
            ("secure_template.yaml", """
name: "Secure Phishing Template"
threat_type: "phishing"
delivery_vector: "email"
description: "A secure phishing simulation template"
metadata:
  name: "Secure Phishing Template"
  author: "Security Team"
  version: "1.0.0"
  created_at: "2023-01-01T00:00:00Z"
  updated_at: "2023-01-01T00:00:00Z"
  tags: ["phishing", "training", "security"]
  references: []
"""),
            ("fixable_template.yaml", """
name: "Template with Issues"
threat_type: "invalid_threat_type"
delivery_vector: "multi_channel"
simulation_parameters:
  max_iterations: "3"
  max_duration_minutes: "60"
metadata:
  name: "Template with Issues"
  author: "Test Author"
  version: "1.0.0"
  created_at: "2023-01-01T00:00:00Z"
  updated_at: "2023-01-01T00:00:00Z"
  tags: []
  references: []
"""),
            ("malicious_template.yaml", """
name: "Malicious Template"
threat_type: "phishing"
delivery_vector: "email"
description: "This template contains javascript:alert('xss') which should be blocked"
metadata:
  name: "Malicious Template"
  author: "Attacker"
  version: "1.0.0"
  created_at: "2023-01-01T00:00:00Z"
  updated_at: "2023-01-01T00:00:00Z"
  tags: ["malicious"]
  references: []
""")
        ]
        
        for filename, content in templates:
            (temp_path / filename).write_text(content)
            console.print(f"✓ Created {filename}")
        
        # Demonstrate service-based validation
        console.print("\n[bold cyan]3. Service-based Validation[/bold cyan]")
        
        # Validate all templates
        results = manager.validate_all_templates()
        
        # Show validation results
        table = Table(title="Template Validation Results")
        table.add_column("Template", style="cyan")
        table.add_column("Status", style="white")
        table.add_column("Issues", style="red")
        
        for valid in results["valid"]:
            table.add_row(
                valid["file"], 
                "✓ Valid", 
                "None"
            )
        
        for invalid in results["invalid"]:
            table.add_row(
                invalid["file"], 
                "✗ Invalid", 
                invalid["error"][:50] + "..."
            )
        
        console.print(table)
        console.print(f"\nSuccess Rate: {results['statistics']['success_rate']:.1%}")
        
        # Demonstrate caching
        console.print("\n[bold cyan]4. Caching Service[/bold cyan]")
        
        secure_template = temp_path / "secure_template.yaml"
        
        # First validation (cache miss)
        console.print("First validation (cache miss)...")
        result1 = manager.validate_template_security(secure_template, user_id="demo_user")
        
        # Second validation (cache hit)
        console.print("Second validation (cache hit)...")
        result2 = manager.validate_template_security(secure_template, user_id="demo_user")
        
        # Show cache statistics
        cache_stats = manager.get_cache_info()
        console.print(f"Cache hit rate: {cache_stats['hit_rate']:.2%}")
        console.print(f"Cache utilization: {cache_stats['utilization']:.2%}")
        console.print(f"Cache size: {cache_stats['size']}/{cache_stats['max_size']}")
        
        # Demonstrate template fixing
        console.print("\n[bold cyan]5. Template Fixing Service[/bold cyan]")
        
        fixable_template = temp_path / "fixable_template.yaml"
        console.print(f"Fixing {fixable_template.name}...")
        
        success = manager.fix_template_issues(fixable_template)
        if success:
            console.print("✓ Template fixed successfully")
            
            # Show backup files
            backup_files = list(temp_path.glob("*.backup_*.yaml"))
            if backup_files:
                console.print(f"✓ Backup created: {backup_files[0].name}")
        
        # Demonstrate comprehensive statistics
        console.print("\n[bold cyan]6. Comprehensive Statistics[/bold cyan]")
        
        stats = manager.get_validation_statistics()
        
        stats_table = Table(title="Service Statistics")
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="white")
        
        key_metrics = [
            ("Total Validations", stats['total_validations']),
            ("Cache Hit Rate", f"{stats['cache_hit_rate']:.2%}"),
            ("Security Block Rate", f"{stats.get('security_block_rate', 0):.2%}"),
            ("Schema Success Rate", f"{stats['schema_success_rate']:.2%}"),
            ("Cache Utilization", f"{stats['cache_utilization']:.2%}"),
            ("Templates Fixed", stats['templates_fixed']),
            ("Avg Validation Duration", f"{stats.get('average_validation_duration_ms', 0):.2f}ms"),
            ("Audit Log Size", f"{stats.get('audit_log_size_mb', 0):.2f}MB")
        ]
        
        for metric, value in key_metrics:
            stats_table.add_row(metric, str(value))
        
        console.print(stats_table)
        
        # Demonstrate health checking
        console.print("\n[bold cyan]7. Health Check[/bold cyan]")
        
        health = manager.check_health()
        
        health_table = Table(title="Service Health")
        health_table.add_column("Service", style="cyan")
        health_table.add_column("Status", style="white")
        health_table.add_column("Details", style="green")
        
        for service_name, service_health in health['services'].items():
            status = service_health['status']
            details = service_health.get('statistics', {}).get('total_requests', 'N/A')
            
            status_style = {
                'healthy': 'green',
                'degraded': 'yellow',
                'unhealthy': 'red'
            }.get(status, 'white')
            
            health_table.add_row(
                service_name.title(),
                f"[{status_style}]{status}[/{status_style}]",
                str(details)
            )
        
        console.print(health_table)
        
        if health['issues']:
            console.print("\n[red]Health Issues:[/red]")
            for issue in health['issues']:
                console.print(f"  • {issue}")
        else:
            console.print("\n[green]✓ All services healthy[/green]")
        
        # Demonstrate service access
        console.print("\n[bold cyan]8. Direct Service Access[/bold cyan]")
        
        # Access individual services
        security_service = manager.get_security_service()
        cache_service = manager.get_cache_service()
        audit_service = manager.get_audit_service()
        
        console.print("✓ Accessed Security Service")
        console.print("✓ Accessed Cache Service")
        console.print("✓ Accessed Audit Service")
        
        # Show security service features
        if security_service:
            security_health = security_service.check_validator_health()
            console.print(f"✓ Security validator health: {security_health['status']}")
        
        # Show cache service features
        if cache_service:
            expired_count = cache_service.cleanup_expired()
            console.print(f"✓ Cleaned up {expired_count} expired cache entries")
        
        # Show audit service features
        if audit_service:
            audit_stats = audit_service.get_log_statistics()
            console.print(f"✓ Audit log files: {audit_stats['file_count']}")
        
        console.print("\n[bold green]Demo completed successfully![/bold green]")
        console.print("\n[dim]Key improvements demonstrated:[/dim]")
        console.print("• Service-based architecture with clear responsibilities")
        console.print("• Enhanced security with proper caching and audit logging")
        console.print("• Comprehensive health monitoring and statistics")
        console.print("• Backward compatibility with existing API")
        console.print("• Better error handling and observability")


if __name__ == "__main__":
    try:
        demo_simplified_architecture()
    except KeyboardInterrupt:
        console.print("\n[yellow]Demo interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]Demo failed: {e}[/red]")
        sys.exit(1)
