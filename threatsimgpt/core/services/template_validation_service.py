"""Template Validation Service for schema validation and template management.

Provides comprehensive template validation with:
- Schema validation using Pydantic models
- Template fixing capabilities
- Batch validation operations
- Template creation and cloning
"""

import shutil
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from threatsimgpt.config.models import ThreatScenario
from threatsimgpt.config.yaml_loader import YAMLConfigLoader


class ValidationError(Exception):
    """Raised when template validation fails."""
    pass


class TemplateFixResult:
    """Result of template fixing operation."""
    
    def __init__(
        self,
        success: bool,
        fixes_applied: List[str],
        backup_path: Optional[Path] = None,
        error: Optional[str] = None
    ):
        self.success = success
        self.fixes_applied = fixes_applied
        self.backup_path = backup_path
        self.error = error


class TemplateValidationService:
    """Service for template schema validation and management.
    
    Handles:
    - Schema validation using ThreatScenario model
    - Template fixing and repair
    - Template creation and cloning
    - Batch validation operations
    """
    
    def __init__(self, templates_dir: Optional[Path] = None):
        """Initialize validation service.
        
        Args:
            templates_dir: Directory containing templates
        """
        self.templates_dir = templates_dir or Path("templates")
        self.loader = YAMLConfigLoader()
        
        # Validation statistics
        self._stats = {
            'total_validations': 0,
            'schema_failures': 0,
            'templates_fixed': 0,
            'templates_created': 0,
            'templates_cloned': 0
        }
    
    def validate_template_schema(self, template_path: Path) -> Tuple[bool, Optional[ThreatScenario], Optional[str]]:
        """Validate template against ThreatScenario schema.
        
        Args:
            template_path: Path to template file
            
        Returns:
            Tuple of (is_valid, validated_scenario, error_message)
            
        Raises:
            ValidationError: If template cannot be loaded or parsed
        """
        if not template_path.exists():
            return False, None, f"Template file not found: {template_path}"
        
        if not template_path.is_file():
            return False, None, f"Template path is not a file: {template_path}"
        
        try:
            # Load and validate using Pydantic model
            scenario = self.loader.load_and_validate_scenario(template_path)
            
            # Update statistics
            self._stats['total_validations'] += 1
            
            return True, scenario, None
            
        except Exception as e:
            self._stats['total_validations'] += 1
            self._stats['schema_failures'] += 1
            
            error_msg = f"Schema validation failed: {str(e)}"
            return False, None, error_msg
    
    def validate_template_content_schema(
        self, 
        content: str, 
        template_name: str = "unknown"
    ) -> Tuple[bool, Optional[ThreatScenario], Optional[str]]:
        """Validate template content against schema.
        
        Args:
            content: Template content as YAML string
            template_name: Name for identification
            
        Returns:
            Tuple of (is_valid, validated_scenario, error_message)
        """
        try:
            # Parse YAML content
            template_data = yaml.safe_load(content)
            
            # Validate using Pydantic model
            scenario = ThreatScenario.parse_obj(template_data)
            
            self._stats['total_validations'] += 1
            
            return True, scenario, None
            
        except Exception as e:
            self._stats['total_validations'] += 1
            self._stats['schema_failures'] += 1
            
            error_msg = f"Schema validation failed for '{template_name}': {str(e)}"
            return False, None, error_msg
    
    def validate_templates_batch(
        self,
        template_paths: List[Path]
    ) -> Dict[str, Tuple[bool, Optional[str]]]:
        """Validate multiple templates against schema.
        
        Args:
            template_paths: List of template file paths
            
        Returns:
            Dictionary mapping template paths to (is_valid, error_message)
        """
        results = {}
        
        for template_path in template_paths:
            is_valid, scenario, error = self.validate_template_schema(template_path)
            results[str(template_path)] = (is_valid, error)
        
        return results
    
    def fix_template_issues(self, template_path: Path) -> TemplateFixResult:
        """Attempt to automatically fix common template issues.
        
        Args:
            template_path: Path to template file to fix
            
        Returns:
            TemplateFixResult with details of fixes applied
        """
        if not template_path.exists():
            return TemplateFixResult(
                success=False,
                fixes_applied=[],
                error=f"Template file not found: {template_path}"
            )
        
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse YAML
            template_data = yaml.safe_load(content)
            if template_data is None:
                return TemplateFixResult(
                    success=False,
                    fixes_applied=[],
                    error="Template file is empty or invalid YAML"
                )
            
            # Apply fixes
            fixes_applied = self._apply_common_fixes(template_data)
            
            if not fixes_applied:
                return TemplateFixResult(
                    success=True,
                    fixes_applied=[],
                    error="No fixes needed"
                )
            
            # Create backup
            backup_path = template_path.with_suffix(
                f".backup_{int(datetime.now().timestamp())}.yaml"
            )
            shutil.copy2(template_path, backup_path)
            
            # Save fixed version
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write("# ThreatSimGPT Threat Scenario Template (Auto-fixed)\n")
                f.write(f"# Fixes applied: {', '.join(fixes_applied)}\n")
                f.write(f"# Fixed at: {datetime.utcnow().isoformat()}Z\n\n")
                yaml.dump(template_data, f, default_flow_style=False, sort_keys=False)
            
            self._stats['templates_fixed'] += 1
            
            return TemplateFixResult(
                success=True,
                fixes_applied=fixes_applied,
                backup_path=backup_path
            )
            
        except Exception as e:
            return TemplateFixResult(
                success=False,
                fixes_applied=[],
                error=f"Failed to fix template: {str(e)}"
            )
    
    def _apply_common_fixes(self, template_data: Dict[str, Any]) -> List[str]:
        """Apply common fixes to template data.
        
        Args:
            template_data: Template data to fix
            
        Returns:
            List of fixes applied
        """
        fixes_applied = []
        
        # Fix threat_type issues
        if "threat_type" in template_data:
            original = template_data["threat_type"]
            fixed = self._fix_threat_type(original)
            if fixed != original:
                template_data["threat_type"] = fixed
                fixes_applied.append(f"threat_type: {original} -> {fixed}")
        
        # Fix delivery_vector issues
        if "delivery_vector" in template_data:
            original = template_data["delivery_vector"]
            fixed = self._fix_delivery_vector(original)
            if fixed != original:
                template_data["delivery_vector"] = fixed
                fixes_applied.append(f"delivery_vector: {original} -> {fixed}")
        
        # Fix simulation parameters
        if "simulation_parameters" in template_data:
            sim_params = template_data["simulation_parameters"]
            param_fixes = self._fix_simulation_parameters(sim_params)
            fixes_applied.extend(param_fixes)
        
        # Remove extra fields that cause validation errors
        extra_fields = ["success_metrics", "compliance_controls", "post_simulation_analysis"]
        for field in extra_fields:
            if field in template_data:
                del template_data[field]
                fixes_applied.append(f"Removed extra field: {field}")
        
        # Ensure metadata exists
        if "metadata" not in template_data:
            template_data["metadata"] = {
                "name": "Unknown Template",
                "description": "Auto-generated description",
                "author": "System",
                "version": "1.0.0",
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z",
                "tags": [],
                "references": []
            }
            fixes_applied.append("Added missing metadata section")
        
        return fixes_applied
    
    def _fix_threat_type(self, value: str) -> str:
        """Fix common threat_type issues.
        
        Args:
            value: Original threat_type value
            
        Returns:
            Fixed threat_type value
        """
        mappings = {
            "hybrid_attack": "advanced_persistent_threat",
            "multi_vector": "advanced_persistent_threat",
            "healthcare_targeted_attack": "spear_phishing",
            "apt": "advanced_persistent_threat",
            "advanced_persistent_threat": "advanced_persistent_threat"
        }
        
        return mappings.get(value.lower().replace("-", "_"), value)
    
    def _fix_delivery_vector(self, value: str) -> str:
        """Fix common delivery_vector issues.
        
        Args:
            value: Original delivery_vector value
            
        Returns:
            Fixed delivery_vector value
        """
        mappings = {
            "multi_channel": "email",
            "multi_vector": "email",
            "sms": "sms",
            "voice": "phone_call",
            "phone": "phone_call"
        }
        
        return mappings.get(value.lower().replace("-", "_"), value)
    
    def _fix_simulation_parameters(self, sim_params: Dict[str, Any]) -> List[str]:
        """Fix simulation parameters.
        
        Args:
            sim_params: Simulation parameters to fix
            
        Returns:
            List of fixes applied
        """
        fixes_applied = []
        
        # Fix numeric fields that might be strings
        numeric_fields = ["max_iterations", "max_duration_minutes", "urgency_level"]
        
        for field in numeric_fields:
            if field in sim_params and isinstance(sim_params[field], str):
                try:
                    sim_params[field] = int(sim_params[field])
                    fixes_applied.append(f"simulation_parameters.{field}: converted to int")
                except (ValueError, TypeError):
                    # Set default values
                    defaults = {
                        "max_iterations": 3,
                        "max_duration_minutes": 60,
                        "urgency_level": 5
                    }
                    if field in defaults:
                        sim_params[field] = defaults[field]
                        fixes_applied.append(f"simulation_parameters.{field}: defaulted to {defaults[field]}")
        
        # Ensure boolean fields are properly typed
        boolean_fields = ["escalation_enabled", "response_adaptation", "time_pressure_simulation"]
        
        for field in boolean_fields:
            if field in sim_params and isinstance(sim_params[field], str):
                sim_params[field] = sim_params[field].lower() in ("true", "1", "yes", "on")
                fixes_applied.append(f"simulation_parameters.{field}: converted to boolean")
        
        return fixes_applied
    
    def create_template_from_data(
        self,
        template_data: Dict[str, Any],
        template_name: str,
        overwrite: bool = False
    ) -> Tuple[bool, Optional[Path], Optional[str]]:
        """Create a new template from data.
        
        Args:
            template_data: Template data dictionary
            template_name: Name for the new template
            overwrite: Whether to overwrite existing template
            
        Returns:
            Tuple of (success, template_path, error_message)
        """
        try:
            # Validate template data
            is_valid, scenario, error = self.validate_template_content_schema(
                yaml.dump(template_data), 
                template_name
            )
            
            if not is_valid:
                return False, None, f"Template validation failed: {error}"
            
            # Generate filename
            safe_name = "".join(
                c if c.isalnum() or c in '-_' else '_' 
                for c in template_name.lower()
            )
            filename = f"{safe_name}.yaml"
            template_path = self.templates_dir / filename
            
            # Check if file exists
            if template_path.exists() and not overwrite:
                return False, None, f"Template file already exists: {template_path}"
            
            # Ensure templates directory exists
            self.templates_dir.mkdir(exist_ok=True, parents=True)
            
            # Save template
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write("# ThreatSimGPT Threat Scenario Template\n")
                f.write(f"# Created at: {datetime.utcnow().isoformat()}Z\n\n")
                yaml.dump(template_data, f, default_flow_style=False, sort_keys=False)
            
            self._stats['templates_created'] += 1
            
            return True, template_path, None
            
        except Exception as e:
            return False, None, f"Failed to create template: {str(e)}"
    
    def clone_template(
        self,
        source_template: str,
        new_name: str,
        modifications: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, Optional[Path], Optional[str]]:
        """Create a new template by copying and modifying an existing one.
        
        Args:
            source_template: Name or path of source template
            new_name: Name for the new template
            modifications: Optional modifications to apply
            
        Returns:
            Tuple of (success, new_template_path, error_message)
        """
        try:
            # Find source template
            source_path = self._find_template(source_template)
            if not source_path:
                return False, None, f"Source template not found: {source_template}"
            
            # Load source template
            with open(source_path, 'r', encoding='utf-8') as f:
                template_data = yaml.safe_load(f)
            
            # Apply modifications
            if modifications:
                template_data.update(modifications)
            
            # Update metadata for cloned template
            if "metadata" not in template_data:
                template_data["metadata"] = {}
            
            template_data["metadata"].update({
                "name": new_name,
                "description": f"Cloned from {source_template}",
                "version": "1.0.0",
                "author": "System",
                "created_at": datetime.utcnow().isoformat() + "Z",
                "updated_at": datetime.utcnow().isoformat() + "Z"
            })
            
            # Create new template
            success, new_path, error = self.create_template_from_data(
                template_data, 
                new_name, 
                overwrite=False
            )
            
            if success:
                self._stats['templates_cloned'] += 1
            
            return success, new_path, error
            
        except Exception as e:
            return False, None, f"Failed to clone template: {str(e)}"
    
    def _find_template(self, template_name: str) -> Optional[Path]:
        """Find template file by name or path.
        
        Args:
            template_name: Template name or path
            
        Returns:
            Path to template file or None if not found
        """
        # Try as direct path
        template_path = Path(template_name)
        if template_path.exists():
            return template_path
        
        # Try with .yaml extension in templates directory
        template_path = self.templates_dir / f"{template_name}.yaml"
        if template_path.exists():
            return template_path
        
        # Try with .yml extension
        template_path = self.templates_dir / f"{template_name}.yml"
        if template_path.exists():
            return template_path
        
        return None
    
    def get_validation_statistics(self) -> Dict[str, Any]:
        """Get validation service statistics.
        
        Returns:
            Dictionary with validation statistics
        """
        stats = self._stats.copy()
        
        # Calculate success rate
        if stats['total_validations'] > 0:
            stats['success_rate'] = (
                (stats['total_validations'] - stats['schema_failures']) / 
                stats['total_validations']
            )
        else:
            stats['success_rate'] = 0.0
        
        return stats
    
    def reset_statistics(self) -> None:
        """Reset validation statistics."""
        self._stats = {
            'total_validations': 0,
            'schema_failures': 0,
            'templates_fixed': 0,
            'templates_created': 0,
            'templates_cloned': 0
        }
