"""Production-grade secure configuration loader following NASA Power of 10 rules."""

import os
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union

import yaml
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class SecureConfigLoader:
    """Production-grade configuration loader with NASA Power of 10 compliance."""
    
    def __init__(self, config_path: Optional[Union[str, Path]] = None) -> None:
        """Initialize with comprehensive validation."""
        assert config_path is None or isinstance(config_path, (str, Path)), "Invalid config path type"
        
        self.config_path = Path(config_path) if config_path else Path("config.yaml")
        self._config = None
        
        # Validate configuration path (Rule #5)
        assert isinstance(self.config_path, Path), "Config path must be Path object"
        assert self.config_path.suffix in ['.yaml', '.yml'], "Config file must be YAML"
    
    def load_config(self) -> 'ThreatSimGPTConfig':
        """Load configuration with NASA Power of 10 compliance."""
        if self._config is None:
            self._config = self._load_and_validate()
        return self._config
    
    def _load_and_validate(self) -> 'ThreatSimGPTConfig':
        """Load and validate with assertion density (Rule #5)."""
        # Load file configuration
        file_config = self._load_file_config()
        assert isinstance(file_config, dict), "File config must be dictionary"
        
        # Load environment configuration  
        env_config = self._load_environment_config()
        assert isinstance(env_config, dict), "Environment config must be dictionary"
        
        # Merge configurations
        merged_config = self._merge_configurations(file_config, env_config)
        assert isinstance(merged_config, dict), "Merged config must be dictionary"
        
        # Validate final configuration
        return self._validate_final_config(merged_config)
    
    def _load_file_config(self) -> Dict[str, Any]:
        """Load file configuration with return value validation (Rule #7)."""
        assert self.config_path.exists(), f"Config file {self.config_path} does not exist"
        
        # Check file size (Rule #2)
        file_size_mb = self.config_path.stat().st_size / (1024 * 1024)
        assert file_size_mb <= 10, "Config file too large (max 10MB)"
        
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                content = f.read()
                assert content, "Config file cannot be empty"
                assert len(content.split('\n')) <= 1000, "Config file has too many lines"
                
                config_data = yaml.safe_load(content)
                assert config_data is not None, "YAML parsing returned None"
                assert isinstance(config_data, dict), "Config must be dictionary"
                
                return config_data
                
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML configuration: {e}")
        except IOError as e:
            raise ValueError(f"Failed to read config file: {e}")
    
    def _load_environment_config(self) -> Dict[str, Any]:
        """Load environment configuration with API key validation."""
        env_config = {}
        
        # API key validation with proper format checking
        api_keys = {
            'OPENAI_API_KEY': ('sk-', 51),
            'ANTHROPIC_API_KEY': ('sk-ant-', 55),
            'OPENROUTER_API_KEY': ('sk-or-v1-', 73)
        }
        
        for env_var, (prefix, min_length) in api_keys.items():
            value = os.getenv(env_var, '')
            if value:
                validated_key = self._validate_api_key(value, env_var, prefix, min_length)
                provider_name = env_var.lower().replace('_api_key', '')
                
                if 'llm' not in env_config:
                    env_config['llm'] = {}
                if provider_name not in env_config['llm']:
                    env_config['llm'][provider_name] = {}
                
                env_config['llm'][provider_name]['api_key'] = validated_key
        
        # Other environment variables with validation
        if os.getenv('LOG_LEVEL'):
            log_level = os.getenv('LOG_LEVEL')
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            assert log_level in valid_levels, f"Invalid LOG_LEVEL: {log_level}"
            env_config['logging'] = {'level': log_level}
        
        if os.getenv('DEBUG'):
            debug_value = os.getenv('DEBUG')
            assert debug_value.lower() in ['true', 'false', '1', '0'], "DEBUG must be boolean"
            env_config['api'] = {'debug': debug_value.lower() in ['true', '1']}
        
        return env_config
    
    def _validate_api_key(self, key: str, env_var: str, expected_prefix: str, min_length: int) -> str:
        """Validate API key with comprehensive checks (Rule #5, #7)."""
        assert isinstance(key, str), f"{env_var} must be string"
        assert key.strip(), f"{env_var} cannot be empty"
        assert len(key) >= min_length, f"{env_var} too short (min {min_length} chars)"
        assert len(key) <= 200, f"{env_var} too long (max 200 chars)"
        assert key.startswith(expected_prefix), f"{env_var} has invalid prefix"
        
        # Security validation
        assert ' ' not in key, f"{env_var} contains spaces"
        assert '\n' not in key, f"{env_var} contains newlines"
        assert '\t' not in key, f"{env_var} contains tabs"
        assert '\r' not in key, f"{env_var} contains carriage returns"
        
        return key.strip()
    
    def _merge_configurations(self, file_config: Dict[str, Any], env_config: Dict[str, Any]) -> Dict[str, Any]:
        """Merge configurations with validation."""
        merged = file_config.copy()
        
        # Deep merge environment overrides
        for section, values in env_config.items():
            assert isinstance(section, str), "Config section must be string"
            assert isinstance(values, dict), "Config values must be dictionary"
            
            if section not in merged:
                merged[section] = {}
            merged[section].update(values)
        
        return merged
    
    def _validate_final_config(self, config_data: Dict[str, Any]) -> 'ThreatSimGPTConfig':
        """Validate final configuration with production checks."""
        try:
            config = ThreatSimGPTConfig.parse_obj(config_data)
            
            # Production validation
            self._validate_production_readiness(config)
            
            return config
            
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            raise ValueError(f"Invalid configuration: {e}")
    
    def _validate_production_readiness(self, config: 'ThreatSimGPTConfig') -> None:
        """Validate production readiness."""
        # Check for required API keys
        has_api_keys = any(
            provider.get('api_key') 
            for provider in config.llm.values()
        )
        assert has_api_keys, "At least one LLM API key must be configured"
        
        # Check security settings
        assert config.safety.enable_safety_validation, "Safety validation must be enabled"
        assert config.safety.compliance_mode, "Compliance mode must be enabled"
        
        logger.info("Configuration validated for production use")


# Import the original config models
from .loader import ThreatSimGPTConfig, SimulationConfig, SafetyConfig, LoggingConfig, APIConfig
