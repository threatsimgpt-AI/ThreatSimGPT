"""Analysis engine interface and implementations for pluggable intelligence analysis.

This module provides a Strategy pattern implementation for different analysis approaches,
reducing LLM coupling and enabling caching of analysis results.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
import json
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class AnalysisEngine(ABC):
    """Abstract base class for command output analysis engines."""
    
    @abstractmethod
    async def analyze(self, command: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """
        Analyze command output for intelligence gathering.
        
        Args:
            command: Command that was executed
            stdout: Standard output
            stderr: Standard error output
            
        Returns:
            Dictionary containing intelligence findings
        """
        pass
    
    @abstractmethod
    def get_engine_name(self) -> str:
        """Return the name of this analysis engine."""
        pass
    
    @abstractmethod
    def get_reliability_score(self) -> float:
        """Return reliability score (0.0-1.0) for this engine."""
        pass


class LLMAnalysisEngine(AnalysisEngine):
    """LLM-based analysis engine for comprehensive intelligence gathering."""
    
    def __init__(self, llm_manager):
        self.llm = llm_manager
        self._engine_name = "llm"
        self._reliability_score = 0.8  # High but not perfect
    
    async def analyze(self, command: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Analyze using LLM with structured prompt."""
        intelligence = self._get_intelligence_template()
        
        # Build analysis prompt
        analysis_prompt = self._build_analysis_prompt(command, stdout, stderr)
        
        try:
            response = await self._generate_llm_response(analysis_prompt)
            analysis = json.loads(response)
            
            # Validate and merge intelligence
            for key, value in analysis.items():
                if key in intelligence and isinstance(value, list):
                    intelligence[key].extend(value)
                elif key in intelligence and isinstance(value, dict):
                    intelligence[key].update(value)
                    
            logger.debug(f"LLM analysis completed for command: {command[:50]}...")
            return intelligence
            
        except json.JSONDecodeError as e:
            logger.warning(f"LLM JSON parsing failed: {e}")
            raise LLMAnalysisError("JSON parsing failed", e)
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            raise LLMAnalysisError("LLM service failure", e)
    
    async def _generate_llm_response(self, prompt: str) -> str:
        """Generate LLM response, handling different manager interfaces."""
        try:
            # Try async generate method
            if hasattr(self.llm, "generate"):
                if asyncio.iscoroutinefunction(self.llm.generate):
                    return await self.llm.generate(prompt)
                else:
                    return self.llm.generate(prompt)

            # Try generate_content method
            if hasattr(self.llm, "generate_content"):
                result = await self.llm.generate_content(prompt)
                return result.content if hasattr(result, "content") else str(result)

            raise AttributeError("LLM manager has no generate method")

        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            raise LLMAnalysisError("LLM generation failed", e)
    
    def _build_analysis_prompt(self, command: str, stdout: str, stderr: str) -> str:
        """Build structured analysis prompt for LLM."""
        return f"""Analyze this command output for security intelligence.

Command: {command}

Output:
{stdout[:2000]}

Errors:
{stderr[:500]}

Extract and return JSON with these keys:
{{
    "hosts_discovered": ["IP addresses or hostnames"],
    "services_found": [{{"host": "...", "port": 123, "service": "...", "version": "..."}}],
    "credentials_found": [{{"username": "...", "password_hash": "...", "type": "...", "source": "..."}}],
    "vulnerabilities_found": [{{"host": "...", "service": "...", "vulnerability": "...", "severity": "medium/high/critical"}}],
    "users_found": ["usernames"],
    "network_info": {{"interfaces": [{{"name": "...", "ip": "...", "mac": "..."}}], "routes": [...]}} ,
    "file_system_info": {{{"interesting_files": [...], "permissions": [...], "sensitive_data": [...]}}},
    "security_indicators": ["IOCs, detection signatures, etc."]
}}

Only return valid JSON, no explanations.
"""
    
    def _get_intelligence_template(self) -> Dict[str, Any]:
        """Get base intelligence template."""
        return {
            "hosts_discovered": [],
            "services_found": [],
            "credentials_found": [],
            "vulnerabilities_found": [],
            "users_found": [],
            "network_info": {},
            "file_system_info": {},
            "security_indicators": [],
        }
    
    def get_engine_name(self) -> str:
        return self._engine_name
    
    def get_reliability_score(self) -> float:
        return self._reliability_score


class PatternAnalysisEngine(AnalysisEngine):
    """Pattern-based analysis engine for reliable basic intelligence extraction."""
    
    def __init__(self):
        self._engine_name = "pattern"
        self._reliability_score = 0.6  # Lower reliability but always works
    
    async def analyze(self, command: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Analyze using regex patterns for basic intelligence."""
        intelligence = self._get_intelligence_template()
        
        combined = stdout + stderr

        # IP address pattern
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ips = re.findall(ip_pattern, combined)
        intelligence["hosts_discovered"] = list(set(ips))

        # Port/service pattern (nmap style)
        service_pattern = r'(\d+)/(\w+)\s+(\w+)\s+open'
        services = re.findall(service_pattern, combined)
        for port, proto, service in services:
            intelligence["services_found"].append({
                "port": int(port),
                "protocol": proto,
                "service": service,
                "confidence": "medium",
            })

        # Username pattern
        user_pattern = r'\b(?:user|username|login)[:\s]+(\w+)'
        users = re.findall(user_pattern, combined, re.IGNORECASE)
        intelligence["users_found"] = list(set(users))

        logger.debug(f"Pattern analysis completed for command: {command[:50]}...")
        return intelligence
    
    def _get_intelligence_template(self) -> Dict[str, Any]:
        """Get base intelligence template."""
        return {
            "hosts_discovered": [],
            "services_found": [],
            "credentials_found": [],
            "vulnerabilities_found": [],
            "users_found": [],
            "network_info": {},
            "file_system_info": {},
            "security_indicators": [],
        }
    
    def get_engine_name(self) -> str:
        return self._engine_name
    
    def get_reliability_score(self) -> float:
        return self._reliability_score


class HybridAnalysisEngine(AnalysisEngine):
    """Hybrid analysis engine that combines LLM and pattern-based approaches."""
    
    def __init__(self, llm_manager, fallback_engine: Optional[AnalysisEngine] = None):
        self.llm_engine = LLMAnalysisEngine(llm_manager)
        self.pattern_engine = fallback_engine or PatternAnalysisEngine()
        self._engine_name = "hybrid"
        self._reliability_score = 0.9  # Highest reliability due to fallback
    
    async def analyze(self, command: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Analyze using LLM with pattern-based fallback."""
        try:
            # Try LLM analysis first
            return await self.llm_engine.analyze(command, stdout, stderr)
        except LLMAnalysisError as e:
            logger.warning(f"LLM analysis failed, falling back to pattern analysis: {e}")
            # Fall back to pattern-based analysis
            return await self.pattern_engine.analyze(command, stdout, stderr)
        except Exception as e:
            logger.error(f"Unexpected analysis error, using pattern fallback: {e}")
            return await self.pattern_engine.analyze(command, stdout, stderr)
    
    def get_engine_name(self) -> str:
        return self._engine_name
    
    def get_reliability_score(self) -> float:
        return self._reliability_score


class CachedAnalysisEngine(AnalysisEngine):
    """Caching wrapper for analysis engines to improve performance."""
    
    def __init__(self, base_engine: AnalysisEngine, cache_ttl_minutes: int = 30):
        self.base_engine = base_engine
        self.cache = {}
        self.cache_ttl = timedelta(minutes=cache_ttl_minutes)
        self._engine_name = f"cached_{base_engine.get_engine_name()}"
        self._reliability_score = base_engine.get_reliability_score()
    
    def _get_cache_key(self, command: str, stdout: str, stderr: str) -> str:
        """Generate cache key for analysis request."""
        # Use first 200 chars of stdout for caching to avoid memory issues
        content = f"{command}:{stdout[:200]}:{stderr[:100]}"
        return hash(content)
    
    def _is_cache_valid(self, timestamp: datetime) -> bool:
        """Check if cached result is still valid."""
        return datetime.utcnow() - timestamp < self.cache_ttl
    
    async def analyze(self, command: str, stdout: str, stderr: str) -> Dict[str, Any]:
        """Analyze with caching support."""
        cache_key = self._get_cache_key(command, stdout, stderr)
        
        # Check cache
        if cache_key in self.cache:
            cached_result, timestamp = self.cache[cache_key]
            if self._is_cache_valid(timestamp):
                logger.debug(f"Using cached analysis for command: {command[:50]}...")
                return cached_result
            else:
                # Remove expired cache entry
                del self.cache[cache_key]
        
        # Perform analysis
        result = await self.base_engine.analyze(command, stdout, stderr)
        
        # Cache result
        self.cache[cache_key] = (result, datetime.utcnow())
        
        return result
    
    def get_engine_name(self) -> str:
        return self._engine_name
    
    def get_reliability_score(self) -> float:
        return self._reliability_score
    
    def clear_cache(self):
        """Clear the analysis cache."""
        self.cache.clear()
        logger.info("Analysis cache cleared")


class AnalysisEngineFactory:
    """Factory for creating appropriate analysis engines."""
    
    @staticmethod
    def create_engine(engine_type: str, llm_manager=None, **kwargs) -> AnalysisEngine:
        """Create analysis engine of specified type."""
        engines = {
            "llm": lambda: LLMAnalysisEngine(llm_manager),
            "pattern": lambda: PatternAnalysisEngine(),
            "hybrid": lambda: HybridAnalysisEngine(llm_manager),
            "cached_llm": lambda: CachedAnalysisEngine(
                LLMAnalysisEngine(llm_manager), 
                cache_ttl_minutes=kwargs.get('cache_ttl_minutes', 30)
            ),
            "cached_hybrid": lambda: CachedAnalysisEngine(
                HybridAnalysisEngine(llm_manager),
                cache_ttl_minutes=kwargs.get('cache_ttl_minutes', 30)
            ),
        }
        
        if engine_type not in engines:
            raise ValueError(f"Unknown analysis engine type: {engine_type}")
        
        return engines[engine_type]()
    
    @staticmethod
    def get_available_engines() -> list:
        """Get list of available engine types."""
        return ["llm", "pattern", "hybrid", "cached_llm", "cached_hybrid"]


class LLMAnalysisError(Exception):
    """Custom exception for LLM analysis failures."""
    
    def __init__(self, message: str, original_error: Exception = None):
        super().__init__(message)
        self.original_error = original_error
        self.message = message
