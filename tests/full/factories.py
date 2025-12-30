"""
Test Factories
==============

Factory classes for generating test data using factory_boy pattern.
Provides consistent, reproducible test data generation.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Type, TypeVar
from enum import Enum
import random
import string
import uuid
from pathlib import Path

# Type variable for generic factory
T = TypeVar("T")


class FactorySequence:
    """Auto-incrementing sequence for unique values."""
    
    def __init__(self, start: int = 1, prefix: str = ""):
        self._counter = start
        self._prefix = prefix
    
    def __call__(self) -> str:
        value = f"{self._prefix}{self._counter}"
        self._counter += 1
        return value
    
    def reset(self, start: int = 1):
        """Reset sequence counter."""
        self._counter = start


class Faker:
    """Simple faker for generating realistic test data."""
    
    # Cybersecurity-themed data
    THREAT_TYPES = ["phishing", "ransomware", "apt", "insider_threat", "ddos", "malware"]
    ATTACK_VECTORS = ["email", "web", "network", "usb", "social_engineering", "supply_chain"]
    INDUSTRIES = ["finance", "healthcare", "technology", "government", "retail", "energy"]
    DEPARTMENTS = ["IT", "HR", "Finance", "Engineering", "Marketing", "Legal", "Executive"]
    ROLES = ["Analyst", "Manager", "Director", "VP", "Engineer", "Administrator"]
    SEVERITIES = ["low", "medium", "high", "critical"]
    
    # MITRE ATT&CK IDs
    MITRE_TECHNIQUES = [
        "T1566.001", "T1566.002", "T1078", "T1059", "T1047", "T1053",
        "T1055", "T1083", "T1057", "T1082", "T1071", "T1105", "T1041"
    ]
    
    FIRST_NAMES = ["John", "Jane", "Alice", "Bob", "Charlie", "Diana", "Eve", "Frank"]
    LAST_NAMES = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller"]
    DOMAINS = ["acme.com", "corp.local", "enterprise.io", "company.net", "org.example"]
    
    @classmethod
    def uuid(cls) -> str:
        return str(uuid.uuid4())
    
    @classmethod
    def name(cls) -> str:
        return f"{random.choice(cls.FIRST_NAMES)} {random.choice(cls.LAST_NAMES)}"
    
    @classmethod
    def email(cls, domain: Optional[str] = None) -> str:
        domain = domain or random.choice(cls.DOMAINS)
        first = random.choice(cls.FIRST_NAMES).lower()
        last = random.choice(cls.LAST_NAMES).lower()
        return f"{first}.{last}@{domain}"
    
    @classmethod
    def threat_type(cls) -> str:
        return random.choice(cls.THREAT_TYPES)
    
    @classmethod
    def attack_vector(cls) -> str:
        return random.choice(cls.ATTACK_VECTORS)
    
    @classmethod
    def industry(cls) -> str:
        return random.choice(cls.INDUSTRIES)
    
    @classmethod
    def department(cls) -> str:
        return random.choice(cls.DEPARTMENTS)
    
    @classmethod
    def role(cls) -> str:
        return random.choice(cls.ROLES)
    
    @classmethod
    def severity(cls) -> str:
        return random.choice(cls.SEVERITIES)
    
    @classmethod
    def mitre_techniques(cls, count: int = 3) -> List[str]:
        return random.sample(cls.MITRE_TECHNIQUES, min(count, len(cls.MITRE_TECHNIQUES)))
    
    @classmethod
    def text(cls, length: int = 100) -> str:
        words = ["threat", "security", "attack", "defense", "network", "system", 
                 "data", "breach", "protect", "monitor", "detect", "respond"]
        return " ".join(random.choices(words, k=length // 6))
    
    @classmethod
    def api_key(cls, prefix: str = "sk-") -> str:
        chars = string.ascii_letters + string.digits
        return prefix + "".join(random.choices(chars, k=48))
    
    @classmethod
    def timestamp(cls, days_ago: int = 0) -> datetime:
        return datetime.utcnow() - timedelta(days=days_ago)
    
    @classmethod
    def ip_address(cls) -> str:
        return f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    
    @classmethod
    def domain(cls) -> str:
        return random.choice(cls.DOMAINS)


# ==========================================
# Core Model Factories
# ==========================================

@dataclass
class ThreatScenarioFactory:
    """Factory for ThreatScenario test data."""
    
    _sequence = FactorySequence(prefix="scenario_")
    
    @classmethod
    def build(
        cls,
        name: Optional[str] = None,
        threat_type: Optional[str] = None,
        description: Optional[str] = None,
        severity: Optional[str] = None,
        **overrides
    ) -> Dict[str, Any]:
        """Build a threat scenario dictionary."""
        return {
            "name": name or f"Test Scenario {cls._sequence()}",
            "threat_type": threat_type or Faker.threat_type(),
            "description": description or Faker.text(50),
            "severity": severity or Faker.severity(),
            "target_systems": overrides.get("target_systems", ["email", "network"]),
            "attack_vectors": overrides.get("attack_vectors", [Faker.attack_vector()]),
            "mitre_techniques": overrides.get("mitre_techniques", Faker.mitre_techniques()),
            "metadata": overrides.get("metadata", {
                "created_at": Faker.timestamp().isoformat(),
                "author": "test_factory",
            }),
            **{k: v for k, v in overrides.items() if k not in [
                "target_systems", "attack_vectors", "mitre_techniques", "metadata"
            ]}
        }
    
    @classmethod
    def build_batch(cls, count: int = 5, **common_attrs) -> List[Dict[str, Any]]:
        """Build multiple threat scenarios."""
        return [cls.build(**common_attrs) for _ in range(count)]
    
    @classmethod
    def phishing(cls, **overrides) -> Dict[str, Any]:
        """Build a phishing-specific scenario."""
        return cls.build(
            threat_type="phishing",
            attack_vectors=["email", "social_engineering"],
            **overrides
        )
    
    @classmethod
    def ransomware(cls, **overrides) -> Dict[str, Any]:
        """Build a ransomware-specific scenario."""
        return cls.build(
            threat_type="ransomware",
            severity="critical",
            attack_vectors=["malware", "email"],
            **overrides
        )
    
    @classmethod
    def apt(cls, **overrides) -> Dict[str, Any]:
        """Build an APT-specific scenario."""
        return cls.build(
            threat_type="apt",
            severity="critical",
            attack_vectors=["supply_chain", "network", "lateral_movement"],
            mitre_techniques=Faker.mitre_techniques(5),
            **overrides
        )


@dataclass
class TargetProfileFactory:
    """Factory for target profile test data."""
    
    _sequence = FactorySequence(prefix="target_")
    
    @classmethod
    def build(
        cls,
        name: Optional[str] = None,
        role: Optional[str] = None,
        department: Optional[str] = None,
        **overrides
    ) -> Dict[str, Any]:
        """Build a target profile dictionary."""
        return {
            "id": cls._sequence(),
            "name": name or Faker.name(),
            "email": overrides.get("email", Faker.email()),
            "role": role or Faker.role(),
            "department": department or Faker.department(),
            "seniority": overrides.get("seniority", random.choice(["junior", "mid", "senior"])),
            "technical_level": overrides.get("technical_level", random.choice(["low", "medium", "high"])),
            "industry": overrides.get("industry", Faker.industry()),
            "organization": overrides.get("organization", f"Test Corp {random.randint(1, 100)}"),
            **{k: v for k, v in overrides.items() if k not in [
                "email", "seniority", "technical_level", "industry", "organization"
            ]}
        }
    
    @classmethod
    def executive(cls, **overrides) -> Dict[str, Any]:
        """Build an executive target profile."""
        return cls.build(
            role="CEO",
            department="Executive",
            seniority="senior",
            technical_level="low",
            **overrides
        )
    
    @classmethod
    def it_admin(cls, **overrides) -> Dict[str, Any]:
        """Build an IT admin target profile."""
        return cls.build(
            role="System Administrator",
            department="IT",
            seniority="mid",
            technical_level="high",
            **overrides
        )


@dataclass
class SimulationResultFactory:
    """Factory for simulation result test data."""
    
    _sequence = FactorySequence(prefix="sim_")
    
    @classmethod
    def build(
        cls,
        status: str = "completed",
        success: bool = True,
        **overrides
    ) -> Dict[str, Any]:
        """Build a simulation result dictionary."""
        return {
            "id": cls._sequence(),
            "scenario_id": overrides.get("scenario_id", f"scenario_{random.randint(1, 100)}"),
            "status": status,
            "success": success,
            "started_at": Faker.timestamp(1).isoformat(),
            "completed_at": Faker.timestamp().isoformat(),
            "duration_seconds": random.uniform(10, 300),
            "stages_completed": overrides.get("stages_completed", random.randint(1, 5)),
            "total_stages": overrides.get("total_stages", 5),
            "metrics": overrides.get("metrics", {
                "click_rate": random.uniform(0, 1),
                "detection_rate": random.uniform(0, 1),
                "response_time": random.uniform(1, 60),
            }),
            "artifacts": overrides.get("artifacts", []),
            **{k: v for k, v in overrides.items() if k not in [
                "scenario_id", "stages_completed", "total_stages", "metrics", "artifacts"
            ]}
        }


@dataclass
class LLMResponseFactory:
    """Factory for LLM response test data."""
    
    @classmethod
    def build(
        cls,
        content: Optional[str] = None,
        provider: str = "mock",
        model: str = "mock-model",
        **overrides
    ) -> Dict[str, Any]:
        """Build an LLM response dictionary."""
        return {
            "content": content or Faker.text(200),
            "provider": provider,
            "model": model,
            "tokens_used": overrides.get("tokens_used", random.randint(100, 1000)),
            "latency_ms": overrides.get("latency_ms", random.uniform(100, 2000)),
            "finish_reason": overrides.get("finish_reason", "stop"),
            "metadata": overrides.get("metadata", {}),
            **{k: v for k, v in overrides.items() if k not in [
                "tokens_used", "latency_ms", "finish_reason", "metadata"
            ]}
        }
    
    @classmethod
    def phishing_email(cls, **overrides) -> Dict[str, Any]:
        """Build a phishing email response."""
        return cls.build(
            content="""Subject: Urgent: Account Security Update Required

Dear Employee,

We have detected unusual activity on your account. Please verify your credentials immediately by clicking the link below.

[Verify Account]

Best regards,
IT Security Team""",
            **overrides
        )


@dataclass
class ConfigFactory:
    """Factory for configuration test data."""
    
    @classmethod
    def build(cls, **overrides) -> Dict[str, Any]:
        """Build a configuration dictionary."""
        return {
            "llm": overrides.get("llm", {
                "default_provider": "openai",
                "providers": {
                    "openai": {
                        "api_key": Faker.api_key("sk-"),
                        "model": "gpt-4",
                        "max_tokens": 2000,
                    }
                }
            }),
            "simulation": overrides.get("simulation", {
                "max_stages": 5,
                "timeout_seconds": 300,
                "enable_safety_checks": True,
            }),
            "safety": overrides.get("safety", {
                "enabled": True,
                "block_real_attacks": True,
                "audit_logging": True,
            }),
            "logging": overrides.get("logging", {
                "level": "INFO",
                "format": "json",
            }),
            **{k: v for k, v in overrides.items() if k not in [
                "llm", "simulation", "safety", "logging"
            ]}
        }
    
    @classmethod
    def minimal(cls) -> Dict[str, Any]:
        """Build minimal configuration."""
        return {
            "llm": {"default_provider": "mock"},
            "simulation": {"max_stages": 3},
        }
    
    @classmethod
    def production(cls) -> Dict[str, Any]:
        """Build production-like configuration."""
        return cls.build(
            safety={"enabled": True, "block_real_attacks": True, "audit_logging": True},
            logging={"level": "WARNING", "format": "json", "output": "file"},
        )


# ==========================================
# Template Factories
# ==========================================

@dataclass 
class TemplateFactory:
    """Factory for template test data."""
    
    _sequence = FactorySequence(prefix="template_")
    
    @classmethod
    def build(
        cls,
        name: Optional[str] = None,
        template_type: str = "phishing",
        **overrides
    ) -> Dict[str, Any]:
        """Build a template dictionary."""
        return {
            "id": cls._sequence(),
            "name": name or f"Test Template {random.randint(1, 100)}",
            "type": template_type,
            "version": overrides.get("version", "1.0.0"),
            "description": overrides.get("description", Faker.text(30)),
            "author": overrides.get("author", "test_factory"),
            "variables": overrides.get("variables", {
                "target_name": {"type": "string", "required": True},
                "company_name": {"type": "string", "required": True},
                "urgency_level": {"type": "string", "default": "medium"},
            }),
            "content": overrides.get("content", {
                "subject": "{{urgency_level}}: Action Required for {{target_name}}",
                "body": "Dear {{target_name}},\n\nThis is a test email from {{company_name}}.",
            }),
            "metadata": overrides.get("metadata", {
                "created_at": Faker.timestamp().isoformat(),
                "tags": ["test", template_type],
            }),
        }
    
    @classmethod
    def yaml_content(cls, name: str = "test_template") -> str:
        """Generate YAML template content."""
        return f"""name: {name}
type: phishing
version: 1.0.0
description: Test template for unit testing

variables:
  target_name:
    type: string
    required: true
  company_name:
    type: string
    required: true

content:
  subject: "Urgent: Action Required"
  body: |
    Dear {{{{target_name}}}},
    
    This is a test email from {{{{company_name}}}}.
    
    Best regards,
    Test Team
"""


# ==========================================
# API Request/Response Factories
# ==========================================

@dataclass
class APIRequestFactory:
    """Factory for API request test data."""
    
    @classmethod
    def simulate_request(cls, **overrides) -> Dict[str, Any]:
        """Build a simulation API request."""
        return {
            "scenario": ThreatScenarioFactory.build(),
            "target": TargetProfileFactory.build(),
            "options": overrides.get("options", {
                "dry_run": False,
                "save_results": True,
            }),
            **{k: v for k, v in overrides.items() if k != "options"}
        }
    
    @classmethod
    def generate_request(cls, **overrides) -> Dict[str, Any]:
        """Build a content generation API request."""
        return {
            "template_id": overrides.get("template_id", "phishing_email"),
            "variables": overrides.get("variables", {
                "target_name": Faker.name(),
                "company_name": "Test Corp",
            }),
            "provider": overrides.get("provider", "openai"),
            **{k: v for k, v in overrides.items() if k not in [
                "template_id", "variables", "provider"
            ]}
        }


# Reset all sequences (useful in test setup)
def reset_all_factories():
    """Reset all factory sequences."""
    ThreatScenarioFactory._sequence.reset()
    TargetProfileFactory._sequence.reset()
    SimulationResultFactory._sequence.reset()
    TemplateFactory._sequence.reset()
