"""Privacy and compliance framework for ThreatSimGPT intelligence gathering.

This module implements comprehensive privacy controls, data retention policies,
GDPR compliance, and ethical boundaries for responsible OSINT operations.
"""

import hashlib
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4

from pydantic import BaseModel, Field

from .models import IntelligenceSource, OSINTResult


class DataCategory(str, Enum):
    """Categories of data for privacy classification."""
    PUBLIC_PROFILE = "public_profile"
    PROFESSIONAL_INFO = "professional_info"
    COMPANY_DATA = "company_data"
    SOCIAL_MEDIA = "social_media"
    TECHNICAL_INFO = "technical_info"
    PERSONAL_IDENTIFIERS = "personal_identifiers"


class LegalBasis(str, Enum):
    """Legal basis for data processing under GDPR."""
    LEGITIMATE_INTEREST = "legitimate_interest"
    CONSENT = "consent"
    PUBLIC_TASK = "public_task"
    VITAL_INTERESTS = "vital_interests"
    CONTRACT = "contract"
    LEGAL_OBLIGATION = "legal_obligation"


class DataRetentionPolicy(BaseModel):
    """Data retention policy configuration."""
    category: DataCategory
    retention_days: int = Field(..., ge=1, le=2555)  # Max 7 years
    legal_basis: LegalBasis
    anonymization_after_days: Optional[int] = Field(None, ge=1)
    deletion_after_days: int = Field(..., ge=1)
    encryption_required: bool = Field(default=True)
    audit_required: bool = Field(default=True)

    def is_expired(self, collection_date: datetime) -> bool:
        """Check if data retention period has expired."""
        expiry_date = collection_date + timedelta(days=self.deletion_after_days)
        return datetime.utcnow() > expiry_date

    def should_anonymize(self, collection_date: datetime) -> bool:
        """Check if data should be anonymized."""
        if not self.anonymization_after_days:
            return False
        anonymize_date = collection_date + timedelta(days=self.anonymization_after_days)
        return datetime.utcnow() > anonymize_date


class PrivacyControl(BaseModel):
    """Privacy control configuration."""
    control_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: str
    data_categories: List[DataCategory]
    enabled: bool = Field(default=True)
    enforcement_level: str = Field(default="strict")  # strict, moderate, lenient

    # Rate limiting
    requests_per_minute: Optional[int] = Field(None, ge=1)
    requests_per_hour: Optional[int] = Field(None, ge=1)

    # Data minimization
    collect_minimal_data: bool = Field(default=True)
    exclude_sensitive_fields: List[str] = Field(default_factory=list)

    # Consent and notification
    requires_explicit_consent: bool = Field(default=False)
    notification_required: bool = Field(default=True)

    # Technical controls
    encrypt_at_rest: bool = Field(default=True)
    encrypt_in_transit: bool = Field(default=True)
    hash_identifiers: bool = Field(default=True)


class ComplianceFramework:
    """Comprehensive privacy and compliance framework."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.retention_policies = self._initialize_retention_policies()
        self.privacy_controls = self._initialize_privacy_controls()
        self.audit_log: List[Dict[str, Any]] = []

    def _initialize_retention_policies(self) -> Dict[DataCategory, DataRetentionPolicy]:
        """Initialize default data retention policies."""
        return {
            DataCategory.PUBLIC_PROFILE: DataRetentionPolicy(
                category=DataCategory.PUBLIC_PROFILE,
                retention_days=90,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                anonymization_after_days=30,
                deletion_after_days=90,
                encryption_required=True,
                audit_required=True
            ),
            DataCategory.PROFESSIONAL_INFO: DataRetentionPolicy(
                category=DataCategory.PROFESSIONAL_INFO,
                retention_days=180,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                anonymization_after_days=60,
                deletion_after_days=180,
                encryption_required=True,
                audit_required=True
            ),
            DataCategory.COMPANY_DATA: DataRetentionPolicy(
                category=DataCategory.COMPANY_DATA,
                retention_days=365,
                legal_basis=LegalBasis.PUBLIC_TASK,
                anonymization_after_days=None,  # Company data doesn't need anonymization
                deletion_after_days=365,
                encryption_required=False,
                audit_required=True
            ),
            DataCategory.SOCIAL_MEDIA: DataRetentionPolicy(
                category=DataCategory.SOCIAL_MEDIA,
                retention_days=60,
                legal_basis=LegalBasis.LEGITIMATE_INTEREST,
                anonymization_after_days=14,
                deletion_after_days=60,
                encryption_required=True,
                audit_required=True
            ),
            DataCategory.PERSONAL_IDENTIFIERS: DataRetentionPolicy(
                category=DataCategory.PERSONAL_IDENTIFIERS,
                retention_days=30,
                legal_basis=LegalBasis.CONSENT,
                anonymization_after_days=7,
                deletion_after_days=30,
                encryption_required=True,
                audit_required=True
            )
        }

    def _initialize_privacy_controls(self) -> List[PrivacyControl]:
        """Initialize default privacy controls."""
        return [
            PrivacyControl(
                name="Rate Limiting Control",
                description="Prevent aggressive data collection",
                data_categories=[DataCategory.PUBLIC_PROFILE, DataCategory.SOCIAL_MEDIA],
                requests_per_minute=30,
                requests_per_hour=1000
            ),
            PrivacyControl(
                name="Data Minimization Control",
                description="Collect only necessary data fields",
                data_categories=list(DataCategory),
                collect_minimal_data=True,
                exclude_sensitive_fields=["phone", "address", "family_members"]
            ),
            PrivacyControl(
                name="Encryption Control",
                description="Encrypt all collected data",
                data_categories=list(DataCategory),
                encrypt_at_rest=True,
                encrypt_in_transit=True,
                hash_identifiers=True
            ),
            PrivacyControl(
                name="Consent Control",
                description="Require consent for sensitive data collection",
                data_categories=[DataCategory.PERSONAL_IDENTIFIERS],
                requires_explicit_consent=True,
                notification_required=True
            )
        ]

    def validate_collection_request(
        self,
        target: str,
        data_categories: List[DataCategory],
        source: IntelligenceSource
    ) -> Dict[str, Any]:
        """Validate if data collection request complies with privacy policies."""

        validation_result = {
            "approved": True,
            "warnings": [],
            "requirements": [],
            "legal_basis": [],
            "audit_id": str(uuid4())
        }

        # Check each data category against privacy controls
        for category in data_categories:
            # Check retention policy
            if category in self.retention_policies:
                policy = self.retention_policies[category]
                validation_result["legal_basis"].append(policy.legal_basis.value)

                if policy.requires_explicit_consent:
                    validation_result["requirements"].append(
                        f"Explicit consent required for {category.value}"
                    )

            # Check privacy controls
            applicable_controls = [
                control for control in self.privacy_controls
                if category in control.data_categories and control.enabled
            ]

            for control in applicable_controls:
                if control.requires_explicit_consent:
                    validation_result["requirements"].append(
                        f"Consent required by {control.name}"
                    )

                if control.exclude_sensitive_fields:
                    validation_result["warnings"].append(
                        f"Exclude sensitive fields: {', '.join(control.exclude_sensitive_fields)}"
                    )

        # Log validation request
        self._log_audit_event({
            "event_type": "collection_validation",
            "target": self._hash_identifier(target),
            "data_categories": [cat.value for cat in data_categories],
            "source": source.value,
            "result": validation_result,
            "timestamp": datetime.utcnow().isoformat()
        })

        return validation_result

    def apply_privacy_controls(self, osint_result: OSINTResult) -> OSINTResult:
        """Apply privacy controls to OSINT results."""

        # Create a copy to modify
        controlled_result = osint_result.model_copy(deep=True)

        # Apply data minimization
        controlled_result = self._apply_data_minimization(controlled_result)

        # Apply anonymization where required
        controlled_result = self._apply_anonymization(controlled_result)

        # Apply encryption markers
        controlled_result = self._apply_encryption_markers(controlled_result)

        # Update privacy controls applied
        controlled_result.privacy_controls_applied = [
            control.name for control in self.privacy_controls if control.enabled
        ]

        # Log privacy control application
        self._log_audit_event({
            "event_type": "privacy_controls_applied",
            "query_id": controlled_result.query_id,
            "controls_applied": controlled_result.privacy_controls_applied,
            "timestamp": datetime.utcnow().isoformat()
        })

        return controlled_result

    def _apply_data_minimization(self, result: OSINTResult) -> OSINTResult:
        """Apply data minimization controls."""

        # Get fields to exclude
        exclude_fields = set()
        for control in self.privacy_controls:
            if control.enabled and control.collect_minimal_data:
                exclude_fields.update(control.exclude_sensitive_fields)

        # Apply to individual profiles
        for profile in result.individual_profiles:
            for field in exclude_fields:
                if hasattr(profile, field):
                    setattr(profile, field, None)

        # Apply to company intelligence
        if result.company_intelligence:
            for field in exclude_fields:
                if hasattr(result.company_intelligence, field):
                    setattr(result.company_intelligence, field, None)

        return result

    def _apply_anonymization(self, result: OSINTResult) -> OSINTResult:
        """Apply anonymization where required by retention policies."""

        collection_time = result.query_timestamp

        for category, policy in self.retention_policies.items():
            if policy.should_anonymize(collection_time):
                # Apply anonymization based on category
                if category == DataCategory.PERSONAL_IDENTIFIERS:
                    # Hash personal identifiers
                    for profile in result.individual_profiles:
                        if profile.email:
                            profile.email = self._hash_identifier(profile.email)
                        if profile.full_name:
                            profile.full_name = self._anonymize_name(profile.full_name)

        return result

    def _apply_encryption_markers(self, result: OSINTResult) -> OSINTResult:
        """Mark data that should be encrypted."""

        # Add encryption metadata
        if not hasattr(result, 'encryption_metadata'):
            result.encryption_metadata = {}

        for control in self.privacy_controls:
            if control.enabled and control.encrypt_at_rest:
                result.encryption_metadata[control.name] = {
                    "encrypt_at_rest": True,
                    "encrypt_in_transit": control.encrypt_in_transit,
                    "hash_identifiers": control.hash_identifiers
                }

        return result

    def _hash_identifier(self, identifier: str) -> str:
        """Hash an identifier for privacy protection."""
        return hashlib.sha256(identifier.encode()).hexdigest()[:16]

    def _anonymize_name(self, name: str) -> str:
        """Anonymize a name while preserving some utility."""
        parts = name.split()
        if len(parts) >= 2:
            return f"{parts[0][0]}*** {parts[-1][0]}***"
        return f"{name[0]}***"

    def check_data_retention(self) -> Dict[str, Any]:
        """Check data retention compliance and return cleanup recommendations."""

        cleanup_report = {
            "expired_data": [],
            "anonymization_due": [],
            "retention_summary": {},
            "compliance_status": "compliant"
        }

        # In a real implementation, this would check actual stored data
        # against retention policies

        for category, policy in self.retention_policies.items():
            cleanup_report["retention_summary"][category.value] = {
                "retention_days": policy.retention_days,
                "deletion_after_days": policy.deletion_after_days,
                "anonymization_after_days": policy.anonymization_after_days,
                "legal_basis": policy.legal_basis.value
            }

        return cleanup_report

    def _log_audit_event(self, event: Dict[str, Any]) -> None:
        """Log audit event for compliance tracking."""
        event["audit_id"] = str(uuid4())
        event["timestamp"] = datetime.utcnow().isoformat()
        self.audit_log.append(event)

        # In production, this would write to secure audit storage

    def generate_privacy_report(self) -> Dict[str, Any]:
        """Generate comprehensive privacy compliance report."""

        report = {
            "report_id": str(uuid4()),
            "generated_at": datetime.utcnow().isoformat(),
            "compliance_framework": "GDPR + CCPA",
            "retention_policies": len(self.retention_policies),
            "privacy_controls": len([c for c in self.privacy_controls if c.enabled]),
            "audit_events": len(self.audit_log),
            "data_categories_managed": len(self.retention_policies),
            "compliance_status": "compliant"
        }

        # Add detailed policy information
        report["policy_details"] = {}
        for category, policy in self.retention_policies.items():
            report["policy_details"][category.value] = {
                "retention_days": policy.retention_days,
                "legal_basis": policy.legal_basis.value,
                "encryption_required": policy.encryption_required,
                "audit_required": policy.audit_required
            }

        # Add control information
        report["control_details"] = {}
        for control in self.privacy_controls:
            if control.enabled:
                report["control_details"][control.name] = {
                    "description": control.description,
                    "data_categories": [cat.value for cat in control.data_categories],
                    "enforcement_level": control.enforcement_level
                }

        return report

    def export_audit_log(self, start_date: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Export audit log for compliance reporting."""

        if start_date:
            filtered_log = [
                event for event in self.audit_log
                if datetime.fromisoformat(event["timestamp"]) >= start_date
            ]
            return filtered_log

        return self.audit_log.copy()


# Default compliance framework instance
default_compliance_framework = ComplianceFramework()
