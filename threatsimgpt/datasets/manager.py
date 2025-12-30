"""Dataset management module for ThreatSimGPT.

This module provides functionality to integrate and manage various cybersecurity datasets
including Enron corpus, PhishTank, CERT insider threat data, and LANL authentication logs.
"""

import logging
import asyncio
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DatasetType(str, Enum):
    """Supported dataset types."""

    ENRON = "enron"
    PHISHTANK = "phishtank"
    NAZARIO = "nazario"
    CERT_INSIDER = "cert_insider"
    LANL_AUTH = "lanl_auth"
    MITRE_ATTACK = "mitre_attack"


class DatasetStatus(str, Enum):
    """Dataset status indicators."""

    NOT_DOWNLOADED = "not_downloaded"
    DOWNLOADING = "downloading"
    PROCESSING = "processing"
    READY = "ready"
    ERROR = "error"
    OUTDATED = "outdated"


@dataclass
class DatasetInfo:
    """Dataset information and metadata."""

    name: str
    type: DatasetType
    description: str
    source_url: Optional[str]
    version: str
    size_mb: Optional[float]
    last_updated: Optional[datetime]
    status: DatasetStatus
    features: List[str]
    use_cases: List[str]


@dataclass
class EmailPattern:
    """Email communication patterns extracted from datasets."""

    subject_patterns: List[str]
    greeting_styles: List[str]
    closing_phrases: List[str]
    language_tone: str
    formality_level: str
    average_length: int
    common_phrases: List[str]


@dataclass
class PhishingPattern:
    """Phishing patterns from threat datasets."""

    common_domains: List[str]
    suspicious_tlds: List[str]
    url_patterns: List[str]
    subdomain_tricks: List[str]
    typosquatting_techniques: List[str]
    target_keywords: List[str]


@dataclass
class InsiderThreatPattern:
    """Insider threat behavioral patterns."""

    behavioral_indicators: List[str]
    motivation_factors: List[str]
    access_patterns: List[str]
    timeline_characteristics: Dict[str, int]
    detection_methods: List[str]
    risk_factors: List[str]


@dataclass
class AuthenticationPattern:
    """Authentication patterns from network logs."""

    typical_login_times: List[int]
    authentication_methods: List[str]
    session_characteristics: Dict[str, Any]
    failure_patterns: Dict[str, float]
    anomaly_indicators: List[str]
    baseline_metrics: Dict[str, float]


@dataclass
class TTPPattern:
    """Tactics, Techniques, and Procedures patterns from MITRE ATT&CK."""

    tactics: List[str]
    techniques: List[Dict[str, str]]
    procedures: List[str]
    attack_chains: List[Dict[str, Any]]
    detection_methods: List[str]
    mitigation_strategies: List[str]


class DatasetManager:
    """Manages cybersecurity datasets for ThreatSimGPT."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize dataset manager.

        Args:
            config: Dataset configuration
        """
        self.config = config
        self.storage_path = Path(config.get('storage_path', 'data/datasets'))
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self._datasets: Dict[str, DatasetInfo] = {}
        self._patterns_cache: Dict[str, Any] = {}
        self._processors = self._initialize_processors()

    def _initialize_processors(self) -> Dict[DatasetType, Any]:
        """Initialize dataset processors."""
        from .processors import (
            EnronProcessor,
            PhishTankProcessor,
            CERTInsiderProcessor,
            LANLAuthProcessor,
            MITREAttackProcessor
        )

        return {
            DatasetType.ENRON: EnronProcessor(self.storage_path / "enron"),
            DatasetType.PHISHTANK: PhishTankProcessor(self.storage_path / "phishtank"),
            DatasetType.CERT_INSIDER: CERTInsiderProcessor(self.storage_path / "cert_insider"),
            DatasetType.LANL_AUTH: LANLAuthProcessor(self.storage_path / "lanl_auth"),
            DatasetType.MITRE_ATTACK: MITREAttackProcessor(self.storage_path / "mitre_attack")
        }

    async def initialize_datasets(self) -> None:
        """Initialize and scan available datasets."""
        logger.info("Initializing dataset manager...")

        for dataset_type in DatasetType:
            try:
                dataset_config = self.config.get(dataset_type.value, {})
                if dataset_config.get('enabled', False):
                    await self._scan_dataset(dataset_type)
            except Exception as e:
                logger.error(f"Error initializing dataset {dataset_type}: {e}")

    async def _scan_dataset(self, dataset_type: DatasetType) -> None:
        """Scan and assess dataset status."""
        processor = self._processors.get(dataset_type)
        if not processor:
            return

        try:
            info = await processor.get_dataset_info()
            self._datasets[dataset_type.value] = info
            logger.info(f"Dataset {dataset_type.value}: {info.status}")
        except Exception as e:
            logger.error(f"Error scanning dataset {dataset_type}: {e}")

    async def download_dataset(self, dataset_type: DatasetType, force: bool = False) -> bool:
        """Download and setup a dataset.

        Args:
            dataset_type: Type of dataset to download
            force: Force re-download even if exists

        Returns:
            True if successful, False otherwise
        """
        processor = self._processors.get(dataset_type)
        if not processor:
            logger.error(f"No processor found for dataset {dataset_type}")
            return False

        try:
            logger.info(f"Downloading dataset: {dataset_type.value}")

            # Update status
            if dataset_type.value in self._datasets:
                self._datasets[dataset_type.value].status = DatasetStatus.DOWNLOADING

            # Download and process
            success = await processor.download_and_process(force=force)

            # Update status
            status = DatasetStatus.READY if success else DatasetStatus.ERROR
            if dataset_type.value in self._datasets:
                self._datasets[dataset_type.value].status = status
                self._datasets[dataset_type.value].last_updated = datetime.utcnow()

            logger.info(f"Dataset {dataset_type.value} download: {'success' if success else 'failed'}")
            return success

        except Exception as e:
            logger.error(f"Error downloading dataset {dataset_type}: {e}")
            if dataset_type.value in self._datasets:
                self._datasets[dataset_type.value].status = DatasetStatus.ERROR
            return False

    async def update_datasets(self, dataset_types: Optional[List[DatasetType]] = None) -> Dict[str, bool]:
        """Update specified datasets or all enabled datasets.

        Args:
            dataset_types: Specific datasets to update, or None for all

        Returns:
            Dict of dataset_name -> success status
        """
        if dataset_types is None:
            dataset_types = [dt for dt in DatasetType if self.config.get(dt.value, {}).get('enabled')]

        results = {}
        for dataset_type in dataset_types:
            try:
                # Check if update is needed
                if await self._needs_update(dataset_type):
                    success = await self.download_dataset(dataset_type, force=True)
                    results[dataset_type.value] = success
                else:
                    logger.info(f"Dataset {dataset_type.value} is up to date")
                    results[dataset_type.value] = True
            except Exception as e:
                logger.error(f"Error updating dataset {dataset_type}: {e}")
                results[dataset_type.value] = False

        return results

    async def _needs_update(self, dataset_type: DatasetType) -> bool:
        """Check if dataset needs updating."""
        info = self._datasets.get(dataset_type.value)
        if not info or info.status != DatasetStatus.READY:
            return True

        config = self.config.get(dataset_type.value, {})
        update_interval = config.get('update_interval', 'weekly')

        if not info.last_updated:
            return True

        # Calculate update threshold
        now = datetime.utcnow()
        if update_interval == 'daily':
            threshold = now - timedelta(days=1)
        elif update_interval == 'weekly':
            threshold = now - timedelta(weeks=1)
        elif update_interval == 'monthly':
            threshold = now - timedelta(days=30)
        else:
            return False

        return info.last_updated < threshold

    def get_dataset_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all datasets."""
        status = {}
        for name, info in self._datasets.items():
            status[name] = {
                'status': info.status.value,
                'version': info.version,
                'last_updated': info.last_updated.isoformat() if info.last_updated else None,
                'size_mb': info.size_mb,
                'features': info.features,
                'use_cases': info.use_cases
            }
        return status

    async def get_email_patterns(self, role: str = "general", industry: str = "technology") -> EmailPattern:
        """Get email patterns from Enron dataset.

        Args:
            role: Target role (executive, manager, employee)
            industry: Target industry

        Returns:
            EmailPattern with extracted patterns
        """
        cache_key = f"email_patterns_{role}_{industry}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        processor = self._processors.get(DatasetType.ENRON)
        if not processor or DatasetType.ENRON.value not in self._datasets:
            # Return default patterns if dataset not available
            return EmailPattern(
                subject_patterns=["Re: {topic}", "FW: {topic}", "{topic} - Action Required"],
                greeting_styles=["Dear {name},", "Hi {name},", "Hello {name},"],
                closing_phrases=["Best regards,", "Thanks,", "Sincerely,"],
                language_tone="professional",
                formality_level="business",
                average_length=150,
                common_phrases=["Please review", "Let me know", "Thanks for your time"]
            )

        try:
            patterns = await processor.extract_email_patterns(role, industry)
            self._patterns_cache[cache_key] = patterns
            return patterns
        except Exception as e:
            logger.error(f"Error extracting email patterns: {e}")
            return EmailPattern(
                subject_patterns=["Re: {topic}"],
                greeting_styles=["Hi,"],
                closing_phrases=["Thanks,"],
                language_tone="neutral",
                formality_level="casual",
                average_length=100,
                common_phrases=["Please"]
            )

    async def get_phishing_patterns(self, target_sector: str = "general") -> PhishingPattern:
        """Get phishing patterns from PhishTank and Nazario datasets.

        Args:
            target_sector: Target sector for patterns

        Returns:
            PhishingPattern with extracted patterns
        """
        cache_key = f"phishing_patterns_{target_sector}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        processor = self._processors.get(DatasetType.PHISHTANK)
        if not processor:
            # Return default patterns
            return PhishingPattern(
                url_structures=["https://{domain}.{tld}/{path}"],
                domain_patterns=["{brand}-{random}.{tld}"],
                spoofing_techniques=["subdomain", "homograph"],
                common_lures=["account_verification", "security_alert"],
                target_sectors=["banking", "technology"],
                campaign_timing={"peak_hours": [9, 10, 14, 15]}
            )

        try:
            patterns = await processor.extract_phishing_patterns(target_sector)
            self._patterns_cache[cache_key] = patterns
            return patterns
        except Exception as e:
            logger.error(f"Error extracting phishing patterns: {e}")
            return PhishingPattern(
                url_structures=["https://{domain}/{path}"],
                domain_patterns=["{brand}.{tld}"],
                spoofing_techniques=["typosquatting"],
                common_lures=["urgent_action"],
                target_sectors=["general"],
                campaign_timing={"peak_hours": [10, 14]}
            )

    async def get_insider_threat_patterns(self, threat_type: str = "general") -> InsiderThreatPattern:
        """Get insider threat patterns from CERT dataset.

        Args:
            threat_type: Type of insider threat

        Returns:
            InsiderThreatPattern with behavioral patterns
        """
        cache_key = f"insider_patterns_{threat_type}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        processor = self._processors.get(DatasetType.CERT_INSIDER)
        if not processor:
            return InsiderThreatPattern(
                behavioral_indicators=["unusual_access_times", "data_hoarding"],
                attack_progression=["privilege_escalation", "data_collection", "exfiltration"],
                data_targets=["customer_data", "financial_records", "intellectual_property"],
                access_patterns={"off_hours": 0.3, "bulk_access": 0.4},
                time_patterns={"weekend_activity": 0.25, "after_hours": 0.35},
                risk_factors=["recent_discipline", "financial_stress", "job_dissatisfaction"]
            )

        try:
            patterns = await processor.extract_insider_patterns(threat_type)
            self._patterns_cache[cache_key] = patterns
            return patterns
        except Exception as e:
            logger.error(f"Error extracting insider threat patterns: {e}")
            return InsiderThreatPattern(
                behavioral_indicators=["unusual_behavior"],
                attack_progression=["access", "action"],
                data_targets=["sensitive_data"],
                access_patterns={"unusual": 0.5},
                time_patterns={"off_hours": 0.3},
                risk_factors=["motivation"]
            )

    async def enhance_scenario_with_datasets(self, scenario_type: str, target_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance a threat scenario with dataset-derived insights.

        Args:
            scenario_type: Type of threat scenario
            target_profile: Target profile information

        Returns:
            Enhanced scenario data
        """
        enhancements = {}

        try:
            if scenario_type in ["phishing", "spear_phishing", "email_attack"]:
                # Get email patterns
                role = target_profile.get('role', 'employee')
                industry = target_profile.get('industry', 'technology')
                email_patterns = await self.get_email_patterns(role, industry)

                # Get phishing patterns
                sector = target_profile.get('sector', 'general')
                phishing_patterns = await self.get_phishing_patterns(sector)

                enhancements['email_style'] = {
                    'subject_patterns': email_patterns.subject_patterns,
                    'greeting_style': email_patterns.greeting_styles[0],
                    'language_tone': email_patterns.language_tone,
                    'closing_phrase': email_patterns.closing_phrases[0]
                }

                enhancements['phishing_techniques'] = {
                    'url_structure': phishing_patterns.url_structures[0],
                    'domain_pattern': phishing_patterns.domain_patterns[0],
                    'spoofing_method': phishing_patterns.spoofing_techniques[0],
                    'lure_type': phishing_patterns.common_lures[0]
                }

            elif scenario_type in ["insider_threat", "malicious_insider"]:
                threat_type = target_profile.get('threat_type', 'general')
                insider_patterns = await self.get_insider_threat_patterns(threat_type)

                enhancements['behavioral_indicators'] = insider_patterns.behavioral_indicators
                enhancements['attack_chain'] = insider_patterns.attack_progression
                enhancements['target_data'] = insider_patterns.data_targets
                enhancements['risk_profile'] = insider_patterns.risk_factors

            logger.info(f"Enhanced {scenario_type} scenario with dataset insights")
            return enhancements

        except Exception as e:
            logger.error(f"Error enhancing scenario with datasets: {e}")
            return {}

    def clear_cache(self) -> None:
        """Clear the patterns cache."""
        self._patterns_cache.clear()
        logger.info("Dataset patterns cache cleared")

    async def get_dataset_health(self) -> Dict[str, Any]:
        """Get overall dataset health metrics."""
        health = {
            'total_datasets': len(self._datasets),
            'ready_datasets': len([d for d in self._datasets.values() if d.status == DatasetStatus.READY]),
            'error_datasets': len([d for d in self._datasets.values() if d.status == DatasetStatus.ERROR]),
            'outdated_datasets': 0,
            'total_size_mb': 0,
            'last_health_check': datetime.utcnow().isoformat()
        }

        for dataset in self._datasets.values():
            if dataset.size_mb:
                health['total_size_mb'] += dataset.size_mb

            if await self._needs_update(DatasetType(dataset.type)):
                health['outdated_datasets'] += 1

        health['health_score'] = (health['ready_datasets'] / max(health['total_datasets'], 1)) * 100

        return health


# Factory function for easy instantiation
def create_dataset_manager(config: Dict[str, Any]) -> DatasetManager:
    """Create a dataset manager instance.

    Args:
        config: Dataset configuration

    Returns:
        Configured DatasetManager instance
    """
    return DatasetManager(config)
