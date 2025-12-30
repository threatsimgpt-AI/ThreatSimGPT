"""CERT insider threat processor for ThreatSimGPT.

This processor handles CERT insider threat dataset to extract behavioral
patterns and indicators for enhanced insider threat simulations.
"""

import logging
import asyncio
import aiohttp
import csv
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import Counter, defaultdict
import re

from ..manager import DatasetInfo, DatasetStatus, DatasetType, InsiderThreatPattern

logger = logging.getLogger(__name__)


@dataclass
class InsiderThreatRecord:
    """Represents an insider threat incident from CERT database."""

    case_id: str
    industry: str
    job_function: str
    access_level: str
    motivation: str
    incident_type: str
    detection_method: str
    damage_category: str
    timeline_days: Optional[int]
    technical_details: str


class CERTInsiderProcessor:
    """Processor for CERT insider threat database."""

    def __init__(self, storage_path: Path):
        """Initialize CERT processor.

        Args:
            storage_path: Path to store CERT dataset
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # CERT dataset info (note: actual dataset requires access request)
        self.dataset_url = "https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099"
        self.dataset_file = self.storage_path / "cert_insider_threat.csv"
        self.processed_file = self.storage_path / "processed_patterns.json"

        # Processing cache
        self._patterns_cache: Dict[str, InsiderThreatPattern] = {}
        self._processed_data: Optional[Dict[str, Any]] = None

        # Categorization mappings
        self.motivation_categories = {
            'financial': ['money', 'financial', 'debt', 'gambling', 'economic'],
            'revenge': ['revenge', 'retaliation', 'anger', 'fired', 'terminated'],
            'ideology': ['ideology', 'political', 'activism', 'belief', 'cause'],
            'recognition': ['recognition', 'credit', 'status', 'promotion', 'praise'],
            'curiosity': ['curiosity', 'interest', 'exploration', 'knowledge']
        }

        self.behavioral_indicators = {
            'access_patterns': [
                'unusual_hours_access',
                'excessive_file_downloads',
                'unauthorized_system_access',
                'privilege_escalation_attempts',
                'data_hoarding'
            ],
            'communication_patterns': [
                'external_communication_increase',
                'suspicious_email_patterns',
                'encrypted_communication_usage',
                'social_media_complaints',
                'resignation_threats'
            ],
            'performance_indicators': [
                'declining_work_performance',
                'increased_absenteeism',
                'policy_violations',
                'security_awareness_avoidance',
                'supervisor_conflicts'
            ]
        }

    async def get_dataset_info(self) -> DatasetInfo:
        """Get information about the CERT insider threat dataset."""
        status = DatasetStatus.NOT_DOWNLOADED
        version = "2020"
        size_mb = None
        last_updated = None

        if self.dataset_file.exists():
            size_mb = self.dataset_file.stat().st_size / (1024 * 1024)
            last_updated = datetime.fromtimestamp(self.dataset_file.stat().st_mtime)

            if self.processed_file.exists():
                status = DatasetStatus.READY
            else:
                status = DatasetStatus.DOWNLOADED

        return DatasetInfo(
            name="CERT Insider Threat Database",
            type=DatasetType.CERT_INSIDER,
            description="Real insider threat cases with behavioral patterns and detection methods",
            source_url=self.dataset_url,
            version=version,
            size_mb=size_mb,
            last_updated=last_updated,
            status=status,
            features=[
                "behavioral_indicators",
                "motivation_analysis",
                "detection_methods",
                "industry_patterns",
                "timeline_analysis"
            ],
            use_cases=[
                "insider_threat_simulation",
                "behavioral_pattern_modeling",
                "detection_system_training",
                "risk_assessment_scenarios"
            ]
        )

    async def download_and_process(self, force: bool = False) -> bool:
        """Download and process the CERT dataset.

        Note: CERT dataset requires manual download due to access restrictions.
        This method will process existing data or create synthetic patterns.

        Args:
            force: Force re-processing even if exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if dataset file exists
            if not self.dataset_file.exists():
                logger.warning("CERT dataset not found. Creating synthetic patterns based on public research.")
                success = await self._create_synthetic_patterns()
                if not success:
                    return False
            else:
                # Process real dataset
                logger.info("Processing CERT insider threat dataset...")
                success = await self._process_cert_data()
                if not success:
                    return False

            logger.info("CERT dataset processing completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error processing CERT dataset: {e}")
            return False

    async def _create_synthetic_patterns(self) -> bool:
        """Create synthetic insider threat patterns based on public research."""
        try:
            logger.info("Creating synthetic insider threat patterns...")

            # Synthetic data based on CERT public reports and research
            synthetic_data = {
                'total_cases': 1000,  # Simulated
                'processed_date': datetime.utcnow().isoformat(),
                'patterns': {
                    'motivation_distribution': {
                        'financial': 45,
                        'revenge': 30,
                        'ideology': 15,
                        'recognition': 7,
                        'curiosity': 3
                    },
                    'industry_distribution': {
                        'financial_services': 25,
                        'healthcare': 20,
                        'government': 18,
                        'technology': 15,
                        'manufacturing': 12,
                        'retail': 10
                    },
                    'job_function_patterns': {
                        'it_administrator': 22,
                        'database_administrator': 18,
                        'software_developer': 15,
                        'business_analyst': 12,
                        'system_administrator': 10,
                        'financial_analyst': 8,
                        'other': 15
                    },
                    'detection_methods': {
                        'log_analysis': 35,
                        'user_reporting': 25,
                        'data_loss_prevention': 20,
                        'behavioral_analytics': 15,
                        'audit_discovery': 5
                    },
                    'timeline_patterns': {
                        'planning_phase': {'min': 30, 'max': 365, 'avg': 120},
                        'execution_phase': {'min': 1, 'max': 180, 'avg': 45},
                        'detection_time': {'min': 1, 'max': 720, 'avg': 180}
                    },
                    'behavioral_indicators': self.behavioral_indicators,
                    'access_patterns': {
                        'after_hours_access': 60,
                        'weekend_access': 45,
                        'excessive_downloads': 70,
                        'unauthorized_areas': 40,
                        'privilege_abuse': 55
                    }
                },
                'data_source': 'synthetic_based_on_cert_research'
            }

            self._processed_data = synthetic_data

            # Save synthetic patterns
            with open(self.processed_file, 'w') as f:
                json.dump(synthetic_data, f, indent=2)

            logger.info("Synthetic insider threat patterns created successfully")
            return True

        except Exception as e:
            logger.error(f"Error creating synthetic patterns: {e}")
            return False

    async def _process_cert_data(self) -> bool:
        """Process real CERT dataset (if available)."""
        try:
            logger.info("Processing CERT insider threat data...")

            records = []
            with open(self.dataset_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    try:
                        record = InsiderThreatRecord(
                            case_id=row.get('case_id', ''),
                            industry=row.get('industry', ''),
                            job_function=row.get('job_function', ''),
                            access_level=row.get('access_level', ''),
                            motivation=row.get('motivation', ''),
                            incident_type=row.get('incident_type', ''),
                            detection_method=row.get('detection_method', ''),
                            damage_category=row.get('damage_category', ''),
                            timeline_days=self._parse_int(row.get('timeline_days')),
                            technical_details=row.get('technical_details', '')
                        )
                        records.append(record)
                    except Exception as e:
                        logger.debug(f"Error parsing record: {e}")
                        continue

            logger.info(f"Parsed {len(records)} insider threat records")

            # Analyze patterns
            patterns = await self._analyze_insider_patterns(records)

            # Store processed data
            self._processed_data = {
                'total_records': len(records),
                'processed_date': datetime.utcnow().isoformat(),
                'patterns': patterns,
                'data_source': 'cert_database'
            }

            with open(self.processed_file, 'w') as f:
                json.dump(self._processed_data, f, indent=2)

            logger.info("CERT data processing completed")
            return True

        except Exception as e:
            logger.error(f"Error processing CERT data: {e}")
            return False

    def _parse_int(self, value: Optional[str]) -> Optional[int]:
        """Parse integer value safely."""
        if not value:
            return None
        try:
            return int(value)
        except ValueError:
            return None

    async def _analyze_insider_patterns(self, records: List[InsiderThreatRecord]) -> Dict[str, Any]:
        """Analyze insider threat records to extract patterns."""
        patterns = {}

        try:
            # Analyze motivation distribution
            motivations = [record.motivation for record in records if record.motivation]
            motivation_counter = Counter(motivations)
            patterns['motivation_distribution'] = dict(motivation_counter)

            # Analyze industry patterns
            industries = [record.industry for record in records if record.industry]
            industry_counter = Counter(industries)
            patterns['industry_distribution'] = dict(industry_counter)

            # Analyze job function patterns
            job_functions = [record.job_function for record in records if record.job_function]
            job_counter = Counter(job_functions)
            patterns['job_function_patterns'] = dict(job_counter)

            # Analyze detection methods
            detection_methods = [record.detection_method for record in records if record.detection_method]
            detection_counter = Counter(detection_methods)
            patterns['detection_methods'] = dict(detection_counter)

            # Analyze timeline patterns
            timelines = [record.timeline_days for record in records if record.timeline_days]
            if timelines:
                patterns['timeline_patterns'] = {
                    'min': min(timelines),
                    'max': max(timelines),
                    'avg': sum(timelines) / len(timelines)
                }

            return patterns

        except Exception as e:
            logger.error(f"Error analyzing insider patterns: {e}")
            return {}

    async def extract_insider_threat_patterns(self,
                                            industry: str = "general",
                                            job_function: str = "general") -> InsiderThreatPattern:
        """Extract insider threat patterns for specific context.

        Args:
            industry: Target industry
            job_function: Target job function

        Returns:
            InsiderThreatPattern with extracted patterns
        """
        cache_key = f"insider_{industry}_{job_function}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        # Load processed data if not in memory
        if not self._processed_data:
            if self.processed_file.exists():
                with open(self.processed_file, 'r') as f:
                    self._processed_data = json.load(f)
            else:
                logger.warning("No processed CERT data found")
                return self._get_default_patterns()

        try:
            patterns_data = self._processed_data.get('patterns', {})

            # Extract context-specific patterns
            behavioral_indicators = self._extract_behavioral_indicators(patterns_data, job_function)
            risk_factors = self._extract_risk_factors(patterns_data, industry)

            pattern = InsiderThreatPattern(
                behavioral_indicators=behavioral_indicators,
                motivation_factors=self._get_motivation_factors(patterns_data),
                access_patterns=self._get_access_patterns(patterns_data),
                timeline_characteristics=self._get_timeline_characteristics(patterns_data),
                detection_methods=self._get_detection_methods(patterns_data),
                risk_factors=risk_factors
            )

            self._patterns_cache[cache_key] = pattern
            return pattern

        except Exception as e:
            logger.error(f"Error extracting insider threat patterns: {e}")
            return self._get_default_patterns()

    def _extract_behavioral_indicators(self, patterns_data: Dict, job_function: str) -> List[str]:
        """Extract behavioral indicators for specific job function."""
        base_indicators = [
            "unusual_working_hours",
            "excessive_system_access",
            "unauthorized_data_access",
            "policy_violations",
            "performance_decline"
        ]

        # Add job-specific indicators
        job_specific = {
            'it_administrator': [
                "privilege_escalation_attempts",
                "system_configuration_changes",
                "log_deletion_activities"
            ],
            'database_administrator': [
                "unusual_database_queries",
                "bulk_data_extraction",
                "schema_modifications"
            ],
            'software_developer': [
                "code_repository_access",
                "intellectual_property_access",
                "build_system_manipulation"
            ]
        }

        if job_function in job_specific:
            base_indicators.extend(job_specific[job_function])

        return base_indicators

    def _extract_risk_factors(self, patterns_data: Dict, industry: str) -> List[str]:
        """Extract risk factors for specific industry."""
        base_factors = [
            "financial_stress",
            "job_dissatisfaction",
            "pending_termination",
            "recent_policy_changes",
            "increased_workload"
        ]

        # Add industry-specific factors
        industry_specific = {
            'financial_services': [
                "regulatory_pressure",
                "audit_concerns",
                "client_relationship_stress"
            ],
            'healthcare': [
                "patient_privacy_concerns",
                "insurance_fraud_pressure",
                "medical_malpractice_stress"
            ],
            'technology': [
                "intellectual_property_value",
                "competitive_pressure",
                "stock_option_concerns"
            ]
        }

        if industry in industry_specific:
            base_factors.extend(industry_specific[industry])

        return base_factors

    def _get_motivation_factors(self, patterns_data: Dict) -> List[str]:
        """Get motivation factors from patterns."""
        motivation_dist = patterns_data.get('motivation_distribution', {})

        # Return top motivations
        sorted_motivations = sorted(motivation_dist.items(), key=lambda x: x[1], reverse=True)
        return [motivation for motivation, _ in sorted_motivations[:5]]

    def _get_access_patterns(self, patterns_data: Dict) -> List[str]:
        """Get access pattern indicators."""
        return [
            "after_hours_system_access",
            "weekend_database_queries",
            "excessive_file_downloads",
            "unauthorized_network_access",
            "privilege_abuse_attempts"
        ]

    def _get_timeline_characteristics(self, patterns_data: Dict) -> Dict[str, int]:
        """Get timeline characteristics."""
        timeline_data = patterns_data.get('timeline_patterns', {})

        return {
            'planning_phase_days': timeline_data.get('planning_phase', {}).get('avg', 120),
            'execution_phase_days': timeline_data.get('execution_phase', {}).get('avg', 45),
            'detection_time_days': timeline_data.get('detection_time', {}).get('avg', 180)
        }

    def _get_detection_methods(self, patterns_data: Dict) -> List[str]:
        """Get effective detection methods."""
        detection_data = patterns_data.get('detection_methods', {})

        # Return top detection methods
        sorted_methods = sorted(detection_data.items(), key=lambda x: x[1], reverse=True)
        return [method for method, _ in sorted_methods[:5]]

    def _get_default_patterns(self) -> InsiderThreatPattern:
        """Get default insider threat patterns when dataset is not available."""
        return InsiderThreatPattern(
            behavioral_indicators=[
                "unusual_working_hours",
                "excessive_system_access",
                "unauthorized_data_access",
                "policy_violations",
                "performance_decline"
            ],
            motivation_factors=[
                "financial",
                "revenge",
                "ideology",
                "recognition",
                "curiosity"
            ],
            access_patterns=[
                "after_hours_access",
                "weekend_access",
                "excessive_downloads",
                "unauthorized_areas",
                "privilege_abuse"
            ],
            timeline_characteristics={
                'planning_phase_days': 120,
                'execution_phase_days': 45,
                'detection_time_days': 180
            },
            detection_methods=[
                "log_analysis",
                "user_reporting",
                "data_loss_prevention",
                "behavioral_analytics",
                "audit_discovery"
            ],
            risk_factors=[
                "financial_stress",
                "job_dissatisfaction",
                "pending_termination",
                "recent_policy_changes"
            ]
        )
