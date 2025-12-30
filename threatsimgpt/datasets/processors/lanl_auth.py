"""LANL authentication logs processor for ThreatSimGPT.

This processor handles Los Alamos National Laboratory authentication logs
to extract authentication patterns and anomaly indicators.
"""

import logging
import asyncio
import aiohttp
import csv
import json
import gzip
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass
from collections import Counter, defaultdict
import re

from ..manager import DatasetInfo, DatasetStatus, DatasetType, AuthenticationPattern

logger = logging.getLogger(__name__)


@dataclass
class AuthenticationRecord:
    """Represents an authentication record from LANL logs."""

    timestamp: datetime
    source_user: str
    destination_computer: str
    source_computer: str
    auth_type: str
    logon_type: str
    auth_orientation: str
    success_failure: str


class LANLAuthProcessor:
    """Processor for LANL authentication logs dataset."""

    def __init__(self, storage_path: Path):
        """Initialize LANL processor.

        Args:
            storage_path: Path to store LANL dataset
        """
        self.storage_path = storage_path
        self.storage_path.mkdir(parents=True, exist_ok=True)

        # LANL dataset info
        self.dataset_url = "https://csr.lanl.gov/data/cyber1/"
        self.dataset_file = self.storage_path / "auth.txt.gz"
        self.processed_file = self.storage_path / "processed_patterns.json"

        # Processing cache
        self._patterns_cache: Dict[str, AuthenticationPattern] = {}
        self._processed_data: Optional[Dict[str, Any]] = None

    async def get_dataset_info(self) -> DatasetInfo:
        """Get information about the LANL authentication dataset."""
        status = DatasetStatus.NOT_DOWNLOADED
        version = "1.0"
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
            name="LANL Authentication Logs",
            type=DatasetType.LANL_AUTH,
            description="Authentication logs from Los Alamos National Laboratory network",
            source_url=self.dataset_url,
            version=version,
            size_mb=size_mb,
            last_updated=last_updated,
            status=status,
            features=[
                "authentication_patterns",
                "user_behavior_analysis",
                "temporal_patterns",
                "network_access_patterns",
                "anomaly_indicators"
            ],
            use_cases=[
                "authentication_simulation",
                "user_behavior_modeling",
                "anomaly_detection_training",
                "network_access_scenarios"
            ]
        )

    async def download_and_process(self, force: bool = False) -> bool:
        """Download and process the LANL dataset.

        Note: LANL dataset requires manual download from their portal.
        This method will process existing data or create synthetic patterns.

        Args:
            force: Force re-processing even if exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if dataset file exists
            if not self.dataset_file.exists():
                logger.warning("LANL dataset not found. Creating synthetic patterns based on research.")
                success = await self._create_synthetic_patterns()
                if not success:
                    return False
            else:
                # Process real dataset
                logger.info("Processing LANL authentication logs...")
                success = await self._process_lanl_data()
                if not success:
                    return False

            logger.info("LANL dataset processing completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error processing LANL dataset: {e}")
            return False

    async def _create_synthetic_patterns(self) -> bool:
        """Create synthetic authentication patterns based on research."""
        try:
            logger.info("Creating synthetic authentication patterns...")

            # Synthetic data based on LANL public research and common patterns
            synthetic_data = {
                'total_records': 500000,  # Simulated
                'processed_date': datetime.utcnow().isoformat(),
                'patterns': {
                    'temporal_patterns': {
                        'peak_hours': [8, 9, 10, 13, 14, 15, 16, 17],
                        'off_hours_percentage': 15,
                        'weekend_percentage': 8,
                        'night_percentage': 5
                    },
                    'authentication_types': {
                        'negotiate': 60,
                        'kerberos': 30,
                        'ntlm': 8,
                        'other': 2
                    },
                    'logon_types': {
                        'interactive': 45,
                        'network': 30,
                        'batch': 15,
                        'service': 7,
                        'remote_interactive': 3
                    },
                    'success_rates': {
                        'success': 92,
                        'failure': 8
                    },
                    'user_patterns': {
                        'avg_daily_logins': 25,
                        'max_daily_logins': 150,
                        'unique_computers_per_user': 3.2,
                        'cross_department_access': 12
                    },
                    'computer_patterns': {
                        'avg_daily_users': 8,
                        'max_daily_users': 45,
                        'shared_computers_percentage': 25
                    },
                    'anomaly_indicators': {
                        'off_hours_logins': 5,
                        'multiple_failed_attempts': 3,
                        'unusual_computer_access': 2,
                        'bulk_authentication_attempts': 1,
                        'privilege_escalation_attempts': 0.5
                    }
                },
                'data_source': 'synthetic_based_on_lanl_research'
            }

            self._processed_data = synthetic_data

            # Save synthetic patterns
            with open(self.processed_file, 'w') as f:
                json.dump(synthetic_data, f, indent=2)

            logger.info("Synthetic authentication patterns created successfully")
            return True

        except Exception as e:
            logger.error(f"Error creating synthetic patterns: {e}")
            return False

    async def _process_lanl_data(self) -> bool:
        """Process real LANL authentication data (if available)."""
        try:
            logger.info("Processing LANL authentication logs...")

            records = []
            processed_count = 0
            batch_size = 10000

            # Process in batches to handle large dataset
            with gzip.open(self.dataset_file, 'rt') as f:
                for line in f:
                    try:
                        # Parse LANL auth log format
                        # Format: time,source_user@domain,destination_computer@domain,source_computer@domain,auth_type,logon_type,auth_orientation,success_failure
                        parts = line.strip().split(',')
                        if len(parts) >= 8:
                            record = AuthenticationRecord(
                                timestamp=self._parse_timestamp(parts[0]),
                                source_user=parts[1],
                                destination_computer=parts[2],
                                source_computer=parts[3],
                                auth_type=parts[4],
                                logon_type=parts[5],
                                auth_orientation=parts[6],
                                success_failure=parts[7]
                            )
                            records.append(record)
                            processed_count += 1

                            if processed_count % batch_size == 0:
                                logger.info(f"Processed {processed_count} authentication records")

                                # Process batch to avoid memory issues
                                if processed_count >= 100000:  # Limit for processing
                                    break

                    except Exception as e:
                        logger.debug(f"Error parsing record: {e}")
                        continue

            logger.info(f"Parsed {len(records)} authentication records")

            # Analyze patterns
            patterns = await self._analyze_auth_patterns(records)

            # Store processed data
            self._processed_data = {
                'total_records': len(records),
                'processed_date': datetime.utcnow().isoformat(),
                'patterns': patterns,
                'data_source': 'lanl_dataset'
            }

            with open(self.processed_file, 'w') as f:
                json.dump(self._processed_data, f, indent=2)

            logger.info("LANL data processing completed")
            return True

        except Exception as e:
            logger.error(f"Error processing LANL data: {e}")
            return False

    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse timestamp from LANL format."""
        try:
            # LANL uses Unix timestamp
            return datetime.fromtimestamp(int(timestamp_str))
        except ValueError:
            return datetime.now()

    async def _analyze_auth_patterns(self, records: List[AuthenticationRecord]) -> Dict[str, Any]:
        """Analyze authentication records to extract patterns."""
        patterns = {}

        try:
            # Temporal analysis
            hours = [record.timestamp.hour for record in records]
            hour_counter = Counter(hours)
            peak_hours = [hour for hour, count in hour_counter.most_common(8)]

            # Calculate percentages
            total_count = len(records)
            off_hours_count = sum(1 for h in hours if h < 7 or h > 19)
            weekend_count = sum(1 for record in records if record.timestamp.weekday() >= 5)
            night_count = sum(1 for h in hours if h < 6 or h > 22)

            patterns['temporal_patterns'] = {
                'peak_hours': peak_hours,
                'off_hours_percentage': (off_hours_count / total_count) * 100 if total_count > 0 else 0,
                'weekend_percentage': (weekend_count / total_count) * 100 if total_count > 0 else 0,
                'night_percentage': (night_count / total_count) * 100 if total_count > 0 else 0
            }

            # Authentication type analysis
            auth_types = [record.auth_type for record in records]
            auth_counter = Counter(auth_types)
            patterns['authentication_types'] = dict(auth_counter)

            # Logon type analysis
            logon_types = [record.logon_type for record in records]
            logon_counter = Counter(logon_types)
            patterns['logon_types'] = dict(logon_counter)

            # Success/failure analysis
            success_failure = [record.success_failure for record in records]
            success_counter = Counter(success_failure)
            patterns['success_rates'] = dict(success_counter)

            # User behavior patterns
            user_logins = defaultdict(list)
            for record in records:
                user_logins[record.source_user].append(record)

            daily_login_counts = []
            unique_computers_per_user = []

            for user, logins in user_logins.items():
                # Group by day
                daily_groups = defaultdict(list)
                user_computers = set()

                for login in logins:
                    day_key = login.timestamp.date()
                    daily_groups[day_key].append(login)
                    user_computers.add(login.destination_computer)

                daily_counts = [len(day_logins) for day_logins in daily_groups.values()]
                if daily_counts:
                    daily_login_counts.extend(daily_counts)

                unique_computers_per_user.append(len(user_computers))

            patterns['user_patterns'] = {
                'avg_daily_logins': sum(daily_login_counts) / len(daily_login_counts) if daily_login_counts else 0,
                'max_daily_logins': max(daily_login_counts) if daily_login_counts else 0,
                'unique_computers_per_user': sum(unique_computers_per_user) / len(unique_computers_per_user) if unique_computers_per_user else 0
            }

            # Anomaly indicators (simplified)
            failed_auths = sum(1 for record in records if 'fail' in record.success_failure.lower())
            patterns['anomaly_indicators'] = {
                'failure_rate': (failed_auths / total_count) * 100 if total_count > 0 else 0,
                'off_hours_rate': patterns['temporal_patterns']['off_hours_percentage'],
                'weekend_rate': patterns['temporal_patterns']['weekend_percentage']
            }

            return patterns

        except Exception as e:
            logger.error(f"Error analyzing authentication patterns: {e}")
            return {}

    async def extract_authentication_patterns(self,
                                            user_type: str = "general",
                                            time_period: str = "business_hours") -> AuthenticationPattern:
        """Extract authentication patterns for specific context.

        Args:
            user_type: Type of user (executive, employee, admin)
            time_period: Time period focus (business_hours, after_hours, weekend)

        Returns:
            AuthenticationPattern with extracted patterns
        """
        cache_key = f"auth_{user_type}_{time_period}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        # Load processed data if not in memory
        if not self._processed_data:
            if self.processed_file.exists():
                with open(self.processed_file, 'r') as f:
                    self._processed_data = json.load(f)
            else:
                logger.warning("No processed LANL data found")
                return self._get_default_patterns()

        try:
            patterns_data = self._processed_data.get('patterns', {})

            # Extract context-specific patterns
            pattern = AuthenticationPattern(
                typical_login_times=self._get_login_times(patterns_data, time_period),
                authentication_methods=self._get_auth_methods(patterns_data),
                session_characteristics=self._get_session_characteristics(patterns_data, user_type),
                failure_patterns=self._get_failure_patterns(patterns_data),
                anomaly_indicators=self._get_anomaly_indicators(patterns_data),
                baseline_metrics=self._get_baseline_metrics(patterns_data)
            )

            self._patterns_cache[cache_key] = pattern
            return pattern

        except Exception as e:
            logger.error(f"Error extracting authentication patterns: {e}")
            return self._get_default_patterns()

    def _get_login_times(self, patterns_data: Dict, time_period: str) -> List[int]:
        """Get typical login times for time period."""
        temporal_data = patterns_data.get('temporal_patterns', {})
        peak_hours = temporal_data.get('peak_hours', [8, 9, 10, 13, 14, 15, 16, 17])

        if time_period == "business_hours":
            return peak_hours
        elif time_period == "after_hours":
            return [18, 19, 20, 21, 22]
        elif time_period == "weekend":
            return [10, 11, 14, 15, 16]
        else:
            return peak_hours

    def _get_auth_methods(self, patterns_data: Dict) -> List[str]:
        """Get authentication methods in order of prevalence."""
        auth_data = patterns_data.get('authentication_types', {})
        sorted_methods = sorted(auth_data.items(), key=lambda x: x[1], reverse=True)
        return [method for method, _ in sorted_methods]

    def _get_session_characteristics(self, patterns_data: Dict, user_type: str) -> Dict[str, Any]:
        """Get session characteristics for user type."""
        user_data = patterns_data.get('user_patterns', {})

        # Adjust based on user type
        multiplier = {
            'executive': 0.8,    # Fewer but longer sessions
            'admin': 1.5,        # More frequent access
            'employee': 1.0      # Baseline
        }.get(user_type, 1.0)

        return {
            'avg_daily_sessions': int(user_data.get('avg_daily_logins', 25) * multiplier),
            'unique_systems_accessed': int(user_data.get('unique_computers_per_user', 3) * multiplier),
            'session_duration_minutes': 120 if user_type == 'executive' else 60
        }

    def _get_failure_patterns(self, patterns_data: Dict) -> Dict[str, float]:
        """Get authentication failure patterns."""
        success_data = patterns_data.get('success_rates', {})
        anomaly_data = patterns_data.get('anomaly_indicators', {})

        return {
            'normal_failure_rate': anomaly_data.get('failure_rate', 8.0),
            'suspicious_failure_threshold': 15.0,
            'lockout_threshold': 5,
            'retry_window_minutes': 30
        }

    def _get_anomaly_indicators(self, patterns_data: Dict) -> List[str]:
        """Get anomaly indicators."""
        return [
            "off_hours_authentication",
            "unusual_system_access",
            "multiple_failed_attempts",
            "geographically_impossible_logins",
            "privilege_escalation_attempts",
            "bulk_authentication_requests"
        ]

    def _get_baseline_metrics(self, patterns_data: Dict) -> Dict[str, float]:
        """Get baseline metrics for comparison."""
        temporal_data = patterns_data.get('temporal_patterns', {})
        user_data = patterns_data.get('user_patterns', {})

        return {
            'off_hours_percentage': temporal_data.get('off_hours_percentage', 15.0),
            'weekend_percentage': temporal_data.get('weekend_percentage', 8.0),
            'avg_daily_logins': user_data.get('avg_daily_logins', 25.0),
            'max_daily_logins': user_data.get('max_daily_logins', 150.0)
        }

    def _get_default_patterns(self) -> AuthenticationPattern:
        """Get default authentication patterns when dataset is not available."""
        return AuthenticationPattern(
            typical_login_times=[8, 9, 10, 13, 14, 15, 16, 17],
            authentication_methods=["negotiate", "kerberos", "ntlm"],
            session_characteristics={
                'avg_daily_sessions': 25,
                'unique_systems_accessed': 3,
                'session_duration_minutes': 60
            },
            failure_patterns={
                'normal_failure_rate': 8.0,
                'suspicious_failure_threshold': 15.0,
                'lockout_threshold': 5,
                'retry_window_minutes': 30
            },
            anomaly_indicators=[
                "off_hours_authentication",
                "unusual_system_access",
                "multiple_failed_attempts",
                "privilege_escalation_attempts"
            ],
            baseline_metrics={
                'off_hours_percentage': 15.0,
                'weekend_percentage': 8.0,
                'avg_daily_logins': 25.0,
                'max_daily_logins': 150.0
            }
        )
