"""PhishTank database processor for ThreatSimGPT.

This processor handles the PhishTank database to extract realistic
phishing URL patterns and domain characteristics for enhanced simulations.
"""

import logging
import asyncio
import json
import gzip
import csv
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import Counter, defaultdict
from urllib.parse import urlparse
import re

from ..base_processor import BaseDatasetProcessor
from ..manager import DatasetInfo, DatasetStatus, DatasetType, PhishingPattern

logger = logging.getLogger(__name__)


@dataclass
class PhishingRecord:
    """Represents a phishing record from PhishTank."""

    phish_id: str
    url: str
    phish_detail_url: str
    submission_time: datetime
    verified: bool
    verification_time: Optional[datetime]
    online: bool
    target_brand: Optional[str]


class PhishTankProcessor(BaseDatasetProcessor):
    """Processor for PhishTank phishing database."""

    def __init__(self, storage_path: Path):
        """Initialize PhishTank processor.

        Args:
            storage_path: Path to store PhishTank dataset
        """
        super().__init__(str(storage_path))

        # Dataset URLs (PhishTank provides JSON dumps)
        self.base_url = "http://data.phishtank.com/data"
        self.verified_url = f"{self.base_url}/online-valid.json.gz"
        self.all_url = f"{self.base_url}/online-valid.csv.gz"

        self.verified_file = self.storage_path / "verified_phishing.json.gz"
        self.all_file = self.storage_path / "all_phishing.csv.gz"
        self.processed_file = self.storage_path / "processed_patterns.json"

        # Processing cache
        self._patterns_cache: Dict[str, PhishingPattern] = {}
        self._processed_data: Optional[Dict[str, Any]] = None

        # Brand mappings for target identification
        self.brand_keywords = {
            'paypal': ['paypal', 'paypaI', 'payp4l', 'paipal'],
            'apple': ['apple', 'appleid', 'icloud', 'app1e'],
            'microsoft': ['microsoft', 'outlook', 'office365', 'live', 'hotmail'],
            'amazon': ['amazon', 'aws', 'amaz0n', 'amazom'],
            'google': ['google', 'gmail', 'g00gle', 'googIe'],
            'facebook': ['facebook', 'fb', 'faceb00k'],
            'instagram': ['instagram', 'insta', 'instqgram'],
            'banking': ['bank', 'chase', 'wellsfargo', 'bofa', 'citibank'],
            'crypto': ['bitcoin', 'crypto', 'blockchain', 'coinbase', 'binance']
        }

    async def get_dataset_info(self) -> DatasetInfo:
        """Get information about the PhishTank dataset."""
        status = DatasetStatus.NOT_DOWNLOADED
        version = "current"
        size_mb = None
        last_updated = None

        if self.verified_file.exists():
            size_mb = self.verified_file.stat().st_size / (1024 * 1024)
            last_updated = datetime.fromtimestamp(self.verified_file.stat().st_mtime)

            if self.processed_file.exists():
                status = DatasetStatus.READY
            else:
                status = DatasetStatus.DOWNLOADED

        return DatasetInfo(
            name="PhishTank Database",
            type=DatasetType.PHISHTANK,
            description="Real-time phishing URL database with 100,000+ verified phishing sites",
            source_url="https://www.phishtank.com/",
            version=version,
            size_mb=size_mb,
            last_updated=last_updated,
            status=status,
            features=[
                "phishing_url_patterns",
                "domain_characteristics",
                "target_brand_analysis",
                "url_structure_patterns",
                "suspicious_tld_usage"
            ],
            use_cases=[
                "phishing_domain_generation",
                "url_pattern_analysis",
                "brand_impersonation_detection",
                "suspicious_domain_training"
            ]
        )

    async def download_and_process(self, force: bool = False) -> bool:
        """Download and process the PhishTank dataset.

        Args:
            force: Force re-download even if exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Check if recent data exists (PhishTank updates frequently)
            if not force and self._is_data_recent():
                logger.info("Recent PhishTank data exists, skipping download")
            else:
                # Download verified phishing data
                logger.info("Downloading PhishTank verified phishing data...")
                success = await self.download_dataset()
                if not success:
                    return False

            # Process phishing data for pattern extraction
            logger.info("Processing PhishTank data for pattern extraction...")
            success = await self._process_phishing_data()
            if not success:
                return False

            logger.info("PhishTank dataset processing completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error processing PhishTank dataset: {e}")
            return False

    def _is_data_recent(self) -> bool:
        """Check if existing data is recent (less than 7 days old) using base class method."""
        return self.is_data_recent(self.verified_file, max_age_days=7)

    async def download_dataset(self) -> bool:
        """Download the PhishTank dataset using base class method."""
        return await self.download_file(
            url=self.verified_url,
            destination=self.verified_file,
            progress_interval=5 * 1024 * 1024  # 5MB progress updates
        )

    async def process_dataset(self) -> bool:
        """Process phishing data to extract patterns."""
        return await self._process_phishing_data()

    async def _process_phishing_data(self) -> bool:
        """Internal method to process phishing data."""
        try:
            if not self.verified_file.exists():
                logger.error("PhishTank data not downloaded")
                return False

            # Load and parse JSON data
            logger.info("Loading PhishTank data...")
            with gzip.open(self.verified_file, 'rt', encoding='utf-8') as f:
                phishing_data = json.load(f)

            logger.info(f"Loaded {len(phishing_data)} phishing records")

            # Convert to structured records
            records = []
            for item in phishing_data:
                try:
                    record = PhishingRecord(
                        phish_id=str(item.get('phish_id', '')),
                        url=item.get('url', ''),
                        phish_detail_url=item.get('phish_detail_url', ''),
                        submission_time=self._parse_timestamp(item.get('submission_time')),
                        verified=item.get('verified', False),
                        verification_time=self._parse_timestamp(item.get('verification_time')),
                        online=item.get('online', False),
                        target_brand=item.get('target', '')
                    )
                    records.append(record)
                except Exception as e:
                    logger.debug(f"Error parsing record: {e}")
                    continue

            logger.info(f"Parsed {len(records)} valid phishing records")

            # Analyze patterns
            patterns = await self._analyze_phishing_patterns(records)

            # Store processed data
            self._processed_data = {
                'total_records': len(records),
                'processed_date': datetime.utcnow().isoformat(),
                'patterns': patterns,
                'dataset_version': datetime.now().strftime('%Y%m%d')
            }

            with open(self.processed_file, 'w') as f:
                json.dump(self._processed_data, f, indent=2)

            logger.info("PhishTank pattern analysis completed")
            return True

        except Exception as e:
            logger.error(f"Error processing PhishTank data: {e}")
            return False

    def _parse_timestamp(self, timestamp_str: Optional[str]) -> Optional[datetime]:
        """Parse timestamp string to datetime."""
        if not timestamp_str:
            return None

        try:
            # PhishTank uses ISO format
            return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        except Exception:
            return None

    async def _analyze_phishing_patterns(self, records: List[PhishingRecord]) -> Dict[str, Any]:
        """Analyze phishing records to extract patterns."""
        patterns = {
            'domain_patterns': {},
            'url_structures': {},
            'target_brands': {},
            'tld_analysis': {},
            'suspicious_keywords': {},
            'domain_lengths': {},
            'subdomain_patterns': {}
        }

        try:
            # Analyze each record
            all_domains = []
            all_paths = []
            all_subdomains = []
            target_brands = []

            for record in records:
                try:
                    parsed_url = urlparse(record.url)
                    domain = parsed_url.netloc.lower()
                    path = parsed_url.path

                    all_domains.append(domain)
                    all_paths.append(path)

                    # Extract subdomains
                    domain_parts = domain.split('.')
                    if len(domain_parts) > 2:
                        subdomain = '.'.join(domain_parts[:-2])
                        all_subdomains.append(subdomain)

                    # Identify target brand
                    brand = self._identify_target_brand(record.url, record.target_brand)
                    if brand:
                        target_brands.append(brand)

                except Exception as e:
                    logger.debug(f"Error analyzing record {record.phish_id}: {e}")
                    continue

            # Analyze domain patterns
            patterns['domain_patterns'] = self._analyze_domains(all_domains)
            patterns['url_structures'] = self._analyze_url_structures(all_paths)
            patterns['target_brands'] = self._analyze_target_brands(target_brands)
            patterns['tld_analysis'] = self._analyze_tlds(all_domains)
            patterns['suspicious_keywords'] = self._extract_suspicious_keywords(all_domains)
            patterns['domain_lengths'] = self._analyze_domain_lengths(all_domains)
            patterns['subdomain_patterns'] = self._analyze_subdomains(all_subdomains)

            return patterns

        except Exception as e:
            logger.error(f"Error in pattern analysis: {e}")
            return patterns

    def _identify_target_brand(self, url: str, target_hint: str = None) -> Optional[str]:
        """Identify the target brand from URL and hint."""
        url_lower = url.lower()

        # First check explicit target hint
        if target_hint:
            for brand, keywords in self.brand_keywords.items():
                if any(keyword in target_hint.lower() for keyword in keywords):
                    return brand

        # Then analyze URL
        for brand, keywords in self.brand_keywords.items():
            if any(keyword in url_lower for keyword in keywords):
                return brand

        return None

    def _analyze_domains(self, domains: List[str]) -> Dict[str, Any]:
        """Analyze domain patterns."""
        domain_counter = Counter(domains)

        # Extract patterns
        patterns = {
            'most_common': domain_counter.most_common(20),
            'total_unique': len(set(domains)),
            'average_length': sum(len(d) for d in domains) / len(domains) if domains else 0,
            'character_patterns': self._extract_character_patterns(domains),
            'typosquatting_patterns': self._identify_typosquatting(domains)
        }

        return patterns

    def _analyze_url_structures(self, paths: List[str]) -> Dict[str, Any]:
        """Analyze URL path structures."""
        path_patterns = Counter()
        common_dirs = Counter()

        for path in paths:
            if not path or path == '/':
                path_patterns['root'] += 1
                continue

            # Extract directory structure
            parts = [p for p in path.split('/') if p]
            if parts:
                first_dir = parts[0]
                common_dirs[first_dir] += 1

                # Categorize path patterns
                if any(keyword in path.lower() for keyword in ['login', 'signin', 'auth']):
                    path_patterns['login_pages'] += 1
                elif any(keyword in path.lower() for keyword in ['secure', 'verify', 'confirm']):
                    path_patterns['verification_pages'] += 1
                elif any(keyword in path.lower() for keyword in ['update', 'account', 'profile']):
                    path_patterns['account_pages'] += 1
                else:
                    path_patterns['other'] += 1

        return {
            'path_categories': dict(path_patterns),
            'common_directories': common_dirs.most_common(10),
            'total_paths': len(paths)
        }

    def _analyze_target_brands(self, brands: List[str]) -> Dict[str, Any]:
        """Analyze target brand distribution."""
        brand_counter = Counter(brands)

        return {
            'distribution': dict(brand_counter),
            'most_targeted': brand_counter.most_common(10),
            'total_brands': len(set(brands))
        }

    def _analyze_tlds(self, domains: List[str]) -> Dict[str, Any]:
        """Analyze top-level domain usage."""
        tld_counter = Counter()

        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                tld = parts[-1]
                tld_counter[tld] += 1

        # Identify suspicious TLDs (commonly abused)
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'top', 'click', 'download'}
        suspicious_count = sum(tld_counter[tld] for tld in suspicious_tlds if tld in tld_counter)

        return {
            'distribution': dict(tld_counter),
            'most_common': tld_counter.most_common(15),
            'suspicious_tlds': suspicious_count,
            'suspicious_percentage': (suspicious_count / len(domains)) * 100 if domains else 0
        }

    def _extract_suspicious_keywords(self, domains: List[str]) -> Dict[str, Any]:
        """Extract suspicious keywords from domains."""
        keywords = [
            'secure', 'verify', 'update', 'confirm', 'account', 'login',
            'auth', 'signin', 'validation', 'security', 'support',
            'service', 'customer', 'help', 'official', 'portal'
        ]

        keyword_counter = Counter()

        for domain in domains:
            domain_lower = domain.lower().replace('-', '').replace('.', '')
            for keyword in keywords:
                if keyword in domain_lower:
                    keyword_counter[keyword] += 1

        return {
            'distribution': dict(keyword_counter),
            'most_common': keyword_counter.most_common(10),
            'total_occurrences': sum(keyword_counter.values())
        }

    def _analyze_domain_lengths(self, domains: List[str]) -> Dict[str, Any]:
        """Analyze domain length distribution."""
        lengths = [len(domain) for domain in domains]

        if not lengths:
            return {'average': 0, 'distribution': {}}

        length_counter = Counter(lengths)

        return {
            'average': sum(lengths) / len(lengths),
            'min': min(lengths),
            'max': max(lengths),
            'distribution': dict(length_counter),
            'common_ranges': {
                'short (5-10)': sum(1 for l in lengths if 5 <= l <= 10),
                'medium (11-20)': sum(1 for l in lengths if 11 <= l <= 20),
                'long (21-30)': sum(1 for l in lengths if 21 <= l <= 30),
                'very_long (31+)': sum(1 for l in lengths if l > 30)
            }
        }

    def _analyze_subdomains(self, subdomains: List[str]) -> Dict[str, Any]:
        """Analyze subdomain patterns."""
        if not subdomains:
            return {'count': 0, 'patterns': {}}

        subdomain_counter = Counter(subdomains)

        # Common suspicious subdomain patterns
        suspicious_patterns = [
            'www-', 'secure-', 'login-', 'auth-', 'verify-',
            'account-', 'service-', 'support-', 'help-'
        ]

        suspicious_count = 0
        for subdomain in subdomains:
            if any(pattern in subdomain for pattern in suspicious_patterns):
                suspicious_count += 1

        return {
            'count': len(subdomains),
            'unique_count': len(set(subdomains)),
            'most_common': subdomain_counter.most_common(10),
            'suspicious_count': suspicious_count,
            'suspicious_percentage': (suspicious_count / len(subdomains)) * 100
        }

    def _extract_character_patterns(self, domains: List[str]) -> Dict[str, Any]:
        """Extract character usage patterns in domains."""
        char_patterns = {
            'hyphen_usage': sum(1 for d in domains if '-' in d),
            'number_usage': sum(1 for d in domains if any(c.isdigit() for c in d)),
            'mixed_case': sum(1 for d in domains if any(c.isupper() for c in d)),
            'special_chars': sum(1 for d in domains if any(c in d for c in ['_', '+', '=']))
        }

        total = len(domains)
        return {
            'counts': char_patterns,
            'percentages': {k: (v / total) * 100 for k, v in char_patterns.items()} if total > 0 else {}
        }

    def _identify_typosquatting(self, domains: List[str]) -> Dict[str, Any]:
        """Identify potential typosquatting patterns."""
        # Common typosquatting techniques
        patterns = {
            'character_substitution': 0,  # o->0, i->1, etc.
            'character_insertion': 0,     # extra chars
            'character_omission': 0,      # missing chars
            'homograph_attack': 0         # similar looking chars
        }

        # Simple heuristic checks
        substitutions = {'0': 'o', '1': 'i', '3': 'e', '5': 's'}

        for domain in domains:
            # Check for character substitutions
            if any(sub in domain for sub in substitutions.keys()):
                patterns['character_substitution'] += 1

            # Check for excessive length (potential insertion)
            if len(domain) > 25:
                patterns['character_insertion'] += 1

        return patterns

    async def extract_phishing_patterns(self, target_brand: str = "general") -> PhishingPattern:
        """Extract phishing patterns for specific target brand.

        Args:
            target_brand: Target brand to focus patterns on

        Returns:
            PhishingPattern with extracted patterns
        """
        cache_key = f"phishing_{target_brand}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        # Load processed data if not in memory
        if not self._processed_data:
            if self.processed_file.exists():
                with open(self.processed_file, 'r') as f:
                    self._processed_data = json.load(f)
            else:
                logger.warning("No processed PhishTank data found")
                return self._get_default_patterns()

        try:
            patterns_data = self._processed_data.get('patterns', {})

            # Extract relevant patterns
            domain_patterns = self._extract_domain_patterns_for_brand(patterns_data, target_brand)
            url_structures = self._extract_url_structures_for_brand(patterns_data, target_brand)

            pattern = PhishingPattern(
                common_domains=domain_patterns.get('common_domains', []),
                suspicious_tlds=self._get_suspicious_tlds(patterns_data),
                url_patterns=url_structures.get('patterns', []),
                subdomain_tricks=self._get_subdomain_tricks(patterns_data),
                typosquatting_techniques=self._get_typosquatting_techniques(patterns_data),
                target_keywords=self._get_target_keywords(patterns_data, target_brand)
            )

            self._patterns_cache[cache_key] = pattern
            return pattern

        except Exception as e:
            logger.error(f"Error extracting phishing patterns: {e}")
            return self._get_default_patterns()

    def _extract_domain_patterns_for_brand(self, patterns_data: Dict, brand: str) -> Dict[str, List[str]]:
        """Extract domain patterns specific to target brand."""
        domain_data = patterns_data.get('domain_patterns', {})

        # Get general common domains
        common_domains = []
        if 'most_common' in domain_data:
            common_domains = [domain for domain, _ in domain_data['most_common'][:10]]

        return {
            'common_domains': common_domains,
            'brand_specific': self._generate_brand_domains(brand)
        }

    def _extract_url_structures_for_brand(self, patterns_data: Dict, brand: str) -> Dict[str, List[str]]:
        """Extract URL structure patterns."""
        url_data = patterns_data.get('url_structures', {})

        patterns = [
            "/login",
            "/signin",
            "/account/verify",
            "/secure/update",
            "/auth/confirm",
            "/support/help"
        ]

        return {'patterns': patterns}

    def _get_suspicious_tlds(self, patterns_data: Dict) -> List[str]:
        """Get list of suspicious TLDs."""
        tld_data = patterns_data.get('tld_analysis', {})

        # Default suspicious TLDs plus analysis results
        suspicious = ['tk', 'ml', 'ga', 'cf', 'top', 'click', 'download', 'zip']

        if 'most_common' in tld_data:
            # Add commonly abused TLDs from data
            for tld, count in tld_data['most_common']:
                if tld not in ['com', 'org', 'net', 'edu', 'gov'] and count > 10:
                    suspicious.append(tld)

        return suspicious[:15]

    def _get_subdomain_tricks(self, patterns_data: Dict) -> List[str]:
        """Get common subdomain tricks."""
        return [
            "www-{brand}",
            "secure-{brand}",
            "login-{brand}",
            "verify-{brand}",
            "account-{brand}",
            "support-{brand}",
            "{brand}-security",
            "{brand}-verify"
        ]

    def _get_typosquatting_techniques(self, patterns_data: Dict) -> List[str]:
        """Get typosquatting techniques."""
        return [
            "character_substitution",  # paypal -> payp4l
            "character_insertion",     # paypal -> paypall
            "character_omission",      # paypal -> paypl
            "homograph_attack",        # paypal -> payраl (cyrillic)
            "subdomain_abuse",         # paypal.evil.com
        ]

    def _get_target_keywords(self, patterns_data: Dict, brand: str) -> List[str]:
        """Get keywords commonly used to target specific brand."""
        keyword_data = patterns_data.get('suspicious_keywords', {})

        general_keywords = ['secure', 'verify', 'update', 'account', 'login', 'auth']

        # Add brand-specific keywords
        brand_keywords = self.brand_keywords.get(brand, [])

        return general_keywords + brand_keywords

    def _generate_brand_domains(self, brand: str) -> List[str]:
        """Generate example domains for specific brand."""
        if brand == 'general':
            return []

        return [
            f"{brand}-secure.com",
            f"verify-{brand}.net",
            f"{brand}security.org",
            f"www-{brand}.tk",
            f"{brand}support.ml"
        ]

    def _get_default_patterns(self) -> PhishingPattern:
        """Get default phishing patterns when dataset is not available."""
        return PhishingPattern(
            common_domains=["secure-login.tk", "verify-account.ml", "update-info.ga"],
            suspicious_tlds=["tk", "ml", "ga", "cf", "top", "click"],
            url_patterns=["/login", "/verify", "/secure", "/account"],
            subdomain_tricks=["www-", "secure-", "verify-", "account-"],
            typosquatting_techniques=["character_substitution", "subdomain_abuse"],
            target_keywords=["secure", "verify", "update", "account", "urgent"]
        )
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the processed PhishTank dataset.

        Returns:
            Dictionary with dataset statistics
        """
        if not self._processed_data:
            return {
                "status": "not_processed",
                "total_records": 0
            }

        return {
            "status": "processed",
            "total_records": self._processed_data.get("total_records", 0),
            "unique_domains": self._processed_data.get("unique_domains", 0),
            "unique_tlds": self._processed_data.get("unique_tlds", 0),
            "top_brands": self._processed_data.get("top_brands", []),
            "processing_time": self._processed_data.get("processing_time"),
            **self.get_processing_info()
        }
