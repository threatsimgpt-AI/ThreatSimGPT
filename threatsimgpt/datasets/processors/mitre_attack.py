"""MITRE ATT&CK framework processor for ThreatSimGPT.

This processor handles the MITRE ATT&CK framework data to extract
tactics, techniques, and procedures (TTPs) for enhanced threat modeling.
"""

import logging
import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional, Any, Set
from datetime import datetime
from dataclasses import dataclass
from collections import Counter, defaultdict

from ..base_processor import BaseDatasetProcessor
from ..manager import DatasetInfo, DatasetStatus, DatasetType, TTPPattern

logger = logging.getLogger(__name__)


@dataclass
class ATTACKTechnique:
    """Represents a MITRE ATT&CK technique."""

    technique_id: str
    name: str
    description: str
    tactic: str
    subtechniques: List[str]
    platforms: List[str]
    data_sources: List[str]
    mitigations: List[str]


class MITREAttackProcessor(BaseDatasetProcessor):
    """Processor for MITRE ATT&CK framework data."""

    def __init__(self, storage_path: Path):
        """Initialize MITRE ATT&CK processor.

        Args:
            storage_path: Path to store MITRE ATT&CK dataset
        """
        super().__init__(str(storage_path))

        # MITRE ATT&CK STIX data URLs
        self.enterprise_url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        self.mobile_url = "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json"
        self.ics_url = "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json"

        self.enterprise_file = self.storage_path / "enterprise-attack.json"
        self.mobile_file = self.storage_path / "mobile-attack.json"
        self.ics_file = self.storage_path / "ics-attack.json"
        self.processed_file = self.storage_path / "processed_ttps.json"

        # Processing cache
        self._patterns_cache: Dict[str, TTPPattern] = {}
        self._processed_data: Optional[Dict[str, Any]] = None

        # Tactic mappings
        self.tactic_descriptions = {
            'initial-access': 'Getting into your network',
            'execution': 'Running malicious code',
            'persistence': 'Maintaining their foothold',
            'privilege-escalation': 'Gaining higher-level permissions',
            'defense-evasion': 'Avoiding being detected',
            'credential-access': 'Stealing account names and passwords',
            'discovery': 'Figuring out your environment',
            'lateral-movement': 'Moving through your environment',
            'collection': 'Gathering data of interest',
            'command-and-control': 'Communicating with compromised systems',
            'exfiltration': 'Stealing data',
            'impact': 'Manipulate, interrupt, or destroy systems and data'
        }

    async def get_dataset_info(self) -> DatasetInfo:
        """Get information about the MITRE ATT&CK dataset."""
        status = DatasetStatus.NOT_DOWNLOADED
        version = "current"
        size_mb = None
        last_updated = None

        if self.enterprise_file.exists():
            size_mb = sum(
                f.stat().st_size for f in [self.enterprise_file, self.mobile_file, self.ics_file]
                if f.exists()
            ) / (1024 * 1024)
            last_updated = datetime.fromtimestamp(self.enterprise_file.stat().st_mtime)

            if self.processed_file.exists():
                status = DatasetStatus.READY
            else:
                status = DatasetStatus.DOWNLOADED

        return DatasetInfo(
            name="MITRE ATT&CK Framework",
            type=DatasetType.MITRE_ATTACK,
            description="Global knowledge base of adversary tactics, techniques and procedures",
            source_url="https://attack.mitre.org/",
            version=version,
            size_mb=size_mb,
            last_updated=last_updated,
            status=status,
            features=[
                "tactics_techniques_procedures",
                "attack_patterns",
                "threat_actor_mapping",
                "mitigation_strategies",
                "detection_methods"
            ],
            use_cases=[
                "attack_simulation_scenarios",
                "threat_modeling",
                "red_team_planning",
                "defense_strategy_development"
            ]
        )

    async def download_and_process(self, force: bool = False) -> bool:
        """Download and process the MITRE ATT&CK dataset.

        Args:
            force: Force re-download even if exists

        Returns:
            True if successful, False otherwise
        """
        try:
            # Download MITRE ATT&CK data
            if force or not self._all_files_exist():
                logger.info("Downloading MITRE ATT&CK framework data...")
                success = await self.download_dataset()
                if not success:
                    return False

            # Process ATT&CK data for TTP extraction
            logger.info("Processing MITRE ATT&CK data for TTP extraction...")
            success = await self.process_dataset()
            if not success:
                return False

            logger.info("MITRE ATT&CK dataset processing completed successfully")
            return True

        except Exception as e:
            logger.error(f"Error processing MITRE ATT&CK dataset: {e}")
            return False

    def _all_files_exist(self) -> bool:
        """Check if all required files exist."""
        return all(f.exists() for f in [self.enterprise_file, self.mobile_file, self.ics_file])

    async def download_dataset(self) -> bool:
        """Download MITRE ATT&CK data files (implements BaseDatasetProcessor abstract method)."""
        downloads = [
            (self.enterprise_url, self.enterprise_file),
            (self.mobile_url, self.mobile_file),
            (self.ics_url, self.ics_file)
        ]

        try:
            for url, file_path in downloads:
                logger.info(f"Downloading {url}")
                success = await self.download_file(url, file_path, progress_interval=1)
                if not success:
                    logger.error(f"Failed to download {url}")
                    return False
                logger.info(f"Downloaded {file_path.name}")

            logger.info("MITRE ATT&CK data download completed")
            return True

        except Exception as e:
            logger.error(f"Error downloading MITRE ATT&CK data: {e}")
            return False

    async def process_dataset(self) -> bool:
        """Process MITRE ATT&CK data to extract TTPs (implements BaseDatasetProcessor abstract method)."""
        try:
            all_techniques = []

            # Process each matrix
            matrices = [
                ("enterprise", self.enterprise_file),
                ("mobile", self.mobile_file),
                ("ics", self.ics_file)
            ]

            for matrix_name, file_path in matrices:
                if file_path.exists():
                    logger.info(f"Processing {matrix_name} ATT&CK matrix")
                    techniques = await self._parse_attack_matrix(file_path, matrix_name)
                    all_techniques.extend(techniques)

            logger.info(f"Parsed {len(all_techniques)} techniques total")

            # Analyze and organize TTPs
            ttp_patterns = await self._analyze_ttp_patterns(all_techniques)

            # Store processed data
            self._processed_data = {
                'total_techniques': len(all_techniques),
                'processed_date': datetime.utcnow().isoformat(),
                'matrices': ['enterprise', 'mobile', 'ics'],
                'ttp_patterns': ttp_patterns,
                'version': 'current'
            }

            with open(self.processed_file, 'w') as f:
                json.dump(self._processed_data, f, indent=2)

            logger.info("MITRE ATT&CK processing completed")
            return True

        except Exception as e:
            logger.error(f"Error processing MITRE ATT&CK data: {e}")
            return False

    async def _parse_attack_matrix(self, file_path: Path, matrix_name: str) -> List[ATTACKTechnique]:
        """Parse a single ATT&CK matrix file."""
        techniques = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)

            # Parse STIX objects
            for obj in data.get('objects', []):
                if obj.get('type') == 'attack-pattern':
                    try:
                        technique = self._parse_technique(obj, matrix_name)
                        if technique:
                            techniques.append(technique)
                    except Exception as e:
                        logger.debug(f"Error parsing technique: {e}")
                        continue

            logger.info(f"Parsed {len(techniques)} techniques from {matrix_name}")
            return techniques

        except Exception as e:
            logger.error(f"Error parsing {file_path}: {e}")
            return []

    def _parse_technique(self, obj: Dict, matrix_name: str) -> Optional[ATTACKTechnique]:
        """Parse a single technique object."""
        try:
            # Extract technique ID from external references
            technique_id = ""
            for ref in obj.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    technique_id = ref.get('external_id', '')
                    break

            if not technique_id:
                return None

            # Extract kill chain phases (tactics)
            tactics = []
            for phase in obj.get('kill_chain_phases', []):
                if phase.get('kill_chain_name') == 'mitre-attack':
                    tactics.append(phase.get('phase_name', ''))

            # Extract platforms
            platforms = obj.get('x_mitre_platforms', [])
            if isinstance(platforms, str):
                platforms = [platforms]

            # Extract data sources
            data_sources = []
            for ds in obj.get('x_mitre_data_sources', []):
                if isinstance(ds, str):
                    data_sources.append(ds)
                elif isinstance(ds, dict):
                    data_sources.append(ds.get('name', ''))

            return ATTACKTechnique(
                technique_id=technique_id,
                name=obj.get('name', ''),
                description=obj.get('description', ''),
                tactic=tactics[0] if tactics else '',  # Primary tactic
                subtechniques=[],  # Could be expanded
                platforms=platforms,
                data_sources=data_sources,
                mitigations=[]  # Could be populated from relationships
            )

        except Exception as e:
            logger.debug(f"Error parsing technique object: {e}")
            return None

    async def _analyze_ttp_patterns(self, techniques: List[ATTACKTechnique]) -> Dict[str, Any]:
        """Analyze techniques to extract TTP patterns."""
        patterns = {}

        try:
            # Tactic distribution
            tactic_counter = Counter(tech.tactic for tech in techniques if tech.tactic)
            patterns['tactic_distribution'] = dict(tactic_counter)

            # Platform distribution
            all_platforms = []
            for tech in techniques:
                all_platforms.extend(tech.platforms)
            platform_counter = Counter(all_platforms)
            patterns['platform_distribution'] = dict(platform_counter)

            # Techniques by tactic
            techniques_by_tactic = defaultdict(list)
            for tech in techniques:
                if tech.tactic:
                    techniques_by_tactic[tech.tactic].append({
                        'id': tech.technique_id,
                        'name': tech.name,
                        'platforms': tech.platforms
                    })
            patterns['techniques_by_tactic'] = dict(techniques_by_tactic)

            # Common attack chains (simplified)
            patterns['common_attack_chains'] = self._identify_common_chains()

            # Data source patterns
            all_data_sources = []
            for tech in techniques:
                all_data_sources.extend(tech.data_sources)
            ds_counter = Counter(all_data_sources)
            patterns['data_source_coverage'] = dict(ds_counter.most_common(20))

            return patterns

        except Exception as e:
            logger.error(f"Error analyzing TTP patterns: {e}")
            return {}

    def _identify_common_chains(self) -> List[Dict[str, Any]]:
        """Identify common attack chains."""
        # Simplified common attack chains based on MITRE research
        return [
            {
                'name': 'Initial Access to Persistence',
                'tactics': ['initial-access', 'execution', 'persistence'],
                'description': 'Gain access, execute code, maintain presence'
            },
            {
                'name': 'Credential Access Chain',
                'tactics': ['credential-access', 'lateral-movement', 'collection'],
                'description': 'Steal credentials, move laterally, collect data'
            },
            {
                'name': 'Defense Evasion to Impact',
                'tactics': ['defense-evasion', 'discovery', 'impact'],
                'description': 'Avoid detection, discover environment, cause damage'
            },
            {
                'name': 'Full Kill Chain',
                'tactics': [
                    'initial-access', 'execution', 'persistence', 'privilege-escalation',
                    'defense-evasion', 'credential-access', 'discovery', 'lateral-movement',
                    'collection', 'exfiltration'
                ],
                'description': 'Complete attack lifecycle'
            }
        ]

    async def extract_ttp_patterns(self,
                                 tactic: str = "general",
                                 platform: str = "general") -> TTPPattern:
        """Extract TTP patterns for specific tactic and platform.

        Args:
            tactic: Target tactic (initial-access, persistence, etc.)
            platform: Target platform (Windows, Linux, macOS, etc.)

        Returns:
            TTPPattern with extracted patterns
        """
        cache_key = f"ttp_{tactic}_{platform}"

        if cache_key in self._patterns_cache:
            return self._patterns_cache[cache_key]

        # Load processed data if not in memory
        if not self._processed_data:
            if self.processed_file.exists():
                with open(self.processed_file, 'r') as f:
                    self._processed_data = json.load(f)
            else:
                logger.warning("No processed MITRE ATT&CK data found")
                return self._get_default_patterns()

        try:
            ttp_data = self._processed_data.get('ttp_patterns', {})

            # Extract context-specific patterns
            pattern = TTPPattern(
                tactics=self._get_relevant_tactics(ttp_data, tactic),
                techniques=self._get_relevant_techniques(ttp_data, tactic, platform),
                procedures=self._get_procedures(ttp_data, tactic),
                attack_chains=self._get_attack_chains(ttp_data, tactic),
                detection_methods=self._get_detection_methods(ttp_data, tactic),
                mitigation_strategies=self._get_mitigations(ttp_data, tactic)
            )

            self._patterns_cache[cache_key] = pattern
            return pattern

        except Exception as e:
            logger.error(f"Error extracting TTP patterns: {e}")
            return self._get_default_patterns()

    def _get_relevant_tactics(self, ttp_data: Dict, target_tactic: str) -> List[str]:
        """Get relevant tactics for target."""
        tactic_dist = ttp_data.get('tactic_distribution', {})

        if target_tactic != "general" and target_tactic in tactic_dist:
            return [target_tactic]

        # Return top tactics
        sorted_tactics = sorted(tactic_dist.items(), key=lambda x: x[1], reverse=True)
        return [tactic for tactic, _ in sorted_tactics[:8]]

    def _get_relevant_techniques(self, ttp_data: Dict, tactic: str, platform: str) -> List[Dict[str, str]]:
        """Get relevant techniques for tactic and platform."""
        techniques_by_tactic = ttp_data.get('techniques_by_tactic', {})

        if tactic != "general" and tactic in techniques_by_tactic:
            techniques = techniques_by_tactic[tactic]

            # Filter by platform if specified
            if platform != "general":
                filtered_techniques = []
                for tech in techniques:
                    if any(platform.lower() in p.lower() for p in tech.get('platforms', [])):
                        filtered_techniques.append(tech)
                return filtered_techniques[:10]

            return techniques[:10]

        # Return sample techniques from all tactics
        all_techniques = []
        for tactic_techniques in techniques_by_tactic.values():
            all_techniques.extend(tactic_techniques)

        return all_techniques[:15]

    def _get_procedures(self, ttp_data: Dict, tactic: str) -> List[str]:
        """Get example procedures for tactic."""
        # Simplified procedures - could be enhanced with real procedure data
        procedure_examples = {
            'initial-access': [
                "Spearphishing attachment with malicious macro",
                "Drive-by compromise via watering hole",
                "Valid accounts through credential stuffing"
            ],
            'persistence': [
                "Registry Run Keys modification",
                "Scheduled task creation",
                "Service installation"
            ],
            'privilege-escalation': [
                "UAC bypass techniques",
                "Token manipulation",
                "Process injection"
            ],
            'defense-evasion': [
                "Process hollowing",
                "DLL side-loading",
                "Timestomp file modification times"
            ]
        }

        return procedure_examples.get(tactic, [
            "Custom implementation specific to target",
            "Adaptation of known techniques",
            "Novel combination of methods"
        ])

    def _get_attack_chains(self, ttp_data: Dict, tactic: str) -> List[Dict[str, Any]]:
        """Get relevant attack chains."""
        common_chains = ttp_data.get('common_attack_chains', [])

        if tactic != "general":
            # Filter chains that include the target tactic
            relevant_chains = []
            for chain in common_chains:
                if tactic in chain.get('tactics', []):
                    relevant_chains.append(chain)
            return relevant_chains

        return common_chains

    def _get_detection_methods(self, ttp_data: Dict, tactic: str) -> List[str]:
        """Get detection methods for tactic."""
        # Based on common data sources
        data_sources = ttp_data.get('data_source_coverage', {})

        detection_methods = [
            "Process monitoring",
            "Network traffic analysis",
            "File monitoring",
            "Registry monitoring",
            "Authentication logs",
            "DNS monitoring",
            "Email monitoring",
            "API monitoring"
        ]

        return detection_methods[:6]

    def _get_mitigations(self, ttp_data: Dict, tactic: str) -> List[str]:
        """Get mitigation strategies for tactic."""
        # General mitigation strategies mapped to tactics
        mitigation_map = {
            'initial-access': [
                "Email security solutions",
                "Network segmentation",
                "User training and awareness"
            ],
            'persistence': [
                "Registry monitoring",
                "Scheduled task auditing",
                "Service monitoring"
            ],
            'privilege-escalation': [
                "User Account Control",
                "Privileged account management",
                "Application whitelisting"
            ]
        }

        return mitigation_map.get(tactic, [
            "Defense in depth strategy",
            "Regular security assessments",
            "Incident response planning"
        ])

    def _get_default_patterns(self) -> TTPPattern:
        """Get default TTP patterns when dataset is not available."""
        return TTPPattern(
            tactics=[
                "initial-access", "execution", "persistence",
                "privilege-escalation", "defense-evasion", "credential-access"
            ],
            techniques=[
                {"id": "T1566", "name": "Phishing"},
                {"id": "T1059", "name": "Command and Scripting Interpreter"},
                {"id": "T1547", "name": "Boot or Logon Autostart Execution"}
            ],
            procedures=[
                "Spearphishing attachment",
                "PowerShell execution",
                "Registry Run Keys"
            ],
            attack_chains=[
                {
                    'name': 'Basic Attack Chain',
                    'tactics': ['initial-access', 'execution', 'persistence'],
                    'description': 'Simple attack progression'
                }
            ],
            detection_methods=[
                "Process monitoring",
                "Network analysis",
                "File monitoring"
            ],
            mitigation_strategies=[
                "User training",
                "Email security",
                "System hardening"
            ]
        )
    async def get_stats(self) -> Dict[str, Any]:
        """Get statistics about the MITRE ATT&CK dataset (implements BaseDatasetProcessor abstract method).

        Returns:
            Dict containing dataset statistics
        """
        stats = {
            'status': 'not_processed',
            'enterprise_file': str(self.enterprise_file),
            'mobile_file': str(self.mobile_file),
            'ics_file': str(self.ics_file),
            'enterprise_exists': self.enterprise_file.exists(),
            'mobile_exists': self.mobile_file.exists(),
            'ics_exists': self.ics_file.exists(),
        }

        # Add file sizes if available
        total_size_mb = 0
        for file_path in [self.enterprise_file, self.mobile_file, self.ics_file]:
            if file_path.exists():
                size_mb = self.get_file_size_mb(file_path)
                stats[f'{file_path.stem}_size_mb'] = size_mb
                total_size_mb += size_mb

        stats['total_size_mb'] = total_size_mb

        # Add processed data stats if available
        if self._processed_data:
            stats.update({
                'status': 'processed',
                'total_techniques': self._processed_data.get('total_techniques', 0),
                'processed_date': self._processed_data.get('processed_date'),
                'matrices': self._processed_data.get('matrices', []),
                'version': self._processed_data.get('version'),
                'patterns_cached': len(self._patterns_cache)
            })

        # Include base processor info
        stats['processor_info'] = self.get_processing_info()

        return stats
