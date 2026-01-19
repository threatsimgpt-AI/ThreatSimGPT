"""Complete MITRE ATT&CK Framework Integration for ThreatSimGPT.

This module provides comprehensive MITRE ATT&CK coverage including:
- All Enterprise ATT&CK techniques and sub-techniques
- Mobile and ICS matrices
- Procedure examples from real threat actors
- Detection recommendations mapped to data sources
- Mitigation strategies with implementation guidance

Issue: #42 - Implement MITRE ATT&CK Full Coverage
Owner: David Onoja (@ocheme1107)
Track: Security/MITRE
"""

from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple, Union

import httpx

logger = logging.getLogger(__name__)


# ============================================================================
# Validation Patterns
# ============================================================================


# Technique ID pattern: T followed by 4 digits, optionally followed by .XXX
TECHNIQUE_ID_PATTERN = re.compile(r'^T\d{4}(\.\d{3})?$')

# Mitigation ID pattern: M followed by 4 digits
MITIGATION_ID_PATTERN = re.compile(r'^M\d{4}$')

# Group ID pattern: G followed by 4 digits
GROUP_ID_PATTERN = re.compile(r'^G\d{4}$')

# Software ID pattern: S followed by 4 digits
SOFTWARE_ID_PATTERN = re.compile(r'^S\d{4}$')


# ============================================================================
# MITRE ATT&CK Constants
# ============================================================================


class ATTACKMatrix(str, Enum):
    """MITRE ATT&CK matrices."""
    ENTERPRISE = "enterprise-attack"
    MOBILE = "mobile-attack"
    ICS = "ics-attack"


class ATTACKDomain(str, Enum):
    """MITRE ATT&CK domains."""
    ENTERPRISE = "enterprise"
    MOBILE = "mobile"
    ICS = "ics"


# Enterprise ATT&CK Tactics in kill chain order
ENTERPRISE_TACTICS = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_DESCRIPTIONS = {
    "reconnaissance": "Gathering information to plan future operations",
    "resource-development": "Establishing resources to support operations",
    "initial-access": "Trying to get into your network",
    "execution": "Trying to run malicious code",
    "persistence": "Trying to maintain their foothold",
    "privilege-escalation": "Trying to gain higher-level permissions",
    "defense-evasion": "Trying to avoid being detected",
    "credential-access": "Trying to steal account names and passwords",
    "discovery": "Trying to figure out your environment",
    "lateral-movement": "Trying to move through your environment",
    "collection": "Trying to gather data of interest to their goal",
    "command-and-control": "Trying to communicate with compromised systems",
    "exfiltration": "Trying to steal data",
    "impact": "Trying to manipulate, interrupt, or destroy systems and data",
}

# Platform categories
PLATFORMS = {
    "enterprise": [
        "Windows", "macOS", "Linux", "Cloud", "Office 365", "Azure AD",
        "Google Workspace", "SaaS", "IaaS", "Network", "Containers", "PRE"
    ],
    "mobile": ["Android", "iOS"],
    "ics": [
        "Windows", "Human-Machine Interface", "Control Server",
        "Data Historian", "Engineering Workstation", "Field Controller/RTU/PLC/IED",
        "Input/Output Server", "Safety Instrumented System/Protection Relay"
    ]
}


# ============================================================================
# Data Models
# ============================================================================


@dataclass
class ATTACKDataSource:
    """MITRE ATT&CK Data Source."""
    id: str
    name: str
    description: str
    platforms: List[str] = field(default_factory=list)
    collection_layers: List[str] = field(default_factory=list)
    components: List[str] = field(default_factory=list)


@dataclass
class ATTACKMitigation:
    """MITRE ATT&CK Mitigation."""
    id: str
    name: str
    description: str
    techniques_mitigated: List[str] = field(default_factory=list)


@dataclass
class ATTACKDetection:
    """Detection information for a technique."""
    data_sources: List[str]
    data_components: List[str]
    detection_notes: str
    analytic_details: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ATTACKProcedure:
    """Procedure example from threat intelligence."""
    technique_id: str
    threat_actor: Optional[str]
    software: Optional[str]
    description: str
    reference_url: Optional[str] = None


@dataclass
class ATTACKSubTechnique:
    """MITRE ATT&CK Sub-technique."""
    id: str
    name: str
    description: str
    parent_technique_id: str
    platforms: List[str] = field(default_factory=list)
    detection: Optional[ATTACKDetection] = None
    mitigations: List[str] = field(default_factory=list)
    procedures: List[ATTACKProcedure] = field(default_factory=list)


@dataclass
class ATTACKTechnique:
    """Complete MITRE ATT&CK Technique representation."""
    id: str
    name: str
    description: str
    tactics: List[str]
    platforms: List[str]
    permissions_required: List[str] = field(default_factory=list)
    effective_permissions: List[str] = field(default_factory=list)
    defense_bypassed: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: Optional[ATTACKDetection] = None
    mitigations: List[ATTACKMitigation] = field(default_factory=list)
    sub_techniques: List[ATTACKSubTechnique] = field(default_factory=list)
    procedures: List[ATTACKProcedure] = field(default_factory=list)
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    matrix: ATTACKMatrix = ATTACKMatrix.ENTERPRISE
    version: str = ""
    created: Optional[datetime] = None
    modified: Optional[datetime] = None
    revoked: bool = False
    deprecated: bool = False
    
    @property
    def full_id(self) -> str:
        """Get full technique ID including parent if sub-technique."""
        if self.is_subtechnique and self.parent_technique_id:
            return f"{self.parent_technique_id}.{self.id.split('.')[-1]}"
        return self.id
    
    @property
    def technique_url(self) -> str:
        """Get MITRE ATT&CK URL for this technique."""
        base_url = "https://attack.mitre.org/techniques"
        if self.is_subtechnique:
            parent, sub = self.id.rsplit(".", 1)
            return f"{base_url}/{parent}/{sub}/"
        return f"{base_url}/{self.id}/"


@dataclass
class ATTACKGroup:
    """MITRE ATT&CK Threat Group/Actor."""
    id: str
    name: str
    aliases: List[str]
    description: str
    techniques_used: List[str] = field(default_factory=list)
    software_used: List[str] = field(default_factory=list)
    associated_groups: List[str] = field(default_factory=list)


@dataclass
class ATTACKSoftware:
    """MITRE ATT&CK Software (Malware/Tool)."""
    id: str
    name: str
    type: str  # "malware" or "tool"
    description: str
    platforms: List[str] = field(default_factory=list)
    techniques_used: List[str] = field(default_factory=list)
    aliases: List[str] = field(default_factory=list)


@dataclass 
class ATTACKCampaign:
    """MITRE ATT&CK Campaign."""
    id: str
    name: str
    description: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    techniques_used: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    software: List[str] = field(default_factory=list)


# ============================================================================
# MITRE ATT&CK Full Coverage Engine
# ============================================================================


class MITREATTACKEngine:
    """Comprehensive MITRE ATT&CK Framework Engine.
    
    Provides complete coverage of:
    - All Enterprise, Mobile, and ICS techniques
    - Sub-techniques with full mapping
    - Procedure examples from threat actors and malware
    - Detection recommendations with data source mapping
    - Mitigation strategies with implementation guidance
    
    Thread Safety:
        This engine uses asyncio.Lock for thread-safe initialization.
        All query methods are safe to call concurrently after initialization.
    
    Example:
        engine = MITREATTACKEngine(storage_path=Path("data/mitre"))
        await engine.initialize()
        
        # Get technique details
        technique = engine.get_technique("T1566.001")
        
        # Get techniques for a tactic
        initial_access = engine.get_techniques_by_tactic("initial-access")
        
        # Get detection recommendations
        detections = engine.get_detection_recommendations("T1059")
        
        # Search techniques
        results = engine.search_techniques("powershell")
        
        # Using as async context manager
        async with MITREATTACKEngine(storage_path) as engine:
            technique = engine.get_technique("T1566")
    """
    
    # STIX 2.1 URLs for MITRE CTI
    STIX_URLS = {
        ATTACKMatrix.ENTERPRISE: "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        ATTACKMatrix.MOBILE: "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
        ATTACKMatrix.ICS: "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
    }
    
    # Default cache TTL: 7 days (MITRE updates quarterly, weekly check is safe)
    DEFAULT_CACHE_TTL_DAYS = 7
    
    # Maximum retry attempts for downloads
    MAX_RETRY_ATTEMPTS = 3
    
    # Maximum procedures to store in memory per technique
    MAX_PROCEDURES_PER_TECHNIQUE = 50
    
    def __init__(
        self,
        storage_path: Path,
        cache_ttl_days: int = DEFAULT_CACHE_TTL_DAYS,
        verify_ssl: Union[bool, str] = True,
        http_client: Optional[httpx.AsyncClient] = None,
    ):
        """Initialize MITRE ATT&CK Engine.
        
        Args:
            storage_path: Path to store downloaded MITRE data
            cache_ttl_days: Days before cached data is considered stale
            verify_ssl: SSL verification (True, False, or path to CA bundle)
            http_client: Optional pre-configured HTTP client for testing
        """
        self.storage_path = Path(storage_path).resolve()
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._cache_ttl = timedelta(days=cache_ttl_days)
        self._verify_ssl = verify_ssl
        self._http_client = http_client
        
        # Core data stores
        self._techniques: Dict[str, ATTACKTechnique] = {}
        self._sub_techniques: Dict[str, ATTACKSubTechnique] = {}
        self._mitigations: Dict[str, ATTACKMitigation] = {}
        self._data_sources: Dict[str, ATTACKDataSource] = {}
        self._groups: Dict[str, ATTACKGroup] = {}
        self._software: Dict[str, ATTACKSoftware] = {}
        self._campaigns: Dict[str, ATTACKCampaign] = {}
        
        # Relationship mappings
        self._technique_to_mitigations: Dict[str, List[str]] = defaultdict(list)
        self._technique_to_groups: Dict[str, List[str]] = defaultdict(list)
        self._technique_to_software: Dict[str, List[str]] = defaultdict(list)
        self._technique_to_data_sources: Dict[str, List[str]] = defaultdict(list)
        self._tactic_to_techniques: Dict[str, List[str]] = defaultdict(list)
        self._platform_to_techniques: Dict[str, List[str]] = defaultdict(list)
        self._parent_to_subtechniques: Dict[str, List[str]] = defaultdict(list)
        
        # Procedure examples (limited per technique)
        self._procedures: List[ATTACKProcedure] = []
        
        # Metadata
        self._initialized = False
        self._initializing = False
        self._version: Optional[str] = None
        self._attack_spec_version: Optional[str] = None
        self._last_updated: Optional[datetime] = None
        
        # Thread safety
        self._init_lock = asyncio.Lock()
        
        logger.info(f"MITREATTACKEngine initialized with storage at {storage_path}")
    
    # ========================================================================
    # Async Context Manager Support
    # ========================================================================
    
    async def __aenter__(self) -> "MITREATTACKEngine":
        """Async context manager entry."""
        await self.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        """Async context manager exit."""
        await self.close()
    
    async def close(self) -> None:
        """Clean up resources."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        logger.debug("MITREATTACKEngine closed")
    
    # ========================================================================
    # Initialization and Data Loading
    # ========================================================================
    
    async def initialize(self, force_download: bool = False) -> bool:
        """Initialize the engine by downloading and parsing MITRE data.
        
        Thread-safe initialization with lock to prevent concurrent initialization.
        
        Args:
            force_download: Force re-download even if data exists
            
        Returns:
            True if initialization successful
        """
        # Fast path: already initialized
        if self._initialized:
            return True
        
        # Acquire lock for thread-safe initialization
        async with self._init_lock:
            # Double-check after acquiring lock
            if self._initialized:
                return True
            
            if self._initializing:
                logger.warning("Initialization already in progress")
                return False
            
            self._initializing = True
            
            try:
                logger.info("Initializing MITRE ATT&CK Engine...")
                
                # Download data if needed or stale
                for matrix in ATTACKMatrix:
                    file_path = self._get_matrix_file_path(matrix)
                    needs_download = (
                        force_download
                        or not file_path.exists()
                        or self._is_cache_stale(file_path)
                    )
                    
                    if needs_download:
                        logger.info(f"Downloading {matrix.value} matrix...")
                        success = await self._download_matrix_with_retry(matrix)
                        if not success:
                            logger.error(f"Failed to download {matrix.value} after retries")
                            # Continue with potentially stale data if available
                            if not file_path.exists():
                                raise RuntimeError(f"No data available for {matrix.value}")
                
                # Parse all matrices
                for matrix in ATTACKMatrix:
                    logger.info(f"Parsing {matrix.value} matrix...")
                    await self._parse_matrix(matrix)
                
                # Build relationship indexes (copy-on-write pattern)
                self._build_indexes()
                
                self._initialized = True
                self._last_updated = datetime.utcnow()
                
                logger.info(
                    f"MITRE ATT&CK Engine initialized: "
                    f"{len(self._techniques)} techniques, "
                    f"{len(self._sub_techniques)} sub-techniques, "
                    f"{len(self._groups)} groups, "
                    f"{len(self._software)} software entries"
                )
                
                return True
                
            except Exception as e:
                logger.error(f"Failed to initialize MITRE ATT&CK Engine: {e}")
                return False
            finally:
                self._initializing = False
    
    def _is_cache_stale(self, file_path: Path) -> bool:
        """Check if cached file is stale based on TTL."""
        if not file_path.exists():
            return True
        
        try:
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
            age = datetime.now() - mtime
            is_stale = age > self._cache_ttl
            
            if is_stale:
                logger.info(f"Cache stale for {file_path.name} (age: {age.days} days)")
            
            return is_stale
        except Exception as e:
            logger.warning(f"Error checking cache staleness: {e}")
            return True
    
    def _get_matrix_file_path(self, matrix: ATTACKMatrix) -> Path:
        """Get file path for a matrix with path traversal protection."""
        filename = f"{matrix.value}.json"
        file_path = (self.storage_path / filename).resolve()
        
        # Security: Ensure path doesn't escape storage directory
        if not str(file_path).startswith(str(self.storage_path)):
            raise ValueError(f"Invalid matrix path: attempted path traversal")
        
        return file_path
    
    async def _download_matrix_with_retry(self, matrix: ATTACKMatrix) -> bool:
        """Download matrix with exponential backoff retry.
        
        Args:
            matrix: The ATT&CK matrix to download
            
        Returns:
            True if download successful
        """
        url = self.STIX_URLS[matrix]
        file_path = self._get_matrix_file_path(matrix)
        
        for attempt in range(self.MAX_RETRY_ATTEMPTS):
            try:
                success = await self._download_matrix(matrix)
                if success:
                    return True
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 429:  # Rate limited
                    wait_time = int(e.response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited, waiting {wait_time}s")
                    await asyncio.sleep(wait_time)
                elif e.response.status_code >= 500:  # Server error
                    pass  # Will retry
                else:
                    raise  # Client error, don't retry
            except (httpx.TimeoutException, httpx.ConnectError) as e:
                logger.warning(f"Network error on attempt {attempt + 1}: {e}")
            
            if attempt < self.MAX_RETRY_ATTEMPTS - 1:
                # Exponential backoff with jitter (not security-sensitive)
                wait_time = (2 ** attempt) + random.uniform(0, 1)  # nosec B311
                logger.info(f"Retrying in {wait_time:.1f}s (attempt {attempt + 2}/{self.MAX_RETRY_ATTEMPTS})")
                await asyncio.sleep(wait_time)
        
        return False
    
    async def _download_matrix(self, matrix: ATTACKMatrix) -> bool:
        """Download a MITRE ATT&CK matrix.
        
        Uses injected HTTP client if available, otherwise creates one.
        Supports custom SSL verification for corporate proxy environments.
        """
        url = self.STIX_URLS[matrix]
        file_path = self._get_matrix_file_path(matrix)
        
        try:
            # Use injected client or create new one
            if self._http_client:
                client = self._http_client
                should_close = False
            else:
                client = httpx.AsyncClient(timeout=60.0, verify=self._verify_ssl)
                should_close = True
            
            try:
                response = await client.get(url)
                response.raise_for_status()
                
                # Atomic write: write to temp file, then rename
                temp_path = file_path.with_suffix('.tmp')
                with open(temp_path, 'w', encoding='utf-8') as f:
                    f.write(response.text)
                temp_path.rename(file_path)
                
                # Log relative path only for security
                logger.info(f"Downloaded {matrix.value} matrix ({len(response.text)} bytes)")
                return True
            finally:
                if should_close:
                    await client.aclose()
                
        except Exception as e:
            logger.error(f"Failed to download {matrix.value}: {type(e).__name__}")
            return False
    
    async def _parse_matrix(self, matrix: ATTACKMatrix) -> None:
        """Parse a MITRE ATT&CK matrix from STIX JSON."""
        file_path = self._get_matrix_file_path(matrix)
        
        if not file_path.exists():
            logger.warning(f"Matrix file not found: {file_path}")
            return
        
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Track STIX IDs for relationship resolution
        stix_id_map: Dict[str, Any] = {}
        relationships: List[Dict] = []
        
        # First pass: Parse all objects
        for obj in data.get('objects', []):
            obj_type = obj.get('type', '')
            stix_id = obj.get('id', '')
            
            if stix_id:
                stix_id_map[stix_id] = obj
            
            if obj_type == 'attack-pattern':
                self._parse_attack_pattern(obj, matrix)
            elif obj_type == 'course-of-action':
                self._parse_mitigation(obj)
            elif obj_type == 'intrusion-set':
                self._parse_group(obj)
            elif obj_type == 'malware' or obj_type == 'tool':
                self._parse_software(obj, obj_type)
            elif obj_type == 'campaign':
                self._parse_campaign(obj)
            elif obj_type == 'x-mitre-data-source':
                self._parse_data_source(obj)
            elif obj_type == 'relationship':
                relationships.append(obj)
        
        # Second pass: Resolve relationships
        self._resolve_relationships(relationships, stix_id_map)
    
    def _parse_attack_pattern(self, obj: Dict, matrix: ATTACKMatrix) -> None:
        """Parse an attack-pattern (technique) object."""
        # Skip revoked/deprecated
        if obj.get('revoked', False) or obj.get('x_mitre_deprecated', False):
            return
        
        # Extract technique ID
        technique_id = self._extract_external_id(obj, 'mitre-attack')
        if not technique_id:
            return
        
        # Check if sub-technique
        is_subtechnique = obj.get('x_mitre_is_subtechnique', False)
        parent_id = None
        
        if is_subtechnique and '.' in technique_id:
            parent_id = technique_id.rsplit('.', 1)[0]
        
        # Extract tactics
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
        
        # Create detection info
        detection = ATTACKDetection(
            data_sources=data_sources,
            data_components=[],
            detection_notes=obj.get('x_mitre_detection', ''),
            analytic_details=[]
        )
        
        technique = ATTACKTechnique(
            id=technique_id,
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            tactics=tactics,
            platforms=platforms,
            permissions_required=obj.get('x_mitre_permissions_required', []),
            effective_permissions=obj.get('x_mitre_effective_permissions', []),
            defense_bypassed=obj.get('x_mitre_defense_bypassed', []),
            data_sources=data_sources,
            detection=detection,
            is_subtechnique=is_subtechnique,
            parent_technique_id=parent_id,
            matrix=matrix,
            version=obj.get('x_mitre_version', ''),
            created=self._parse_datetime(obj.get('created')),
            modified=self._parse_datetime(obj.get('modified')),
            revoked=obj.get('revoked', False),
            deprecated=obj.get('x_mitre_deprecated', False),
        )
        
        if is_subtechnique:
            sub_tech = ATTACKSubTechnique(
                id=technique_id,
                name=technique.name,
                description=technique.description,
                parent_technique_id=parent_id or '',
                platforms=platforms,
                detection=detection,
            )
            self._sub_techniques[technique_id] = sub_tech
            if parent_id:
                self._parent_to_subtechniques[parent_id].append(technique_id)
        
        self._techniques[technique_id] = technique
    
    def _parse_mitigation(self, obj: Dict) -> None:
        """Parse a course-of-action (mitigation) object."""
        if obj.get('revoked', False) or obj.get('x_mitre_deprecated', False):
            return
        
        mitigation_id = self._extract_external_id(obj, 'mitre-attack')
        if not mitigation_id:
            return
        
        mitigation = ATTACKMitigation(
            id=mitigation_id,
            name=obj.get('name', ''),
            description=obj.get('description', ''),
        )
        self._mitigations[mitigation_id] = mitigation
    
    def _parse_group(self, obj: Dict) -> None:
        """Parse an intrusion-set (threat group) object."""
        if obj.get('revoked', False):
            return
        
        group_id = self._extract_external_id(obj, 'mitre-attack')
        if not group_id:
            return
        
        aliases = obj.get('aliases', [])
        if obj.get('name') and obj.get('name') not in aliases:
            aliases = [obj.get('name')] + aliases
        
        group = ATTACKGroup(
            id=group_id,
            name=obj.get('name', ''),
            aliases=aliases,
            description=obj.get('description', ''),
        )
        self._groups[group_id] = group
    
    def _parse_software(self, obj: Dict, software_type: str) -> None:
        """Parse a malware or tool object."""
        if obj.get('revoked', False):
            return
        
        software_id = self._extract_external_id(obj, 'mitre-attack')
        if not software_id:
            return
        
        software = ATTACKSoftware(
            id=software_id,
            name=obj.get('name', ''),
            type=software_type,
            description=obj.get('description', ''),
            platforms=obj.get('x_mitre_platforms', []),
            aliases=obj.get('x_mitre_aliases', []),
        )
        self._software[software_id] = software
    
    def _parse_campaign(self, obj: Dict) -> None:
        """Parse a campaign object."""
        if obj.get('revoked', False):
            return
        
        campaign_id = self._extract_external_id(obj, 'mitre-attack')
        if not campaign_id:
            return
        
        campaign = ATTACKCampaign(
            id=campaign_id,
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            first_seen=self._parse_datetime(obj.get('first_seen')),
            last_seen=self._parse_datetime(obj.get('last_seen')),
        )
        self._campaigns[campaign_id] = campaign
    
    def _parse_data_source(self, obj: Dict) -> None:
        """Parse a data source object."""
        ds_id = self._extract_external_id(obj, 'mitre-attack')
        if not ds_id:
            return
        
        # Extract components from x_mitre_data_source_ref relationships
        components = []
        
        data_source = ATTACKDataSource(
            id=ds_id,
            name=obj.get('name', ''),
            description=obj.get('description', ''),
            platforms=obj.get('x_mitre_platforms', []),
            collection_layers=obj.get('x_mitre_collection_layers', []),
            components=components,
        )
        self._data_sources[ds_id] = data_source
    
    def _resolve_relationships(
        self, 
        relationships: List[Dict], 
        stix_id_map: Dict[str, Any]
    ) -> None:
        """Resolve STIX relationships to link objects.
        
        Logs statistics about relationship resolution for data quality monitoring.
        """
        resolved_count = 0
        skipped_count = 0
        
        for rel in relationships:
            rel_type = rel.get('relationship_type', '')
            source_ref = rel.get('source_ref', '')
            target_ref = rel.get('target_ref', '')
            
            source_obj = stix_id_map.get(source_ref, {})
            target_obj = stix_id_map.get(target_ref, {})
            
            source_id = self._extract_external_id(source_obj, 'mitre-attack')
            target_id = self._extract_external_id(target_obj, 'mitre-attack')
            
            if not source_id or not target_id:
                skipped_count += 1
                logger.debug(
                    f"Skipping relationship: missing external ID "
                    f"(source_ref={source_ref[:20]}..., target_ref={target_ref[:20]}...)"
                )
                continue
            
            resolved_count += 1
            
            if rel_type == 'mitigates':
                # Mitigation -> Technique
                self._technique_to_mitigations[target_id].append(source_id)
                if source_id in self._mitigations:
                    self._mitigations[source_id].techniques_mitigated.append(target_id)
            
            elif rel_type == 'uses':
                # Group/Software -> Technique
                source_type = source_obj.get('type', '')
                
                if source_type == 'intrusion-set':
                    self._technique_to_groups[target_id].append(source_id)
                    if source_id in self._groups:
                        self._groups[source_id].techniques_used.append(target_id)
                    
                    # Create procedure example
                    description = rel.get('description', '')
                    if description:
                        procedure = ATTACKProcedure(
                            technique_id=target_id,
                            threat_actor=self._groups.get(source_id, ATTACKGroup(source_id, '', [], '')).name,
                            software=None,
                            description=description,
                        )
                        self._procedures.append(procedure)
                        if target_id in self._techniques:
                            self._techniques[target_id].procedures.append(procedure)
                
                elif source_type in ('malware', 'tool'):
                    self._technique_to_software[target_id].append(source_id)
                    if source_id in self._software:
                        self._software[source_id].techniques_used.append(target_id)
                    
                    # Create procedure example
                    description = rel.get('description', '')
                    if description:
                        procedure = ATTACKProcedure(
                            technique_id=target_id,
                            threat_actor=None,
                            software=self._software.get(source_id, ATTACKSoftware(source_id, '', '', '')).name,
                            description=description,
                        )
                        self._procedures.append(procedure)
                        if target_id in self._techniques:
                            self._techniques[target_id].procedures.append(procedure)
            
            elif rel_type == 'detects':
                # Data Component -> Technique
                self._technique_to_data_sources[target_id].append(source_id)
        
        # Log relationship resolution statistics
        logger.info(
            f"Relationship resolution: {resolved_count} resolved, "
            f"{skipped_count} skipped (missing external IDs)"
        )
    
    def _build_indexes(self) -> None:
        """Build lookup indexes for fast querying."""
        # Clear existing indexes
        self._tactic_to_techniques.clear()
        self._platform_to_techniques.clear()
        
        for tech_id, technique in self._techniques.items():
            # Skip sub-techniques for tactic index (they inherit from parent)
            if not technique.is_subtechnique:
                for tactic in technique.tactics:
                    self._tactic_to_techniques[tactic].append(tech_id)
            
            for platform in technique.platforms:
                self._platform_to_techniques[platform.lower()].append(tech_id)
            
            # Link sub-techniques to parent
            if tech_id in self._parent_to_subtechniques:
                technique.sub_techniques = [
                    self._sub_techniques[sub_id]
                    for sub_id in self._parent_to_subtechniques[tech_id]
                    if sub_id in self._sub_techniques
                ]
            
            # Link mitigations
            if tech_id in self._technique_to_mitigations:
                technique.mitigations = [
                    self._mitigations[mit_id]
                    for mit_id in self._technique_to_mitigations[tech_id]
                    if mit_id in self._mitigations
                ]
    
    def _extract_external_id(self, obj: Dict, source_name: str) -> Optional[str]:
        """Extract external ID from STIX object."""
        for ref in obj.get('external_references', []):
            if ref.get('source_name') == source_name:
                return ref.get('external_id')
        return None
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime string."""
        if not dt_str:
            return None
        try:
            # Handle STIX datetime format
            return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return None
    
    # ========================================================================
    # Input Validation Helpers
    # ========================================================================
    
    def _validate_technique_id(self, technique_id: str) -> bool:
        """Validate technique ID format.
        
        Args:
            technique_id: ID to validate (e.g., "T1566" or "T1566.001")
            
        Returns:
            True if valid format
        """
        if not technique_id or not isinstance(technique_id, str):
            return False
        return bool(TECHNIQUE_ID_PATTERN.match(technique_id))
    
    def _validate_mitigation_id(self, mitigation_id: str) -> bool:
        """Validate mitigation ID format."""
        if not mitigation_id or not isinstance(mitigation_id, str):
            return False
        return bool(MITIGATION_ID_PATTERN.match(mitigation_id))
    
    def _validate_group_id(self, group_id: str) -> bool:
        """Validate group ID format."""
        if not group_id or not isinstance(group_id, str):
            return False
        return bool(GROUP_ID_PATTERN.match(group_id))
    
    def _validate_software_id(self, software_id: str) -> bool:
        """Validate software ID format."""
        if not software_id or not isinstance(software_id, str):
            return False
        return bool(SOFTWARE_ID_PATTERN.match(software_id))
    
    # ========================================================================
    # Query Methods
    # ========================================================================
    
    def get_technique(self, technique_id: str) -> Optional[ATTACKTechnique]:
        """Get a technique by ID.
        
        Args:
            technique_id: Technique ID (e.g., "T1566" or "T1566.001")
            
        Returns:
            ATTACKTechnique or None if not found or invalid ID
        """
        if not self._validate_technique_id(technique_id):
            logger.warning(f"Invalid technique ID format: {technique_id}")
            return None
        return self._techniques.get(technique_id)
    
    def get_all_techniques(
        self,
        include_subtechniques: bool = True,
        matrix: Optional[ATTACKMatrix] = None
    ) -> List[ATTACKTechnique]:
        """Get all techniques.
        
        Args:
            include_subtechniques: Include sub-techniques in results
            matrix: Filter by specific matrix
            
        Returns:
            List of techniques
        """
        techniques = []
        for technique in self._techniques.values():
            if not include_subtechniques and technique.is_subtechnique:
                continue
            if matrix and technique.matrix != matrix:
                continue
            techniques.append(technique)
        return techniques
    
    def get_techniques_by_tactic(
        self,
        tactic: str,
        include_subtechniques: bool = False
    ) -> List[ATTACKTechnique]:
        """Get techniques for a specific tactic.
        
        Args:
            tactic: Tactic name (e.g., "initial-access")
            include_subtechniques: Include sub-techniques
            
        Returns:
            List of techniques for the tactic
        """
        technique_ids = self._tactic_to_techniques.get(tactic, [])
        techniques = [
            self._techniques[tid]
            for tid in technique_ids
            if tid in self._techniques
        ]
        
        if include_subtechniques:
            subtechniques = []
            for tech in techniques:
                subtechniques.extend(tech.sub_techniques)
            # Convert SubTechnique to Technique references
            for sub in subtechniques:
                if sub.id in self._techniques:
                    techniques.append(self._techniques[sub.id])
        
        return techniques
    
    def get_techniques_by_platform(
        self,
        platform: str,
        include_subtechniques: bool = True
    ) -> List[ATTACKTechnique]:
        """Get techniques for a specific platform.
        
        Args:
            platform: Platform name (e.g., "Windows", "Linux")
            include_subtechniques: Include sub-techniques
            
        Returns:
            List of techniques for the platform
        """
        technique_ids = self._platform_to_techniques.get(platform.lower(), [])
        techniques = [
            self._techniques[tid]
            for tid in technique_ids
            if tid in self._techniques and (include_subtechniques or not self._techniques[tid].is_subtechnique)
        ]
        return techniques
    
    def get_sub_techniques(self, parent_id: str) -> List[ATTACKSubTechnique]:
        """Get sub-techniques for a parent technique.
        
        Args:
            parent_id: Parent technique ID (e.g., "T1566")
            
        Returns:
            List of sub-techniques
        """
        # Validate parent ID (without sub-technique suffix)
        if not parent_id or not re.match(r'^T\d{4}$', parent_id):
            logger.warning(f"Invalid parent technique ID format: {parent_id}")
            return []
        
        sub_ids = self._parent_to_subtechniques.get(parent_id, [])
        return [
            self._sub_techniques[sub_id]
            for sub_id in sub_ids
            if sub_id in self._sub_techniques
        ]
    
    def get_mitigation(self, mitigation_id: str) -> Optional[ATTACKMitigation]:
        """Get a mitigation by ID."""
        if not self._validate_mitigation_id(mitigation_id):
            logger.warning(f"Invalid mitigation ID format: {mitigation_id}")
            return None
        return self._mitigations.get(mitigation_id)
    
    def get_mitigations_for_technique(
        self,
        technique_id: str
    ) -> List[ATTACKMitigation]:
        """Get mitigations for a technique.
        
        Args:
            technique_id: Technique ID
            
        Returns:
            List of mitigations
        """
        if not self._validate_technique_id(technique_id):
            logger.warning(f"Invalid technique ID format: {technique_id}")
            return []
        
        mitigation_ids = self._technique_to_mitigations.get(technique_id, [])
        return [
            self._mitigations[mid]
            for mid in mitigation_ids
            if mid in self._mitigations
        ]
    
    def get_group(self, group_id: str) -> Optional[ATTACKGroup]:
        """Get a threat group by ID."""
        if not self._validate_group_id(group_id):
            logger.warning(f"Invalid group ID format: {group_id}")
            return None
        return self._groups.get(group_id)
    
    def get_groups_using_technique(
        self,
        technique_id: str
    ) -> List[ATTACKGroup]:
        """Get threat groups that use a technique.
        
        Args:
            technique_id: Technique ID
            
        Returns:
            List of threat groups
        """
        if not self._validate_technique_id(technique_id):
            logger.warning(f"Invalid technique ID format: {technique_id}")
            return []
        
        group_ids = self._technique_to_groups.get(technique_id, [])
        return [
            self._groups[gid]
            for gid in group_ids
            if gid in self._groups
        ]
    
    def get_software(self, software_id: str) -> Optional[ATTACKSoftware]:
        """Get software by ID."""
        if not self._validate_software_id(software_id):
            logger.warning(f"Invalid software ID format: {software_id}")
            return None
        return self._software.get(software_id)
    
    def get_software_using_technique(
        self,
        technique_id: str
    ) -> List[ATTACKSoftware]:
        """Get software that uses a technique.
        
        Args:
            technique_id: Technique ID
            
        Returns:
            List of software (malware/tools)
        """
        software_ids = self._technique_to_software.get(technique_id, [])
        return [
            self._software[sid]
            for sid in software_ids
            if sid in self._software
        ]
    
    def get_procedures_for_technique(
        self,
        technique_id: str,
        limit: int = 10
    ) -> List[ATTACKProcedure]:
        """Get procedure examples for a technique.
        
        Args:
            technique_id: Technique ID
            limit: Maximum procedures to return
            
        Returns:
            List of procedure examples
        """
        technique = self._techniques.get(technique_id)
        if technique:
            return technique.procedures[:limit]
        return []
    
    def get_detection_recommendations(
        self,
        technique_id: str
    ) -> Dict[str, Any]:
        """Get detection recommendations for a technique.
        
        Args:
            technique_id: Technique ID
            
        Returns:
            Detection recommendations including data sources and analytics
        """
        technique = self._techniques.get(technique_id)
        if not technique:
            return {}
        
        recommendations = {
            "technique_id": technique_id,
            "technique_name": technique.name,
            "data_sources": technique.data_sources,
            "detection_notes": technique.detection.detection_notes if technique.detection else "",
            "recommended_data_sources": [],
            "detection_analytics": [],
        }
        
        # Add detailed data source info
        for ds_name in technique.data_sources:
            ds_info = {
                "name": ds_name,
                "description": "",
                "collection_guidance": self._get_collection_guidance(ds_name),
            }
            recommendations["recommended_data_sources"].append(ds_info)
        
        # Add detection analytics suggestions
        recommendations["detection_analytics"] = self._suggest_analytics(technique)
        
        return recommendations
    
    def _get_collection_guidance(self, data_source: str) -> str:
        """Get collection guidance for a data source."""
        guidance_map = {
            "Process": "Enable process creation auditing via Windows Security Event 4688 or Sysmon Event 1",
            "Command": "Enable command line logging in process events",
            "File": "Monitor file system changes with Windows Security Events or file integrity monitoring",
            "Network Traffic": "Deploy network monitoring at perimeter and internal segments",
            "Windows Registry": "Enable registry auditing via Windows Security Events",
            "User Account": "Enable account logon and management events",
            "Logon Session": "Monitor authentication logs and session creation",
            "Module": "Enable module load events via Sysmon Event 7",
            "Script": "Enable script block logging for PowerShell",
            "WMI": "Enable WMI event subscription monitoring",
        }
        
        for key, guidance in guidance_map.items():
            if key.lower() in data_source.lower():
                return guidance
        
        return "Implement appropriate logging and monitoring for this data source"
    
    def _suggest_analytics(self, technique: ATTACKTechnique) -> List[Dict[str, str]]:
        """Suggest detection analytics for a technique."""
        analytics = []
        
        # Based on technique characteristics, suggest analytics
        if "Process" in str(technique.data_sources):
            analytics.append({
                "name": "Suspicious Process Creation",
                "description": f"Monitor for processes associated with {technique.name}",
                "type": "threshold"
            })
        
        if "Network Traffic" in str(technique.data_sources):
            analytics.append({
                "name": "Anomalous Network Connections",
                "description": f"Detect unusual network patterns related to {technique.name}",
                "type": "anomaly"
            })
        
        if "Command" in str(technique.data_sources):
            analytics.append({
                "name": "Command Line Pattern Matching",
                "description": f"Match command patterns used in {technique.name}",
                "type": "signature"
            })
        
        return analytics
    
    def search_techniques(
        self,
        query: str,
        fields: Optional[List[str]] = None,
        limit: int = 20
    ) -> List[ATTACKTechnique]:
        """Search techniques by keyword.
        
        Args:
            query: Search query
            fields: Fields to search (default: name, description)
            limit: Maximum results
            
        Returns:
            List of matching techniques
        """
        if fields is None:
            fields = ['name', 'description']
        
        query_lower = query.lower()
        results = []
        
        for technique in self._techniques.values():
            score = 0
            
            if 'name' in fields and query_lower in technique.name.lower():
                score += 10
            if 'description' in fields and query_lower in technique.description.lower():
                score += 5
            if 'id' in fields and query_lower in technique.id.lower():
                score += 15
            
            if score > 0:
                results.append((score, technique))
        
        # Sort by score descending
        results.sort(key=lambda x: x[0], reverse=True)
        
        return [tech for _, tech in results[:limit]]
    
    # ========================================================================
    # Statistics and Coverage
    # ========================================================================
    
    def get_coverage_stats(self) -> Dict[str, Any]:
        """Get coverage statistics for the loaded data.
        
        Returns:
            Dictionary with coverage statistics
        """
        enterprise_techniques = [
            t for t in self._techniques.values()
            if t.matrix == ATTACKMatrix.ENTERPRISE and not t.is_subtechnique
        ]
        enterprise_subtechniques = [
            t for t in self._techniques.values()
            if t.matrix == ATTACKMatrix.ENTERPRISE and t.is_subtechnique
        ]
        
        mobile_techniques = [
            t for t in self._techniques.values()
            if t.matrix == ATTACKMatrix.MOBILE
        ]
        
        ics_techniques = [
            t for t in self._techniques.values()
            if t.matrix == ATTACKMatrix.ICS
        ]
        
        return {
            "total_techniques": len(self._techniques),
            "enterprise": {
                "techniques": len(enterprise_techniques),
                "sub_techniques": len(enterprise_subtechniques),
                "tactics_covered": len(set(
                    t for tech in enterprise_techniques for t in tech.tactics
                )),
            },
            "mobile": {
                "techniques": len(mobile_techniques),
            },
            "ics": {
                "techniques": len(ics_techniques),
            },
            "mitigations": len(self._mitigations),
            "threat_groups": len(self._groups),
            "software_entries": len(self._software),
            "campaigns": len(self._campaigns),
            "procedure_examples": len(self._procedures),
            "data_sources": len(self._data_sources),
            "tactics": list(self._tactic_to_techniques.keys()),
            "platforms": list(self._platform_to_techniques.keys()),
        }
    
    def get_tactic_coverage(self) -> Dict[str, Dict[str, Any]]:
        """Get technique coverage by tactic.
        
        Returns:
            Dictionary mapping tactics to their technique counts and details
        """
        coverage = {}
        
        for tactic in ENTERPRISE_TACTICS:
            techniques = self.get_techniques_by_tactic(tactic)
            sub_count = sum(len(t.sub_techniques) for t in techniques)
            
            coverage[tactic] = {
                "name": tactic.replace("-", " ").title(),
                "description": TACTIC_DESCRIPTIONS.get(tactic, ""),
                "technique_count": len(techniques),
                "subtechnique_count": sub_count,
                "techniques": [
                    {"id": t.id, "name": t.name}
                    for t in techniques[:10]  # Top 10
                ]
            }
        
        return coverage
    
    def export_to_json(self, output_path: Path) -> None:
        """Export all data to JSON file.
        
        Args:
            output_path: Path to output JSON file
        """
        export_data = {
            "version": self._version,
            "exported_at": datetime.utcnow().isoformat(),
            "statistics": self.get_coverage_stats(),
            "techniques": {
                tid: {
                    "id": t.id,
                    "name": t.name,
                    "description": t.description[:500] if t.description else "",
                    "tactics": t.tactics,
                    "platforms": t.platforms,
                    "is_subtechnique": t.is_subtechnique,
                    "parent_id": t.parent_technique_id,
                    "sub_technique_count": len(t.sub_techniques),
                    "mitigation_count": len(t.mitigations),
                    "procedure_count": len(t.procedures),
                }
                for tid, t in self._techniques.items()
            },
            "mitigations": {
                mid: {
                    "id": m.id,
                    "name": m.name,
                    "techniques_mitigated": m.techniques_mitigated[:10],
                }
                for mid, m in self._mitigations.items()
            },
            "groups": {
                gid: {
                    "id": g.id,
                    "name": g.name,
                    "aliases": g.aliases[:5],
                    "technique_count": len(g.techniques_used),
                }
                for gid, g in self._groups.items()
            },
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Exported MITRE ATT&CK data to {output_path}")


# ============================================================================
# Factory Function
# ============================================================================


async def create_mitre_attack_engine(
    storage_path: Optional[Path] = None,
    force_download: bool = False
) -> MITREATTACKEngine:
    """Factory function to create and initialize MITRE ATT&CK Engine.
    
    Args:
        storage_path: Path to store data (default: data/mitre)
        force_download: Force re-download of MITRE data
        
    Returns:
        Initialized MITREATTACKEngine
        
    Example:
        engine = await create_mitre_attack_engine()
        techniques = engine.get_techniques_by_tactic("initial-access")
    """
    if storage_path is None:
        storage_path = Path("data/mitre")
    
    engine = MITREATTACKEngine(storage_path)
    await engine.initialize(force_download=force_download)
    
    return engine
