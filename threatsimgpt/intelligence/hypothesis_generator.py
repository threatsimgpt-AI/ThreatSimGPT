"""
Intelligence-Based Hypothesis Generator

This module provides hypothesis generation capabilities for automated threat hunting
by leveraging threat intelligence, MITRE ATT&CK data, and historical patterns.

Author: David Onoja (@ocheme1107)
Purpose: Generate data-driven hunting hypotheses from multiple intelligence sources
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import re
import hashlib

from .mitre_attack import MITREAttackEngine
from .services import ThreatIntelligenceServices
from ..analytics.detection_rules import DetectionRuleGenerator
from ..core.event_sourcing import EventStore

logger = logging.getLogger(__name__)


class HypothesisType(Enum):
    """Types of hunting hypotheses"""
    TECHNIQUE_BASED = "technique_based"
    IOC_BASED = "ioc_based"
    BEHAVIORAL = "behavioral"
    VULNERABILITY_BASED = "vulnerability_based"
    THREAT_ACTOR_BASED = "threat_actor_based"
    ANOMALY_BASED = "anomaly_based"


class HypothesisPriority(Enum):
    """Priority levels for hypotheses"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DataSource(Enum):
    """Data sources for hunting"""
    WINDOWS_EVENT_LOGS = "windows_event_logs"
    SYSMON = "sysmon"
    NETWORK_TRAFFIC = "network_traffic"
    EDR_TELEMETRY = "edr_telemetry"
    CLOUD_LOGS = "cloud_logs"
    DNS_LOGS = "dns_logs"
    FIREWALL_LOGS = "firewall_logs"


@dataclass
class HuntingHypothesis:
    """Represents a hunting hypothesis"""
    id: str
    title: str
    description: str
    hypothesis_type: HypothesisType
    priority: HypothesisPriority
    data_sources: List[DataSource]
    query_templates: List[str]
    mitre_techniques: List[str]
    indicators: List[str]
    confidence_score: float
    created_at: datetime
    expires_at: Optional[datetime]
    tags: List[str]
    metadata: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert hypothesis to dictionary"""
        data = asdict(self)
        data['hypothesis_type'] = self.hypothesis_type.value
        data['priority'] = self.priority.value
        data['data_sources'] = [ds.value for ds in self.data_sources]
        data['created_at'] = self.created_at.isoformat()
        if self.expires_at:
            data['expires_at'] = self.expires_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HuntingHypothesis':
        """Create hypothesis from dictionary"""
        data['hypothesis_type'] = HypothesisType(data['hypothesis_type'])
        data['priority'] = HypothesisPriority(data['priority'])
        data['data_sources'] = [DataSource(ds) for ds in data['data_sources']]
        data['created_at'] = datetime.fromisoformat(data['created_at'])
        if data.get('expires_at'):
            data['expires_at'] = datetime.fromisoformat(data['expires_at'])
        return cls(**data)


@dataclass
class HypothesisGenerationRequest:
    """Request for hypothesis generation"""
    request_id: str
    hypothesis_types: List[HypothesisType]
    data_sources: List[DataSource]
    time_range: Tuple[datetime, datetime]
    priority_threshold: HypothesisPriority
    max_hypotheses: int
    context: Dict[str, Any]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert request to dictionary"""
        data = asdict(self)
        data['hypothesis_types'] = [ht.value for ht in self.hypothesis_types]
        data['data_sources'] = [ds.value for ds in self.data_sources]
        data['priority_threshold'] = self.priority_threshold.value
        data['time_range'] = {
            'start': self.time_range[0].isoformat(),
            'end': self.time_range[1].isoformat()
        }
        return data


class IntelligenceHypothesisEngine:
    """Intelligence-driven hypothesis generation engine"""
    
    def __init__(self):
        self.mitre_engine = MITREAttackEngine()
        self.threat_intel = ThreatIntelligenceServices()
        self.detection_rules = DetectionRuleGenerator()
        self.event_store = EventStore()
        
        # Hypothesis generation parameters
        self.confidence_threshold = 0.6
        self.max_indicators_per_hypothesis = 50
        self.default_hypothesis_ttl = timedelta(days=30)
        
        # Learning parameters
        self.success_history = {}
        self.pattern_weights = {}
        
        logger.info("IntelligenceHypothesisEngine initialized")
    
    async def generate_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hunting hypotheses based on intelligence data"""
        logger.info(f"Generating hypotheses for request {request.request_id}")
        
        hypotheses = []
        
        # Generate technique-based hypotheses
        if HypothesisType.TECHNIQUE_BASED in request.hypothesis_types:
            technique_hypotheses = await self._generate_technique_based_hypotheses(request)
            hypotheses.extend(technique_hypotheses)
        
        # Generate IOC-based hypotheses
        if HypothesisType.IOC_BASED in request.hypothesis_types:
            ioc_hypotheses = await self._generate_ioc_based_hypotheses(request)
            hypotheses.extend(ioc_hypotheses)
        
        # Generate behavioral hypotheses
        if HypothesisType.BEHAVIORAL in request.hypothesis_types:
            behavioral_hypotheses = await self._generate_behavioral_hypotheses(request)
            hypotheses.extend(behavioral_hypotheses)
        
        # Generate vulnerability-based hypotheses
        if HypothesisType.VULNERABILITY_BASED in request.hypothesis_types:
            vuln_hypotheses = await self._generate_vulnerability_based_hypotheses(request)
            hypotheses.extend(vuln_hypotheses)
        
        # Generate threat actor-based hypotheses
        if HypothesisType.THREAT_ACTOR_BASED in request.hypothesis_types:
            actor_hypotheses = await self._generate_threat_actor_based_hypotheses(request)
            hypotheses.extend(actor_hypotheses)
        
        # Generate anomaly-based hypotheses
        if HypothesisType.ANOMALY_BASED in request.hypothesis_types:
            anomaly_hypotheses = await self._generate_anomaly_based_hypotheses(request)
            hypotheses.extend(anomaly_hypotheses)
        
        # Filter and prioritize hypotheses
        filtered_hypotheses = self._filter_hypotheses(hypotheses, request)
        prioritized_hypotheses = self._prioritize_hypotheses(filtered_hypotheses)
        
        # Limit to maximum hypotheses
        final_hypotheses = prioritized_hypotheses[:request.max_hypotheses]
        
        logger.info(f"Generated {len(final_hypotheses)} hypotheses for request {request.request_id}")
        return final_hypotheses
    
    async def _generate_technique_based_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on MITRE ATT&CK techniques"""
        hypotheses = []
        
        try:
            # Get relevant techniques from MITRE ATT&CK
            techniques = await self.mitre_engine.get_all_techniques()
            
            # Filter techniques based on data sources and context
            relevant_techniques = self._filter_techniques_by_context(techniques, request)
            
            for technique in relevant_techniques[:20]:  # Limit to top 20 techniques
                hypothesis = await self._create_technique_hypothesis(technique, request)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating technique-based hypotheses: {e}")
        
        return hypotheses
    
    async def _generate_ioc_based_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on indicators of compromise"""
        hypotheses = []
        
        try:
            # Get recent threat intelligence
            intel_data = await self.threat_intel.get_recent_intelligence(days=7)
            
            # Extract IOCs from intelligence
            iocs = self._extract_iocs_from_intelligence(intel_data)
            
            # Group IOCs by type and create hypotheses
            ioc_groups = self._group_iocs_by_type(iocs)
            
            for ioc_type, ioc_list in ioc_groups.items():
                if len(ioc_list) >= 3:  # Only create hypotheses with sufficient IOCs
                    hypothesis = await self._create_ioc_hypothesis(ioc_type, ioc_list, request)
                    if hypothesis:
                        hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating IOC-based hypotheses: {e}")
        
        return hypotheses
    
    async def _generate_behavioral_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on behavioral patterns"""
        hypotheses = []
        
        try:
            # Get historical patterns and anomalies
            historical_data = await self._get_historical_patterns(request.time_range)
            
            # Identify anomalous patterns
            anomalies = self._identify_anomalies(historical_data)
            
            # Create hypotheses for significant anomalies
            for anomaly in anomalies:
                hypothesis = await self._create_behavioral_hypothesis(anomaly, request)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating behavioral hypotheses: {e}")
        
        return hypotheses
    
    async def _generate_vulnerability_based_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on recent vulnerabilities"""
        hypotheses = []
        
        try:
            # Get recent CVEs and exploit data
            recent_cves = await self._get_recent_vulnerabilities(days=30)
            
            # Filter for critical/high severity vulnerabilities
            critical_cves = [cve for cve in recent_cves if cve.get('severity', 'LOW') in ['CRITICAL', 'HIGH']]
            
            # Create hypotheses for exploitable vulnerabilities
            for cve in critical_cves[:10]:  # Limit to top 10 CVEs
                hypothesis = await self._create_vulnerability_hypothesis(cve, request)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating vulnerability-based hypotheses: {e}")
        
        return hypotheses
    
    async def _generate_threat_actor_based_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on threat actor TTPs"""
        hypotheses = []
        
        try:
            # Get active threat actor intelligence
            threat_actors = await self._get_active_threat_actors()
            
            # Generate hypotheses for high-profile actors
            for actor in threat_actors[:5]:  # Limit to top 5 actors
                hypothesis = await self._create_threat_actor_hypothesis(actor, request)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating threat actor-based hypotheses: {e}")
        
        return hypotheses
    
    async def _generate_anomaly_based_hypotheses(self, request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Generate hypotheses based on statistical anomalies"""
        hypotheses = []
        
        try:
            # Get baseline metrics and identify anomalies
            baseline_metrics = await self._get_baseline_metrics(request.time_range)
            anomalies = self._detect_statistical_anomalies(baseline_metrics)
            
            # Create hypotheses for significant anomalies
            for anomaly in anomalies:
                hypothesis = await self._create_anomaly_hypothesis(anomaly, request)
                if hypothesis:
                    hypotheses.append(hypothesis)
        
        except Exception as e:
            logger.error(f"Error generating anomaly-based hypotheses: {e}")
        
        return hypotheses
    
    def _filter_techniques_by_context(self, techniques: List[Dict], request: HypothesisGenerationRequest) -> List[Dict]:
        """Filter techniques based on request context and data sources"""
        relevant_techniques = []
        
        for technique in techniques:
            # Check if technique is relevant to available data sources
            if self._is_technique_relevant_to_sources(technique, request.data_sources):
                # Check if technique matches context
                if self._matches_context(technique, request.context):
                    relevant_techniques.append(technique)
        
        return relevant_techniques
    
    def _is_technique_relevant_to_sources(self, technique: Dict, data_sources: List[DataSource]) -> bool:
        """Check if technique can be detected with available data sources"""
        technique_data_sources = technique.get('data_sources', [])
        
        # Map technique data sources to available sources
        source_mapping = {
            'Windows Event Logs': DataSource.WINDOWS_EVENT_LOGS,
            'Sysmon': DataSource.SYSMON,
            'Network Traffic': DataSource.NETWORK_TRAFFIC,
            'EDR': DataSource.EDR_TELEMETRY,
            'Cloud Logs': DataSource.CLOUD_LOGS,
            'DNS': DataSource.DNS_LOGS,
            'Firewall': DataSource.FIREWALL_LOGS,
        }
        
        for tech_source in technique_data_sources:
            if source_mapping.get(tech_source) in data_sources:
                return True
        
        return False
    
    def _matches_context(self, technique: Dict, context: Dict[str, Any]) -> bool:
        """Check if technique matches the provided context"""
        # Check platform relevance
        if 'platforms' in context:
            technique_platforms = technique.get('platforms', [])
            if not any(platform in technique_platforms for platform in context['platforms']):
                return False
        
        # Check industry relevance
        if 'industry' in context:
            technique_industries = technique.get('industries', [])
            if technique_industries and context['industry'] not in technique_industries:
                return False
        
        return True
    
    async def _create_technique_hypothesis(self, technique: Dict, request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create a hypothesis for a specific MITRE technique"""
        try:
            technique_id = technique.get('technique_id', '')
            technique_name = technique.get('name', 'Unknown Technique')
            description = technique.get('description', '')
            
            # Generate query templates for this technique
            query_templates = await self._generate_technique_queries(technique, request.data_sources)
            
            # Calculate confidence score
            confidence = self._calculate_technique_confidence(technique, request)
            
            if confidence < self.confidence_threshold:
                return None
            
            # Create hypothesis
            hypothesis_id = self._generate_hypothesis_id(technique_id, request.request_id)
            
            hypothesis = HuntingHypothesis(
                id=hypothesis_id,
                title=f"Hunt for {technique_name} ({technique_id})",
                description=f"Detect potential {technique_name} activity based on MITRE ATT&CK {technique_id}",
                hypothesis_type=HypothesisType.TECHNIQUE_BASED,
                priority=self._determine_priority(confidence),
                data_sources=request.data_sources,
                query_templates=query_templates,
                mitre_techniques=[technique_id],
                indicators=self._extract_technique_indicators(technique),
                confidence_score=confidence,
                created_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + self.default_hypothesis_ttl,
                tags=[technique_id, 'technique_based', 'mitre_attack'],
                metadata={
                    'technique_data': technique,
                    'generation_method': 'technique_based',
                    'request_id': request.request_id
                }
            )
            
            return hypothesis
        
        except Exception as e:
            logger.error(f"Error creating technique hypothesis: {e}")
            return None
    
    def _generate_hypothesis_id(self, technique_id: str, request_id: str) -> str:
        """Generate unique hypothesis ID"""
        timestamp = datetime.utcnow().isoformat()
        content = f"{technique_id}_{request_id}_{timestamp}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _determine_priority(self, confidence: float) -> HypothesisPriority:
        """Determine hypothesis priority based on confidence score"""
        if confidence >= 0.9:
            return HypothesisPriority.CRITICAL
        elif confidence >= 0.7:
            return HypothesisPriority.HIGH
        elif confidence >= 0.5:
            return HypothesisPriority.MEDIUM
        else:
            return HypothesisPriority.LOW
    
    def _calculate_technique_confidence(self, technique: Dict, request: HypothesisGenerationRequest) -> float:
        """Calculate confidence score for technique-based hypothesis"""
        confidence = 0.5  # Base confidence
        
        # Boost confidence based on technique prevalence
        if technique.get('prevalence', 'low') == 'high':
            confidence += 0.2
        elif technique.get('prevalence', 'low') == 'medium':
            confidence += 0.1
        
        # Boost confidence based on recent activity
        if technique.get('recent_activity', False):
            confidence += 0.15
        
        # Boost confidence based on detection capability
        if technique.get('detection_capability', 'low') == 'high':
            confidence += 0.1
        
        # Apply learning from previous success
        technique_id = technique.get('technique_id', '')
        if technique_id in self.success_history:
            success_rate = self.success_history[technique_id]
            confidence += success_rate * 0.1
        
        return min(confidence, 1.0)
    
    def _filter_hypotheses(self, hypotheses: List[HuntingHypothesis], request: HypothesisGenerationRequest) -> List[HuntingHypothesis]:
        """Filter hypotheses based on request criteria"""
        filtered = []
        
        for hypothesis in hypotheses:
            # Filter by priority threshold
            priority_order = {
                HypothesisPriority.CRITICAL: 4,
                HypothesisPriority.HIGH: 3,
                HypothesisPriority.MEDIUM: 2,
                HypothesisPriority.LOW: 1
            }
            
            threshold_order = priority_order[request.priority_threshold]
            hypothesis_order = priority_order[hypothesis.priority]
            
            if hypothesis_order >= threshold_order:
                filtered.append(hypothesis)
        
        return filtered
    
    def _prioritize_hypotheses(self, hypotheses: List[HuntingHypothesis]) -> List[HuntingHypothesis]:
        """Prioritize hypotheses by confidence and priority"""
        def sort_key(hypothesis):
            priority_order = {
                HypothesisPriority.CRITICAL: 4,
                HypothesisPriority.HIGH: 3,
                HypothesisPriority.MEDIUM: 2,
                HypothesisPriority.LOW: 1
            }
            return (priority_order[hypothesis.priority], hypothesis.confidence_score)
        
        return sorted(hypotheses, key=sort_key, reverse=True)
    
    async def _generate_technique_queries(self, technique: Dict, data_sources: List[DataSource]) -> List[str]:
        """Generate query templates for a technique"""
        queries = []
        technique_id = technique.get('technique_id', '')
        
        # Generate queries based on data sources
        for data_source in data_sources:
            if data_source == DataSource.WINDOWS_EVENT_LOGS:
                queries.extend(self._generate_windows_queries(technique))
            elif data_source == DataSource.SYSMON:
                queries.extend(self._generate_sysmon_queries(technique))
            elif data_source == DataSource.NETWORK_TRAFFIC:
                queries.extend(self._generate_network_queries(technique))
            elif data_source == DataSource.EDR_TELEMETRY:
                queries.extend(self._generate_edr_queries(technique))
        
        return queries
    
    def _generate_windows_queries(self, technique: Dict) -> List[str]:
        """Generate Windows Event Log queries for technique"""
        queries = []
        technique_id = technique.get('technique_id', '')
        
        # Common Windows Event Log query patterns
        if technique_id.startswith('T1055'):  # Process injection
            queries.append(
                "EventID=4688 AND (CommandLine LIKE '%-inject%' OR CommandLine LIKE '%-load%')"
            )
        elif technique_id.startswith('T1053'):  # Scheduled tasks
            queries.append(
                "EventID=4698 AND (TaskName LIKE '%\\%' OR Author LIKE '%Administrator%')"
            )
        elif technique_id.startswith('T1068'):  # Exploitation for privilege escalation
            queries.append(
                "EventID=4672 AND (PrivilegeList LIKE '%SeDebugPrivilege%' OR PrivilegeList LIKE '%SeTakeOwnershipPrivilege%')"
            )
        
        return queries
    
    def _generate_sysmon_queries(self, technique: Dict) -> List[str]:
        """Generate Sysmon queries for technique"""
        queries = []
        technique_id = technique.get('technique_id', '')
        
        if technique_id.startswith('T1055'):  # Process injection
            queries.append(
                "EventID=7 AND (ImageLoaded LIKE '%*.dll' AND NOT ImageLoaded LIKE '%System32%')"
            )
        elif technique_id.startswith('T1056'):  # Input capture
            queries.append(
                "EventID=10 AND (TargetImage LIKE '*keyboard*' OR TargetImage LIKE '*mouse*')"
            )
        elif technique_id.startswith('T1083'):  # File and directory discovery
            queries.append(
                "EventID=11 AND (Operation='CreateFile' AND FileName LIKE '%\\Users\\%')"
            )
        
        return queries
    
    def _generate_network_queries(self, technique: Dict) -> List[str]:
        """Generate network traffic queries for technique"""
        queries = []
        technique_id = technique.get('technique_id', '')
        
        if technique_id.startswith('T1021'):  # Remote services
            queries.append(
                "DestinationPort IN (445, 3389, 22, 5985) AND BytesSent > 1000"
            )
        elif technique_id.startswith('T1071'):  # Application layer protocol
            queries.append(
                "Protocol IN (HTTP, HTTPS) AND UserAgent LIKE '*curl*' OR UserAgent LIKE '*wget*'"
            )
        elif technique_id.startswith('T1041'):  # Exfiltration over C2 channel
            queries.append(
                "DestinationPort IN (443, 80) AND Duration > 300 AND BytesReceived > 1000000"
            )
        
        return queries
    
    def _generate_edr_queries(self, technique: Dict) -> List[str]:
        """Generate EDR telemetry queries for technique"""
        queries = []
        technique_id = technique.get('technique_id', '')
        
        # EDR-specific query patterns
        if technique_id.startswith('T1055'):  # Process injection
            queries.append(
                "ProcessType='injection' AND ParentProcessName NOT LIKE '%System32%'"
            )
        elif technique_id.startswith('T1566'):  # Phishing
            queries.append(
                "EventType='email' AND (Subject LIKE '%urgent%' OR Subject LIKE '%account%')"
            )
        elif technique_id.startswith('T1486'):  # Data encrypted for impact
            queries.append(
                "EventType='file_encryption' AND FileExtension IN ('.locked', '.crypt', '.enc')"
            )
        
        return queries
    
    def _extract_technique_indicators(self, technique: Dict) -> List[str]:
        """Extract indicators from technique data"""
        indicators = []
        
        # Add technique ID as primary indicator
        technique_id = technique.get('technique_id', '')
        if technique_id:
            indicators.append(technique_id)
        
        # Add common file names, paths, or patterns
        if 'indicators' in technique:
            indicators.extend(technique['indicators'])
        
        # Add process names if available
        if 'processes' in technique:
            indicators.extend(technique['processes'])
        
        return indicators[:self.max_indicators_per_hypothesis]
    
    # Placeholder methods for other hypothesis types
    async def _get_historical_patterns(self, time_range: Tuple[datetime, datetime]) -> Dict:
        """Get historical patterns for behavioral analysis"""
        # This would integrate with event store and analytics
        return {}
    
    def _identify_anomalies(self, historical_data: Dict) -> List[Dict]:
        """Identify anomalies in historical data"""
        # Implement anomaly detection logic
        return []
    
    async def _create_behavioral_hypothesis(self, anomaly: Dict, request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create behavioral hypothesis from anomaly"""
        # Implement behavioral hypothesis creation
        return None
    
    def _extract_iocs_from_intelligence(self, intel_data: Dict) -> List[str]:
        """Extract IOCs from threat intelligence data"""
        iocs = []
        
        # Extract various IOC types
        if 'indicators' in intel_data:
            iocs.extend(intel_data['indicators'])
        
        if 'domains' in intel_data:
            iocs.extend(intel_data['domains'])
        
        if 'ips' in intel_data:
            iocs.extend(intel_data['ips'])
        
        if 'hashes' in intel_data:
            iocs.extend(intel_data['hashes'])
        
        return iocs
    
    def _group_iocs_by_type(self, iocs: List[str]) -> Dict[str, List[str]]:
        """Group IOCs by type for hypothesis generation"""
        grouped = {
            'domains': [],
            'ips': [],
            'hashes': [],
            'urls': []
        }
        
        for ioc in iocs:
            if self._is_domain(ioc):
                grouped['domains'].append(ioc)
            elif self._is_ip(ioc):
                grouped['ips'].append(ioc)
            elif self._is_hash(ioc):
                grouped['hashes'].append(ioc)
            elif self._is_url(ioc):
                grouped['urls'].append(ioc)
        
        return grouped
    
    def _is_domain(self, ioc: str) -> bool:
        """Check if IOC is a domain name"""
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, ioc)) and '.' in ioc
    
    def _is_ip(self, ioc: str) -> bool:
        """Check if IOC is an IP address"""
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        return bool(re.match(ip_pattern, ioc))
    
    def _is_hash(self, ioc: str) -> bool:
        """Check if IOC is a hash"""
        hash_patterns = [
            r'^[a-fA-F0-9]{32}$',  # MD5
            r'^[a-fA-F0-9]{40}$',  # SHA1
            r'^[a-fA-F0-9]{64}$',  # SHA256
        ]
        return any(bool(re.match(pattern, ioc)) for pattern in hash_patterns)
    
    def _is_url(self, ioc: str) -> bool:
        """Check if IOC is a URL"""
        url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
        return bool(re.match(url_pattern, ioc))
    
    async def _create_ioc_hypothesis(self, ioc_type: str, ioc_list: List[str], request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create IOC-based hypothesis"""
        # Implement IOC hypothesis creation
        return None
    
    async def _get_recent_vulnerabilities(self, days: int) -> List[Dict]:
        """Get recent CVEs and vulnerability data"""
        # This would integrate with vulnerability intelligence feeds
        return []
    
    async def _create_vulnerability_hypothesis(self, cve: Dict, request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create vulnerability-based hypothesis"""
        # Implement vulnerability hypothesis creation
        return None
    
    async def _get_active_threat_actors(self) -> List[Dict]:
        """Get active threat actor intelligence"""
        # This would integrate with threat actor databases
        return []
    
    async def _create_threat_actor_hypothesis(self, actor: Dict, request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create threat actor-based hypothesis"""
        # Implement threat actor hypothesis creation
        return None
    
    async def _get_baseline_metrics(self, time_range: Tuple[datetime, datetime]) -> Dict:
        """Get baseline metrics for anomaly detection"""
        # This would integrate with analytics engine
        return {}
    
    def _detect_statistical_anomalies(self, baseline_metrics: Dict) -> List[Dict]:
        """Detect statistical anomalies in baseline metrics"""
        # Implement statistical anomaly detection
        return []
    
    async def _create_anomaly_hypothesis(self, anomaly: Dict, request: HypothesisGenerationRequest) -> Optional[HuntingHypothesis]:
        """Create anomaly-based hypothesis"""
        # Implement anomaly hypothesis creation
        return None
    
    async def update_hypothesis_success(self, hypothesis_id: str, success: bool, results: Dict):
        """Update hypothesis success history for learning"""
        # Update success history for learning
        if hypothesis_id not in self.success_history:
            self.success_history[hypothesis_id] = 0.0
        
        # Apply exponential moving average
        alpha = 0.3  # Learning rate
        current_success = 1.0 if success else 0.0
        self.success_history[hypothesis_id] = (
            alpha * current_success + 
            (1 - alpha) * self.success_history[hypothesis_id]
        )
        
        logger.info(f"Updated hypothesis {hypothesis_id} success rate: {self.success_history[hypothesis_id]:.2f}")
    
    async def get_hypothesis_performance_metrics(self) -> Dict[str, Any]:
        """Get performance metrics for hypothesis generation"""
        return {
            'total_hypotheses_generated': len(self.success_history),
            'average_success_rate': sum(self.success_history.values()) / len(self.success_history) if self.success_history else 0.0,
            'top_performing_hypotheses': sorted(self.success_history.items(), key=lambda x: x[1], reverse=True)[:10],
            'underperforming_hypotheses': sorted(self.success_history.items(), key=lambda x: x[1])[:10],
        }
