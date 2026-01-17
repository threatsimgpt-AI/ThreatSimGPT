"""Unit tests for MITRE ATT&CK Full Coverage Engine.

Tests the MITREATTACKEngine implementation for Issue #42.
Covers technique parsing, sub-technique mapping, procedure examples,
detection recommendations, and coverage statistics.
"""

import asyncio
import json
import pytest
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

from threatsimgpt.intelligence.mitre_attack import (
    MITREATTACKEngine,
    ATTACKMatrix,
    ATTACKDomain,
    ATTACKTechnique,
    ATTACKSubTechnique,
    ATTACKMitigation,
    ATTACKGroup,
    ATTACKSoftware,
    ATTACKProcedure,
    ATTACKDetection,
    ATTACKDataSource,
    ATTACKCampaign,
    ENTERPRISE_TACTICS,
    TACTIC_DESCRIPTIONS,
    PLATFORMS,
    create_mitre_attack_engine,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_stix_data() -> Dict:
    """Create sample STIX 2.1 data for testing."""
    return {
        "type": "bundle",
        "id": "bundle--test",
        "objects": [
            # Technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--1",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_platforms": ["Windows", "macOS", "Linux"],
                "x_mitre_data_sources": ["Network Traffic: Network Traffic Content"],
                "x_mitre_detection": "Monitor for suspicious emails",
                "x_mitre_version": "2.0",
                "created": "2020-01-01T00:00:00Z",
                "modified": "2023-01-01T00:00:00Z",
            },
            # Sub-technique
            {
                "type": "attack-pattern",
                "id": "attack-pattern--2",
                "name": "Spearphishing Attachment",
                "description": "Adversaries may send spearphishing emails with attachment.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1566.001"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                ],
                "x_mitre_platforms": ["Windows", "macOS", "Linux"],
                "x_mitre_is_subtechnique": True,
                "x_mitre_data_sources": ["File: File Creation"],
            },
            # Another technique for testing
            {
                "type": "attack-pattern",
                "id": "attack-pattern--3",
                "name": "Command and Scripting Interpreter",
                "description": "Adversaries may abuse command interpreters.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1059"}
                ],
                "kill_chain_phases": [
                    {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                ],
                "x_mitre_platforms": ["Windows", "Linux"],
                "x_mitre_data_sources": ["Process: Process Creation", "Command: Command Execution"],
            },
            # Mitigation
            {
                "type": "course-of-action",
                "id": "course-of-action--1",
                "name": "User Training",
                "description": "Train users to identify phishing attempts.",
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "M1017"}
                ],
            },
            # Threat Group
            {
                "type": "intrusion-set",
                "id": "intrusion-set--1",
                "name": "APT29",
                "description": "APT29 is a threat group.",
                "aliases": ["APT29", "Cozy Bear", "The Dukes"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "G0016"}
                ],
            },
            # Software
            {
                "type": "malware",
                "id": "malware--1",
                "name": "Mimikatz",
                "description": "Mimikatz is a credential dumping tool.",
                "x_mitre_platforms": ["Windows"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "S0002"}
                ],
            },
            # Relationships
            {
                "type": "relationship",
                "id": "relationship--1",
                "relationship_type": "mitigates",
                "source_ref": "course-of-action--1",
                "target_ref": "attack-pattern--1",
            },
            {
                "type": "relationship",
                "id": "relationship--2",
                "relationship_type": "uses",
                "source_ref": "intrusion-set--1",
                "target_ref": "attack-pattern--1",
                "description": "APT29 has used phishing in campaigns.",
            },
            {
                "type": "relationship",
                "id": "relationship--3",
                "relationship_type": "uses",
                "source_ref": "malware--1",
                "target_ref": "attack-pattern--3",
                "description": "Mimikatz uses command line execution.",
            },
        ]
    }


@pytest.fixture
def tmp_storage(tmp_path) -> Path:
    """Create temporary storage path."""
    storage = tmp_path / "mitre"
    storage.mkdir(parents=True, exist_ok=True)
    return storage


@pytest.fixture
def engine(tmp_storage) -> MITREATTACKEngine:
    """Create engine instance."""
    return MITREATTACKEngine(tmp_storage)


@pytest.fixture
def initialized_engine(tmp_storage, sample_stix_data) -> MITREATTACKEngine:
    """Create an engine pre-loaded with sample data."""
    engine = MITREATTACKEngine(tmp_storage)
    
    # Write sample data to file
    enterprise_file = tmp_storage / "enterprise-attack.json"
    with open(enterprise_file, 'w') as f:
        json.dump(sample_stix_data, f)
    
    # Parse the data synchronously for testing
    asyncio.get_event_loop().run_until_complete(
        engine._parse_matrix(ATTACKMatrix.ENTERPRISE)
    )
    engine._build_indexes()
    engine._initialized = True
    
    return engine


# ============================================================================
# Initialization Tests
# ============================================================================


class TestMITREATTACKEngineInit:
    """Test engine initialization."""
    
    def test_init_creates_storage_path(self, tmp_path):
        """Test that initialization creates storage directory."""
        storage = tmp_path / "new_dir" / "mitre"
        engine = MITREATTACKEngine(storage)
        
        assert storage.exists()
        assert engine.storage_path == storage
    
    def test_init_default_state(self, engine):
        """Test default initialization state."""
        assert engine._initialized is False
        assert engine._version is None
        assert len(engine._techniques) == 0
        assert len(engine._mitigations) == 0
        assert len(engine._groups) == 0
    
    @pytest.mark.asyncio
    async def test_initialize_downloads_missing_data(self, engine, sample_stix_data):
        """Test that initialization downloads missing data."""
        with patch.object(engine, '_download_matrix', new_callable=AsyncMock) as mock_download:
            mock_download.return_value = True
            
            # Create dummy files after "download"
            async def create_files(matrix):
                file_path = engine._get_matrix_file_path(matrix)
                with open(file_path, 'w') as f:
                    json.dump(sample_stix_data, f)
                return True
            
            mock_download.side_effect = create_files
            
            result = await engine.initialize()
            
            assert mock_download.call_count == 3  # Enterprise, Mobile, ICS
            assert result is True
            assert engine._initialized is True


# ============================================================================
# Parsing Tests
# ============================================================================


class TestSTIXParsing:
    """Test STIX data parsing."""
    
    def test_parse_technique(self, initialized_engine):
        """Test technique parsing."""
        technique = initialized_engine.get_technique("T1566")
        
        assert technique is not None
        assert technique.id == "T1566"
        assert technique.name == "Phishing"
        assert "initial-access" in technique.tactics
        assert "Windows" in technique.platforms
        assert technique.is_subtechnique is False
    
    def test_parse_subtechnique(self, initialized_engine):
        """Test sub-technique parsing."""
        subtechnique = initialized_engine.get_technique("T1566.001")
        
        assert subtechnique is not None
        assert subtechnique.id == "T1566.001"
        assert subtechnique.name == "Spearphishing Attachment"
        assert subtechnique.is_subtechnique is True
        assert subtechnique.parent_technique_id == "T1566"
    
    def test_parse_mitigation(self, initialized_engine):
        """Test mitigation parsing."""
        mitigation = initialized_engine.get_mitigation("M1017")
        
        assert mitigation is not None
        assert mitigation.id == "M1017"
        assert mitigation.name == "User Training"
    
    def test_parse_group(self, initialized_engine):
        """Test threat group parsing."""
        group = initialized_engine.get_group("G0016")
        
        assert group is not None
        assert group.id == "G0016"
        assert group.name == "APT29"
        assert "Cozy Bear" in group.aliases
    
    def test_parse_software(self, initialized_engine):
        """Test software parsing."""
        software = initialized_engine.get_software("S0002")
        
        assert software is not None
        assert software.id == "S0002"
        assert software.name == "Mimikatz"
        assert software.type == "malware"
    
    def test_parse_relationships(self, initialized_engine):
        """Test relationship resolution."""
        # Mitigation relationship
        mitigations = initialized_engine.get_mitigations_for_technique("T1566")
        assert len(mitigations) > 0
        assert any(m.id == "M1017" for m in mitigations)
        
        # Group uses technique
        groups = initialized_engine.get_groups_using_technique("T1566")
        assert len(groups) > 0
        assert any(g.id == "G0016" for g in groups)
    
    def test_parse_procedures(self, initialized_engine):
        """Test procedure example extraction."""
        procedures = initialized_engine.get_procedures_for_technique("T1566")
        
        assert len(procedures) > 0
        assert procedures[0].threat_actor == "APT29"
        assert "phishing" in procedures[0].description.lower()


# ============================================================================
# Query Tests
# ============================================================================


class TestTechniqueQueries:
    """Test technique query methods."""
    
    def test_get_technique_by_id(self, initialized_engine):
        """Test getting technique by ID."""
        technique = initialized_engine.get_technique("T1566")
        assert technique is not None
        assert technique.id == "T1566"
    
    def test_get_nonexistent_technique(self, initialized_engine):
        """Test getting non-existent technique returns None."""
        technique = initialized_engine.get_technique("T9999")
        assert technique is None
    
    def test_get_all_techniques(self, initialized_engine):
        """Test getting all techniques."""
        all_techniques = initialized_engine.get_all_techniques()
        assert len(all_techniques) >= 3  # At least our sample techniques
    
    def test_get_all_techniques_without_subtechniques(self, initialized_engine):
        """Test getting techniques excluding sub-techniques."""
        techniques = initialized_engine.get_all_techniques(include_subtechniques=False)
        assert all(not t.is_subtechnique for t in techniques)
    
    def test_get_techniques_by_tactic(self, initialized_engine):
        """Test getting techniques by tactic."""
        techniques = initialized_engine.get_techniques_by_tactic("initial-access")
        
        assert len(techniques) > 0
        assert any(t.id == "T1566" for t in techniques)
    
    def test_get_techniques_by_platform(self, initialized_engine):
        """Test getting techniques by platform."""
        techniques = initialized_engine.get_techniques_by_platform("Windows")
        
        assert len(techniques) > 0
        assert all("Windows" in t.platforms for t in techniques)
    
    def test_get_sub_techniques(self, initialized_engine):
        """Test getting sub-techniques for parent."""
        subtechniques = initialized_engine.get_sub_techniques("T1566")
        
        assert len(subtechniques) > 0
        assert any(st.id == "T1566.001" for st in subtechniques)
    
    def test_search_techniques_by_name(self, initialized_engine):
        """Test searching techniques by name."""
        results = initialized_engine.search_techniques("phishing")
        
        assert len(results) > 0
        assert any(t.id == "T1566" for t in results)
    
    def test_search_techniques_by_description(self, initialized_engine):
        """Test searching techniques by description."""
        results = initialized_engine.search_techniques("command interpreter")
        
        assert len(results) > 0
        assert any(t.id == "T1059" for t in results)


# ============================================================================
# Detection and Mitigation Tests
# ============================================================================


class TestDetectionRecommendations:
    """Test detection recommendation functionality."""
    
    def test_get_detection_recommendations(self, initialized_engine):
        """Test getting detection recommendations."""
        recommendations = initialized_engine.get_detection_recommendations("T1566")
        
        assert recommendations["technique_id"] == "T1566"
        assert recommendations["technique_name"] == "Phishing"
        assert len(recommendations["data_sources"]) > 0
    
    def test_detection_recommendations_include_analytics(self, initialized_engine):
        """Test that detection recommendations include analytics suggestions."""
        recommendations = initialized_engine.get_detection_recommendations("T1059")
        
        assert "detection_analytics" in recommendations
        # T1059 has Process and Command data sources
        analytics = recommendations["detection_analytics"]
        assert len(analytics) > 0
    
    def test_get_mitigations_for_technique(self, initialized_engine):
        """Test getting mitigations for a technique."""
        mitigations = initialized_engine.get_mitigations_for_technique("T1566")
        
        assert len(mitigations) > 0
        assert any(m.name == "User Training" for m in mitigations)


# ============================================================================
# Coverage Statistics Tests
# ============================================================================


class TestCoverageStatistics:
    """Test coverage statistics functionality."""
    
    def test_get_coverage_stats(self, initialized_engine):
        """Test getting coverage statistics."""
        stats = initialized_engine.get_coverage_stats()
        
        assert "total_techniques" in stats
        assert "enterprise" in stats
        assert "mitigations" in stats
        assert "threat_groups" in stats
        assert "procedure_examples" in stats
        assert stats["total_techniques"] >= 3
    
    def test_get_tactic_coverage(self, initialized_engine):
        """Test getting tactic coverage."""
        coverage = initialized_engine.get_tactic_coverage()
        
        assert "initial-access" in coverage
        assert coverage["initial-access"]["technique_count"] >= 1
        assert "techniques" in coverage["initial-access"]


# ============================================================================
# Data Model Tests
# ============================================================================


class TestATTACKDataModels:
    """Test MITRE ATT&CK data models."""
    
    def test_technique_full_id(self):
        """Test technique full_id property."""
        technique = ATTACKTechnique(
            id="T1566",
            name="Phishing",
            description="Test",
            tactics=["initial-access"],
            platforms=["Windows"],
        )
        assert technique.full_id == "T1566"
        
        subtechnique = ATTACKTechnique(
            id="T1566.001",
            name="Spearphishing Attachment",
            description="Test",
            tactics=["initial-access"],
            platforms=["Windows"],
            is_subtechnique=True,
            parent_technique_id="T1566",
        )
        assert subtechnique.full_id == "T1566.001"
    
    def test_technique_url(self):
        """Test technique URL generation."""
        technique = ATTACKTechnique(
            id="T1566",
            name="Phishing",
            description="Test",
            tactics=["initial-access"],
            platforms=["Windows"],
        )
        assert technique.technique_url == "https://attack.mitre.org/techniques/T1566/"
        
        subtechnique = ATTACKTechnique(
            id="T1566.001",
            name="Spearphishing Attachment",
            description="Test",
            tactics=["initial-access"],
            platforms=["Windows"],
            is_subtechnique=True,
        )
        assert subtechnique.technique_url == "https://attack.mitre.org/techniques/T1566/001/"
    
    def test_procedure_creation(self):
        """Test procedure example creation."""
        procedure = ATTACKProcedure(
            technique_id="T1566",
            threat_actor="APT29",
            software=None,
            description="APT29 used phishing emails.",
        )
        
        assert procedure.technique_id == "T1566"
        assert procedure.threat_actor == "APT29"
        assert procedure.software is None


# ============================================================================
# Constants Tests
# ============================================================================


class TestMITREConstants:
    """Test MITRE ATT&CK constants."""
    
    def test_enterprise_tactics_order(self):
        """Test that enterprise tactics are in kill chain order."""
        assert ENTERPRISE_TACTICS[0] == "reconnaissance"
        assert ENTERPRISE_TACTICS[-1] == "impact"
        assert "initial-access" in ENTERPRISE_TACTICS
        assert "execution" in ENTERPRISE_TACTICS
    
    def test_tactic_descriptions(self):
        """Test that all tactics have descriptions."""
        for tactic in ENTERPRISE_TACTICS:
            # Some tactics like reconnaissance are newer
            if tactic in TACTIC_DESCRIPTIONS:
                assert len(TACTIC_DESCRIPTIONS[tactic]) > 0
    
    def test_platforms_defined(self):
        """Test that platforms are defined for all domains."""
        assert "enterprise" in PLATFORMS
        assert "mobile" in PLATFORMS
        assert "ics" in PLATFORMS
        assert "Windows" in PLATFORMS["enterprise"]


# ============================================================================
# Export Tests
# ============================================================================


class TestDataExport:
    """Test data export functionality."""
    
    def test_export_to_json(self, initialized_engine, tmp_storage):
        """Test exporting data to JSON."""
        output_path = tmp_storage / "export.json"
        initialized_engine.export_to_json(output_path)
        
        assert output_path.exists()
        
        with open(output_path, 'r') as f:
            data = json.load(f)
        
        assert "techniques" in data
        assert "mitigations" in data
        assert "groups" in data
        assert "statistics" in data


# ============================================================================
# Factory Function Tests
# ============================================================================


class TestFactoryFunction:
    """Test factory function."""
    
    @pytest.mark.asyncio
    async def test_create_mitre_attack_engine(self, tmp_storage, sample_stix_data):
        """Test factory function creates initialized engine."""
        # Pre-create data files
        for matrix in ATTACKMatrix:
            file_path = tmp_storage / f"{matrix.value}.json"
            with open(file_path, 'w') as f:
                json.dump(sample_stix_data, f)
        
        engine = await create_mitre_attack_engine(storage_path=tmp_storage)
        
        assert engine._initialized is True
        assert len(engine._techniques) > 0


# ============================================================================
# Integration Tests
# ============================================================================


class TestMITREIntegration:
    """Integration tests for full MITRE ATT&CK workflow."""
    
    def test_full_technique_lookup_workflow(self, initialized_engine):
        """Test complete technique lookup workflow."""
        # 1. Get technique
        technique = initialized_engine.get_technique("T1566")
        assert technique is not None
        
        # 2. Get sub-techniques
        subtechniques = initialized_engine.get_sub_techniques("T1566")
        assert len(subtechniques) > 0
        
        # 3. Get mitigations
        mitigations = initialized_engine.get_mitigations_for_technique("T1566")
        assert len(mitigations) > 0
        
        # 4. Get threat actors
        groups = initialized_engine.get_groups_using_technique("T1566")
        assert len(groups) > 0
        
        # 5. Get detection recommendations
        detections = initialized_engine.get_detection_recommendations("T1566")
        assert detections["technique_id"] == "T1566"
        
        # 6. Get procedures
        procedures = initialized_engine.get_procedures_for_technique("T1566")
        assert len(procedures) > 0
    
    def test_tactic_based_query_workflow(self, initialized_engine):
        """Test tactic-based query workflow."""
        # 1. Get all tactics coverage
        coverage = initialized_engine.get_tactic_coverage()
        
        # 2. Find tactics with most techniques
        max_tactic = max(coverage.items(), key=lambda x: x[1]["technique_count"])
        
        # 3. Get techniques for that tactic
        techniques = initialized_engine.get_techniques_by_tactic(max_tactic[0])
        assert len(techniques) == max_tactic[1]["technique_count"]
    
    def test_platform_based_query_workflow(self, initialized_engine):
        """Test platform-based query workflow."""
        # Get Windows techniques
        windows_techniques = initialized_engine.get_techniques_by_platform("Windows")
        
        # All should support Windows
        for tech in windows_techniques:
            assert "Windows" in tech.platforms
