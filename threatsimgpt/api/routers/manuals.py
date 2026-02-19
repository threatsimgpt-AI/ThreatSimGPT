"""Field Manuals API Router.

Provides API endpoints for generating, updating, and managing security field manuals
with AI-enhanced content generation and RAG-powered knowledge retrieval.
"""

import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
from enum import Enum

from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from pydantic import BaseModel, Field
import os

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/manuals", tags=["Field Manuals"])


# =============================================================================
# Enums
# =============================================================================

class SecurityTeam(str, Enum):
    """Security teams for manual generation."""
    BLUE_TEAM = "blue_team"
    RED_TEAM = "red_team"
    PURPLE_TEAM = "purple_team"
    SOC = "soc"
    THREAT_INTEL = "threat_intel"
    GRC = "grc"
    INCIDENT_RESPONSE = "incident_response"
    SECURITY_AWARENESS = "security_awareness"


class ThreatCategory(str, Enum):
    """Categories of threats."""
    PHISHING = "phishing"
    SPEAR_PHISHING = "spear_phishing"
    BUSINESS_EMAIL_COMPROMISE = "business_email_compromise"
    VISHING = "vishing"
    SMISHING = "smishing"
    SOCIAL_ENGINEERING = "social_engineering"
    RANSOMWARE = "ransomware"
    MALWARE = "malware"
    APT = "apt"
    INSIDER_THREAT = "insider_threat"
    SUPPLY_CHAIN = "supply_chain"


class IndustryContext(str, Enum):
    """Industry contexts for manual generation."""
    GENERAL = "general"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    TECHNOLOGY = "technology"
    GOVERNMENT = "government"
    RETAIL = "retail"
    MANUFACTURING = "manufacturing"
    ENERGY = "energy"
    EDUCATION = "education"
    LEGAL = "legal"


class OrganizationSize(str, Enum):
    """Organization size context."""
    STARTUP = "startup"
    SMB = "smb"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"


class ManualQuality(str, Enum):
    """Quality level for manual generation."""
    BASIC = "basic"
    ENHANCED = "enhanced"
    COMPREHENSIVE = "comprehensive"
    EXPERT = "expert"


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    NIST = "NIST"
    ISO27001 = "ISO27001"
    SOC2 = "SOC2"
    PCI_DSS = "PCI-DSS"
    HIPAA = "HIPAA"
    GDPR = "GDPR"
    CMMC = "CMMC"
    CIS = "CIS"
    MITRE = "MITRE"


# =============================================================================
# Request/Response Models
# =============================================================================

class ManualGenerationRequest(BaseModel):
    """Request model for field manual generation."""
    team: SecurityTeam = Field(..., description="Target security team")
    threat_type: ThreatCategory = Field(
        default=ThreatCategory.SPEAR_PHISHING,
        description="Type of threat scenario"
    )
    scenario_name: str = Field(
        default="Advanced Threat Scenario",
        description="Name of the threat scenario"
    )
    industry: IndustryContext = Field(
        default=IndustryContext.GENERAL,
        description="Industry context"
    )
    organization_size: OrganizationSize = Field(
        default=OrganizationSize.ENTERPRISE,
        description="Organization size"
    )
    difficulty_level: int = Field(
        default=7,
        ge=1,
        le=10,
        description="Difficulty level (1-10)"
    )
    compliance_frameworks: List[ComplianceFramework] = Field(
        default_factory=list,
        description="Applicable compliance frameworks"
    )
    mitre_techniques: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs"
    )
    quality: ManualQuality = Field(
        default=ManualQuality.COMPREHENSIVE,
        description="Quality level for generation"
    )
    use_rag: bool = Field(
        default=True,
        description="Use RAG for enhanced context retrieval"
    )
    custom_context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional custom context for generation"
    )


class ManualUpdateRequest(BaseModel):
    """Request model for updating an existing manual."""
    manual_id: str = Field(..., description="ID of the manual to update")
    section: Optional[str] = Field(
        default=None,
        description="Specific section to update (or full manual if None)"
    )
    new_data: Dict[str, Any] = Field(
        ...,
        description="New data to incorporate into the manual"
    )
    merge_strategy: str = Field(
        default="enhance",
        description="How to merge new data: 'replace', 'enhance', 'append'"
    )
    use_ai: bool = Field(
        default=True,
        description="Use AI to intelligently merge content"
    )


class ManualMetadata(BaseModel):
    """Metadata for a field manual."""
    threat_type: ThreatCategory
    industry: IndustryContext
    organization_size: OrganizationSize
    difficulty_level: int
    compliance_frameworks: List[str]
    mitre_techniques: List[str]
    rag_enabled: bool
    generation_time_seconds: float
    llm_provider: Optional[str] = None
    tokens_used: int = 0
    file_path: Optional[str] = None


class ManualSection(BaseModel):
    """A section within a field manual."""
    title: str
    content: str
    subsections: List["ManualSection"] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ManualResponse(BaseModel):
    """Response model for generated manual."""
    manual_id: str
    team: SecurityTeam
    title: str
    content: str
    sections: List[ManualSection] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    version: str = "1.0.0"
    quality: ManualQuality
    word_count: int
    rag_sources_used: int = 0


class ManualListResponse(BaseModel):
    """Response model for listing manuals."""
    manuals: List[Dict[str, Any]]
    total: int
    page: int
    page_size: int


class ManualStatusResponse(BaseModel):
    """Response for manual generation status."""
    status: str
    team: SecurityTeam
    manuals_count: int
    knowledge_base_entries: int
    last_updated: Optional[datetime]
    suggestions_count: int


class BulkGenerationRequest(BaseModel):
    """Request for generating manuals for multiple teams."""
    teams: List[SecurityTeam] = Field(
        default_factory=lambda: list(SecurityTeam),
        description="Teams to generate manuals for"
    )
    threat_type: ThreatCategory = Field(default=ThreatCategory.SPEAR_PHISHING)
    industry: IndustryContext = Field(default=IndustryContext.GENERAL)
    quality: ManualQuality = Field(default=ManualQuality.COMPREHENSIVE)


class BulkGenerationResponse(BaseModel):
    """Response for bulk manual generation."""
    task_id: str
    teams_queued: List[SecurityTeam]
    estimated_time_minutes: float
    status: str


# =============================================================================
# API Endpoints
# =============================================================================

@router.post("/generate", response_model=ManualResponse, status_code=status.HTTP_201_CREATED)
async def generate_manual(request: ManualGenerationRequest):
    """
    Generate a comprehensive field manual for a security team.

    This endpoint uses AI-enhanced generation with optional RAG retrieval
    to create detailed, actionable field manuals tailored to the specified
    context (team, threat type, industry, compliance requirements).

    The manual includes:
    - Threat overview and intelligence
    - Detection engineering rules
    - Response procedures
    - Mitigation strategies
    - Compliance mappings
    - Tool configurations and commands
    """
    try:
        from threatsimgpt.core.ai_enhanced_playbooks import (
            AIEnhancedPlaybookGenerator,
            PlaybookContext,
            PlaybookQuality,
        )
        import uuid

        start_time = datetime.utcnow()

        # Map quality levels
        quality_map = {
            ManualQuality.BASIC: PlaybookQuality.BASIC,
            ManualQuality.ENHANCED: PlaybookQuality.ENHANCED,
            ManualQuality.COMPREHENSIVE: PlaybookQuality.COMPREHENSIVE,
            ManualQuality.EXPERT: PlaybookQuality.EXPERT,
        }

        # Default MITRE techniques if not provided
        mitre_techniques = request.mitre_techniques or _get_default_mitre(request.threat_type)

        # Create playbook context
        context = PlaybookContext(
            scenario_name=request.scenario_name,
            threat_type=request.threat_type.value,
            mitre_techniques=mitre_techniques,
            difficulty_level=request.difficulty_level,
            industry=request.industry.value,
            organization_size=request.organization_size.value,
            compliance_frameworks=[f.value for f in request.compliance_frameworks],
            custom_requirements=request.custom_context or {},
        )

        # Initialize generator
        generator = AIEnhancedPlaybookGenerator()

        # RAG retrieval if enabled
        rag_sources_used = 0
        if request.use_rag:
            try:
                from threatsimgpt.rag.retriever import HybridRetriever
                from threatsimgpt.rag.config import RetrieverConfig

                retriever = HybridRetriever(RetrieverConfig())
                rag_context = await retriever.retrieve(
                    query=f"{request.threat_type.value} {request.team.value} playbook",
                    top_k=10
                )
                rag_sources_used = len(rag_context)

                # Inject RAG context into custom requirements
                context.custom_requirements["rag_context"] = [
                    {"content": r.chunk.content, "source": r.chunk.source}
                    for r in rag_context
                ]
            except Exception as e:
                logger.warning(f"RAG retrieval failed, continuing without: {e}")

        # Generate the manual
        manual_content = generator.generate_field_manual_sync(
            team=request.team.value,
            context=context,
            quality=quality_map.get(request.quality, PlaybookQuality.COMPREHENSIVE),
        )

        end_time = datetime.utcnow()
        generation_time = (end_time - start_time).total_seconds()

        # Create response
        manual_id = str(uuid.uuid4())
        now = datetime.utcnow()

        # Save to storage
        output_dir = Path("generated_content/field_manuals") / request.team.value
        output_dir.mkdir(parents=True, exist_ok=True)
        filename = f"{request.team.value}_{request.threat_type.value}_{manual_id[:8]}.md"
        file_path = output_dir / filename
        file_path.write_text(manual_content)

        return ManualResponse(
            manual_id=manual_id,
            team=request.team,
            title=f"{request.team.value.replace('_', ' ').title()} Field Manual - {request.scenario_name}",
            content=manual_content,
            sections=[],  # Parse sections if needed
            metadata={
                "threat_type": request.threat_type,
                "industry": request.industry,
                "organization_size": request.organization_size,
                "difficulty_level": request.difficulty_level,
                "compliance_frameworks": [f.value for f in request.compliance_frameworks],
                "mitre_techniques": mitre_techniques,
                "rag_enabled": request.use_rag,
                "generation_time_seconds": generation_time,
                "file_path": str(file_path),
            },
            created_at=now,
            updated_at=now,
            quality=request.quality,
            word_count=len(manual_content.split()),
            rag_sources_used=rag_sources_used,
        )

    except Exception as e:
        logger.error(f"Manual generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Manual generation failed: {str(e)}"
        )


@router.put("/update", response_model=ManualResponse)
async def update_manual(request: ManualUpdateRequest):
    """
    Update an existing field manual with new data.

    The AI will intelligently merge new threat intelligence, procedures,
    or context into the existing manual while maintaining consistency
    and the standard manual format.

    Merge strategies:
    - 'replace': Replace the section/manual entirely
    - 'enhance': AI enhances existing content with new data
    - 'append': Append new content to existing sections
    """
    try:
        from threatsimgpt.llm.manager import LLMManager
        import json

        # Find the manual
        manuals_dir = Path("generated_content/field_manuals")
        manual_path = None

        for team_dir in manuals_dir.iterdir():
            if team_dir.is_dir():
                for file in team_dir.glob("*.md"):
                    if request.manual_id[:8] in file.stem:
                        manual_path = file
                        break

        if not manual_path or not manual_path.exists():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Manual not found: {request.manual_id}"
            )

        # Read existing content
        existing_content = manual_path.read_text()

        if not request.use_ai:
            # Simple merge without AI
            if request.merge_strategy == "replace":
                updated_content = json.dumps(request.new_data, indent=2)
            elif request.merge_strategy == "append":
                updated_content = existing_content + "\n\n## Updates\n" + json.dumps(request.new_data, indent=2)
            else:
                updated_content = existing_content
        else:
            # AI-enhanced merge
            llm = LLMManager()

            merge_prompt = f"""You are updating a security field manual with new intelligence data.

EXISTING MANUAL:
{existing_content[:10000]}  # Truncate for context

NEW DATA TO INCORPORATE:
{json.dumps(request.new_data, indent=2)}

MERGE STRATEGY: {request.merge_strategy}
{'SPECIFIC SECTION: ' + request.section if request.section else 'UPDATE ENTIRE MANUAL'}

Instructions:
1. Analyze the new data and identify relevant insights
2. Integrate the new information into the appropriate sections
3. Maintain the professional field manual format
4. Ensure all new detection rules, IOCs, or procedures are properly formatted
5. Update any timestamps or version information
6. Preserve existing content while enhancing with new data

Return the updated manual content."""

            response = await llm.generate_content(
                prompt=merge_prompt,
                scenario_type="manual_update",
                max_tokens=4000,
                temperature=0.3,
            )
            updated_content = response.content

        # Save updated manual
        manual_path.write_text(updated_content)

        # Parse team from path
        team_name = manual_path.parent.name

        return ManualResponse(
            manual_id=request.manual_id,
            team=SecurityTeam(team_name),
            title=f"Updated Manual - {request.manual_id[:8]}",
            content=updated_content,
            sections=[],
            metadata={
                "merge_strategy": request.merge_strategy,
                "ai_enhanced": request.use_ai,
                "update_section": request.section,
            },
            created_at=datetime.fromtimestamp(manual_path.stat().st_ctime),
            updated_at=datetime.utcnow(),
            quality=ManualQuality.COMPREHENSIVE,
            word_count=len(updated_content.split()),
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Manual update failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Manual update failed: {str(e)}"
        )


@router.get("/list", response_model=ManualListResponse)
async def list_manuals(
    team: Optional[SecurityTeam] = None,
    page: int = 1,
    page_size: int = 20,
):
    """
    List all generated field manuals.

    Optionally filter by team and paginate results.
    """
    try:
        manuals_dir = Path("generated_content/field_manuals")
        manuals = []

        if not manuals_dir.exists():
            return ManualListResponse(manuals=[], total=0, page=page, page_size=page_size)

        for team_dir in manuals_dir.iterdir():
            if team_dir.is_dir():
                if team and team_dir.name != team.value:
                    continue

                for file in team_dir.glob("*.md"):
                    stat = file.stat()
                    manuals.append({
                        "manual_id": file.stem.split("_")[-1] if "_" in file.stem else file.stem,
                        "team": team_dir.name,
                        "filename": file.name,
                        "path": str(file),
                        "size_bytes": stat.st_size,
                        "created_at": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "updated_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    })

        # Sort by updated time
        manuals.sort(key=lambda x: x["updated_at"], reverse=True)

        # Paginate
        start = (page - 1) * page_size
        end = start + page_size
        paginated = manuals[start:end]

        return ManualListResponse(
            manuals=paginated,
            total=len(manuals),
            page=page,
            page_size=page_size,
        )

    except Exception as e:
        logger.error(f"Failed to list manuals: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list manuals: {str(e)}"
        )


@router.get("/{manual_id}", response_model=ManualResponse)
async def get_manual(manual_id: str):
    """
    Get a specific field manual by ID.
    """
    try:
        manuals_dir = Path("generated_content/field_manuals")

        for team_dir in manuals_dir.iterdir():
            if team_dir.is_dir():
                for file in team_dir.glob("*.md"):
                    if manual_id in file.stem:
                        content = file.read_text()
                        stat = file.stat()

                        return ManualResponse(
                            manual_id=manual_id,
                            team=SecurityTeam(team_dir.name),
                            title=file.stem.replace("_", " ").title(),
                            content=content,
                            sections=[],
                            metadata={"file_path": str(file)},
                            created_at=datetime.fromtimestamp(stat.st_ctime),
                            updated_at=datetime.fromtimestamp(stat.st_mtime),
                            quality=ManualQuality.COMPREHENSIVE,
                            word_count=len(content.split()),
                        )

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manual not found: {manual_id}"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get manual: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get manual: {str(e)}"
        )


@router.delete("/{manual_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_manual(manual_id: str):
    """
    Delete a field manual.
    """
    try:
        manuals_dir = Path("generated_content/field_manuals")

        for team_dir in manuals_dir.iterdir():
            if team_dir.is_dir():
                for file in team_dir.glob("*.md"):
                    if manual_id in file.stem:
                        file.unlink()
                        return

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Manual not found: {manual_id}"
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to delete manual: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete manual: {str(e)}"
        )


@router.post("/bulk-generate", response_model=BulkGenerationResponse)
async def bulk_generate_manuals(
    request: BulkGenerationRequest,
    background_tasks: BackgroundTasks,
):
    """
    Generate field manuals for multiple teams in the background.

    Returns a task ID that can be used to check progress.
    """
    import uuid

    task_id = str(uuid.uuid4())

    queued = False
    redis_url = os.getenv("REDIS_URL")

    if redis_url:
        try:
            from threatsimgpt.workers.queue import RedisQueue

            queue = RedisQueue(redis_url)
            await queue.connect()
            await queue.enqueue(
                queue_name="manuals",
                message_type="manuals.bulk_generate",
                payload={
                    "task_id": task_id,
                    "teams": [team.value for team in request.teams],
                    "threat_type": request.threat_type.value,
                    "industry": request.industry.value,
                    "quality": request.quality.value,
                },
                message_id=task_id,
            )
            await queue.close()
            queued = True
        except Exception as exc:
            logger.error("Failed to enqueue manual generation: %s", exc)

    if not queued:
        background_tasks.add_task(
            _background_bulk_generate,
            task_id,
            request.teams,
            request.threat_type,
            request.industry,
            request.quality,
        )

    return BulkGenerationResponse(
        task_id=task_id,
        teams_queued=request.teams,
        estimated_time_minutes=len(request.teams) * 2.0,  # ~2 min per team
        status="queued" if queued else "queued_local",
    )


@router.get("/status/{team}", response_model=ManualStatusResponse)
async def get_team_status(team: SecurityTeam):
    """
    Get the status of manual generation and knowledge base for a team.
    """
    try:
        from threatsimgpt.core.ai_enhanced_playbooks import ai_playbook_generator
        import json

        manuals_dir = Path("generated_content/field_manuals") / team.value
        kb_dir = Path("generated_content/knowledge_base")

        # Count manuals
        manual_count = len(list(manuals_dir.glob("*.md"))) if manuals_dir.exists() else 0

        # Check knowledge base
        kb_file = kb_dir / f"{team.value}_knowledge.json"
        kb_entries = 0
        last_updated = None

        if kb_file.exists():
            try:
                kb = json.loads(kb_file.read_text())
                kb_entries = len(kb.get("entries", []))
                if kb.get("last_updated"):
                    last_updated = datetime.fromisoformat(kb["last_updated"])
            except Exception:
                pass

        # Get suggestions
        suggestions = ai_playbook_generator.get_improvement_suggestions(team.value)

        return ManualStatusResponse(
            status="active",
            team=team,
            manuals_count=manual_count,
            knowledge_base_entries=kb_entries,
            last_updated=last_updated,
            suggestions_count=len(suggestions),
        )

    except Exception as e:
        logger.error(f"Failed to get team status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get team status: {str(e)}"
        )


@router.get("/teams", response_model=List[Dict[str, str]])
async def list_teams():
    """
    List all available security teams for manual generation.
    """
    team_info = {
        SecurityTeam.BLUE_TEAM: ("Defense, detection, monitoring, hardening", "🛡️"),
        SecurityTeam.RED_TEAM: ("Offensive security, penetration testing", "⚔️"),
        SecurityTeam.PURPLE_TEAM: ("Collaborative testing, gap analysis", "🟣"),
        SecurityTeam.SOC: ("Security operations, alert triage", "🖥️"),
        SecurityTeam.THREAT_INTEL: ("Threat analysis, IOC management", "🔍"),
        SecurityTeam.GRC: ("Governance, risk, compliance", "📋"),
        SecurityTeam.INCIDENT_RESPONSE: ("IR procedures, forensics, recovery", "🚨"),
        SecurityTeam.SECURITY_AWARENESS: ("Training, phishing simulations", "📚"),
    }

    return [
        {
            "id": team.value,
            "name": team.value.replace("_", " ").title(),
            "description": info[0],
            "icon": info[1],
        }
        for team, info in team_info.items()
    ]


# =============================================================================
# Helper Functions
# =============================================================================

def _get_default_mitre(threat_type: ThreatCategory) -> List[str]:
    """Get default MITRE ATT&CK techniques for a threat type."""
    defaults = {
        ThreatCategory.PHISHING: ["T1566.001", "T1566.002"],
        ThreatCategory.SPEAR_PHISHING: ["T1566.001", "T1566.002", "T1598"],
        ThreatCategory.BUSINESS_EMAIL_COMPROMISE: ["T1566.002", "T1534"],
        ThreatCategory.VISHING: ["T1598.001"],
        ThreatCategory.SMISHING: ["T1566.002"],
        ThreatCategory.SOCIAL_ENGINEERING: ["T1598", "T1566"],
        ThreatCategory.RANSOMWARE: ["T1486", "T1490", "T1489"],
        ThreatCategory.MALWARE: ["T1059", "T1204", "T1105"],
        ThreatCategory.APT: ["T1566", "T1078", "T1083", "T1005"],
        ThreatCategory.INSIDER_THREAT: ["T1078", "T1213", "T1005"],
        ThreatCategory.SUPPLY_CHAIN: ["T1195", "T1199"],
    }
    return defaults.get(threat_type, ["T1566"])


async def _background_bulk_generate(
    task_id: str,
    teams: List[SecurityTeam],
    threat_type: ThreatCategory,
    industry: IndustryContext,
    quality: ManualQuality,
):
    """Background task for bulk manual generation."""
    from threatsimgpt.core.ai_enhanced_playbooks import (
        AIEnhancedPlaybookGenerator,
        PlaybookContext,
        PlaybookQuality,
    )

    logger.info(f"Starting bulk generation task {task_id} for {len(teams)} teams")

    generator = AIEnhancedPlaybookGenerator()
    quality_map = {
        ManualQuality.BASIC: PlaybookQuality.BASIC,
        ManualQuality.ENHANCED: PlaybookQuality.ENHANCED,
        ManualQuality.COMPREHENSIVE: PlaybookQuality.COMPREHENSIVE,
        ManualQuality.EXPERT: PlaybookQuality.EXPERT,
    }

    for team in teams:
        try:
            context = PlaybookContext(
                scenario_name=f"Bulk Generation - {threat_type.value}",
                threat_type=threat_type.value,
                mitre_techniques=_get_default_mitre(threat_type),
                difficulty_level=7,
                industry=industry.value,
            )

            manual_content = generator.generate_field_manual_sync(
                team=team.value,
                context=context,
                quality=quality_map.get(quality, PlaybookQuality.COMPREHENSIVE),
            )

            # Save
            output_dir = Path("generated_content/field_manuals") / team.value
            output_dir.mkdir(parents=True, exist_ok=True)
            filename = f"{team.value}_{threat_type.value}_bulk_{task_id[:8]}.md"
            (output_dir / filename).write_text(manual_content)

            logger.info(f"Generated manual for {team.value}")

        except Exception as e:
            logger.error(f"Failed to generate manual for {team.value}: {e}")

    logger.info(f"Bulk generation task {task_id} completed")
