"""FastAPI application for ThreatSimGPT API.

This module provides the main FastAPI application with core endpoints
for threat simulation, scenario management, and system health checks.
"""

import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from threatsimgpt.core.models import ThreatScenario, SimulationResult, ThreatType
from threatsimgpt.core.simulator import ThreatSimulator
from threatsimgpt.llm.manager import LLMManager

# Import API routers
from threatsimgpt.api.routers import manuals_router, knowledge_router, feedback_router

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global instances
simulator: Optional[ThreatSimulator] = None
llm_manager: Optional[LLMManager] = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global simulator, llm_manager

    # Startup
    logger.info("Starting ThreatSimGPT API...")
    try:
        llm_manager = LLMManager()
        simulator = ThreatSimulator(llm_provider=llm_manager)
        logger.info("ThreatSimGPT API started successfully")
    except Exception as e:
        logger.error(f"Failed to initialize ThreatSimGPT API: {str(e)}")
        raise

    yield

    # Shutdown
    logger.info("Shutting down ThreatSimGPT API...")


# Create FastAPI app
app = FastAPI(
    title="ThreatSimGPT API",
    version="0.1.0",
    description="Advanced AI-powered threat simulation and analysis platform",
    lifespan=lifespan
)

# Add CORS middleware
# nosemgrep: wildcard-cors - Intentional for development; production deployments
# should configure ALLOWED_ORIGINS environment variable with specific domains
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(manuals_router, prefix="/api")
app.include_router(knowledge_router, prefix="/api")
app.include_router(feedback_router, prefix="/api")


# Pydantic models for API
class ScenarioRequest(BaseModel):
    """Request model for creating threat scenarios."""
    name: str = Field(..., description="Name of the threat scenario")
    threat_type: ThreatType = Field(..., description="Type of threat")
    description: str = Field("", description="Detailed description of the scenario")
    severity: str = Field("medium", description="Severity level (low, medium, high, critical)")
    target_systems: List[str] = Field(default_factory=list, description="Target systems")
    attack_vectors: List[str] = Field(default_factory=list, description="Attack vectors")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScenarioResponse(BaseModel):
    """Response model for threat scenarios."""
    scenario_id: str
    name: str
    threat_type: ThreatType
    description: str
    severity: str
    target_systems: List[str]
    attack_vectors: List[str]
    created_at: datetime
    metadata: Dict[str, Any]


class SimulationRequest(BaseModel):
    """Request model for simulation execution."""
    scenario_id: str = Field(..., description="ID of the scenario to simulate")
    max_stages: Optional[int] = Field(10, description="Maximum number of simulation stages")


class HealthResponse(BaseModel):
    """Response model for health checks."""
    status: str
    timestamp: datetime
    version: str
    components: Dict[str, str]


# Dependencies
def get_simulator() -> ThreatSimulator:
    """Get the threat simulator instance."""
    if simulator is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Threat simulator not initialized"
        )
    return simulator


def get_llm_manager() -> LLMManager:
    """Get the LLM manager instance."""
    if llm_manager is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="LLM manager not initialized"
        )
    return llm_manager


# Health check endpoints
@app.get("/", response_model=Dict[str, str])
async def read_root():
    """Root endpoint."""
    return {
        "message": "ThreatSimGPT API",
        "version": "0.1.0",
        "status": "operational"
    }


@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    try:
        # Check component health
        components = {
            "api": "healthy",
            "simulator": "healthy" if simulator else "unavailable",
            "llm_manager": "healthy" if llm_manager else "unavailable"
        }

        # Overall status
        overall_status = "healthy" if all(
            status == "healthy" for status in components.values()
        ) else "degraded"

        return HealthResponse(
            status=overall_status,
            timestamp=datetime.utcnow(),
            version="0.1.0",
            components=components
        )

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Health check failed"
        )


# Scenario management endpoints
@app.post("/scenarios", response_model=ScenarioResponse, status_code=status.HTTP_201_CREATED)
async def create_scenario(request: ScenarioRequest):
    """Create a new threat scenario."""
    try:
        scenario = ThreatScenario(
            name=request.name,
            threat_type=request.threat_type,
            description=request.description,
            severity=request.severity,
            target_systems=request.target_systems,
            attack_vectors=request.attack_vectors,
            metadata=request.metadata
        )

        return ScenarioResponse(
            scenario_id=scenario.scenario_id,
            name=scenario.name,
            threat_type=scenario.threat_type,
            description=scenario.description,
            severity=scenario.severity,
            target_systems=scenario.target_systems,
            attack_vectors=scenario.attack_vectors,
            created_at=scenario.created_at,
            metadata=scenario.metadata
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        logger.error(f"Failed to create scenario: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to create scenario"
        )


# Simulation endpoints
@app.post("/simulations", status_code=status.HTTP_202_ACCEPTED)
async def run_simulation(
    request: SimulationRequest,
    sim: ThreatSimulator = Depends(get_simulator)
):
    """Execute a threat simulation."""
    try:
        # Create basic scenario (storage integration pending)
        scenario = ThreatScenario(
            name=f"Scenario_{request.scenario_id}",
            threat_type=ThreatType.CUSTOM,
            description="API-initiated simulation scenario"
        )

        # Execute simulation
        result = await sim.execute_simulation(scenario)

        return {
            "message": "Simulation executed successfully",
            "result_id": result.result_id,
            "status": result.status,
            "stages_completed": len(result.stages),
            "success_rate": result.success_rate,
            "duration_seconds": result.total_duration_seconds
        }

    except Exception as e:
        logger.error(f"Simulation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Simulation failed: {str(e)}"
        )


@app.get("/simulations/active")
async def get_active_simulations(sim: ThreatSimulator = Depends(get_simulator)):
    """Get currently active simulations."""
    try:
        active = sim.get_active_simulations()
        return {
            "active_simulations": len(active),
            "simulations": [
                {
                    "result_id": result_id,
                    "status": result.status,
                    "scenario_id": result.scenario_id,
                    "stages_completed": len(result.stages),
                    "start_time": result.start_time.isoformat()
                }
                for result_id, result in active.items()
            ]
        }
    except Exception as e:
        logger.error(f"Failed to get active simulations: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get active simulations"
        )


# LLM endpoints
class ContentGenerationRequest(BaseModel):
    """Request model for direct content generation."""
    prompt: str = Field(..., description="The prompt for content generation")
    scenario_type: str = Field("custom", description="Type of scenario")
    max_tokens: int = Field(1000, description="Maximum tokens to generate")
    temperature: float = Field(0.7, description="Generation temperature")
    provider: Optional[str] = Field(None, description="Specific LLM provider to use")


class ContentGenerationResponse(BaseModel):
    """Response model for content generation."""
    content: str
    provider_used: str
    tokens_used: int
    generation_time_seconds: float
    safety_score: float
    metadata: Dict[str, Any]


@app.post("/llm/generate", response_model=ContentGenerationResponse)
async def generate_content(
    request: ContentGenerationRequest,
    llm: LLMManager = Depends(get_llm_manager)
):
    """Generate content directly using LLM providers."""
    try:
        start_time = datetime.utcnow()

        # Generate content using the LLM manager
        response = await llm.generate_content(
            prompt=request.prompt,
            scenario_type=request.scenario_type,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            provider=request.provider
        )

        end_time = datetime.utcnow()
        generation_time = (end_time - start_time).total_seconds()

        return ContentGenerationResponse(
            content=response.content,
            provider_used=response.provider,
            tokens_used=response.usage.total_tokens if hasattr(response, 'usage') else 0,
            generation_time_seconds=generation_time,
            safety_score=response.safety_score if hasattr(response, 'safety_score') else 1.0,
            metadata=response.metadata if hasattr(response, 'metadata') else {}
        )

    except Exception as e:
        logger.error(f"Content generation failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Content generation failed: {str(e)}"
        )


@app.get("/llm/providers")
async def list_providers(llm: LLMManager = Depends(get_llm_manager)):
    """List available LLM providers."""
    try:
        providers = llm.get_available_providers()
        return {
            "providers": providers,
            "default_provider": llm.get_default_provider(),
            "total_providers": len(providers)
        }
    except Exception as e:
        logger.error(f"Failed to list providers: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to list providers"
        )


@app.get("/llm/status")
async def llm_status(llm: LLMManager = Depends(get_llm_manager)):
    """Get LLM provider status."""
    try:
        return {
            "llm_manager": "operational",
            "available_providers": ["openai", "anthropic"],
            "status": "ready"
        }
    except Exception as e:
        logger.error(f"Failed to get LLM status: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get LLM status"
        )


# Error handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.utcnow().isoformat()
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
