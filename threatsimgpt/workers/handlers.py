"""Worker job handlers."""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from threatsimgpt.api.routers.feedback import _process_feedback_async
from threatsimgpt.api.routers.manuals import (
    _background_bulk_generate,
    IndustryContext,
    ManualQuality,
    SecurityTeam,
    ThreatCategory,
)
from threatsimgpt.core.models import SimulationStatus, ThreatScenario
from threatsimgpt.core.simulator import ThreatSimulator
from threatsimgpt.deployment import DeploymentConfig, ThreatDeploymentEngine
from threatsimgpt.rag import IntelligenceIngester, RAGConfig
from threatsimgpt.rag.config import GeneratorConfig
from threatsimgpt.rag.generator import PlaybookGenerator
from threatsimgpt.rag.ingest import TextChunker
from threatsimgpt.rag.retriever import HybridRetriever
from threatsimgpt.rag.vectorstore import VectorStoreManager
from threatsimgpt.rag.generator import OpenAIProvider
from threatsimgpt.workers.job_store import RedisJobStore

logger = logging.getLogger(__name__)


def _load_rag_config() -> RAGConfig:
    config_path = os.getenv("RAG_CONFIG_PATH", "./config/rag.yaml")
    if Path(config_path).exists():
        config = RAGConfig.from_yaml(config_path)
    else:
        config = RAGConfig.default()

    neo4j_uri = os.getenv("NEO4J_URI")
    if neo4j_uri:
        from urllib.parse import urlparse
        parsed = urlparse(neo4j_uri)
        if parsed.hostname:
            config.vectorstore.host = parsed.hostname
        if parsed.port:
            config.vectorstore.port = parsed.port

    return config


def _coerce_enum_list(values: List[str], enum_cls):
    result = []
    for value in values:
        result.append(enum_cls(value))
    return result


def _coerce_enum(value: str, enum_cls):
    return enum_cls(value)


async def handle_manuals_bulk_generate(payload: Dict[str, Any]) -> Dict[str, Any]:
    task_id = payload["task_id"]
    teams = _coerce_enum_list(payload["teams"], SecurityTeam)
    threat_type = _coerce_enum(payload["threat_type"], ThreatCategory)
    industry = _coerce_enum(payload["industry"], IndustryContext)
    quality = _coerce_enum(payload["quality"], ManualQuality)

    await _background_bulk_generate(task_id, teams, threat_type, industry, quality)
    return {"task_id": task_id, "status": "completed"}


async def handle_feedback_process(payload: Dict[str, Any]) -> Dict[str, Any]:
    feedback_id = payload["feedback_id"]
    await _process_feedback_async(feedback_id)
    return {"feedback_id": feedback_id, "status": "processed"}


async def handle_rag_ingest(payload: Dict[str, Any]) -> Dict[str, Any]:
    config = _load_rag_config()
    ingester = IntelligenceIngester(config.sources, output_dir=Path(config.data_directory) / "documents")
    documents = await ingester.ingest_all()

    if not documents:
        return {"documents": 0, "chunks": 0, "status": "no_documents"}

    chunker = TextChunker(config.chunking)
    chunks: List[Dict[str, Any]] = []
    for doc in documents:
        chunks.extend(chunker.chunk_document(doc))

    store_manager = VectorStoreManager(config.vectorstore, config.embedding)
    await store_manager.initialize()
    await store_manager.add_documents(chunks)

    return {
        "documents": len(documents),
        "chunks": len(chunks),
        "status": "indexed",
    }


async def handle_rag_generate(payload: Dict[str, Any]) -> Dict[str, Any]:
    config = _load_rag_config()

    scenario = payload["scenario"]
    sector = payload.get("sector")
    playbook_type = payload.get("playbook_type", "tactical")
    output_path = payload.get("output_path")

    store_manager = VectorStoreManager(config.vectorstore, config.embedding)
    await store_manager.initialize()

    retriever = HybridRetriever(config.retrieval, store_manager)
    await retriever.initialize()

    llm = OpenAIProvider(
        api_key=os.environ.get("OPENAI_API_KEY", ""),
        model=config.generation.model,
    )

    gen_config = GeneratorConfig(
        temperature=config.generation.temperature,
        max_output_tokens=config.generation.max_tokens,
    )
    generator = PlaybookGenerator(gen_config, retriever, llm)

    if playbook_type == "tactical":
        playbook = await generator.generate_tactical_playbook(scenario=scenario, sector=sector)
    else:
        playbook = await generator.generate_sector_playbook(sector=sector or scenario)

    content = playbook.get("content", "") if isinstance(playbook, dict) else playbook.content

    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(content)

    return {
        "scenario": scenario,
        "playbook_type": playbook_type,
        "output_path": output_path,
        "status": "generated",
    }


async def handle_deployment_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    generated_content = payload["generated_content"]
    deployment_config = DeploymentConfig.model_validate(payload["deployment_config"])

    engine = ThreatDeploymentEngine(payload.get("deployment_settings", {}))
    campaign_id, results = await engine.deploy_threat_campaign(generated_content, deployment_config)

    return {
        "campaign_id": campaign_id,
        "results": [r.model_dump() for r in results],
    }


async def handle_simulation_execute(payload: Dict[str, Any]) -> Dict[str, Any]:
    job_id = payload["job_id"]
    max_stages = int(payload.get("max_stages", 10))
    scenario_data = payload.get("scenario", {})

    job_store = RedisJobStore.from_env()
    if job_store:
        await job_store.connect()
        await job_store.update_job(
            job_id,
            status="running",
            started_at=datetime.now(timezone.utc).isoformat(),
        )

    try:
        scenario = ThreatScenario(**scenario_data)
        simulator = ThreatSimulator(max_stages=max_stages)
        result = await simulator.execute_simulation(scenario)

        summary = {
            "result_id": result.result_id,
            "status": result.status.value if hasattr(result.status, "value") else str(result.status),
            "stages_completed": len(result.stages),
            "success_rate": result.success_rate,
            "duration_seconds": result.total_duration_seconds,
        }

        if job_store:
            await job_store.update_job(
                job_id,
                status="completed" if result.status == SimulationStatus.COMPLETED else "failed",
                completed_at=datetime.now(timezone.utc).isoformat(),
                result=summary,
                error=result.error_message or "",
            )

        return summary
    except Exception as exc:
        if job_store:
            await job_store.update_job(
                job_id,
                status="failed",
                completed_at=datetime.now(timezone.utc).isoformat(),
                error={"message": str(exc)},
            )
        raise
    finally:
        if job_store:
            await job_store.close()


HANDLERS = {
    "manuals.bulk_generate": handle_manuals_bulk_generate,
    "feedback.process": handle_feedback_process,
    "rag.ingest": handle_rag_ingest,
    "rag.generate": handle_rag_generate,
    "deployment.execute": handle_deployment_execute,
    "simulation.execute": handle_simulation_execute,
}
