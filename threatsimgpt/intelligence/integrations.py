"""Intelligence integration layer for ThreatSimGPT.

This module integrates OSINT reconnaissance data with LLM prompt engineering
to create highly personalized and realistic threat simulation scenarios.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from ..config.models import ThreatScenario
from ..llm import ContentGenerationService, ContentType
from .models import ConfidenceLevel, IntelligenceSource, OSINTResult
from .services import OSINTService


class IntelligenceEngine:
    """Central intelligence processing engine for ThreatSimGPT."""

    def __init__(self, osint_service: OSINTService, cache_ttl_hours: int = 24):
        self.osint_service = osint_service
        self.cache_ttl_hours = cache_ttl_hours
        self.intelligence_cache: Dict[str, Tuple[OSINTResult, datetime]] = {}

    async def gather_target_intelligence(
        self,
        target_identifier: str,
        intelligence_types: List[str] = None,
        force_refresh: bool = False
    ) -> OSINTResult:
        """Gather comprehensive intelligence for a target."""

        # Check cache first
        if not force_refresh and target_identifier in self.intelligence_cache:
            cached_result, cached_time = self.intelligence_cache[target_identifier]
            if (datetime.utcnow() - cached_time).total_seconds() < (self.cache_ttl_hours * 3600):
                return cached_result

        # Gather fresh intelligence
        result = await self.osint_service.comprehensive_reconnaissance(
            target=target_identifier,
            recon_types=intelligence_types
        )

        # Cache the result
        self.intelligence_cache[target_identifier] = (result, datetime.utcnow())

        return result

    async def enrich_threat_scenario(
        self,
        scenario: ThreatScenario,
        target_identifier: str
    ) -> Tuple[ThreatScenario, OSINTResult]:
        """Enrich a threat scenario with real-time intelligence."""

        # Gather intelligence for the target
        intelligence = await self.gather_target_intelligence(target_identifier)

        # Create enriched scenario based on intelligence
        enriched_scenario = await self._apply_intelligence_to_scenario(scenario, intelligence)

        return enriched_scenario, intelligence

    async def _apply_intelligence_to_scenario(
        self,
        scenario: ThreatScenario,
        intelligence: OSINTResult
    ) -> ThreatScenario:
        """Apply intelligence data to enhance a threat scenario."""

        # Create a copy of the scenario to modify
        enhanced_scenario = scenario.model_copy(deep=True)

        # Enhance target profile with real intelligence
        if intelligence.individual_profiles:
            profile = intelligence.individual_profiles[0]

            # Update target profile with real data
            if profile.job_title:
                enhanced_scenario.target_profile.role = profile.job_title
            if profile.company:
                enhanced_scenario.target_profile.company_name = profile.company
            if profile.interests:
                enhanced_scenario.target_profile.interests = profile.interests

        # Enhance with company intelligence
        if intelligence.company_intelligence:
            company = intelligence.company_intelligence

            # Add company context to custom parameters
            enhanced_scenario.custom_parameters.update({
                "company_name": company.company_name,
                "company_industry": company.industry,
                "company_size": company.company_size,
                "recent_company_news": [
                    news.get("title", "") for news in company.recent_news[:3]
                ],
                "company_executives": [
                    exec_info.get("name", "") for exec_info in company.executives[:5]
                ]
            })

        # Enhance with social media intelligence
        if intelligence.social_media_intelligence:
            social_platforms = []
            interests = []

            for social_intel in intelligence.social_media_intelligence:
                social_platforms.append(social_intel.platform)
                interests.extend(social_intel.topics_of_interest)

            enhanced_scenario.custom_parameters.update({
                "social_media_platforms": social_platforms,
                "social_media_interests": list(set(interests))
            })

        # Add intelligence metadata
        enhanced_scenario.custom_parameters.update({
            "intelligence_sources": [source.value for source in intelligence.data_sources_used],
            "intelligence_confidence": intelligence.overall_confidence.value,
            "intelligence_freshness_hours": intelligence.query_timestamp,
            "personalization_score": intelligence.completeness_score
        })

        return enhanced_scenario


class LLMIntelligenceIntegrator:
    """Integrates intelligence data with LLM content generation."""

    def __init__(self, content_service: ContentGenerationService):
        self.content_service = content_service

    async def generate_intelligence_enhanced_content(
        self,
        content_type: ContentType,
        base_scenario: ThreatScenario,
        intelligence: OSINTResult,
        **kwargs
    ) -> Dict[str, Any]:
        """Generate content enhanced with real intelligence data."""

        # Create intelligence-enhanced prompt context
        enhanced_context = self._build_intelligence_context(intelligence)

        # Create personalized scenario with intelligence
        personalized_scenario = await self._personalize_scenario_with_intelligence(
            base_scenario, intelligence
        )

        # Generate content with enhanced context
        content_result = await self.content_service.generate_content(
            content_type=content_type,
            scenario=personalized_scenario,
            custom_context=enhanced_context,
            **kwargs
        )

        # Add intelligence metadata to the result
        content_result.metadata.update({
            "intelligence_enhanced": True,
            "intelligence_sources": len(intelligence.data_sources_used),
            "personalization_factors": self._extract_personalization_factors(intelligence),
            "realism_enhancers": intelligence.realism_factors
        })

        return content_result

    def _build_intelligence_context(self, intelligence: OSINTResult) -> Dict[str, Any]:
        """Build enhanced context from intelligence data."""
        context = {
            "target_intelligence": {},
            "company_intelligence": {},
            "social_intelligence": {},
            "personalization_data": intelligence.personalization_data
        }

        # Add individual profile data
        if intelligence.individual_profiles:
            profile = intelligence.individual_profiles[0]
            context["target_intelligence"] = {
                "role": profile.job_title,
                "company": profile.company,
                "interests": profile.interests,
                "skills": profile.skills,
                "location": profile.location,
                "professional_network_size": len(profile.connections)
            }

        # Add company intelligence
        if intelligence.company_intelligence:
            company = intelligence.company_intelligence
            context["company_intelligence"] = {
                "name": company.company_name,
                "industry": company.industry,
                "size": company.company_size,
                "recent_news": company.recent_news[:3],
                "executives": [exec_info.get("name") for exec_info in company.executives[:3]],
                "technologies": company.technologies_used,
                "locations": company.office_locations
            }

        # Add social media intelligence
        if intelligence.social_media_intelligence:
            social_data = {}
            for social_intel in intelligence.social_media_intelligence:
                social_data[social_intel.platform] = {
                    "username": social_intel.username,
                    "interests": social_intel.topics_of_interest,
                    "posting_patterns": social_intel.posting_patterns,
                    "follower_count": social_intel.follower_count
                }
            context["social_intelligence"] = social_data

        return context

    async def _personalize_scenario_with_intelligence(
        self,
        scenario: ThreatScenario,
        intelligence: OSINTResult
    ) -> ThreatScenario:
        """Personalize scenario using intelligence data."""

        # Create enhanced scenario
        enhanced_scenario = scenario.model_copy(deep=True)

        # Apply intelligence-based personalizations
        personalizations = self._generate_personalizations(intelligence)

        # Update scenario parameters with personalizations
        enhanced_scenario.custom_parameters.update(personalizations)

        # Adjust difficulty based on target's security awareness (if available)
        if intelligence.individual_profiles:
            profile = intelligence.individual_profiles[0]
            # Would analyze profile for security awareness indicators

        return enhanced_scenario

    def _generate_personalizations(self, intelligence: OSINTResult) -> Dict[str, Any]:
        """Generate personalization parameters from intelligence."""
        personalizations = {}

        # Company-specific personalizations
        if intelligence.company_intelligence:
            company = intelligence.company_intelligence
            personalizations.update({
                "use_company_branding": True,
                "company_specific_terminology": True,
                "reference_recent_company_events": len(company.recent_news) > 0,
                "include_executive_names": len(company.executives) > 0,
                "company_technology_context": company.technologies_used
            })

        # Social media personalizations
        if intelligence.social_media_intelligence:
            personalizations.update({
                "incorporate_social_interests": True,
                "reference_social_connections": True,
                "use_social_posting_patterns": True
            })

        # Timing personalizations based on intelligence freshness
        hours_since_collection = intelligence.data_freshness_hours
        if hours_since_collection < 6:
            personalizations["urgency_multiplier"] = 1.2
        elif hours_since_collection > 48:
            personalizations["urgency_multiplier"] = 0.8

        return personalizations

    def _extract_personalization_factors(self, intelligence: OSINTResult) -> List[str]:
        """Extract factors that contributed to personalization."""
        factors = []

        if intelligence.individual_profiles:
            factors.append("individual_profile_data")

        if intelligence.company_intelligence:
            factors.append("company_intelligence")
            factors.append("recent_company_news")

        if intelligence.social_media_intelligence:
            factors.append("social_media_presence")
            factors.append("interest_mapping")

        if intelligence.threat_intelligence:
            factors.append("threat_context")

        return factors


class RealTimeReconnaissanceService:
    """Real-time reconnaissance service for active simulations."""

    def __init__(self, intelligence_engine: IntelligenceEngine):
        self.intelligence_engine = intelligence_engine
        self.active_reconnaissance: Dict[str, asyncio.Task] = {}

    async def start_continuous_reconnaissance(
        self,
        simulation_id: str,
        target_identifier: str,
        update_interval_minutes: int = 60
    ) -> None:
        """Start continuous reconnaissance for an active simulation."""

        if simulation_id in self.active_reconnaissance:
            # Cancel existing reconnaissance
            self.active_reconnaissance[simulation_id].cancel()

        # Start new reconnaissance task
        task = asyncio.create_task(
            self._continuous_reconnaissance_loop(
                simulation_id, target_identifier, update_interval_minutes
            )
        )
        self.active_reconnaissance[simulation_id] = task

    async def stop_continuous_reconnaissance(self, simulation_id: str) -> None:
        """Stop continuous reconnaissance for a simulation."""
        if simulation_id in self.active_reconnaissance:
            self.active_reconnaissance[simulation_id].cancel()
            del self.active_reconnaissance[simulation_id]

    async def _continuous_reconnaissance_loop(
        self,
        simulation_id: str,
        target_identifier: str,
        update_interval_minutes: int
    ) -> None:
        """Continuous reconnaissance loop."""

        while True:
            try:
                # Gather fresh intelligence
                intelligence = await self.intelligence_engine.gather_target_intelligence(
                    target_identifier, force_refresh=True
                )

                # Process intelligence updates
                await self._process_intelligence_updates(simulation_id, intelligence)

                # Wait for next update cycle
                await asyncio.sleep(update_interval_minutes * 60)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error and continue
                await asyncio.sleep(60)  # Wait 1 minute before retrying

    async def _process_intelligence_updates(
        self,
        simulation_id: str,
        intelligence: OSINTResult
    ) -> None:
        """Process intelligence updates for active simulation."""

        # Analyze changes in intelligence
        changes = self._detect_intelligence_changes(intelligence)

        if changes:
            # Notify simulation engine of intelligence changes
            await self._notify_simulation_updates(simulation_id, changes)

    def _detect_intelligence_changes(self, intelligence: OSINTResult) -> List[Dict[str, Any]]:
        """Detect significant changes in intelligence data."""
        changes = []

        # This would compare with previous intelligence data
        # and identify significant changes that could affect simulation

        return changes

    async def _notify_simulation_updates(
        self,
        simulation_id: str,
        changes: List[Dict[str, Any]]
    ) -> None:
        """Notify simulation engine of intelligence updates."""

        # This would integrate with the simulation engine
        # to update active simulations based on new intelligence
        pass

    def get_active_reconnaissance_status(self) -> Dict[str, Dict[str, Any]]:
        """Get status of all active reconnaissance operations."""
        status = {}

        for simulation_id, task in self.active_reconnaissance.items():
            status[simulation_id] = {
                "active": not task.done(),
                "cancelled": task.cancelled(),
                "exception": task.exception() if task.done() and not task.cancelled() else None
            }

        return status
