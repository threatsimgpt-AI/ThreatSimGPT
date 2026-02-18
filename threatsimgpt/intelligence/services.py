"""OSINT and reconnaissance services for ThreatSimGPT.

This module provides internet-connected intelligence gathering services
for real-time target reconnaissance and enhanced threat simulation.
"""

import asyncio
import json
import re
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Union
from urllib.parse import urlparse

import aiohttp
import requests
from bs4 import BeautifulSoup
from pydantic import HttpUrl

from .models import (
    CompanyIntelligence,
    ConfidenceLevel,
    IntelligenceProfile,
    IntelligenceSource,
    OSINTResult,
    SocialMediaIntelligence,
    ThreatIntelligence,
)


class BaseIntelligenceService(ABC):
    """Base class for intelligence gathering services."""

    def __init__(self, rate_limit_requests_per_minute: int = 60):
        self.rate_limit = rate_limit_requests_per_minute
        self.request_timestamps: List[datetime] = []
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession()
        return self._session

    async def cleanup(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def _rate_limit_check(self) -> None:
        """Check and enforce rate limiting."""
        now = datetime.utcnow()
        # Remove requests older than 1 minute
        self.request_timestamps = [
            ts for ts in self.request_timestamps
            if (now - ts).total_seconds() < 60
        ]

        if len(self.request_timestamps) >= self.rate_limit:
            sleep_time = 60 - (now - self.request_timestamps[0]).total_seconds()
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)

        self.request_timestamps.append(now)

    @abstractmethod
    async def gather_intelligence(self, target: str, **kwargs) -> Dict[str, Any]:
        """Gather intelligence for a specific target."""
        pass


class LinkedInIntelligence(BaseIntelligenceService):
    """LinkedIn intelligence gathering service."""

    def __init__(self, api_key: Optional[str] = None, rate_limit: int = 30):
        super().__init__(rate_limit)
        self.api_key = api_key
        self.base_url = "https://api.linkedin.com/v2"

    async def gather_intelligence(self, target: str, **kwargs) -> Dict[str, Any]:
        """Gather LinkedIn intelligence for a target."""
        await self._rate_limit_check()

        # Parse target (could be profile URL, email, or name)
        if target.startswith("https://linkedin.com") or target.startswith("https://www.linkedin.com"):
            return await self._gather_by_profile_url(target)
        elif "@" in target:
            return await self._gather_by_email(target)
        else:
            return await self._gather_by_name(target, kwargs.get("company"))

    async def _gather_by_profile_url(self, profile_url: str) -> Dict[str, Any]:
        """Gather intelligence from LinkedIn profile URL."""
        # Implementation would use LinkedIn API or ethical scraping
        # This is a placeholder implementation
        return {
            "profile_url": profile_url,
            "data_available": False,
            "error": "LinkedIn API integration required",
            "confidence": ConfidenceLevel.LOW,
            "source": IntelligenceSource.LINKEDIN
        }

    async def _gather_by_email(self, email: str) -> Dict[str, Any]:
        """Gather intelligence by email address."""
        # Would integrate with services like Hunter.io, Clearbit, etc.
        domain = email.split("@")[1]
        return {
            "email": email,
            "domain": domain,
            "profile_found": False,
            "confidence": ConfidenceLevel.LOW,
            "source": IntelligenceSource.LINKEDIN
        }

    async def _gather_by_name(self, name: str, company: Optional[str] = None) -> Dict[str, Any]:
        """Gather intelligence by name and optional company."""
        return {
            "name": name,
            "company": company,
            "profiles_found": 0,
            "confidence": ConfidenceLevel.LOW,
            "source": IntelligenceSource.LINKEDIN
        }


class CompanyProfileService(BaseIntelligenceService):
    """Company intelligence gathering service."""

    def __init__(self, rate_limit: int = 60):
        super().__init__(rate_limit)

    async def gather_intelligence(self, domain: str, **kwargs) -> CompanyIntelligence:
        """Gather comprehensive company intelligence."""
        await self._rate_limit_check()

        # Combine multiple intelligence sources
        website_data = await self._scrape_company_website(domain)
        whois_data = await self._gather_whois_data(domain)
        news_data = await self._gather_company_news(domain)
        social_media = await self._gather_company_social_media(domain)

        return CompanyIntelligence(
            company_name=website_data.get("company_name", domain),
            domain=domain,
            website_url=f"https://{domain}",
            industry=website_data.get("industry", "Unknown"),
            company_size=website_data.get("company_size"),
            headquarters=whois_data.get("location"),
            business_description=website_data.get("description"),
            recent_news=news_data.get("articles", []),
            linkedin_company_page=social_media.get("linkedin"),
            twitter_accounts=social_media.get("twitter", []),
            confidence_level=ConfidenceLevel.MEDIUM,
            sources=[IntelligenceSource.COMPANY_WEBSITE, IntelligenceSource.DOMAIN_WHOIS]
        )

    async def _scrape_company_website(self, domain: str) -> Dict[str, Any]:
        """Scrape company website for basic information."""
        try:
            session = await self._get_session()
            timeout = aiohttp.ClientTimeout(total=10)
            async with session.get(f"https://{domain}", timeout=timeout) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')

                    # Extract basic information
                    title = soup.find('title')
                    description = soup.find('meta', attrs={'name': 'description'})

                    return {
                        "company_name": title.get_text() if title else domain,
                        "description": description.get('content') if description else None,
                        "industry": self._extract_industry_from_content(html),
                        "company_size": self._extract_company_size(html)
                    }
        except Exception as e:
            return {"error": str(e), "domain": domain}

    async def _gather_whois_data(self, domain: str) -> Dict[str, Any]:
        """Gather WHOIS data for domain."""
        # Would integrate with whois services
        return {
            "domain": domain,
            "registrar": "Unknown",
            "location": "Unknown",
            "creation_date": None
        }

    async def _gather_company_news(self, domain: str) -> Dict[str, Any]:
        """Gather recent news about the company."""
        # Would integrate with news APIs like NewsAPI, Google News, etc.
        return {
            "articles": [],
            "source": "news_api_placeholder"
        }

    async def _gather_company_social_media(self, domain: str) -> Dict[str, Any]:
        """Find company social media profiles."""
        # Would use various techniques to find social media profiles
        return {
            "linkedin": None,
            "twitter": [],
            "facebook": None
        }

    def _extract_industry_from_content(self, html: str) -> str:
        """Extract industry information from website content."""
        # Simple keyword-based industry detection
        industries = {
            "technology": ["software", "tech", "IT", "development", "programming"],
            "finance": ["bank", "financial", "investment", "trading", "fintech"],
            "healthcare": ["medical", "health", "hospital", "pharmaceutical", "biotech"],
            "retail": ["shop", "store", "retail", "commerce", "shopping"],
            "manufacturing": ["manufacturing", "production", "factory", "industrial"]
        }

        html_lower = html.lower()
        for industry, keywords in industries.items():
            if any(keyword in html_lower for keyword in keywords):
                return industry

        return "Unknown"

    def _extract_company_size(self, html: str) -> Optional[str]:
        """Extract company size information."""
        # Look for employee count indicators
        size_patterns = [
            r"(\d+[\+\-\d]*)\s*employees",
            r"team\s*of\s*(\d+)",
            r"(\d+)\s*people"
        ]

        for pattern in size_patterns:
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                count = int(match.group(1).replace("+", "").replace("-", ""))
                if count < 50:
                    return "Small (1-49)"
                elif count < 250:
                    return "Medium (50-249)"
                elif count < 1000:
                    return "Large (250-999)"
                else:
                    return "Enterprise (1000+)"

        return None


class SocialMediaMonitor(BaseIntelligenceService):
    """Social media intelligence gathering service."""

    def __init__(self, rate_limit: int = 100):
        super().__init__(rate_limit)
        self.supported_platforms = ["twitter", "facebook", "instagram", "github"]

    async def gather_intelligence(self, target: str, platform: str = "all", **kwargs) -> List[SocialMediaIntelligence]:
        """Gather social media intelligence for target."""
        await self._rate_limit_check()

        results = []
        platforms = self.supported_platforms if platform == "all" else [platform]

        for platform_name in platforms:
            if platform_name == "twitter":
                result = await self._gather_twitter_intelligence(target)
            elif platform_name == "github":
                result = await self._gather_github_intelligence(target)
            else:
                result = await self._gather_generic_social_media(target, platform_name)

            if result:
                results.append(result)

        return results

    async def _gather_twitter_intelligence(self, target: str) -> Optional[SocialMediaIntelligence]:
        """Gather Twitter intelligence."""
        # Would integrate with Twitter API
        return SocialMediaIntelligence(
            platform="twitter",
            username=target if not target.startswith("@") else target[1:],
            profile_url=f"https://twitter.com/{target.replace('@', '')}",
            confidence_level=ConfidenceLevel.LOW,
            data_source=IntelligenceSource.TWITTER
        )

    async def _gather_github_intelligence(self, target: str) -> Optional[SocialMediaIntelligence]:
        """Gather GitHub intelligence."""
        try:
            session = await self._get_session()
            async with session.get(f"https://api.github.com/users/{target}") as response:
                if response.status == 200:
                    data = await response.json()
                    return SocialMediaIntelligence(
                        platform="github",
                        username=target,
                        profile_url=data.get("html_url"),
                        display_name=data.get("name"),
                        bio=data.get("bio"),
                        follower_count=data.get("followers"),
                        following_count=data.get("following"),
                        post_count=data.get("public_repos"),
                        confidence_level=ConfidenceLevel.HIGH,
                        data_source=IntelligenceSource.GITHUB
                    )
        except Exception:
            return None

    async def _gather_generic_social_media(self, target: str, platform: str) -> Optional[SocialMediaIntelligence]:
        """Gather generic social media intelligence."""
        return SocialMediaIntelligence(
            platform=platform,
            username=target,
            profile_url=f"https://{platform}.com/{target}",
            confidence_level=ConfidenceLevel.LOW,
            data_source=IntelligenceSource.WEB_SCRAPING
        )


class ThreatIntelligenceService(BaseIntelligenceService):
    """Threat intelligence gathering service."""

    def __init__(self, rate_limit: int = 60):
        super().__init__(rate_limit)
        self.threat_feeds = [
            "misp",
            "otx",
            "threatcrowd",
            "virustotal"
        ]

    async def gather_intelligence(self, ioc: str, **kwargs) -> List[ThreatIntelligence]:
        """Gather threat intelligence for indicators of compromise."""
        await self._rate_limit_check()

        results = []

        # Determine IOC type
        ioc_type = self._determine_ioc_type(ioc)

        if ioc_type == "domain":
            results.extend(await self._gather_domain_threat_intel(ioc))
        elif ioc_type == "ip":
            results.extend(await self._gather_ip_threat_intel(ioc))
        elif ioc_type == "hash":
            results.extend(await self._gather_hash_threat_intel(ioc))

        return results

    def _determine_ioc_type(self, ioc: str) -> str:
        """Determine the type of indicator of compromise."""
        if re.match(r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$', ioc):
            return "hash"
        elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ioc):
            return "ip"
        elif "." in ioc:
            return "domain"
        else:
            return "unknown"

    async def _gather_domain_threat_intel(self, domain: str) -> List[ThreatIntelligence]:
        """Gather threat intelligence for a domain."""
        # Would integrate with threat intelligence feeds
        return [
            ThreatIntelligence(
                threat_name=f"Domain Analysis: {domain}",
                threat_type="domain_reputation",
                description=f"Threat intelligence analysis for domain {domain}",
                severity="medium",
                target_industries=["all"],
                confidence_level=ConfidenceLevel.MEDIUM,
                sources=[IntelligenceSource.THREAT_FEEDS]
            )
        ]

    async def _gather_ip_threat_intel(self, ip: str) -> List[ThreatIntelligence]:
        """Gather threat intelligence for an IP address."""
        return [
            ThreatIntelligence(
                threat_name=f"IP Analysis: {ip}",
                threat_type="ip_reputation",
                description=f"Threat intelligence analysis for IP {ip}",
                severity="medium",
                confidence_level=ConfidenceLevel.MEDIUM,
                sources=[IntelligenceSource.THREAT_FEEDS]
            )
        ]

    async def _gather_hash_threat_intel(self, hash_value: str) -> List[ThreatIntelligence]:
        """Gather threat intelligence for a file hash."""
        return [
            ThreatIntelligence(
                threat_name=f"Hash Analysis: {hash_value[:8]}...",
                threat_type="malware_analysis",
                description=f"Threat intelligence analysis for hash {hash_value}",
                severity="high",
                confidence_level=ConfidenceLevel.MEDIUM,
                sources=[IntelligenceSource.THREAT_FEEDS]
            )
        ]


class DomainAnalysisService(BaseIntelligenceService):
    """Domain analysis and reconnaissance service."""

    def __init__(self, rate_limit: int = 60):
        super().__init__(rate_limit)

    async def gather_intelligence(self, domain: str, **kwargs) -> Dict[str, Any]:
        """Perform comprehensive domain analysis."""
        await self._rate_limit_check()

        results = {}

        # DNS analysis
        results["dns_records"] = await self._gather_dns_records(domain)

        # Subdomain enumeration
        results["subdomains"] = await self._enumerate_subdomains(domain)

        # SSL/TLS analysis
        results["ssl_info"] = await self._analyze_ssl_certificate(domain)

        # Domain reputation
        results["reputation"] = await self._check_domain_reputation(domain)

        # Technology stack
        results["technologies"] = await self._identify_technologies(domain)

        return results

    async def _gather_dns_records(self, domain: str) -> Dict[str, Any]:
        """Gather DNS records for domain."""
        # Would use DNS resolution libraries
        return {
            "a_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": []
        }

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains for the target domain."""
        # Would use various subdomain enumeration techniques
        common_subdomains = [
            "www", "mail", "ftp", "admin", "api", "dev", "test", "staging"
        ]

        found_subdomains = []
        for subdomain in common_subdomains:
            # Check if subdomain exists (placeholder)
            found_subdomains.append(f"{subdomain}.{domain}")

        return found_subdomains

    async def _analyze_ssl_certificate(self, domain: str) -> Dict[str, Any]:
        """Analyze SSL certificate for domain."""
        # Would analyze SSL certificate details
        return {
            "issuer": "Unknown",
            "valid_from": None,
            "valid_to": None,
            "san_domains": []
        }

    async def _check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation across various sources."""
        return {
            "reputation_score": 0,
            "blacklisted": False,
            "reputation_sources": []
        }

    async def _identify_technologies(self, domain: str) -> List[str]:
        """Identify technologies used by the domain."""
        # Would analyze HTTP headers, content, etc.
        return []


class OSINTService:
    """Orchestration service for all OSINT gathering capabilities."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}

        # Initialize individual services
        self.linkedin = LinkedInIntelligence(
            api_key=self.config.get("linkedin_api_key"),
            rate_limit=self.config.get("linkedin_rate_limit", 30)
        )
        self.company_profile = CompanyProfileService(
            rate_limit=self.config.get("company_rate_limit", 60)
        )
        self.social_media = SocialMediaMonitor(
            rate_limit=self.config.get("social_media_rate_limit", 100)
        )
        self.threat_intel = ThreatIntelligenceService(
            rate_limit=self.config.get("threat_intel_rate_limit", 60)
        )
        self.domain_analysis = DomainAnalysisService(
            rate_limit=self.config.get("domain_rate_limit", 60)
        )

    async def comprehensive_reconnaissance(
        self,
        target: str,
        recon_types: List[str] = None,
        **kwargs
    ) -> OSINTResult:
        """Perform comprehensive OSINT reconnaissance on a target."""

        if recon_types is None:
            recon_types = ["profile", "company", "social_media", "threat_intel", "domain"]

        start_time = datetime.utcnow()

        # Initialize result
        result = OSINTResult(
            target_identifier=target,
            query_type="comprehensive_reconnaissance",
            overall_confidence=ConfidenceLevel.MEDIUM,
            data_sources_used=[],
            collection_duration_seconds=0.0,
            completeness_score=0.0,
            data_retention_policy="30_days_standard"
        )

        # Gather intelligence from various sources
        tasks = []

        if "profile" in recon_types:
            tasks.append(self._gather_profile_intelligence(target, result))

        if "company" in recon_types and self._is_domain(target):
            tasks.append(self._gather_company_intelligence(target, result))

        if "social_media" in recon_types:
            tasks.append(self._gather_social_media_intelligence(target, result))

        if "threat_intel" in recon_types:
            tasks.append(self._gather_threat_intelligence(target, result))

        if "domain" in recon_types and self._is_domain(target):
            tasks.append(self._gather_domain_intelligence(target, result))

        # Execute all reconnaissance tasks concurrently
        await asyncio.gather(*tasks, return_exceptions=True)

        # Calculate final metrics
        end_time = datetime.utcnow()
        result.collection_duration_seconds = (end_time - start_time).total_seconds()
        result.completeness_score = self._calculate_completeness_score(result)

        # Generate insights and recommendations
        result.key_findings = self._generate_key_findings(result)
        result.scenario_enhancement_suggestions = self._generate_scenario_suggestions(result)

        return result

    async def _gather_profile_intelligence(self, target: str, result: OSINTResult) -> None:
        """Gather individual profile intelligence."""
        try:
            linkedin_data = await self.linkedin.gather_intelligence(target)
            # Process and add to result
            result.data_sources_used.append(IntelligenceSource.LINKEDIN)
        except Exception as e:
            # Log error but continue
            pass

    async def _gather_company_intelligence(self, domain: str, result: OSINTResult) -> None:
        """Gather company intelligence."""
        try:
            company_data = await self.company_profile.gather_intelligence(domain)
            result.company_intelligence = company_data
            result.data_sources_used.extend(company_data.sources)
        except Exception as e:
            pass

    async def _gather_social_media_intelligence(self, target: str, result: OSINTResult) -> None:
        """Gather social media intelligence."""
        try:
            social_data = await self.social_media.gather_intelligence(target)
            result.social_media_intelligence.extend(social_data)
            for intel in social_data:
                result.data_sources_used.append(intel.data_source)
        except Exception as e:
            pass

    async def _gather_threat_intelligence(self, target: str, result: OSINTResult) -> None:
        """Gather threat intelligence."""
        try:
            threat_data = await self.threat_intel.gather_intelligence(target)
            result.threat_intelligence.extend(threat_data)
            for intel in threat_data:
                result.data_sources_used.extend(intel.sources)
        except Exception as e:
            pass

    async def _gather_domain_intelligence(self, domain: str, result: OSINTResult) -> None:
        """Gather domain analysis intelligence."""
        try:
            domain_data = await self.domain_analysis.gather_intelligence(domain)
            # Add domain analysis results to the result object
            result.data_sources_used.extend([
                IntelligenceSource.DNS_RECORDS,
                IntelligenceSource.DOMAIN_WHOIS
            ])
        except Exception as e:
            pass

    def _is_domain(self, target: str) -> bool:
        """Check if target appears to be a domain."""
        return "." in target and "@" not in target and not target.startswith("http")

    def _calculate_completeness_score(self, result: OSINTResult) -> float:
        """Calculate how complete the reconnaissance was."""
        total_possible_sources = len(IntelligenceSource)
        sources_used = len(set(result.data_sources_used))
        return min(sources_used / total_possible_sources, 1.0)

    def _generate_key_findings(self, result: OSINTResult) -> List[str]:
        """Generate key findings from the reconnaissance."""
        findings = []

        if result.company_intelligence:
            findings.append(f"Company intelligence gathered for {result.company_intelligence.company_name}")

        if result.social_media_intelligence:
            platforms = [intel.platform for intel in result.social_media_intelligence]
            findings.append(f"Social media presence found on: {', '.join(platforms)}")

        if result.threat_intelligence:
            findings.append(f"Found {len(result.threat_intelligence)} threat intelligence indicators")

        return findings

    def _generate_scenario_suggestions(self, result: OSINTResult) -> List[str]:
        """Generate suggestions for enhancing simulation scenarios."""
        suggestions = []

        if result.company_intelligence:
            suggestions.append("Use company-specific terminology and recent news in phishing emails")
            suggestions.append("Reference actual company structure and executives")

        if result.social_media_intelligence:
            suggestions.append("Incorporate social media interests and posting patterns")
            suggestions.append("Use social connections for pretexting scenarios")

        return suggestions
