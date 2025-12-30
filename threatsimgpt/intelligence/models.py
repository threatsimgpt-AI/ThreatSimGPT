"""Intelligence data models for ThreatSimGPT OSINT capabilities.

This module defines data structures for storing and processing
real-time intelligence gathered from various online sources.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator


class ConfidenceLevel(str, Enum):
    """Confidence levels for intelligence data."""
    VERY_HIGH = "very_high"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    VERY_LOW = "very_low"


class IntelligenceSource(str, Enum):
    """Sources of intelligence data."""
    LINKEDIN = "linkedin"
    TWITTER = "twitter"
    FACEBOOK = "facebook"
    COMPANY_WEBSITE = "company_website"
    NEWS_ARTICLES = "news_articles"
    SEC_FILINGS = "sec_filings"
    DOMAIN_WHOIS = "domain_whois"
    DNS_RECORDS = "dns_records"
    SSL_CERTIFICATES = "ssl_certificates"
    GITHUB = "github"
    GLASSDOOR = "glassdoor"
    CRUNCHBASE = "crunchbase"
    THREAT_FEEDS = "threat_feeds"
    OSINT_AGGREGATORS = "osint_aggregators"
    WEB_SCRAPING = "web_scraping"


class IntelligenceProfile(BaseModel):
    """Comprehensive intelligence profile for a target individual."""

    # Basic identification
    full_name: str = Field(..., description="Full name of the target")
    email: Optional[str] = Field(None, description="Email address if known")
    job_title: Optional[str] = Field(None, description="Current job title")
    company: Optional[str] = Field(None, description="Current company")
    department: Optional[str] = Field(None, description="Department or division")

    # Professional information
    linkedin_profile: Optional[HttpUrl] = Field(None, description="LinkedIn profile URL")
    professional_experience: List[Dict[str, Any]] = Field(
        default_factory=list, description="Work history and experience"
    )
    skills: List[str] = Field(default_factory=list, description="Professional skills")
    certifications: List[str] = Field(default_factory=list, description="Professional certifications")
    education: List[Dict[str, Any]] = Field(
        default_factory=list, description="Educational background"
    )

    # Social media presence
    twitter_handle: Optional[str] = Field(None, description="Twitter username")
    facebook_profile: Optional[HttpUrl] = Field(None, description="Facebook profile URL")
    github_username: Optional[str] = Field(None, description="GitHub username")
    other_social_media: Dict[str, str] = Field(
        default_factory=dict, description="Other social media profiles"
    )

    # Personal information (ethically gathered)
    interests: List[str] = Field(default_factory=list, description="Personal interests")
    hobbies: List[str] = Field(default_factory=list, description="Hobbies and activities")
    location: Optional[str] = Field(None, description="Geographic location")
    languages: List[str] = Field(default_factory=list, description="Languages spoken")

    # Professional network
    connections: List[Dict[str, Any]] = Field(
        default_factory=list, description="Professional connections"
    )
    industry_involvement: List[str] = Field(
        default_factory=list, description="Industry groups and involvement"
    )

    # Intelligence metadata
    profile_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique profile ID")
    confidence_level: ConfidenceLevel = Field(..., description="Overall confidence in data")
    sources: List[IntelligenceSource] = Field(..., description="Data sources used")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    data_freshness_hours: int = Field(default=0, description="Hours since data was collected")

    # Privacy and compliance
    collection_consent: bool = Field(default=False, description="Whether collection was consented")
    data_retention_days: int = Field(default=90, description="Days to retain this data")
    anonymization_required: bool = Field(default=True, description="Whether anonymization is required")


class CompanyIntelligence(BaseModel):
    """Intelligence profile for target organization."""

    # Basic company information
    company_name: str = Field(..., description="Official company name")
    domain: str = Field(..., description="Primary domain name")
    website_url: HttpUrl = Field(..., description="Main website URL")
    industry: str = Field(..., description="Primary industry sector")
    company_size: Optional[str] = Field(None, description="Employee count category")
    headquarters: Optional[str] = Field(None, description="Headquarters location")

    # Business intelligence
    annual_revenue: Optional[str] = Field(None, description="Annual revenue if public")
    stock_symbol: Optional[str] = Field(None, description="Stock ticker symbol")
    founding_year: Optional[int] = Field(None, description="Year founded")
    business_description: Optional[str] = Field(None, description="Business description")
    key_products: List[str] = Field(default_factory=list, description="Key products/services")

    # Organizational structure
    executives: List[Dict[str, Any]] = Field(
        default_factory=list, description="Executive team information"
    )
    departments: List[str] = Field(default_factory=list, description="Known departments")
    office_locations: List[Dict[str, str]] = Field(
        default_factory=list, description="Office locations"
    )

    # Recent activity and news
    recent_news: List[Dict[str, Any]] = Field(
        default_factory=list, description="Recent news articles"
    )
    press_releases: List[Dict[str, Any]] = Field(
        default_factory=list, description="Recent press releases"
    )
    financial_filings: List[Dict[str, Any]] = Field(
        default_factory=list, description="SEC filings if public company"
    )

    # Technology and security
    technologies_used: List[str] = Field(
        default_factory=list, description="Known technologies and platforms"
    )
    email_domains: List[str] = Field(
        default_factory=list, description="Email domains used"
    )
    security_policies: Dict[str, Any] = Field(
        default_factory=dict, description="Known security policies"
    )

    # Social media and online presence
    linkedin_company_page: Optional[HttpUrl] = Field(None, description="LinkedIn company page")
    twitter_accounts: List[str] = Field(default_factory=list, description="Official Twitter accounts")
    facebook_page: Optional[HttpUrl] = Field(None, description="Official Facebook page")
    youtube_channel: Optional[HttpUrl] = Field(None, description="YouTube channel")

    # Competitive intelligence
    competitors: List[str] = Field(default_factory=list, description="Known competitors")
    partnerships: List[str] = Field(default_factory=list, description="Strategic partnerships")
    acquisitions: List[Dict[str, Any]] = Field(
        default_factory=list, description="Recent acquisitions"
    )

    # Intelligence metadata
    intelligence_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique intelligence ID")
    confidence_level: ConfidenceLevel = Field(..., description="Overall confidence in data")
    sources: List[IntelligenceSource] = Field(..., description="Data sources used")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")
    data_freshness_hours: int = Field(default=0, description="Hours since data was collected")


class SocialMediaIntelligence(BaseModel):
    """Social media intelligence for targets."""

    # Platform-specific data
    platform: str = Field(..., description="Social media platform")
    username: str = Field(..., description="Username or handle")
    profile_url: HttpUrl = Field(..., description="Profile URL")

    # Profile information
    display_name: Optional[str] = Field(None, description="Display name")
    bio: Optional[str] = Field(None, description="Profile biography")
    follower_count: Optional[int] = Field(None, description="Number of followers")
    following_count: Optional[int] = Field(None, description="Number following")
    post_count: Optional[int] = Field(None, description="Number of posts")

    # Recent activity
    recent_posts: List[Dict[str, Any]] = Field(
        default_factory=list, description="Recent posts and content"
    )
    posting_patterns: Dict[str, Any] = Field(
        default_factory=dict, description="Posting frequency and timing patterns"
    )
    engagement_metrics: Dict[str, Any] = Field(
        default_factory=dict, description="Engagement statistics"
    )

    # Content analysis
    topics_of_interest: List[str] = Field(
        default_factory=list, description="Topics frequently discussed"
    )
    sentiment_analysis: Dict[str, Any] = Field(
        default_factory=dict, description="Sentiment analysis of posts"
    )
    hashtags_used: List[str] = Field(
        default_factory=list, description="Frequently used hashtags"
    )

    # Network analysis
    connections: List[Dict[str, Any]] = Field(
        default_factory=list, description="Social connections"
    )
    influencers_followed: List[str] = Field(
        default_factory=list, description="Influencers or thought leaders followed"
    )

    # Privacy and security
    privacy_settings: Dict[str, bool] = Field(
        default_factory=dict, description="Known privacy settings"
    )
    security_indicators: List[str] = Field(
        default_factory=list, description="Security awareness indicators"
    )

    # Intelligence metadata
    intelligence_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique intelligence ID")
    confidence_level: ConfidenceLevel = Field(..., description="Confidence in data accuracy")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")
    data_source: IntelligenceSource = Field(..., description="Data source")


class ThreatIntelligence(BaseModel):
    """Threat intelligence data for enhanced simulation realism."""

    # Threat identification
    threat_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique threat ID")
    threat_name: str = Field(..., description="Threat name or identifier")
    threat_type: str = Field(..., description="Type of threat")

    # MITRE ATT&CK mapping
    mitre_techniques: List[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK techniques"
    )
    mitre_tactics: List[str] = Field(
        default_factory=list, description="Associated MITRE ATT&CK tactics"
    )

    # Threat details
    description: str = Field(..., description="Detailed threat description")
    severity: str = Field(..., description="Threat severity level")
    indicators_of_compromise: List[str] = Field(
        default_factory=list, description="Known IoCs"
    )

    # Campaign information
    campaign_name: Optional[str] = Field(None, description="Associated campaign name")
    threat_actor: Optional[str] = Field(None, description="Known threat actor")
    target_industries: List[str] = Field(
        default_factory=list, description="Targeted industries"
    )
    target_regions: List[str] = Field(
        default_factory=list, description="Targeted geographic regions"
    )

    # Technical details
    attack_vectors: List[str] = Field(
        default_factory=list, description="Attack vectors used"
    )
    malware_families: List[str] = Field(
        default_factory=list, description="Associated malware families"
    )
    infrastructure: Dict[str, Any] = Field(
        default_factory=dict, description="Associated infrastructure"
    )

    # Temporal information
    first_seen: Optional[datetime] = Field(None, description="First observation date")
    last_seen: Optional[datetime] = Field(None, description="Last observation date")
    is_active: bool = Field(default=True, description="Whether threat is currently active")

    # Intelligence metadata
    confidence_level: ConfidenceLevel = Field(..., description="Confidence in threat data")
    sources: List[IntelligenceSource] = Field(..., description="Intelligence sources")
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Collection timestamp")

    # Simulation relevance
    simulation_applicability: Dict[str, Any] = Field(
        default_factory=dict, description="How this threat applies to simulations"
    )
    realism_enhancement: List[str] = Field(
        default_factory=list, description="Ways this enhances simulation realism"
    )


class OSINTResult(BaseModel):
    """Complete OSINT reconnaissance result."""

    # Query information
    query_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique query ID")
    target_identifier: str = Field(..., description="Target identifier (email, domain, name)")
    query_type: str = Field(..., description="Type of OSINT query")
    query_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Query timestamp")

    # Results
    individual_profiles: List[IntelligenceProfile] = Field(
        default_factory=list, description="Individual intelligence profiles"
    )
    company_intelligence: Optional[CompanyIntelligence] = Field(
        None, description="Company intelligence if applicable"
    )
    social_media_intelligence: List[SocialMediaIntelligence] = Field(
        default_factory=list, description="Social media intelligence"
    )
    threat_intelligence: List[ThreatIntelligence] = Field(
        default_factory=list, description="Relevant threat intelligence"
    )

    # Analysis and insights
    key_findings: List[str] = Field(
        default_factory=list, description="Key intelligence findings"
    )
    attack_surface_analysis: Dict[str, Any] = Field(
        default_factory=dict, description="Attack surface assessment"
    )
    vulnerability_indicators: List[str] = Field(
        default_factory=list, description="Potential vulnerability indicators"
    )

    # Social engineering insights
    psychological_profile: Dict[str, Any] = Field(
        default_factory=dict, description="Psychological profiling insights"
    )
    social_engineering_vectors: List[str] = Field(
        default_factory=list, description="Potential social engineering approaches"
    )
    personalization_data: Dict[str, Any] = Field(
        default_factory=dict, description="Data for personalizing attacks"
    )

    # Quality and reliability
    overall_confidence: ConfidenceLevel = Field(..., description="Overall confidence in results")
    data_sources_used: List[IntelligenceSource] = Field(..., description="All data sources used")
    collection_duration_seconds: float = Field(..., description="Time taken to collect data")
    completeness_score: float = Field(..., ge=0.0, le=1.0, description="Data completeness score")

    # Privacy and compliance
    privacy_controls_applied: List[str] = Field(
        default_factory=list, description="Privacy controls applied during collection"
    )
    data_retention_policy: str = Field(..., description="Data retention policy applied")
    ethical_guidelines_followed: bool = Field(default=True, description="Whether ethical guidelines were followed")

    # Simulation enhancement
    scenario_enhancement_suggestions: List[str] = Field(
        default_factory=list, description="Suggestions for enhancing simulation scenarios"
    )
    realism_factors: Dict[str, Any] = Field(
        default_factory=dict, description="Factors that enhance simulation realism"
    )

    @field_validator('completeness_score')
    @classmethod
    def validate_completeness_score(cls, v):
        """Validate completeness score is between 0 and 1."""
        if not 0.0 <= v <= 1.0:
            raise ValueError("Completeness score must be between 0.0 and 1.0")
        return v

    @field_validator('collection_duration_seconds')
    @classmethod
    def validate_collection_duration(cls, v):
        """Validate collection duration is positive."""
        if v < 0:
            raise ValueError("Collection duration must be positive")
        return v
