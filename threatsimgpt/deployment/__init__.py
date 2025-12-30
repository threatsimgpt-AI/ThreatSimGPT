"""Threat deployment and delivery services for ThreatSimGPT.

This module provides comprehensive deployment capabilities for AI-generated
threat content across multiple channels with real-time metrics collection.
"""

import asyncio
import json
from abc import ABC, abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable
from uuid import uuid4

from pydantic import BaseModel, Field


class DeploymentChannel(str, Enum):
    """Available deployment channels for threat campaigns."""
    EMAIL = "email"
    SMS = "sms"
    VOICE = "voice"
    SOCIAL_MEDIA = "social_media"
    WEB = "web"
    PHYSICAL = "physical"


class DeploymentStatus(str, Enum):
    """Status of threat deployment."""
    PENDING = "pending"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class MetricType(str, Enum):
    """Types of metrics collected during campaigns."""
    DELIVERY = "delivery"
    ENGAGEMENT = "engagement"
    BEHAVIORAL = "behavioral"
    SECURITY_RESPONSE = "security_response"
    BUSINESS_IMPACT = "business_impact"


class DeploymentConfig(BaseModel):
    """Configuration for threat deployment."""

    deployment_id: str = Field(default_factory=lambda: str(uuid4()))
    campaign_name: str = Field(..., description="Name of the threat campaign")
    channels: List[DeploymentChannel] = Field(..., description="Deployment channels to use")
    targets: List[Dict[str, Any]] = Field(..., description="Target configurations")

    # Timing configuration
    start_time: Optional[datetime] = Field(None, description="Campaign start time")
    duration_hours: int = Field(24, description="Campaign duration in hours")

    # Content configuration
    content_variants: List[Dict[str, Any]] = Field(
        default_factory=list, description="Content variations to deploy"
    )
    personalization_level: str = Field("high", description="Level of personalization")

    # Safety and compliance
    compliance_approved: bool = Field(False, description="Whether deployment is compliance approved")
    safety_controls_enabled: bool = Field(True, description="Whether safety controls are enabled")
    test_mode: bool = Field(True, description="Whether to run in test mode")

    # Metrics configuration
    metrics_collection_enabled: bool = Field(True, description="Enable metrics collection")
    real_time_dashboard: bool = Field(True, description="Enable real-time dashboard")

    def get_targets_for_channel(self, channel: DeploymentChannel) -> List[Dict[str, Any]]:
        """Get targets configured for a specific channel."""
        return [
            target for target in self.targets
            if channel.value in target.get("channels", [])
        ]


class DeploymentResult(BaseModel):
    """Result of threat deployment operation."""

    deployment_id: str
    channel: DeploymentChannel
    status: DeploymentStatus

    # Deployment metrics
    targets_attempted: int = Field(0, description="Number of targets attempted")
    targets_successful: int = Field(0, description="Number of successful deployments")
    targets_failed: int = Field(0, description="Number of failed deployments")

    # Timing information
    deployment_start: datetime = Field(default_factory=datetime.utcnow)
    deployment_duration_seconds: float = Field(0.0, description="Deployment duration")

    # Results data
    deployment_details: Dict[str, Any] = Field(default_factory=dict)
    error_details: List[Dict[str, Any]] = Field(default_factory=list)

    # Metrics tracking
    metrics_endpoint: Optional[str] = Field(None, description="Metrics collection endpoint")
    tracking_ids: List[str] = Field(default_factory=list, description="Individual tracking IDs")


class CampaignMetrics(BaseModel):
    """Comprehensive campaign metrics."""

    campaign_id: str
    collection_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Primary engagement metrics
    emails_sent: int = 0
    emails_delivered: int = 0
    emails_opened: int = 0
    links_clicked: int = 0
    attachments_downloaded: int = 0
    credentials_submitted: int = 0

    # Multi-channel metrics
    sms_sent: int = 0
    sms_delivered: int = 0
    sms_clicked: int = 0

    voice_calls_attempted: int = 0
    voice_calls_connected: int = 0
    voice_calls_successful: int = 0

    # Behavioral metrics
    security_escalations: int = 0
    verification_attempts: int = 0
    suspicious_behavior_detected: int = 0

    # Advanced analytics
    average_response_time_seconds: float = 0.0
    peak_engagement_hour: Optional[int] = None
    geographic_distribution: Dict[str, int] = Field(default_factory=dict)
    demographic_patterns: Dict[str, Any] = Field(default_factory=dict)

    # Business impact
    training_effectiveness_score: float = 0.0
    security_awareness_improvement: float = 0.0
    policy_compliance_impact: float = 0.0

    def calculate_engagement_rate(self) -> float:
        """Calculate overall engagement rate."""
        if self.emails_sent == 0:
            return 0.0
        return (self.emails_opened + self.links_clicked) / self.emails_sent

    def calculate_success_rate(self) -> float:
        """Calculate campaign success rate."""
        total_interactions = (
            self.links_clicked +
            self.attachments_downloaded +
            self.credentials_submitted +
            self.sms_clicked +
            self.voice_calls_successful
        )
        total_attempts = (
            self.emails_sent +
            self.sms_sent +
            self.voice_calls_attempted
        )

        if total_attempts == 0:
            return 0.0
        return total_interactions / total_attempts


class BaseDeploymentService(ABC):
    """Base class for threat deployment services."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.metrics_callback: Optional[Callable] = None

    @abstractmethod
    async def deploy(
        self,
        content: Dict[str, Any],
        targets: List[Dict[str, Any]],
        metrics_callback: Optional[Callable] = None
    ) -> DeploymentResult:
        """Deploy threat content to targets."""
        pass

    @abstractmethod
    async def get_deployment_status(self, deployment_id: str) -> DeploymentStatus:
        """Get current deployment status."""
        pass

    @abstractmethod
    async def cancel_deployment(self, deployment_id: str) -> bool:
        """Cancel an active deployment."""
        pass


class EmailDeploymentService(BaseDeploymentService):
    """Email-based threat deployment service."""

    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.email_provider = config.get("email_provider", "sendgrid")
        self.domain_setup = config.get("domain_setup", {})

    async def deploy(
        self,
        content: Dict[str, Any],
        targets: List[Dict[str, Any]],
        metrics_callback: Optional[Callable] = None
    ) -> DeploymentResult:
        """Deploy phishing emails to targets."""

        deployment_id = str(uuid4())
        start_time = datetime.utcnow()

        # Set up email infrastructure
        infrastructure = await self._setup_email_infrastructure(content)

        # Deploy emails
        successful_deployments = 0
        failed_deployments = 0
        tracking_ids = []

        for target in targets:
            try:
                # Personalize content for target
                personalized_content = await self._personalize_email_content(content, target)

                # Send email
                tracking_id = await self._send_email(
                    target=target,
                    content=personalized_content,
                    infrastructure=infrastructure
                )

                tracking_ids.append(tracking_id)
                successful_deployments += 1

                # Record metrics
                if metrics_callback:
                    await metrics_callback("email_sent", {
                        "deployment_id": deployment_id,
                        "target_id": target.get("id"),
                        "tracking_id": tracking_id,
                        "timestamp": datetime.utcnow()
                    })

            except Exception as e:
                failed_deployments += 1
                # Log error but continue

        # Calculate deployment duration
        deployment_duration = (datetime.utcnow() - start_time).total_seconds()

        return DeploymentResult(
            deployment_id=deployment_id,
            channel=DeploymentChannel.EMAIL,
            status=DeploymentStatus.COMPLETED if failed_deployments == 0 else DeploymentStatus.ACTIVE,
            targets_attempted=len(targets),
            targets_successful=successful_deployments,
            targets_failed=failed_deployments,
            deployment_start=start_time,
            deployment_duration_seconds=deployment_duration,
            tracking_ids=tracking_ids,
            deployment_details={
                "email_provider": self.email_provider,
                "infrastructure": infrastructure,
                "personalization_applied": True
            }
        )

    async def _setup_email_infrastructure(self, content: Dict[str, Any]) -> Dict[str, Any]:
        """Set up email infrastructure for the campaign."""

        # Register spoofed domains
        spoofed_domains = await self._register_spoofed_domains(content)

        # Create landing pages
        landing_pages = await self._create_landing_pages(content)

        # Set up tracking
        tracking_infrastructure = await self._setup_tracking()

        return {
            "spoofed_domains": spoofed_domains,
            "landing_pages": landing_pages,
            "tracking": tracking_infrastructure,
            "smtp_servers": await self._setup_smtp_servers(spoofed_domains)
        }

    async def _personalize_email_content(
        self,
        content: Dict[str, Any],
        target: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Personalize email content for specific target."""

        personalized = content.copy()

        # Replace personalization tokens
        replacements = {
            "{target_name}": target.get("name", ""),
            "{target_company}": target.get("company", ""),
            "{target_role}": target.get("role", ""),
            "{current_date}": datetime.now().strftime("%Y-%m-%d")
        }

        # Apply replacements to subject and body
        for field in ["subject", "body_text", "body_html"]:
            if field in personalized:
                for token, replacement in replacements.items():
                    personalized[field] = personalized[field].replace(token, replacement)

        return personalized

    async def _send_email(
        self,
        target: Dict[str, Any],
        content: Dict[str, Any],
        infrastructure: Dict[str, Any]
    ) -> str:
        """Send personalized email to target.

        This method requires a configured email provider (sendgrid, ses, smtp).
        Set the provider in config with required credentials.
        """

        tracking_id = str(uuid4())

        email_data = {
            "to": target.get("email"),
            "from": content.get("sender_email"),
            "subject": content.get("subject"),
            "body": content.get("body_html"),
            "tracking_id": tracking_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        # Route to configured email provider
        if self.email_provider == "sendgrid":
            await self._send_via_sendgrid(email_data)
        elif self.email_provider == "ses":
            await self._send_via_ses(email_data)
        elif self.email_provider == "smtp":
            await self._send_via_smtp(email_data, infrastructure)
        else:
            raise NotImplementedError(
                f"Email provider '{self.email_provider}' is not configured. "
                "Supported providers: sendgrid, ses, smtp. "
                "Configure provider credentials in deployment config."
            )

        return tracking_id

    async def _send_via_sendgrid(self, email_data: Dict[str, Any]) -> None:
        """Send email via SendGrid API."""
        api_key = self.config.get("sendgrid_api_key")
        if not api_key:
            raise ValueError("SendGrid API key not configured. Set 'sendgrid_api_key' in config.")

        # SendGrid API integration
        import aiohttp
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json"
            }
            payload = {
                "personalizations": [{"to": [{"email": email_data["to"]}]}],
                "from": {"email": email_data["from"]},
                "subject": email_data["subject"],
                "content": [{"type": "text/html", "value": email_data["body"]}],
                "custom_args": {"tracking_id": email_data["tracking_id"]}
            }
            async with session.post(
                "https://api.sendgrid.com/v3/mail/send",
                headers=headers,
                json=payload
            ) as response:
                if response.status not in (200, 202):
                    error_text = await response.text()
                    raise RuntimeError(f"SendGrid API error: {response.status} - {error_text}")

    async def _send_via_ses(self, email_data: Dict[str, Any]) -> None:
        """Send email via AWS SES."""
        try:
            import aiobotocore.session
        except ImportError:
            raise ImportError("aiobotocore required for SES. Install with: pip install aiobotocore")

        session = aiobotocore.session.get_session()
        async with session.create_client(
            'ses',
            region_name=self.config.get("aws_region", "us-east-1"),
            aws_access_key_id=self.config.get("aws_access_key_id"),
            aws_secret_access_key=self.config.get("aws_secret_access_key")
        ) as client:
            await client.send_email(
                Source=email_data["from"],
                Destination={"ToAddresses": [email_data["to"]]},
                Message={
                    "Subject": {"Data": email_data["subject"]},
                    "Body": {"Html": {"Data": email_data["body"]}}
                }
            )

    async def _send_via_smtp(
        self,
        email_data: Dict[str, Any],
        infrastructure: Dict[str, Any]
    ) -> None:
        """Send email via SMTP server."""
        import aiosmtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        smtp_config = self.config.get("smtp", {})
        smtp_server = smtp_config.get("server") or infrastructure.get("smtp_servers", [{}])[0].get("smtp_server")
        smtp_port = smtp_config.get("port", 587)
        smtp_username = smtp_config.get("username")
        smtp_password = smtp_config.get("password")

        if not smtp_server:
            raise ValueError("SMTP server not configured. Set 'smtp.server' in config.")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = email_data["subject"]
        msg["From"] = email_data["from"]
        msg["To"] = email_data["to"]
        msg["X-Tracking-ID"] = email_data["tracking_id"]
        msg.attach(MIMEText(email_data["body"], "html"))

        await aiosmtplib.send(
            msg,
            hostname=smtp_server,
            port=smtp_port,
            username=smtp_username,
            password=smtp_password,
            start_tls=True
        )

    async def _register_spoofed_domains(self, content: Dict[str, Any]) -> List[str]:
        """Register spoofed domains for the campaign."""
        # Development domain registration
        return ["fake-company.com", "secure-login.net"]

    async def _create_landing_pages(self, content: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Create credential harvesting landing pages."""
        # Development landing page creation
        return [
            {
                "url": "https://fake-company.com/login",
                "type": "credential_harvest",
                "template": "office365_clone"
            }
        ]

    async def _setup_tracking(self) -> Dict[str, Any]:
        """Set up tracking infrastructure."""
        return {
            "tracking_domain": "analytics.fake-company.com",
            "pixel_tracking": True,
            "link_tracking": True,
            "download_tracking": True
        }

    async def _setup_smtp_servers(self, domains: List[str]) -> List[Dict[str, Any]]:
        """Set up SMTP servers for spoofed domains."""
        return [
            {
                "domain": domain,
                "smtp_server": f"mail.{domain}",
                "port": 587,
                "encryption": "TLS"
            }
            for domain in domains
        ]

    async def get_deployment_status(self, deployment_id: str) -> DeploymentStatus:
        """Get current deployment status."""
        # Development status check
        return DeploymentStatus.ACTIVE

    async def cancel_deployment(self, deployment_id: str) -> bool:
        """Cancel an active deployment."""
        # Development cancellation
        return True


class SMSDeploymentService(BaseDeploymentService):
    """SMS-based threat deployment service."""

    async def deploy(
        self,
        content: Dict[str, Any],
        targets: List[Dict[str, Any]],
        metrics_callback: Optional[Callable] = None
    ) -> DeploymentResult:
        """Deploy smishing messages to targets."""

        deployment_id = str(uuid4())
        start_time = datetime.utcnow()

        successful_deployments = 0
        failed_deployments = 0
        tracking_ids = []

        for target in targets:
            try:
                # Personalize SMS content
                personalized_sms = await self._personalize_sms_content(content, target)

                # Send SMS
                tracking_id = await self._send_sms(target, personalized_sms)
                tracking_ids.append(tracking_id)
                successful_deployments += 1

                # Record metrics
                if metrics_callback:
                    await metrics_callback("sms_sent", {
                        "deployment_id": deployment_id,
                        "target_id": target.get("id"),
                        "tracking_id": tracking_id,
                        "timestamp": datetime.utcnow()
                    })

            except Exception as e:
                failed_deployments += 1

        deployment_duration = (datetime.utcnow() - start_time).total_seconds()

        return DeploymentResult(
            deployment_id=deployment_id,
            channel=DeploymentChannel.SMS,
            status=DeploymentStatus.COMPLETED,
            targets_attempted=len(targets),
            targets_successful=successful_deployments,
            targets_failed=failed_deployments,
            deployment_start=start_time,
            deployment_duration_seconds=deployment_duration,
            tracking_ids=tracking_ids
        )

    async def _personalize_sms_content(
        self,
        content: Dict[str, Any],
        target: Dict[str, Any]
    ) -> str:
        """Personalize SMS content for target."""

        message = content.get("message", "")

        # Apply personalization
        replacements = {
            "{target_name}": target.get("name", ""),
            "{target_company}": target.get("company", "")
        }

        for token, replacement in replacements.items():
            message = message.replace(token, replacement)

        return message

    async def _send_sms(self, target: Dict[str, Any], message: str) -> str:
        """Send SMS to target.

        This method requires a configured SMS provider (twilio, nexmo, aws_sns).
        Set the provider in config with required credentials.
        """

        tracking_id = str(uuid4())

        sms_data = {
            "to": target.get("phone"),
            "message": message,
            "tracking_id": tracking_id,
            "timestamp": datetime.utcnow().isoformat()
        }

        sms_provider = self.config.get("sms_provider", "twilio")

        if sms_provider == "twilio":
            await self._send_via_twilio(sms_data)
        elif sms_provider == "nexmo":
            await self._send_via_nexmo(sms_data)
        elif sms_provider == "aws_sns":
            await self._send_via_sns(sms_data)
        else:
            raise NotImplementedError(
                f"SMS provider '{sms_provider}' is not configured. "
                "Supported providers: twilio, nexmo, aws_sns. "
                "Configure provider credentials in deployment config."
            )

        return tracking_id

    async def _send_via_twilio(self, sms_data: Dict[str, Any]) -> None:
        """Send SMS via Twilio API."""
        account_sid = self.config.get("twilio_account_sid")
        auth_token = self.config.get("twilio_auth_token")
        from_number = self.config.get("twilio_from_number")

        if not all([account_sid, auth_token, from_number]):
            raise ValueError(
                "Twilio credentials not configured. Set 'twilio_account_sid', "
                "'twilio_auth_token', and 'twilio_from_number' in config."
            )

        import aiohttp
        import base64

        auth = base64.b64encode(f"{account_sid}:{auth_token}".encode()).decode()

        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Basic {auth}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            payload = {
                "To": sms_data["to"],
                "From": from_number,
                "Body": sms_data["message"]
            }
            async with session.post(
                f"https://api.twilio.com/2010-04-01/Accounts/{account_sid}/Messages.json",
                headers=headers,
                data=payload
            ) as response:
                if response.status not in (200, 201):
                    error_text = await response.text()
                    raise RuntimeError(f"Twilio API error: {response.status} - {error_text}")

    async def _send_via_nexmo(self, sms_data: Dict[str, Any]) -> None:
        """Send SMS via Nexmo/Vonage API."""
        api_key = self.config.get("nexmo_api_key")
        api_secret = self.config.get("nexmo_api_secret")
        from_number = self.config.get("nexmo_from_number")

        if not all([api_key, api_secret, from_number]):
            raise ValueError(
                "Nexmo credentials not configured. Set 'nexmo_api_key', "
                "'nexmo_api_secret', and 'nexmo_from_number' in config."
            )

        import aiohttp

        async with aiohttp.ClientSession() as session:
            payload = {
                "api_key": api_key,
                "api_secret": api_secret,
                "to": sms_data["to"],
                "from": from_number,
                "text": sms_data["message"]
            }
            async with session.post(
                "https://rest.nexmo.com/sms/json",
                json=payload
            ) as response:
                result = await response.json()
                if result.get("messages", [{}])[0].get("status") != "0":
                    raise RuntimeError(f"Nexmo API error: {result}")

    async def _send_via_sns(self, sms_data: Dict[str, Any]) -> None:
        """Send SMS via AWS SNS."""
        try:
            import aiobotocore.session
        except ImportError:
            raise ImportError("aiobotocore required for SNS. Install with: pip install aiobotocore")

        session = aiobotocore.session.get_session()
        async with session.create_client(
            'sns',
            region_name=self.config.get("aws_region", "us-east-1"),
            aws_access_key_id=self.config.get("aws_access_key_id"),
            aws_secret_access_key=self.config.get("aws_secret_access_key")
        ) as client:
            await client.publish(
                PhoneNumber=sms_data["to"],
                Message=sms_data["message"]
            )

    async def get_deployment_status(self, deployment_id: str) -> DeploymentStatus:
        return DeploymentStatus.ACTIVE

    async def cancel_deployment(self, deployment_id: str) -> bool:
        return True


class ThreatMetricsCollector:
    """Comprehensive metrics collection for threat campaigns."""

    def __init__(self):
        self.metrics_storage = {}  # In production, use proper database
        self.active_campaigns = {}

    async def start_campaign_tracking(
        self,
        campaign_config: DeploymentConfig,
        deployment_results: List[DeploymentResult]
    ) -> str:
        """Start tracking metrics for a campaign."""

        campaign_id = str(uuid4())

        # Initialize campaign metrics
        self.active_campaigns[campaign_id] = CampaignMetrics(
            campaign_id=campaign_id
        )

        return campaign_id

    async def record_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Record a campaign event."""

        campaign_id = event_data.get("campaign_id")
        if not campaign_id or campaign_id not in self.active_campaigns:
            return

        metrics = self.active_campaigns[campaign_id]

        # Update metrics based on event type
        if event_type == "email_sent":
            metrics.emails_sent += 1
        elif event_type == "email_delivered":
            metrics.emails_delivered += 1
        elif event_type == "email_opened":
            metrics.emails_opened += 1
        elif event_type == "link_clicked":
            metrics.links_clicked += 1
        elif event_type == "credentials_submitted":
            metrics.credentials_submitted += 1
        elif event_type == "sms_sent":
            metrics.sms_sent += 1
        elif event_type == "security_escalation":
            metrics.security_escalations += 1

        # Store event details
        event_record = {
            "campaign_id": campaign_id,
            "event_type": event_type,
            "event_data": event_data,
            "timestamp": datetime.utcnow().isoformat()
        }

        if campaign_id not in self.metrics_storage:
            self.metrics_storage[campaign_id] = []

        self.metrics_storage[campaign_id].append(event_record)

    async def get_campaign_metrics(self, campaign_id: str) -> Optional[CampaignMetrics]:
        """Get current metrics for a campaign."""
        return self.active_campaigns.get(campaign_id)

    async def get_real_time_dashboard_data(self, campaign_id: str) -> Dict[str, Any]:
        """Get real-time dashboard data for a campaign."""

        metrics = self.active_campaigns.get(campaign_id)
        if not metrics:
            return {}

        return {
            "campaign_id": campaign_id,
            "active_since": metrics.collection_timestamp.isoformat(),
            "engagement_metrics": {
                "emails_sent": metrics.emails_sent,
                "emails_opened": metrics.emails_opened,
                "links_clicked": metrics.links_clicked,
                "credentials_submitted": metrics.credentials_submitted,
                "engagement_rate": metrics.calculate_engagement_rate()
            },
            "security_metrics": {
                "escalations": metrics.security_escalations,
                "verification_attempts": metrics.verification_attempts,
                "suspicious_behavior": metrics.suspicious_behavior_detected
            },
            "performance_metrics": {
                "success_rate": metrics.calculate_success_rate(),
                "average_response_time": metrics.average_response_time_seconds,
                "peak_engagement_hour": metrics.peak_engagement_hour
            }
        }


class ThreatDeploymentEngine:
    """Main orchestrator for threat deployment across multiple channels."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.deployment_services = {
            DeploymentChannel.EMAIL: EmailDeploymentService(config.get("email", {})),
            DeploymentChannel.SMS: SMSDeploymentService(config.get("sms", {})),
            # Add other services as needed
        }
        self.metrics_collector = ThreatMetricsCollector()

    async def deploy_threat_campaign(
        self,
        generated_content: Dict[str, Any],
        deployment_config: DeploymentConfig
    ) -> tuple[str, List[DeploymentResult]]:
        """Deploy AI-generated content through configured channels."""

        # Validate deployment configuration
        if not deployment_config.compliance_approved and not deployment_config.test_mode:
            raise ValueError("Deployment must be compliance approved for production use")

        # Deploy across channels
        deployment_results = []

        for channel in deployment_config.channels:
            if channel not in self.deployment_services:
                continue

            # Get targets for this channel
            channel_targets = deployment_config.get_targets_for_channel(channel)
            if not channel_targets:
                continue

            # Deploy through channel
            service = self.deployment_services[channel]
            result = await service.deploy(
                content=generated_content.get(channel.value, {}),
                targets=channel_targets,
                metrics_callback=self.metrics_collector.record_event
            )

            deployment_results.append(result)

        # Start campaign tracking
        campaign_id = await self.metrics_collector.start_campaign_tracking(
            campaign_config=deployment_config,
            deployment_results=deployment_results
        )

        return campaign_id, deployment_results

    async def get_campaign_status(self, campaign_id: str) -> Dict[str, Any]:
        """Get comprehensive campaign status."""

        metrics = await self.metrics_collector.get_campaign_metrics(campaign_id)
        dashboard_data = await self.metrics_collector.get_real_time_dashboard_data(campaign_id)

        return {
            "campaign_id": campaign_id,
            "metrics": metrics.model_dump() if metrics else {},
            "dashboard": dashboard_data,
            "status": "active"  # Determine actual status
        }

    async def cancel_campaign(self, campaign_id: str) -> bool:
        """Cancel an active campaign."""

        # Cancel all active deployments for this campaign
        success = True

        for service in self.deployment_services.values():
            try:
                await service.cancel_deployment(campaign_id)
            except Exception:
                success = False

        return success
