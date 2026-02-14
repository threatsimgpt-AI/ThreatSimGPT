"""Real-time analytics and dashboard services for ThreatSimGPT campaigns.

This module provides comprehensive analytics, machine learning-enhanced
insights, and real-time dashboards for threat simulation campaigns.
"""

import asyncio
import json
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING
from uuid import uuid4

from pydantic import BaseModel, Field

# Lazy-load ML dependencies (only needed for ML analytics, not detection rules)
# This allows detection_rules submodule to work without sklearn/numpy
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.cluster import KMeans
    from sklearn.preprocessing import StandardScaler
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    np = None
    RandomForestClassifier = None
    KMeans = None
    StandardScaler = None


class AnalyticsEventType(str, Enum):
    """Types of analytics events."""
    EMAIL_SENT = "email_sent"
    EMAIL_DELIVERED = "email_delivered"
    EMAIL_OPENED = "email_opened"
    EMAIL_BOUNCED = "email_bounced"
    LINK_CLICKED = "link_clicked"
    ATTACHMENT_DOWNLOADED = "attachment_downloaded"
    CREDENTIALS_SUBMITTED = "credentials_submitted"
    FORM_SUBMITTED = "form_submitted"
    PAGE_VISITED = "page_visited"
    SECURITY_ALERT = "security_alert"
    USER_REPORTED = "user_reported"
    TRAINING_COMPLETED = "training_completed"


class BehavioralPattern(BaseModel):
    """Behavioral pattern detected in campaign data."""

    pattern_id: str = Field(default_factory=lambda: str(uuid4()))
    pattern_type: str = Field(..., description="Type of behavioral pattern")
    description: str = Field(..., description="Human-readable pattern description")

    # Pattern characteristics
    frequency: float = Field(..., description="Pattern frequency (0-1)")
    confidence: float = Field(..., description="Pattern confidence score (0-1)")
    risk_level: str = Field(..., description="Risk level: low, medium, high, critical")

    # Affected population
    affected_users: List[str] = Field(default_factory=list)
    affected_percentage: float = Field(..., description="Percentage of users affected")

    # Temporal information
    first_observed: datetime = Field(default_factory=datetime.utcnow)
    last_observed: datetime = Field(default_factory=datetime.utcnow)
    peak_activity_hour: Optional[int] = Field(None, description="Hour of peak activity (0-23)")

    # Contextual data
    associated_events: List[str] = Field(default_factory=list)
    geographic_distribution: Dict[str, int] = Field(default_factory=dict)
    demographic_patterns: Dict[str, Any] = Field(default_factory=dict)


class PredictiveInsight(BaseModel):
    """Predictive insight generated from campaign data."""

    insight_id: str = Field(default_factory=lambda: str(uuid4()))
    insight_type: str = Field(..., description="Type of predictive insight")
    prediction: str = Field(..., description="Predicted outcome or behavior")

    # Prediction accuracy
    confidence_score: float = Field(..., description="Prediction confidence (0-1)")
    accuracy_estimate: float = Field(..., description="Estimated accuracy based on historical data")

    # Time horizon
    prediction_horizon_hours: int = Field(..., description="How far into future this applies")
    valid_until: datetime = Field(..., description="When this prediction expires")

    # Supporting data
    supporting_evidence: List[str] = Field(default_factory=list)
    historical_precedents: List[Dict[str, Any]] = Field(default_factory=list)

    # Actionable recommendations
    recommended_actions: List[str] = Field(default_factory=list)
    risk_mitigation: List[str] = Field(default_factory=list)


class ROICalculation(BaseModel):
    """Return on investment calculation for campaigns."""

    calculation_id: str = Field(default_factory=lambda: str(uuid4()))
    campaign_id: str = Field(..., description="Associated campaign ID")
    calculation_date: datetime = Field(default_factory=datetime.utcnow)

    # Cost factors
    campaign_setup_cost: float = Field(0.0, description="Setup and configuration costs")
    platform_costs: float = Field(0.0, description="Platform and service costs")
    personnel_hours: float = Field(0.0, description="Staff time invested")
    infrastructure_costs: float = Field(0.0, description="Infrastructure and hosting costs")
    total_investment: float = Field(0.0, description="Total campaign investment")

    # Benefit factors
    training_engagement_improvement: float = Field(0.0, description="Improvement in training engagement")
    security_awareness_increase: float = Field(0.0, description="Measured security awareness increase")
    policy_compliance_improvement: float = Field(0.0, description="Policy compliance improvement")
    incident_reduction_estimate: float = Field(0.0, description="Estimated incident reduction")

    # Risk reduction
    risk_exposure_before: float = Field(0.0, description="Risk exposure before campaign")
    risk_exposure_after: float = Field(0.0, description="Risk exposure after campaign")
    risk_reduction_percentage: float = Field(0.0, description="Percentage risk reduction")

    # Financial impact
    estimated_loss_prevention: float = Field(0.0, description="Estimated financial losses prevented")
    productivity_impact: float = Field(0.0, description="Productivity impact (positive/negative)")

    # ROI calculations
    roi_percentage: float = Field(0.0, description="Return on investment percentage")
    payback_period_months: float = Field(0.0, description="Payback period in months")
    net_present_value: float = Field(0.0, description="Net present value of investment")

    def calculate_roi(self) -> float:
        """Calculate ROI percentage."""
        if self.total_investment == 0:
            return 0.0

        total_benefit = (
            self.estimated_loss_prevention +
            self.productivity_impact
        )

        self.roi_percentage = ((total_benefit - self.total_investment) / self.total_investment) * 100
        return self.roi_percentage


class CampaignAnalytics(BaseModel):
    """Comprehensive analytics for a campaign."""

    campaign_id: str
    analysis_timestamp: datetime = Field(default_factory=datetime.utcnow)

    # Engagement analytics
    total_interactions: int = Field(0, description="Total user interactions")
    unique_users_engaged: int = Field(0, description="Unique users who engaged")
    average_response_time_minutes: float = Field(0.0, description="Average response time")
    peak_engagement_periods: List[Dict[str, Any]] = Field(default_factory=list)

    # Behavioral insights
    behavioral_patterns: List[BehavioralPattern] = Field(default_factory=list)
    user_segments: Dict[str, List[str]] = Field(default_factory=dict)
    risk_profiles: Dict[str, float] = Field(default_factory=dict)

    # Predictive analytics
    predictive_insights: List[PredictiveInsight] = Field(default_factory=list)
    trend_analysis: Dict[str, Any] = Field(default_factory=dict)
    future_projections: Dict[str, Any] = Field(default_factory=dict)

    # Performance metrics
    success_rate_by_channel: Dict[str, float] = Field(default_factory=dict)
    effectiveness_by_demographic: Dict[str, float] = Field(default_factory=dict)
    content_performance_ranking: List[Dict[str, Any]] = Field(default_factory=list)

    # ROI and business impact
    roi_calculation: Optional[ROICalculation] = None
    business_impact_metrics: Dict[str, Any] = Field(default_factory=dict)
    comparative_analysis: Dict[str, Any] = Field(default_factory=dict)


class MLAnalyticsEngine:
    """Machine learning-powered analytics engine."""

    def __init__(self):
        if ML_AVAILABLE:
            self.behavioral_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
            self.user_segmentation_model = KMeans(n_clusters=5, random_state=42)
            self.scaler = StandardScaler()
        else:
            self.behavioral_classifier = None
            self.user_segmentation_model = None
            self.scaler = None
        self.is_trained = False

    async def train_models(self, historical_data: List[Dict[str, Any]]) -> bool:
        """Train ML models on historical campaign data."""

        if not ML_AVAILABLE or not historical_data:
            return False

        try:
            # Prepare training data
            features, labels = self._prepare_training_data(historical_data)

            if len(features) < 10:  # Need minimum data for training
                return False

            # Scale features
            features_scaled = self.scaler.fit_transform(features)

            # Train behavioral classifier
            self.behavioral_classifier.fit(features_scaled, labels)

            # Train user segmentation model
            self.user_segmentation_model.fit(features_scaled)

            self.is_trained = True
            return True

        except Exception as e:
            print(f"Error training ML models: {e}")
            return False

    def _prepare_training_data(self, data: List[Dict[str, Any]]) -> Tuple[Any, Any]:
        """Prepare training data for ML models.
        
        Returns:
            Tuple of (features: np.ndarray, labels: np.ndarray) when numpy available
        """

        features = []
        labels = []

        for record in data:
            # Extract features
            feature_vector = [
                record.get('response_time_seconds', 0),
                record.get('email_opens', 0),
                record.get('link_clicks', 0),
                record.get('credentials_submitted', 0),
                record.get('hour_of_day', 12),
                record.get('day_of_week', 1),
                len(record.get('previous_interactions', [])),
                record.get('security_awareness_score', 50)
            ]

            features.append(feature_vector)

            # Create label (high risk behavior = 1, low risk = 0)
            high_risk = (
                record.get('credentials_submitted', 0) > 0 or
                record.get('link_clicks', 0) > 2 or
                record.get('response_time_seconds', 300) < 30
            )
            labels.append(1 if high_risk else 0)

        return np.array(features), np.array(labels)

    async def predict_user_behavior(self, user_data: Dict[str, Any]) -> Dict[str, Any]:
        """Predict user behavior based on current data."""

        if not ML_AVAILABLE or not self.is_trained:
            return {"error": "Models not trained"}

        try:
            # Prepare feature vector
            features = np.array([[
                user_data.get('avg_response_time', 0),
                user_data.get('total_email_opens', 0),
                user_data.get('total_link_clicks', 0),
                user_data.get('credentials_submitted_count', 0),
                datetime.now().hour,
                datetime.now().weekday(),
                user_data.get('interaction_history_length', 0),
                user_data.get('security_training_score', 50)
            ]])

            # Scale features
            features_scaled = self.scaler.transform(features)

            # Predict risk level
            risk_probability = self.behavioral_classifier.predict_proba(features_scaled)[0]
            risk_prediction = self.behavioral_classifier.predict(features_scaled)[0]

            # Determine user segment
            user_segment = self.user_segmentation_model.predict(features_scaled)[0]

            return {
                "risk_level": "high" if risk_prediction == 1 else "low",
                "risk_probability": float(risk_probability[1]),
                "user_segment": int(user_segment),
                "confidence": float(max(risk_probability))
            }

        except Exception as e:
            return {"error": f"Prediction failed: {e}"}

    async def detect_behavioral_patterns(self, campaign_data: List[Dict[str, Any]]) -> List[BehavioralPattern]:
        """Detect behavioral patterns in campaign data."""

        patterns = []

        if not campaign_data:
            return patterns

        # Analyze response time patterns
        response_times = [event.get('response_time_seconds', 0) for event in campaign_data if event.get('response_time_seconds')]

        if response_times:
            # Fast responders (potential security risk)
            fast_responders = [t for t in response_times if t < 30]
            if len(fast_responders) > len(response_times) * 0.1:  # More than 10%
                patterns.append(BehavioralPattern(
                    pattern_type="fast_response",
                    description="Unusually fast response times detected",
                    frequency=len(fast_responders) / len(response_times),
                    confidence=0.85,
                    risk_level="high",
                    affected_percentage=(len(fast_responders) / len(response_times)) * 100
                ))

        # Analyze temporal patterns
        hours = [datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())).hour
                for event in campaign_data if event.get('timestamp')]

        if hours:
            # Peak activity detection
            hour_counts = {}
            for hour in hours:
                hour_counts[hour] = hour_counts.get(hour, 0) + 1

            peak_hour = max(hour_counts, key=hour_counts.get)
            peak_activity = hour_counts[peak_hour] / len(hours)

            if peak_activity > 0.3:  # More than 30% of activity in one hour
                patterns.append(BehavioralPattern(
                    pattern_type="temporal_clustering",
                    description=f"High activity concentration at hour {peak_hour}",
                    frequency=peak_activity,
                    confidence=0.9,
                    risk_level="medium",
                    affected_percentage=peak_activity * 100,
                    peak_activity_hour=peak_hour
                ))

        # Analyze credential submission patterns
        credential_events = [event for event in campaign_data if event.get('event_type') == 'credentials_submitted']

        if credential_events:
            # High credential submission rate
            submission_rate = len(credential_events) / len(campaign_data)

            if submission_rate > 0.05:  # More than 5% submitted credentials
                patterns.append(BehavioralPattern(
                    pattern_type="high_credential_submission",
                    description="High rate of credential submissions detected",
                    frequency=submission_rate,
                    confidence=0.95,
                    risk_level="critical",
                    affected_percentage=submission_rate * 100
                ))

        return patterns


class RealTimeDashboard:
    """Real-time dashboard for campaign monitoring."""

    def __init__(self):
        self.active_campaigns = {}
        self.dashboard_data = {}
        self.update_interval = 5  # seconds

    async def add_campaign(self, campaign_id: str, campaign_config: Dict[str, Any]) -> None:
        """Add a campaign to real-time monitoring."""

        self.active_campaigns[campaign_id] = {
            "config": campaign_config,
            "start_time": datetime.utcnow(),
            "last_update": datetime.utcnow(),
            "total_events": 0,
            "event_buffer": []
        }

        # Initialize dashboard data
        self.dashboard_data[campaign_id] = {
            "live_metrics": {
                "events_per_minute": 0,
                "active_users": 0,
                "conversion_rate": 0.0,
                "engagement_trend": []
            },
            "alerts": [],
            "performance_indicators": {}
        }

    async def process_event(self, campaign_id: str, event: Dict[str, Any]) -> None:
        """Process a real-time event for dashboard updates."""

        if campaign_id not in self.active_campaigns:
            return

        campaign = self.active_campaigns[campaign_id]
        dashboard = self.dashboard_data[campaign_id]

        # Add event to buffer
        event['processed_at'] = datetime.utcnow()
        campaign['event_buffer'].append(event)
        campaign['total_events'] += 1
        campaign['last_update'] = datetime.utcnow()

        # Update live metrics
        await self._update_live_metrics(campaign_id, event)

        # Check for alerts
        await self._check_alerts(campaign_id, event)

        # Cleanup old events (keep last 1000)
        if len(campaign['event_buffer']) > 1000:
            campaign['event_buffer'] = campaign['event_buffer'][-1000:]

    async def get_dashboard_data(self, campaign_id: str) -> Dict[str, Any]:
        """Get current dashboard data for a campaign."""

        if campaign_id not in self.dashboard_data:
            return {}

        dashboard_data = self.dashboard_data[campaign_id].copy()
        campaign = self.active_campaigns.get(campaign_id, {})

        # Add campaign status
        dashboard_data['campaign_status'] = {
            "id": campaign_id,
            "start_time": campaign.get('start_time', datetime.utcnow()).isoformat(),
            "last_update": campaign.get('last_update', datetime.utcnow()).isoformat(),
            "total_events": campaign.get('total_events', 0),
            "uptime_minutes": (datetime.utcnow() - campaign.get('start_time', datetime.utcnow())).total_seconds() / 60
        }

        return dashboard_data

    async def _update_live_metrics(self, campaign_id: str, event: Dict[str, Any]) -> None:
        """Update live metrics based on new event."""

        dashboard = self.dashboard_data[campaign_id]
        campaign = self.active_campaigns[campaign_id]

        # Calculate events per minute
        recent_events = [
            e for e in campaign['event_buffer']
            if (datetime.utcnow() - e.get('processed_at', datetime.utcnow())).total_seconds() < 60
        ]
        dashboard['live_metrics']['events_per_minute'] = len(recent_events)

        # Count active users (users with activity in last 5 minutes)
        recent_user_events = [
            e for e in campaign['event_buffer']
            if (datetime.utcnow() - e.get('processed_at', datetime.utcnow())).total_seconds() < 300
        ]
        active_users = len(set(e.get('user_id') for e in recent_user_events if e.get('user_id')))
        dashboard['live_metrics']['active_users'] = active_users

        # Calculate conversion rate
        total_interactions = len([e for e in campaign['event_buffer'] if e.get('event_type') in ['email_opened', 'link_clicked']])
        conversions = len([e for e in campaign['event_buffer'] if e.get('event_type') == 'credentials_submitted'])

        if total_interactions > 0:
            dashboard['live_metrics']['conversion_rate'] = conversions / total_interactions

        # Update engagement trend (last 10 minutes, minute by minute)
        now = datetime.utcnow()
        engagement_trend = []

        for i in range(10):
            minute_start = now - timedelta(minutes=i+1)
            minute_end = now - timedelta(minutes=i)

            minute_events = [
                e for e in campaign['event_buffer']
                if minute_start <= e.get('processed_at', datetime.utcnow()) < minute_end
            ]

            engagement_trend.append({
                "minute": i,
                "events": len(minute_events),
                "timestamp": minute_start.isoformat()
            })

        dashboard['live_metrics']['engagement_trend'] = list(reversed(engagement_trend))

    async def _check_alerts(self, campaign_id: str, event: Dict[str, Any]) -> None:
        """Check for alert conditions based on new event."""

        dashboard = self.dashboard_data[campaign_id]
        campaign = self.active_campaigns[campaign_id]

        # High credential submission rate alert
        credential_events = [
            e for e in campaign['event_buffer']
            if e.get('event_type') == 'credentials_submitted'
        ]

        if len(credential_events) > len(campaign['event_buffer']) * 0.1:  # More than 10%
            alert = {
                "alert_id": str(uuid4()),
                "type": "high_credential_submission",
                "message": f"High credential submission rate detected: {len(credential_events)} submissions",
                "severity": "high",
                "timestamp": datetime.utcnow().isoformat()
            }

            # Don't duplicate alerts
            existing_alerts = [a for a in dashboard['alerts'] if a['type'] == 'high_credential_submission']
            if not existing_alerts:
                dashboard['alerts'].append(alert)

        # Rapid response alert
        if event.get('response_time_seconds', 300) < 10:
            alert = {
                "alert_id": str(uuid4()),
                "type": "rapid_response",
                "message": f"Unusually fast response detected: {event.get('response_time_seconds')}s",
                "severity": "medium",
                "timestamp": datetime.utcnow().isoformat(),
                "user_id": event.get('user_id')
            }
            dashboard['alerts'].append(alert)

        # Keep only last 50 alerts
        if len(dashboard['alerts']) > 50:
            dashboard['alerts'] = dashboard['alerts'][-50:]


class CampaignAnalyticsEngine:
    """Main analytics engine orchestrating all analytics components.
    
    Issue #125 Refactor: Enhanced delegation methods to provide meaningful
    analytics processing instead of simple pass-through delegation.
    """

    def __init__(self):
        self.ml_engine = MLAnalyticsEngine()
        self.dashboard = RealTimeDashboard()
        self.campaign_data = {}
        # Issue #125: Track user risk profiles for enrichment
        self._user_risk_cache: Dict[str, Dict[str, Any]] = {}

    async def initialize(self, historical_data: Optional[List[Dict[str, Any]]] = None) -> bool:
        """Initialize the analytics engine with historical data."""

        if historical_data:
            success = await self.ml_engine.train_models(historical_data)
            if success:
                print("ML models trained successfully")
            else:
                print("Warning: ML models could not be trained")

        return True

    async def start_campaign_analytics(self, campaign_id: str, campaign_config: Dict[str, Any]) -> None:
        """Start analytics for a new campaign."""

        # Initialize campaign data storage
        self.campaign_data[campaign_id] = {
            "events": [],
            "config": campaign_config,
            "start_time": datetime.utcnow(),
            # Issue #125: Add aggregated metrics storage
            "aggregated_metrics": {
                "hourly_event_counts": defaultdict(int),
                "user_event_counts": defaultdict(int),
                "event_type_counts": defaultdict(int),
                "risk_score_sum": 0.0,
                "risk_event_count": 0
            }
        }

        # Add to real-time dashboard
        await self.dashboard.add_campaign(campaign_id, campaign_config)

    async def process_campaign_event(self, campaign_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Process a campaign event for analytics.
        
        Issue #125 Refactor: Now enriches events with computed analytics
        before storing and delegating to dashboard. Returns enriched event.
        
        Args:
            campaign_id: The campaign identifier
            event: Raw event data
            
        Returns:
            Enriched event with risk scores and derived metrics
        """
        if campaign_id not in self.campaign_data:
            return event

        # Issue #125: Enrich event with computed analytics BEFORE storing
        enriched_event = await self._enrich_event(campaign_id, event)
        
        # Store enriched event
        enriched_event['processed_timestamp'] = datetime.utcnow().isoformat()
        self.campaign_data[campaign_id]['events'].append(enriched_event)
        
        # Issue #125: Update aggregated metrics
        await self._update_aggregated_metrics(campaign_id, enriched_event)

        # Process for real-time dashboard (now with enriched data)
        await self.dashboard.process_event(campaign_id, enriched_event)
        
        return enriched_event

    async def _enrich_event(self, campaign_id: str, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich event with computed analytics.
        
        Issue #125: This method adds meaningful value by computing:
        - Risk scores based on event type and timing
        - User behavior context from historical data
        - Temporal classification
        - Behavioral flags
        """
        enriched = event.copy()
        
        # Compute risk score based on event type
        risk_weights = {
            'credentials_submitted': 90,
            'attachment_downloaded': 70,
            'form_submitted': 60,
            'link_clicked': 50,
            'page_visited': 30,
            'email_opened': 20,
            'email_delivered': 5,
            'email_sent': 0,
            'user_reported': -20,  # Positive behavior reduces risk
            'training_completed': -30
        }
        
        event_type = event.get('event_type', '')
        base_risk = risk_weights.get(event_type, 10)
        
        # Adjust risk based on response time (faster = higher risk)
        response_time = event.get('response_time_seconds', 300)
        if response_time < 10:
            base_risk = min(100, base_risk + 20)
        elif response_time < 30:
            base_risk = min(100, base_risk + 10)
        
        enriched['risk_score'] = base_risk
        enriched['risk_level'] = self._score_to_risk_level(base_risk)
        
        # Add temporal context
        timestamp = event.get('timestamp')
        if timestamp:
            try:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                else:
                    dt = timestamp
                enriched['hour_of_day'] = dt.hour
                enriched['day_of_week'] = dt.weekday()
                enriched['is_business_hours'] = 9 <= dt.hour <= 17
            except (ValueError, AttributeError):
                pass
        
        # Add behavioral flags
        flags = []
        if response_time and response_time < 10:
            flags.append('rapid_response')
        if event_type == 'credentials_submitted':
            flags.append('credential_compromise')
        if event_type == 'attachment_downloaded':
            flags.append('potential_malware')
        if event_type == 'user_reported':
            flags.append('security_aware')
        enriched['behavioral_flags'] = flags
        
        # Update user risk cache
        user_id = event.get('user_id')
        if user_id:
            if user_id not in self._user_risk_cache:
                self._user_risk_cache[user_id] = {
                    'total_events': 0,
                    'risk_events': 0,
                    'total_risk_score': 0
                }
            
            cache = self._user_risk_cache[user_id]
            cache['total_events'] += 1
            cache['total_risk_score'] += base_risk
            if base_risk >= 50:
                cache['risk_events'] += 1
            
            enriched['user_risk_profile'] = {
                'avg_risk_score': cache['total_risk_score'] / cache['total_events'],
                'risk_event_ratio': cache['risk_events'] / cache['total_events'],
                'is_repeat_offender': cache['risk_events'] > 2
            }
        
        return enriched

    def _score_to_risk_level(self, score: float) -> str:
        """Convert numeric risk score to categorical level."""
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 30:
            return 'medium'
        return 'low'

    async def _update_aggregated_metrics(self, campaign_id: str, event: Dict[str, Any]) -> None:
        """Update running aggregated metrics for the campaign.
        
        Issue #125: Maintains aggregated statistics for efficient analytics.
        """
        metrics = self.campaign_data[campaign_id]['aggregated_metrics']
        
        # Update hourly counts
        hour = event.get('hour_of_day', datetime.utcnow().hour)
        metrics['hourly_event_counts'][hour] += 1
        
        # Update user counts
        user_id = event.get('user_id')
        if user_id:
            metrics['user_event_counts'][user_id] += 1
        
        # Update event type counts
        event_type = event.get('event_type', 'unknown')
        metrics['event_type_counts'][event_type] += 1
        
        # Update risk aggregates
        risk_score = event.get('risk_score', 0)
        if risk_score > 0:
            metrics['risk_score_sum'] += risk_score
            metrics['risk_event_count'] += 1

    async def generate_campaign_analytics(self, campaign_id: str) -> CampaignAnalytics:
        """Generate comprehensive analytics for a campaign.
        
        Issue #125 Refactor: Enhanced to use pre-aggregated metrics and
        enriched event data for more efficient and meaningful analytics.
        """
        if campaign_id not in self.campaign_data:
            return CampaignAnalytics(campaign_id=campaign_id)

        campaign_events = self.campaign_data[campaign_id]['events']
        aggregated = self.campaign_data[campaign_id].get('aggregated_metrics', {})

        # Basic engagement metrics
        total_interactions = len(campaign_events)
        unique_users = len(set(event.get('user_id') for event in campaign_events if event.get('user_id')))

        # Response time analysis
        response_times = [
            event.get('response_time_seconds', 0)
            for event in campaign_events
            if event.get('response_time_seconds')
        ]
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0

        # Detect behavioral patterns
        behavioral_patterns = await self.ml_engine.detect_behavioral_patterns(campaign_events)

        # Generate predictive insights
        predictive_insights = await self._generate_predictive_insights(campaign_id, campaign_events)

        # Calculate ROI
        roi_calculation = await self._calculate_campaign_roi(campaign_id, campaign_events)

        # Performance by channel
        success_by_channel = {}
        for event in campaign_events:
            channel = event.get('channel', 'unknown')
            if channel not in success_by_channel:
                success_by_channel[channel] = {'total': 0, 'success': 0}

            success_by_channel[channel]['total'] += 1
            if event.get('event_type') in ['link_clicked', 'credentials_submitted']:
                success_by_channel[channel]['success'] += 1

        # Convert to success rates
        success_rate_by_channel = {}
        for channel, data in success_by_channel.items():
            if data['total'] > 0:
                success_rate_by_channel[channel] = data['success'] / data['total']

        # Issue #125: Add risk profile distribution from enriched events
        risk_profiles = self._calculate_risk_profiles(campaign_events)
        
        # Issue #125: Add user segments based on behavior
        user_segments = self._segment_users(campaign_events)
        
        # Issue #125: Add peak engagement periods from aggregated data
        peak_periods = self._find_peak_periods(aggregated.get('hourly_event_counts', {}))
        
        # Issue #125: Add trend analysis
        trend_analysis = self._analyze_trends(campaign_events, aggregated)

        return CampaignAnalytics(
            campaign_id=campaign_id,
            total_interactions=total_interactions,
            unique_users_engaged=unique_users,
            average_response_time_minutes=avg_response_time / 60,
            behavioral_patterns=behavioral_patterns,
            predictive_insights=predictive_insights,
            success_rate_by_channel=success_rate_by_channel,
            roi_calculation=roi_calculation,
            # Issue #125: New fields from enhanced processing
            risk_profiles=risk_profiles,
            user_segments=user_segments,
            peak_engagement_periods=peak_periods,
            trend_analysis=trend_analysis
        )

    def _calculate_risk_profiles(self, events: List[Dict[str, Any]]) -> Dict[str, float]:
        """Calculate distribution of risk levels across events.
        
        Issue #125: Leverages enriched event data for risk profiling.
        """
        risk_counts = defaultdict(int)
        
        for event in events:
            risk_level = event.get('risk_level', 'unknown')
            risk_counts[risk_level] += 1
        
        total = len(events) or 1
        return {level: count / total for level, count in risk_counts.items()}

    def _segment_users(self, events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Segment users based on their behavior patterns.
        
        Issue #125: Uses enriched event data for user segmentation.
        """
        segments = {
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'security_conscious': []
        }
        
        user_profiles = {}
        for event in events:
            user_id = event.get('user_id')
            if not user_id:
                continue
            
            if user_id not in user_profiles:
                user_profiles[user_id] = {'risk_sum': 0, 'count': 0, 'reported': False}
            
            user_profiles[user_id]['risk_sum'] += event.get('risk_score', 0)
            user_profiles[user_id]['count'] += 1
            
            if event.get('event_type') == 'user_reported':
                user_profiles[user_id]['reported'] = True
        
        for user_id, profile in user_profiles.items():
            avg_risk = profile['risk_sum'] / profile['count'] if profile['count'] > 0 else 0
            
            if profile['reported']:
                segments['security_conscious'].append(user_id)
            elif avg_risk >= 60:
                segments['high_risk'].append(user_id)
            elif avg_risk >= 30:
                segments['medium_risk'].append(user_id)
            else:
                segments['low_risk'].append(user_id)
        
        return segments

    def _find_peak_periods(self, hourly_counts: Dict[int, int]) -> List[Dict[str, Any]]:
        """Find peak engagement periods from hourly data.
        
        Issue #125: Uses pre-aggregated hourly counts for efficiency.
        """
        if not hourly_counts:
            return []
        
        avg_count = sum(hourly_counts.values()) / len(hourly_counts) if hourly_counts else 0
        
        peaks = []
        for hour, count in sorted(hourly_counts.items()):
            if count > avg_count * 1.5:  # 50% above average = peak
                peaks.append({
                    'hour': hour,
                    'event_count': count,
                    'above_average_pct': ((count - avg_count) / avg_count * 100) if avg_count > 0 else 0
                })
        
        return sorted(peaks, key=lambda x: x['event_count'], reverse=True)[:5]

    def _analyze_trends(self, events: List[Dict[str, Any]], aggregated: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze trends in campaign data.
        
        Issue #125: Provides trend analysis from aggregated metrics.
        """
        if not events:
            return {'direction': 'stable', 'risk_trend': 'stable'}
        
        # Analyze risk trend
        risk_count = aggregated.get('risk_event_count', 0)
        risk_sum = aggregated.get('risk_score_sum', 0)
        avg_risk = risk_sum / risk_count if risk_count > 0 else 0
        
        # Simple trend: compare first half vs second half
        mid_point = len(events) // 2
        if mid_point > 0:
            first_half_risk = sum(e.get('risk_score', 0) for e in events[:mid_point]) / mid_point
            second_half_risk = sum(e.get('risk_score', 0) for e in events[mid_point:]) / (len(events) - mid_point)
            
            if second_half_risk > first_half_risk * 1.2:
                risk_trend = 'increasing'
            elif second_half_risk < first_half_risk * 0.8:
                risk_trend = 'decreasing'
            else:
                risk_trend = 'stable'
        else:
            risk_trend = 'stable'
        
        return {
            'direction': risk_trend,
            'risk_trend': risk_trend,
            'average_risk_score': avg_risk,
            'total_events_analyzed': len(events)
        }

    async def get_real_time_dashboard(self, campaign_id: str) -> Dict[str, Any]:
        """Get real-time dashboard data with computed analytics.
        
        Issue #125 Refactor: Now enriches dashboard data with computed
        metrics instead of simple pass-through delegation.
        
        Returns:
            Dashboard data enriched with analytics insights
        """
        # Get base dashboard data
        dashboard_data = await self.dashboard.get_dashboard_data(campaign_id)
        
        if not dashboard_data or campaign_id not in self.campaign_data:
            return dashboard_data
        
        # Issue #125: Enrich with computed analytics
        campaign = self.campaign_data[campaign_id]
        aggregated = campaign.get('aggregated_metrics', {})
        
        # Add risk summary
        risk_count = aggregated.get('risk_event_count', 0)
        risk_sum = aggregated.get('risk_score_sum', 0)
        
        dashboard_data['analytics_summary'] = {
            'average_risk_score': risk_sum / risk_count if risk_count > 0 else 0,
            'high_risk_event_count': sum(
                1 for e in campaign.get('events', [])
                if e.get('risk_level') in ['high', 'critical']
            ),
            'unique_users_at_risk': len([
                uid for uid, profile in self._user_risk_cache.items()
                if profile.get('risk_events', 0) > 0
            ]),
            'event_type_distribution': dict(aggregated.get('event_type_counts', {})),
            'peak_activity_hour': max(
                aggregated.get('hourly_event_counts', {}).items(),
                key=lambda x: x[1],
                default=(None, 0)
            )[0]
        }
        
        # Add trend indicator
        events = campaign.get('events', [])
        if len(events) >= 10:
            recent_risk = sum(e.get('risk_score', 0) for e in events[-10:]) / 10
            older_risk = sum(e.get('risk_score', 0) for e in events[-20:-10]) / 10 if len(events) >= 20 else recent_risk
            
            if recent_risk > older_risk * 1.2:
                trend = 'increasing'
            elif recent_risk < older_risk * 0.8:
                trend = 'decreasing'
            else:
                trend = 'stable'
            
            dashboard_data['analytics_summary']['risk_trend'] = trend
        
        return dashboard_data

    async def _generate_predictive_insights(self, campaign_id: str, events: List[Dict[str, Any]]) -> List[PredictiveInsight]:
        """Generate predictive insights for the campaign."""

        insights = []

        if not events:
            return insights

        # Predict peak engagement times
        hours = [datetime.fromisoformat(event.get('timestamp', datetime.now().isoformat())).hour
                for event in events if event.get('timestamp')]

        if hours:
            hour_counts = {}
            for hour in hours:
                hour_counts[hour] = hour_counts.get(hour, 0) + 1

            peak_hour = max(hour_counts, key=hour_counts.get)

            insights.append(PredictiveInsight(
                insight_type="peak_engagement_prediction",
                prediction=f"Highest engagement likely to occur around hour {peak_hour}",
                confidence_score=0.75,
                accuracy_estimate=0.68,
                prediction_horizon_hours=24,
                valid_until=datetime.utcnow() + timedelta(hours=24),
                recommended_actions=[
                    f"Schedule additional content delivery around hour {peak_hour}",
                    "Increase monitoring during predicted peak times"
                ]
            ))

        # Predict user behavior based on current patterns
        if self.ml_engine.is_trained:
            # Analyze recent user behavior
            recent_events = [e for e in events if (datetime.utcnow() - datetime.fromisoformat(e.get('timestamp', datetime.now().isoformat()))).total_seconds() < 3600]

            if recent_events:
                high_risk_users = 0
                for event in recent_events:
                    user_data = {
                        'avg_response_time': event.get('response_time_seconds', 300),
                        'total_email_opens': 1,
                        'total_link_clicks': 1 if event.get('event_type') == 'link_clicked' else 0,
                        'credentials_submitted_count': 1 if event.get('event_type') == 'credentials_submitted' else 0
                    }

                    prediction = await self.ml_engine.predict_user_behavior(user_data)
                    if prediction.get('risk_level') == 'high':
                        high_risk_users += 1

                if high_risk_users > len(recent_events) * 0.2:  # More than 20% high risk
                    insights.append(PredictiveInsight(
                        insight_type="user_behavior_prediction",
                        prediction="High likelihood of continued risky user behavior",
                        confidence_score=0.82,
                        accuracy_estimate=0.74,
                        prediction_horizon_hours=4,
                        valid_until=datetime.utcnow() + timedelta(hours=4),
                        recommended_actions=[
                            "Implement additional security awareness training",
                            "Monitor high-risk users more closely",
                            "Consider targeted intervention for vulnerable users"
                        ]
                    ))

        return insights

    async def _calculate_campaign_roi(self, campaign_id: str, events: List[Dict[str, Any]]) -> ROICalculation:
        """Calculate ROI for the campaign."""

        # Mock ROI calculation - in production, integrate with actual cost and benefit data
        roi = ROICalculation(
            campaign_id=campaign_id,
            campaign_setup_cost=500.0,
            platform_costs=200.0,
            personnel_hours=8.0,  # 8 hours at $50/hour = $400
            infrastructure_costs=100.0,
            total_investment=1200.0
        )

        # Estimate benefits based on campaign effectiveness
        engagement_events = len([e for e in events if e.get('event_type') in ['link_clicked', 'credentials_submitted']])
        total_users = len(set(e.get('user_id') for e in events if e.get('user_id')))

        if total_users > 0:
            engagement_rate = engagement_events / total_users

            # Estimate security awareness improvement
            roi.security_awareness_increase = min(engagement_rate * 100, 50)  # Cap at 50%

            # Estimate financial impact
            # Assume each engaged user represents $1000 in prevented losses
            roi.estimated_loss_prevention = total_users * 1000 * (engagement_rate / 100)

            # Calculate ROI
            roi.calculate_roi()

        return roi
