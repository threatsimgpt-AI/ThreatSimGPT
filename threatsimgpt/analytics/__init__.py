"""Real-time analytics and dashboard services for ThreatSimGPT campaigns.

This module provides comprehensive analytics, machine learning-enhanced
insights, and real-time dashboards for threat simulation campaigns.
"""

import asyncio
import json
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import numpy as np
from pydantic import BaseModel, Field
from sklearn.ensemble import RandomForestClassifier
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler


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
        self.behavioral_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.user_segmentation_model = KMeans(n_clusters=5, random_state=42)
        self.scaler = StandardScaler()
        self.is_trained = False

    async def train_models(self, historical_data: List[Dict[str, Any]]) -> bool:
        """Train ML models on historical campaign data."""

        if not historical_data:
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

    def _prepare_training_data(self, data: List[Dict[str, Any]]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare training data for ML models."""

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

        if not self.is_trained:
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
    """Main analytics engine orchestrating all analytics components."""

    def __init__(self):
        self.ml_engine = MLAnalyticsEngine()
        self.dashboard = RealTimeDashboard()
        self.campaign_data = {}

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
            "start_time": datetime.utcnow()
        }

        # Add to real-time dashboard
        await self.dashboard.add_campaign(campaign_id, campaign_config)

    async def process_campaign_event(self, campaign_id: str, event: Dict[str, Any]) -> None:
        """Process a campaign event for analytics."""

        if campaign_id not in self.campaign_data:
            return

        # Store event
        event['processed_timestamp'] = datetime.utcnow().isoformat()
        self.campaign_data[campaign_id]['events'].append(event)

        # Process for real-time dashboard
        await self.dashboard.process_event(campaign_id, event)

    async def generate_campaign_analytics(self, campaign_id: str) -> CampaignAnalytics:
        """Generate comprehensive analytics for a campaign."""

        if campaign_id not in self.campaign_data:
            return CampaignAnalytics(campaign_id=campaign_id)

        campaign_events = self.campaign_data[campaign_id]['events']

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

        return CampaignAnalytics(
            campaign_id=campaign_id,
            total_interactions=total_interactions,
            unique_users_engaged=unique_users,
            average_response_time_minutes=avg_response_time / 60,
            behavioral_patterns=behavioral_patterns,
            predictive_insights=predictive_insights,
            success_rate_by_channel=success_rate_by_channel,
            roi_calculation=roi_calculation
        )

    async def get_real_time_dashboard(self, campaign_id: str) -> Dict[str, Any]:
        """Get real-time dashboard data."""
        return await self.dashboard.get_dashboard_data(campaign_id)

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
