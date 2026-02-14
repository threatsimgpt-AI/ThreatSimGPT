"""Unit tests for Issue #125 - Analytics Dashboard Delegation Refactor.

Tests the specific changes made to fix pass-through delegation:
1. process_campaign_event() now enriches events with analytics
2. get_real_time_dashboard() now adds computed metrics
3. New helper methods for aggregation and enrichment

Author: Temidayo
Issue: #125 - Analytics Dashboard Delegation Refactor
"""

import pytest
from datetime import datetime, timedelta
from uuid import uuid4

import sys

from threatsimgpt.analytics import (
    CampaignAnalyticsEngine,
    CampaignAnalytics,
    AnalyticsEventType,
)


# =============================================================================
# FIXTURES
# =============================================================================

@pytest.fixture
def analytics_engine():
    """Create a CampaignAnalyticsEngine instance."""
    return CampaignAnalyticsEngine()


@pytest.fixture
def sample_event():
    """Create a sample event for testing."""
    return {
        'event_id': str(uuid4()),
        'user_id': 'user_001',
        'event_type': 'link_clicked',
        'timestamp': datetime.utcnow().isoformat(),
        'response_time_seconds': 45,
        'channel': 'email'
    }


@pytest.fixture
def high_risk_event():
    """Create a high-risk event for testing."""
    return {
        'event_id': str(uuid4()),
        'user_id': 'user_002',
        'event_type': 'credentials_submitted',
        'timestamp': datetime.utcnow().isoformat(),
        'response_time_seconds': 5,  # Very fast = suspicious
        'channel': 'email'
    }


@pytest.fixture
def security_aware_event():
    """Create an event from a security-aware user."""
    return {
        'event_id': str(uuid4()),
        'user_id': 'user_003',
        'event_type': 'user_reported',
        'timestamp': datetime.utcnow().isoformat(),
        'response_time_seconds': 120,
        'channel': 'email'
    }


# =============================================================================
# ISSUE #125: process_campaign_event ENRICHMENT TESTS
# =============================================================================

class TestProcessCampaignEventEnrichment:
    """Tests for Issue #125: process_campaign_event now enriches events."""

    @pytest.mark.asyncio
    async def test_event_enriched_with_risk_score(self, analytics_engine, sample_event):
        """Test that processed events have risk_score added."""
        campaign_id = 'test_campaign_001'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        assert 'risk_score' in enriched
        assert isinstance(enriched['risk_score'], (int, float))
        assert 0 <= enriched['risk_score'] <= 100

    @pytest.mark.asyncio
    async def test_event_enriched_with_risk_level(self, analytics_engine, sample_event):
        """Test that processed events have risk_level added."""
        campaign_id = 'test_campaign_002'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        assert 'risk_level' in enriched
        assert enriched['risk_level'] in ['low', 'medium', 'high', 'critical']

    @pytest.mark.asyncio
    async def test_high_risk_event_scored_correctly(self, analytics_engine, high_risk_event):
        """Test that credentials_submitted with fast response gets high risk score."""
        campaign_id = 'test_campaign_003'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, high_risk_event)
        
        # credentials_submitted (90) + rapid response bonus (20) = 100+ capped at 100
        assert enriched['risk_score'] >= 90
        assert enriched['risk_level'] in ['high', 'critical']

    @pytest.mark.asyncio
    async def test_security_aware_event_reduces_risk(self, analytics_engine, security_aware_event):
        """Test that user_reported events have negative/low risk scores."""
        campaign_id = 'test_campaign_004'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, security_aware_event)
        
        # user_reported has -20 base risk
        assert enriched['risk_score'] < 0 or enriched['risk_level'] == 'low'

    @pytest.mark.asyncio
    async def test_event_enriched_with_behavioral_flags(self, analytics_engine, high_risk_event):
        """Test that processed events have behavioral_flags added."""
        campaign_id = 'test_campaign_005'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, high_risk_event)
        
        assert 'behavioral_flags' in enriched
        assert isinstance(enriched['behavioral_flags'], list)
        assert 'rapid_response' in enriched['behavioral_flags']
        assert 'credential_compromise' in enriched['behavioral_flags']

    @pytest.mark.asyncio
    async def test_event_enriched_with_temporal_context(self, analytics_engine, sample_event):
        """Test that processed events have temporal context added."""
        campaign_id = 'test_campaign_006'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        assert 'hour_of_day' in enriched
        assert 'day_of_week' in enriched
        assert 'is_business_hours' in enriched

    @pytest.mark.asyncio
    async def test_event_enriched_with_user_risk_profile(self, analytics_engine, sample_event):
        """Test that processed events include user risk profile."""
        campaign_id = 'test_campaign_007'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        assert 'user_risk_profile' in enriched
        assert 'avg_risk_score' in enriched['user_risk_profile']
        assert 'risk_event_ratio' in enriched['user_risk_profile']

    @pytest.mark.asyncio
    async def test_user_risk_profile_updates_with_multiple_events(self, analytics_engine):
        """Test that user risk profile accumulates across events."""
        campaign_id = 'test_campaign_008'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        user_id = 'repeat_user'
        
        # First event - low risk
        event1 = {
            'user_id': user_id,
            'event_type': 'email_opened',
            'timestamp': datetime.utcnow().isoformat(),
            'response_time_seconds': 300
        }
        enriched1 = await analytics_engine.process_campaign_event(campaign_id, event1)
        
        # Second event - high risk
        event2 = {
            'user_id': user_id,
            'event_type': 'credentials_submitted',
            'timestamp': datetime.utcnow().isoformat(),
            'response_time_seconds': 5
        }
        enriched2 = await analytics_engine.process_campaign_event(campaign_id, event2)
        
        # User profile should reflect both events
        assert enriched2['user_risk_profile']['avg_risk_score'] > enriched1['user_risk_profile']['avg_risk_score']
        assert enriched2['user_risk_profile']['risk_event_ratio'] > 0

    @pytest.mark.asyncio
    async def test_returns_enriched_event(self, analytics_engine, sample_event):
        """Test that process_campaign_event returns the enriched event."""
        campaign_id = 'test_campaign_009'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        result = await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        # Should return dict, not None
        assert result is not None
        assert isinstance(result, dict)
        # Should have original fields plus enrichments
        assert result.get('event_type') == sample_event['event_type']
        assert 'risk_score' in result


# =============================================================================
# ISSUE #125: get_real_time_dashboard ENRICHMENT TESTS
# =============================================================================

class TestGetRealTimeDashboardEnrichment:
    """Tests for Issue #125: get_real_time_dashboard now adds computed metrics."""

    @pytest.mark.asyncio
    async def test_dashboard_includes_analytics_summary(self, analytics_engine, sample_event):
        """Test that dashboard data includes analytics_summary."""
        campaign_id = 'test_campaign_010'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert 'analytics_summary' in dashboard

    @pytest.mark.asyncio
    async def test_analytics_summary_has_average_risk_score(self, analytics_engine):
        """Test that analytics_summary includes average_risk_score."""
        campaign_id = 'test_campaign_011'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add multiple events
        for i in range(5):
            event = {
                'user_id': f'user_{i}',
                'event_type': 'link_clicked',
                'timestamp': datetime.utcnow().isoformat(),
                'response_time_seconds': 60
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert 'average_risk_score' in dashboard['analytics_summary']
        assert dashboard['analytics_summary']['average_risk_score'] > 0

    @pytest.mark.asyncio
    async def test_analytics_summary_has_high_risk_count(self, analytics_engine, high_risk_event):
        """Test that analytics_summary includes high_risk_event_count."""
        campaign_id = 'test_campaign_012'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        await analytics_engine.process_campaign_event(campaign_id, high_risk_event)
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert 'high_risk_event_count' in dashboard['analytics_summary']
        assert dashboard['analytics_summary']['high_risk_event_count'] >= 1

    @pytest.mark.asyncio
    async def test_analytics_summary_has_event_type_distribution(self, analytics_engine):
        """Test that analytics_summary includes event_type_distribution."""
        campaign_id = 'test_campaign_013'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add events of different types
        for event_type in ['email_opened', 'link_clicked', 'email_opened']:
            event = {
                'user_id': 'user_1',
                'event_type': event_type,
                'timestamp': datetime.utcnow().isoformat()
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert 'event_type_distribution' in dashboard['analytics_summary']
        assert dashboard['analytics_summary']['event_type_distribution'].get('email_opened') == 2
        assert dashboard['analytics_summary']['event_type_distribution'].get('link_clicked') == 1

    @pytest.mark.asyncio
    async def test_analytics_summary_has_peak_activity_hour(self, analytics_engine):
        """Test that analytics_summary includes peak_activity_hour."""
        campaign_id = 'test_campaign_014'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add events
        for i in range(3):
            event = {
                'user_id': f'user_{i}',
                'event_type': 'email_opened',
                'timestamp': datetime.utcnow().isoformat()
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert 'peak_activity_hour' in dashboard['analytics_summary']


# =============================================================================
# ISSUE #125: AGGREGATED METRICS TESTS
# =============================================================================

class TestAggregatedMetrics:
    """Tests for Issue #125: Pre-aggregated metrics for efficient analytics."""

    @pytest.mark.asyncio
    async def test_campaign_tracks_aggregated_metrics(self, analytics_engine):
        """Test that campaign data includes aggregated_metrics."""
        campaign_id = 'test_campaign_015'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        assert 'aggregated_metrics' in analytics_engine.campaign_data[campaign_id]

    @pytest.mark.asyncio
    async def test_hourly_counts_updated(self, analytics_engine, sample_event):
        """Test that hourly event counts are tracked."""
        campaign_id = 'test_campaign_016'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        metrics = analytics_engine.campaign_data[campaign_id]['aggregated_metrics']
        
        assert sum(metrics['hourly_event_counts'].values()) == 1

    @pytest.mark.asyncio
    async def test_user_counts_updated(self, analytics_engine, sample_event):
        """Test that per-user event counts are tracked."""
        campaign_id = 'test_campaign_017'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        metrics = analytics_engine.campaign_data[campaign_id]['aggregated_metrics']
        
        assert metrics['user_event_counts']['user_001'] == 1

    @pytest.mark.asyncio
    async def test_event_type_counts_updated(self, analytics_engine, sample_event):
        """Test that event type counts are tracked."""
        campaign_id = 'test_campaign_018'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        await analytics_engine.process_campaign_event(campaign_id, sample_event)
        
        metrics = analytics_engine.campaign_data[campaign_id]['aggregated_metrics']
        
        assert metrics['event_type_counts']['link_clicked'] == 1


# =============================================================================
# ISSUE #125: generate_campaign_analytics ENHANCEMENT TESTS
# =============================================================================

class TestGenerateCampaignAnalyticsEnhancements:
    """Tests for Issue #125: Enhanced analytics generation."""

    @pytest.mark.asyncio
    async def test_analytics_includes_risk_profiles(self, analytics_engine):
        """Test that generated analytics include risk_profiles."""
        campaign_id = 'test_campaign_019'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add some events
        for event_type in ['email_opened', 'link_clicked', 'credentials_submitted']:
            event = {
                'user_id': 'user_1',
                'event_type': event_type,
                'timestamp': datetime.utcnow().isoformat(),
                'response_time_seconds': 60
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        analytics = await analytics_engine.generate_campaign_analytics(campaign_id)
        
        assert analytics.risk_profiles is not None
        assert len(analytics.risk_profiles) > 0

    @pytest.mark.asyncio
    async def test_analytics_includes_user_segments(self, analytics_engine):
        """Test that generated analytics include user_segments."""
        campaign_id = 'test_campaign_020'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add events from different users
        for i in range(5):
            event = {
                'user_id': f'user_{i}',
                'event_type': 'link_clicked' if i < 3 else 'credentials_submitted',
                'timestamp': datetime.utcnow().isoformat(),
                'response_time_seconds': 60
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        analytics = await analytics_engine.generate_campaign_analytics(campaign_id)
        
        assert analytics.user_segments is not None
        assert 'high_risk' in analytics.user_segments
        assert 'low_risk' in analytics.user_segments

    @pytest.mark.asyncio
    async def test_analytics_includes_peak_periods(self, analytics_engine):
        """Test that generated analytics include peak_engagement_periods."""
        campaign_id = 'test_campaign_021'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add events
        for i in range(10):
            event = {
                'user_id': f'user_{i}',
                'event_type': 'email_opened',
                'timestamp': datetime.utcnow().isoformat()
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        analytics = await analytics_engine.generate_campaign_analytics(campaign_id)
        
        assert analytics.peak_engagement_periods is not None

    @pytest.mark.asyncio
    async def test_analytics_includes_trend_analysis(self, analytics_engine):
        """Test that generated analytics include trend_analysis."""
        campaign_id = 'test_campaign_022'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        # Add events
        for i in range(5):
            event = {
                'user_id': f'user_{i}',
                'event_type': 'email_opened',
                'timestamp': datetime.utcnow().isoformat()
            }
            await analytics_engine.process_campaign_event(campaign_id, event)
        
        analytics = await analytics_engine.generate_campaign_analytics(campaign_id)
        
        assert analytics.trend_analysis is not None
        assert 'direction' in analytics.trend_analysis


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Edge case tests."""

    @pytest.mark.asyncio
    async def test_process_event_unknown_campaign_returns_original(self, analytics_engine, sample_event):
        """Test processing event for unknown campaign returns original event."""
        result = await analytics_engine.process_campaign_event('nonexistent', sample_event)
        
        assert result == sample_event
        assert 'risk_score' not in result

    @pytest.mark.asyncio
    async def test_dashboard_empty_campaign(self, analytics_engine):
        """Test dashboard for campaign with no events."""
        campaign_id = 'empty_campaign'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        dashboard = await analytics_engine.get_real_time_dashboard(campaign_id)
        
        assert dashboard is not None
        assert 'analytics_summary' in dashboard

    @pytest.mark.asyncio
    async def test_event_without_timestamp(self, analytics_engine):
        """Test processing event without timestamp."""
        campaign_id = 'test_campaign_023'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        event = {
            'user_id': 'user_1',
            'event_type': 'email_opened'
            # No timestamp
        }
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, event)
        
        # Should still work, just without temporal enrichment
        assert 'risk_score' in enriched

    @pytest.mark.asyncio
    async def test_event_without_user_id(self, analytics_engine):
        """Test processing event without user_id."""
        campaign_id = 'test_campaign_024'
        await analytics_engine.start_campaign_analytics(campaign_id, {})
        
        event = {
            'event_type': 'email_sent',
            'timestamp': datetime.utcnow().isoformat()
            # No user_id
        }
        
        enriched = await analytics_engine.process_campaign_event(campaign_id, event)
        
        # Should still work
        assert 'risk_score' in enriched
        assert 'user_risk_profile' not in enriched


# =============================================================================
# RUN TESTS
# =============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
