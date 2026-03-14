**ThreatSimGPT GDPR Consent Management**

**Version:** 1.0  
**Last Updated:** January 20, 2026  
**Owner:** Compliance Team  

---

**Overview**

This document describes ThreatSimGPT's consent management system, ensuring GDPR-compliant consent collection, storage, and withdrawal mechanisms.

---

**1. Consent Requirements**

**Section 1.1 When Consent is Required**

| Processing Activity | Legal Basis | Consent Required |
|---------------------|-------------|------------------|
| Account creation | Contract | No |
| Service delivery | Contract | No |
| Security monitoring | Legitimate interest | No |
| Marketing emails | Consent | Yes |
| Analytics (identified) | Consent | Yes |
| Third-party integrations | Consent | Yes |
| Feature beta programs | Consent | Yes |

**Section 1.2 GDPR Consent Conditions (Article 7)**

| Condition | Implementation |
|-----------|----------------|
| **Freely given** | No service degradation for refusal |
| **Specific** | Separate consent per purpose |
| **Informed** | Clear explanation before collection |
| **Unambiguous** | Affirmative opt-in action |
| **Withdrawable** | Easy withdrawal mechanism |
| **Documented** | Full audit trail |

---

**2. Consent Types**

**Section 2.1 Consent Categories**

```python
from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

class ConsentCategory(Enum):
    """GDPR consent categories for ThreatSimGPT."""
    
    MARKETING_EMAIL = "marketing_email"
    MARKETING_PUSH = "marketing_push"
    ANALYTICS_IDENTIFIED = "analytics_identified"
    THIRD_PARTY_INTEGRATIONS = "third_party_integrations"
    BETA_FEATURES = "beta_features"
    RESEARCH_PARTICIPATION = "research_participation"
    NEWSLETTER = "newsletter"


@dataclass
class ConsentRecord:
    """Individual consent record."""
    
    consent_id: str
    user_id: str
    category: ConsentCategory
    granted: bool
    timestamp: datetime
    method: str  # e.g., "checkbox", "settings_toggle", "api"
    version: str  # Consent text version
    ip_address_hash: str
    user_agent_hash: str
    expiry: Optional[datetime] = None
    withdrawn_at: Optional[datetime] = None
    withdrawal_method: Optional[str] = None
```

**Section 2.2 Consent Text Versions**

Each consent type has versioned explanatory text:

```yaml
**consent_texts.yaml

consent_texts:
  marketing_email:
    version: "1.0"
    effective_date: "2026-01-20"
    title: "Marketing Communications"
    description: |
      I agree to receive marketing emails from ThreatSimGPT, including:
      - Product updates and new features
      - Security tips and best practices
      - Special offers and promotions
      
      You can unsubscribe at any time using the link in each email
      or through your account settings.
    
  analytics_identified:
    version: "1.0"
    effective_date: "2026-01-20"
    title: "Identified Analytics"
    description: |
      I agree to allow ThreatSimGPT to analyze my usage patterns
      to provide personalized recommendations and improve the service.
      
      This includes:
      - Feature usage patterns
      - Simulation preferences
      - Performance optimizations
      
      Your data is never sold to third parties.
    
  beta_features:
    version: "1.0"
    effective_date: "2026-01-20"
    title: "Beta Features Program"
    description: |
      I agree to participate in the ThreatSimGPT Beta Features Program.
      
      This includes:
      - Early access to new features
      - Providing feedback on beta functionality
      - Potential data collection for feature improvement
      
      Beta features may be unstable and are provided as-is.
```

---

**3. Consent Collection**

**Section 3.1 Collection Points**

| Point | Consent Types | Method |
|-------|---------------|--------|
| Registration | Marketing, Newsletter | Opt-in checkboxes |
| Settings page | All types | Toggles |
| Feature prompt | Beta features | Modal dialog |
| Email footer | Marketing | Preference center link |
| API | All types | Explicit endpoints |

**Section 3.2 UI Implementation**

```typescript
// React component for consent collection

interface ConsentCheckboxProps {
  category: ConsentCategory;
  version: string;
  onChange: (granted: boolean) => void;
}

const ConsentCheckbox: React.FC<ConsentCheckboxProps> = ({
  category,
  version,
  onChange
}) => {
  const [checked, setChecked] = useState(false);
  const consentText = useConsentText(category, version);
  
  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const granted = e.target.checked;
    setChecked(granted);
    onChange(granted);
  };
  
  return (
    <div className="consent-checkbox">
      <label>
        <input
          type="checkbox"
          checked={checked}
          onChange={handleChange}
          // No pre-checked boxes - GDPR compliant
        />
        <span className="consent-title">{consentText.title}</span>
      </label>
      <p className="consent-description">{consentText.description}</p>
      <a href="/privacy-policy" target="_blank">
        Learn more about how we use your data
      </a>
    </div>
  );
};
```

**Section 3.3 API Endpoints**

```python
**Consent API endpoints**

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from datetime import datetime

router = APIRouter(prefix="/api/v1/consent", tags=["consent"])


class ConsentRequest(BaseModel):
    """Request to grant or update consent."""
    category: ConsentCategory
    granted: bool
    version: str


class ConsentResponse(BaseModel):
    """Consent operation response."""
    consent_id: str
    category: ConsentCategory
    granted: bool
    timestamp: datetime
    version: str


class ConsentStatusResponse(BaseModel):
    """User's consent status for all categories."""
    consents: List[ConsentResponse]


@router.get("/status", response_model=ConsentStatusResponse)
async def get_consent_status(
    user: User = Depends(get_current_user)
) -> ConsentStatusResponse:
    """Get user's current consent status for all categories."""
    consents = await consent_service.get_user_consents(user.id)
    return ConsentStatusResponse(consents=consents)


@router.post("/grant", response_model=ConsentResponse)
async def grant_consent(
    request: ConsentRequest,
    user: User = Depends(get_current_user)
) -> ConsentResponse:
    """Grant consent for a specific category."""
    
    # Validate version is current
    if not consent_service.is_current_version(request.category, request.version):
        raise HTTPException(
            status_code=400,
            detail="Consent version is outdated. Please review the updated terms."
        )
    
    consent = await consent_service.record_consent(
        user_id=user.id,
        category=request.category,
        granted=request.granted,
        version=request.version,
        method="api",
        ip_hash=hash_ip(request.client.host),
        ua_hash=hash_user_agent(request.headers.get("user-agent"))
    )
    
    return consent


@router.post("/withdraw/{category}")
async def withdraw_consent(
    category: ConsentCategory,
    user: User = Depends(get_current_user)
) -> dict:
    """Withdraw previously granted consent."""
    
    await consent_service.withdraw_consent(
        user_id=user.id,
        category=category,
        method="api"
    )
    
    # Trigger downstream actions (e.g., unsubscribe from marketing)
    await consent_service.execute_withdrawal_actions(user.id, category)
    
    return {"status": "withdrawn", "category": category}


@router.get("/history", response_model=List[ConsentRecord])
async def get_consent_history(
    user: User = Depends(get_current_user)
) -> List[ConsentRecord]:
    """Get full consent history for audit purposes."""
    return await consent_service.get_consent_history(user.id)
```

---

**4. Consent Storage**

**Section 4.1 Database Schema**

```sql
-- Consent records table

CREATE TABLE consent_records (
    consent_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    category VARCHAR(50) NOT NULL,
    granted BOOLEAN NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    method VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    ip_address_hash VARCHAR(64),
    user_agent_hash VARCHAR(64),
    expiry TIMESTAMPTZ,
    withdrawn_at TIMESTAMPTZ,
    withdrawal_method VARCHAR(50),
    
    -- Indexes for common queries
    INDEX idx_consent_user (user_id),
    INDEX idx_consent_category (category),
    INDEX idx_consent_timestamp (timestamp)
);

-- Consent text versions table
CREATE TABLE consent_versions (
    id SERIAL PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    version VARCHAR(20) NOT NULL,
    effective_date DATE NOT NULL,
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    UNIQUE(category, version)
);

-- View for current consent status
CREATE VIEW current_consents AS
SELECT DISTINCT ON (user_id, category)
    consent_id,
    user_id,
    category,
    granted,
    timestamp,
    version,
    withdrawn_at
FROM consent_records
ORDER BY user_id, category, timestamp DESC;
```

**Section 4.2 Consent Service**

```python
**Consent service implementation**

from typing import List, Optional
from datetime import datetime
import hashlib
from uuid import uuid4

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from .models import ConsentRecord, ConsentVersion
from .schemas import ConsentCategory


class ConsentService:
    """Service for managing GDPR consent."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def record_consent(
        self,
        user_id: str,
        category: ConsentCategory,
        granted: bool,
        version: str,
        method: str,
        ip_hash: str,
        ua_hash: str
    ) -> ConsentRecord:
        """Record a consent decision."""
        
        record = ConsentRecord(
            consent_id=str(uuid4()),
            user_id=user_id,
            category=category.value,
            granted=granted,
            timestamp=datetime.utcnow(),
            method=method,
            version=version,
            ip_address_hash=ip_hash,
            user_agent_hash=ua_hash
        )
        
        self.db.add(record)
        await self.db.commit()
        
        # Log for audit
        await self._audit_log(
            action="consent_recorded",
            user_id=user_id,
            details={
                "category": category.value,
                "granted": granted,
                "version": version
            }
        )
        
        return record
    
    async def withdraw_consent(
        self,
        user_id: str,
        category: ConsentCategory,
        method: str
    ) -> None:
        """Withdraw previously granted consent."""
        
        # Get current consent
        current = await self.get_current_consent(user_id, category)
        
        if not current or not current.granted:
            return  # Already withdrawn or never granted
        
        # Record withdrawal
        current.withdrawn_at = datetime.utcnow()
        current.withdrawal_method = method
        
        # Also record as new consent record (granted=False)
        await self.record_consent(
            user_id=user_id,
            category=category,
            granted=False,
            version=current.version,
            method=method,
            ip_hash="",
            ua_hash=""
        )
        
        await self.db.commit()
        
        # Log for audit
        await self._audit_log(
            action="consent_withdrawn",
            user_id=user_id,
            details={"category": category.value}
        )
    
    async def get_current_consent(
        self,
        user_id: str,
        category: ConsentCategory
    ) -> Optional[ConsentRecord]:
        """Get current consent status for a category."""
        
        result = await self.db.execute(
            select(ConsentRecord)
            .where(and_(
                ConsentRecord.user_id == user_id,
                ConsentRecord.category == category.value
            ))
            .order_by(ConsentRecord.timestamp.desc())
            .limit(1)
        )
        
        return result.scalar_one_or_none()
    
    async def get_user_consents(self, user_id: str) -> List[ConsentRecord]:
        """Get all current consents for a user."""
        
        # Get most recent consent for each category
        consents = []
        for category in ConsentCategory:
            consent = await self.get_current_consent(user_id, category)
            if consent:
                consents.append(consent)
        
        return consents
    
    async def has_valid_consent(
        self,
        user_id: str,
        category: ConsentCategory
    ) -> bool:
        """Check if user has valid (granted, not withdrawn) consent."""
        
        consent = await self.get_current_consent(user_id, category)
        
        if not consent:
            return False
        
        if not consent.granted:
            return False
        
        if consent.withdrawn_at:
            return False
        
        if consent.expiry and consent.expiry < datetime.utcnow():
            return False
        
        return True
    
    async def get_consent_history(self, user_id: str) -> List[ConsentRecord]:
        """Get full consent history for audit."""
        
        result = await self.db.execute(
            select(ConsentRecord)
            .where(ConsentRecord.user_id == user_id)
            .order_by(ConsentRecord.timestamp.desc())
        )
        
        return result.scalars().all()
    
    def is_current_version(
        self,
        category: ConsentCategory,
        version: str
    ) -> bool:
        """Check if consent version is current."""
        # In production, query consent_versions table
        return True  # Simplified for example
    
    async def execute_withdrawal_actions(
        self,
        user_id: str,
        category: ConsentCategory
    ) -> None:
        """Execute downstream actions after consent withdrawal."""
        
        actions = {
            ConsentCategory.MARKETING_EMAIL: self._unsubscribe_marketing,
            ConsentCategory.ANALYTICS_IDENTIFIED: self._disable_analytics,
            ConsentCategory.BETA_FEATURES: self._remove_beta_access,
        }
        
        action = actions.get(category)
        if action:
            await action(user_id)
    
    async def _unsubscribe_marketing(self, user_id: str) -> None:
        """Unsubscribe user from marketing emails."""
        # Integration with email service
        pass
    
    async def _disable_analytics(self, user_id: str) -> None:
        """Disable identified analytics for user."""
        # Integration with analytics service
        pass
    
    async def _remove_beta_access(self, user_id: str) -> None:
        """Remove user from beta features program."""
        # Integration with feature flags
        pass
    
    async def _audit_log(
        self,
        action: str,
        user_id: str,
        details: dict
    ) -> None:
        """Log consent action for audit trail."""
        # Integration with audit logging
        pass
```

---

**5. Consent Withdrawal**

**Section 5.1 Withdrawal Methods**

| Method | Location | Process |
|--------|----------|---------|
| Settings toggle | Account settings | Instant effect |
| Unsubscribe link | Email footer | One-click + confirmation |
| API call | Developer access | Programmatic |
| Support request | Support ticket | Manual processing |

**Section 5.2 Withdrawal UI**

```typescript
// Consent management settings component

const ConsentSettings: React.FC = () => {
  const { consents, updateConsent, isLoading } = useConsents();
  
  const handleToggle = async (category: ConsentCategory, granted: boolean) => {
    if (!granted) {
      // Show confirmation for withdrawal
      const confirmed = await showConfirmation({
        title: "Withdraw Consent",
        message: `Are you sure you want to withdraw consent for ${category}? This action takes effect immediately.`,
        confirmText: "Withdraw",
        cancelText: "Cancel"
      });
      
      if (!confirmed) return;
    }
    
    await updateConsent(category, granted);
    
    toast.success(
      granted 
        ? "Consent granted successfully" 
        : "Consent withdrawn successfully"
    );
  };
  
  return (
    <div className="consent-settings">
      <h2>Privacy & Consent Settings</h2>
      <p>Manage how ThreatSimGPT uses your data</p>
      
      {Object.values(ConsentCategory).map(category => (
        <ConsentToggle
          key={category}
          category={category}
          enabled={consents[category]?.granted ?? false}
          onChange={(granted) => handleToggle(category, granted)}
          disabled={isLoading}
        />
      ))}
      
      <div className="consent-info">
        <p>
          <strong>Note:</strong> Withdrawing consent does not affect the 
          lawfulness of processing based on consent before withdrawal.
        </p>
        <a href="/privacy-policy">View Privacy Policy</a>
        <a href="/api/v1/consent/history">Download Consent History</a>
      </div>
    </div>
  );
};
```

**Section 5.3 Withdrawal Effects**

```python
**Consent withdrawal effects matrix**

WITHDRAWAL_EFFECTS = {
    ConsentCategory.MARKETING_EMAIL: {
        "immediate_actions": [
            "Remove from marketing email lists",
            "Cancel scheduled marketing emails",
            "Update CRM preferences"
        ],
        "data_impact": "Marketing preferences deleted",
        "service_impact": "No marketing emails"
    },
    
    ConsentCategory.ANALYTICS_IDENTIFIED: {
        "immediate_actions": [
            "Disable identified tracking",
            "Switch to anonymous analytics",
            "Clear personalization data"
        ],
        "data_impact": "Analytics data anonymized",
        "service_impact": "No personalized recommendations"
    },
    
    ConsentCategory.BETA_FEATURES: {
        "immediate_actions": [
            "Remove beta feature flags",
            "Revert to stable features",
            "Remove from beta user group"
        ],
        "data_impact": "Beta feedback retained (anonymized)",
        "service_impact": "No access to beta features"
    },
    
    ConsentCategory.THIRD_PARTY_INTEGRATIONS: {
        "immediate_actions": [
            "Revoke third-party access tokens",
            "Notify connected services",
            "Disable integrations"
        ],
        "data_impact": "Integration data deleted",
        "service_impact": "Integrations disabled"
    }
}
```

---

**6. Consent Audit Trail**

**Section 6.1 Audit Record Format**

```json
{
  "audit_id": "audit_abc123",
  "timestamp": "2026-01-20T12:30:00Z",
  "event_type": "consent_granted",
  "user_id": "user_123",
  "consent_id": "consent_xyz789",
  "category": "marketing_email",
  "granted": true,
  "version": "1.0",
  "method": "checkbox_registration",
  "metadata": {
    "ip_address_hash": "sha256:...",
    "user_agent_hash": "sha256:...",
    "page_url": "/register",
    "consent_text_displayed": true
  }
}
```

**Section 6.2 Audit Queries**

```python
**Audit query examples**

class ConsentAuditService:
    """Service for consent audit queries."""
    
    async def get_consent_proof(
        self,
        user_id: str,
        category: ConsentCategory,
        as_of: datetime
    ) -> dict:
        """Get proof of consent status at a point in time."""
        
        # Find consent record valid at specified time
        record = await self.db.execute(
            select(ConsentRecord)
            .where(and_(
                ConsentRecord.user_id == user_id,
                ConsentRecord.category == category.value,
                ConsentRecord.timestamp <= as_of
            ))
            .order_by(ConsentRecord.timestamp.desc())
            .limit(1)
        )
        
        consent = record.scalar_one_or_none()
        
        return {
            "user_id": user_id,
            "category": category.value,
            "as_of": as_of.isoformat(),
            "consent_status": consent.granted if consent else None,
            "consent_record": consent.consent_id if consent else None,
            "consent_timestamp": consent.timestamp.isoformat() if consent else None,
            "consent_method": consent.method if consent else None,
            "consent_version": consent.version if consent else None
        }
    
    async def export_consent_audit(
        self,
        user_id: str
    ) -> List[dict]:
        """Export full consent audit trail for a user."""
        
        records = await self.get_consent_history(user_id)
        
        return [
            {
                "consent_id": r.consent_id,
                "category": r.category,
                "granted": r.granted,
                "timestamp": r.timestamp.isoformat(),
                "method": r.method,
                "version": r.version,
                "withdrawn_at": r.withdrawn_at.isoformat() if r.withdrawn_at else None
            }
            for r in records
        ]
```

---

**7. Re-consent Requirements**

**Section 7.1 When Re-consent is Required**

| Scenario | Action Required |
|----------|-----------------|
| Consent text updated | Prompt for new consent |
| Purpose expanded | New consent required |
| New data collection | Specific consent needed |
| Consent expired | Renewal prompt |

**Section 7.2 Re-consent Flow**

```python
**Re-consent check middleware**

async def check_consent_validity(
    user: User,
    required_category: ConsentCategory
) -> bool:
    """Check if user needs to re-consent."""
    
    consent = await consent_service.get_current_consent(
        user.id, 
        required_category
    )
    
    if not consent:
        return False
    
    # Check if consent version is still current
    current_version = await consent_service.get_current_version(required_category)
    
    if consent.version != current_version:
        # Consent text has changed - need re-consent
        return False
    
    # Check expiry
    if consent.expiry and consent.expiry < datetime.utcnow():
        return False
    
    return consent.granted and not consent.withdrawn_at
```

---

**Appendix: Compliance Checklist**

**Section GDPR Article 7 Compliance**

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| Conditions for consent | | Documented above |
| Consent records | | Database + audit trail |
| Withdrawal mechanism | | Multiple methods available |
| Easy to withdraw | | Same ease as granting |
| Separate consents | | Category-based |
| Clear information | | Versioned consent texts |

---

*Document maintained by ThreatSimGPT Compliance Team*
