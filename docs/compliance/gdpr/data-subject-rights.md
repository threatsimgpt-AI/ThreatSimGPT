**ThreatSimGPT Data Subject Rights Implementation**

**Version:** 1.0  
**Last Updated:** January 20, 2026  
**Owner:** Compliance Team  

---

**Overview**

This document details the implementation of GDPR Data Subject Rights (Articles 12-23) in ThreatSimGPT. It provides technical specifications, workflows, and code examples for handling data subject requests.

---

**1. Rights Summary**

| Right | Article | Implementation | Automation |
|-------|---------|----------------|------------|
| Information | 13-14 | Privacy policy, notices | Full |
| Access | 15 | Data export | Full |
| Rectification | 16 | Profile editing | Full |
| Erasure | 17 | Account deletion | Full |
| Restriction | 18 | Processing limits | Partial |
| Portability | 20 | Data export | Full |
| Object | 21 | Opt-out mechanisms | Full |
| Automated decisions | 22 | Not applicable | N/A |

---

**2. Right of Access (Article 15)**

**Section 2.1 Scope**

Users can request:
- Confirmation of processing
- Copy of personal data
- Processing purposes
- Categories of data
- Recipients
- Retention periods
- Rights information
- Source of data

**Section 2.2 Implementation**

```python
**Data Subject Access Request (DSAR) Service**

from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum
import json
import zipfile
import io


class DSARStatus(Enum):
    PENDING = "pending"
    VERIFYING = "verifying"
    PROCESSING = "processing"
    READY = "ready"
    DELIVERED = "delivered"
    EXPIRED = "expired"


@dataclass
class DSARRequest:
    """Data Subject Access Request."""
    request_id: str
    user_id: str
    request_type: str  # "access", "erasure", "portability", etc.
    status: DSARStatus
    created_at: datetime
    verified_at: Optional[datetime]
    completed_at: Optional[datetime]
    download_url: Optional[str]
    download_expiry: Optional[datetime]


class DataAccessService:
    """Service for handling Article 15 access requests."""
    
    def __init__(self, db, storage, email_service):
        self.db = db
        self.storage = storage
        self.email = email_service
    
    async def create_access_request(self, user_id: str) -> DSARRequest:
        """Initiate a data access request."""
        
        request = DSARRequest(
            request_id=generate_uuid(),
            user_id=user_id,
            request_type="access",
            status=DSARStatus.PENDING,
            created_at=datetime.utcnow(),
            verified_at=None,
            completed_at=None,
            download_url=None,
            download_expiry=None
        )
        
        await self.db.save(request)
        
        # Send verification email
        await self.email.send_verification(
            user_id=user_id,
            request_id=request.request_id,
            action="data_access"
        )
        
        return request
    
    async def verify_request(self, request_id: str, token: str) -> bool:
        """Verify the access request via email token."""
        
        request = await self.db.get_request(request_id)
        
        if not request:
            return False
        
        if not await self.email.verify_token(token, request_id):
            return False
        
        request.status = DSARStatus.VERIFYING
        request.verified_at = datetime.utcnow()
        await self.db.save(request)
        
        # Trigger async data compilation
        await self.queue_data_compilation(request_id)
        
        return True
    
    async def compile_user_data(self, user_id: str) -> Dict[str, Any]:
        """Compile all user data for export."""
        
        data = {
            "export_metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "format_version": "1.0",
                "data_controller": "ThreatSimGPT Project",
                "contact": "privacy@threatsimgpt.io"
            },
            "data_subject": await self._get_account_data(user_id),
            "processing_information": self._get_processing_info(),
            "data_categories": await self._get_data_categories(user_id),
            "personal_data": {
                "account": await self._get_account_data(user_id),
                "usage_history": await self._get_usage_data(user_id),
                "simulations": await self._get_simulation_data(user_id),
                "support_tickets": await self._get_support_data(user_id),
                "consent_records": await self._get_consent_data(user_id),
                "api_keys": await self._get_api_keys(user_id),
                "sessions": await self._get_session_data(user_id)
            },
            "data_recipients": self._get_recipients(),
            "retention_periods": self._get_retention_info(),
            "your_rights": self._get_rights_info()
        }
        
        return data
    
    async def _get_account_data(self, user_id: str) -> Dict:
        """Get account profile data."""
        user = await self.db.get_user(user_id)
        return {
            "user_id": user.id,
            "email": user.email,
            "username": user.username,
            "display_name": user.display_name,
            "created_at": user.created_at.isoformat(),
            "last_login": user.last_login.isoformat() if user.last_login else None,
            "email_verified": user.email_verified,
            "mfa_enabled": user.mfa_enabled
        }
    
    async def _get_usage_data(self, user_id: str) -> List[Dict]:
        """Get usage history (last 90 days)."""
        usage = await self.db.get_usage_logs(user_id, days=90)
        return [
            {
                "timestamp": u.timestamp.isoformat(),
                "action": u.action,
                "endpoint": u.endpoint,
                "ip_address": u.ip_address,  # Include for transparency
                "user_agent": u.user_agent
            }
            for u in usage
        ]
    
    async def _get_simulation_data(self, user_id: str) -> List[Dict]:
        """Get simulation history."""
        simulations = await self.db.get_simulations(user_id)
        return [
            {
                "simulation_id": s.id,
                "type": s.simulation_type,
                "created_at": s.created_at.isoformat(),
                "parameters": s.parameters,
                "status": s.status
                # Output not included - user can export separately
            }
            for s in simulations
        ]
    
    async def _get_consent_data(self, user_id: str) -> List[Dict]:
        """Get consent history."""
        consents = await self.db.get_consent_history(user_id)
        return [
            {
                "consent_id": c.consent_id,
                "category": c.category,
                "granted": c.granted,
                "timestamp": c.timestamp.isoformat(),
                "version": c.version,
                "withdrawn_at": c.withdrawn_at.isoformat() if c.withdrawn_at else None
            }
            for c in consents
        ]
    
    def _get_processing_info(self) -> Dict:
        """Get standard processing information."""
        return {
            "purposes": [
                "Service delivery",
                "Security monitoring",
                "Support handling",
                "Service improvement (anonymized)"
            ],
            "legal_bases": {
                "service_delivery": "Contract (Article 6(1)(b))",
                "security": "Legitimate interest (Article 6(1)(f))",
                "support": "Contract (Article 6(1)(b))",
                "marketing": "Consent (Article 6(1)(a))"
            }
        }
    
    def _get_recipients(self) -> List[Dict]:
        """Get data recipient information."""
        return [
            {
                "category": "Cloud infrastructure provider",
                "location": "EU",
                "purpose": "Hosting and data storage",
                "safeguards": "DPA in place"
            },
            {
                "category": "Email service provider",
                "location": "EU",
                "purpose": "Transactional emails",
                "safeguards": "DPA in place"
            }
        ]
    
    def _get_retention_info(self) -> Dict:
        """Get retention period information."""
        return {
            "account_data": "Account lifetime + 30 days",
            "usage_logs": "90 days",
            "security_logs": "1 year",
            "simulation_data": "User-defined (default 30 days)",
            "support_data": "2 years"
        }
    
    def _get_rights_info(self) -> Dict:
        """Get rights information."""
        return {
            "access": "You exercised this right to receive this data",
            "rectification": "Update your data at /settings/profile",
            "erasure": "Request account deletion at /settings/account",
            "restriction": "Contact privacy@threatsimgpt.io",
            "portability": "Export data in machine-readable format",
            "object": "Manage at /settings/privacy",
            "complaint": "Lodge complaint with supervisory authority"
        }
    
    async def create_export_package(
        self, 
        user_id: str,
        format: str = "json"
    ) -> bytes:
        """Create downloadable export package."""
        
        data = await self.compile_user_data(user_id)
        
        # Create ZIP archive
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
            
            # Main data file
            if format == "json":
                zf.writestr(
                    "personal_data.json",
                    json.dumps(data, indent=2, default=str)
                )
            
            # Human-readable summary
            zf.writestr(
                "README.txt",
                self._generate_readme(data)
            )
            
            # Separate CSV for usage history
            zf.writestr(
                "usage_history.csv",
                self._to_csv(data["personal_data"]["usage_history"])
            )
            
            # Separate CSV for simulations
            zf.writestr(
                "simulations.csv",
                self._to_csv(data["personal_data"]["simulations"])
            )
        
        return buffer.getvalue()
    
    def _generate_readme(self, data: Dict) -> str:
        """Generate human-readable README."""
        return f"""
ThreatSimGPT Data Export
========================

Generated: {data['export_metadata']['generated_at']}

This archive contains your personal data as processed by ThreatSimGPT.

Files Included:
- personal_data.json: Complete data in machine-readable format
- usage_history.csv: Your usage history (last 90 days)
- simulations.csv: Your simulation history

Data Controller: {data['export_metadata']['data_controller']}
Contact: {data['export_metadata']['contact']}

Your Rights:
{json.dumps(data['your_rights'], indent=2)}

For questions, contact: privacy@threatsimgpt.io
        """
```

**Section 2.3 API Endpoints**

```python
**DSAR API endpoints**

from fastapi import APIRouter, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse

router = APIRouter(prefix="/api/v1/gdpr", tags=["gdpr"])


@router.post("/access-request")
async def request_data_access(
    user: User = Depends(get_current_user),
    background_tasks: BackgroundTasks = None
) -> dict:
    """Initiate a data access request (Article 15)."""
    
    # Check for existing pending request
    existing = await dsar_service.get_pending_request(user.id, "access")
    if existing:
        return {
            "status": "pending",
            "request_id": existing.request_id,
            "message": "You have a pending request. Check your email."
        }
    
    request = await dsar_service.create_access_request(user.id)
    
    return {
        "status": "initiated",
        "request_id": request.request_id,
        "message": "Verification email sent. Please confirm to proceed.",
        "estimated_completion": "Within 30 days"
    }


@router.get("/access-request/{request_id}/status")
async def get_request_status(
    request_id: str,
    user: User = Depends(get_current_user)
) -> dict:
    """Check status of a data access request."""
    
    request = await dsar_service.get_request(request_id)
    
    if not request or request.user_id != user.id:
        raise HTTPException(status_code=404, detail="Request not found")
    
    return {
        "request_id": request.request_id,
        "status": request.status.value,
        "created_at": request.created_at.isoformat(),
        "download_url": request.download_url,
        "download_expiry": request.download_expiry.isoformat() if request.download_expiry else None
    }


@router.get("/access-request/{request_id}/download")
async def download_data_export(
    request_id: str,
    user: User = Depends(get_current_user)
) -> StreamingResponse:
    """Download completed data export."""
    
    request = await dsar_service.get_request(request_id)
    
    if not request or request.user_id != user.id:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if request.status != DSARStatus.READY:
        raise HTTPException(status_code=400, detail="Export not ready")
    
    if request.download_expiry < datetime.utcnow():
        raise HTTPException(status_code=410, detail="Download link expired")
    
    # Get export file
    export_data = await dsar_service.get_export_file(request_id)
    
    # Mark as delivered
    await dsar_service.mark_delivered(request_id)
    
    return StreamingResponse(
        io.BytesIO(export_data),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=threatsimgpt_data_export_{request_id}.zip"
        }
    )
```

---

**3. Right to Rectification (Article 16)**

**Section 3.1 Implementation**

Users can update their data via:
- Profile settings (self-service)
- API endpoints
- Support request (for data they cannot edit)

```python
**Profile update service**

class ProfileService:
    """Service for profile data management."""
    
    # Editable fields
    EDITABLE_FIELDS = {
        "display_name",
        "email",  # Requires verification
        "username",  # Subject to uniqueness
        "timezone",
        "language"
    }
    
    async def update_profile(
        self,
        user_id: str,
        updates: Dict[str, Any]
    ) -> Dict:
        """Update user profile data."""
        
        # Validate fields
        invalid_fields = set(updates.keys()) - self.EDITABLE_FIELDS
        if invalid_fields:
            raise ValueError(f"Cannot update fields: {invalid_fields}")
        
        user = await self.db.get_user(user_id)
        
        # Handle email change (requires verification)
        if "email" in updates and updates["email"] != user.email:
            await self._initiate_email_change(user_id, updates["email"])
            del updates["email"]  # Don't update until verified
        
        # Handle username change (check uniqueness)
        if "username" in updates:
            if await self.db.username_exists(updates["username"]):
                raise ValueError("Username already taken")
        
        # Apply updates
        for field, value in updates.items():
            setattr(user, field, value)
        
        user.updated_at = datetime.utcnow()
        await self.db.save(user)
        
        # Audit log
        await self._audit_log(
            user_id=user_id,
            action="profile_updated",
            fields=list(updates.keys())
        )
        
        return {"status": "updated", "fields": list(updates.keys())}
```

---

**4. Right to Erasure (Article 17)**

**Section 4.1 Scope**

Users can request deletion of:
- Account and profile data
- Usage history
- Simulation data
- Support tickets (anonymized)

**Section 4.2 Exceptions**

Data retained despite erasure request:
- Security logs (legal obligation) - anonymized
- Aggregated analytics (no personal data)
- Data required for legal claims

**Section 4.3 Implementation**

```python
**Account deletion service**

class AccountDeletionService:
    """Service for handling erasure requests (Article 17)."""
    
    GRACE_PERIOD_DAYS = 30
    
    async def request_deletion(self, user_id: str) -> Dict:
        """Initiate account deletion with grace period."""
        
        # Check for existing deletion request
        existing = await self.db.get_deletion_request(user_id)
        if existing:
            return {
                "status": "pending",
                "deletion_date": existing.deletion_date.isoformat(),
                "cancel_url": f"/api/v1/gdpr/cancel-deletion/{existing.request_id}"
            }
        
        deletion_date = datetime.utcnow() + timedelta(days=self.GRACE_PERIOD_DAYS)
        
        request = DeletionRequest(
            request_id=generate_uuid(),
            user_id=user_id,
            requested_at=datetime.utcnow(),
            deletion_date=deletion_date,
            status="pending"
        )
        
        await self.db.save(request)
        
        # Send confirmation email
        await self.email.send_deletion_scheduled(
            user_id=user_id,
            deletion_date=deletion_date,
            cancel_token=request.cancel_token
        )
        
        # Suspend account immediately
        await self.suspend_account(user_id, reason="deletion_pending")
        
        return {
            "status": "scheduled",
            "deletion_date": deletion_date.isoformat(),
            "grace_period_days": self.GRACE_PERIOD_DAYS,
            "message": "Account scheduled for deletion. You can cancel within the grace period."
        }
    
    async def cancel_deletion(self, request_id: str, token: str) -> bool:
        """Cancel a pending deletion request."""
        
        request = await self.db.get_deletion_request_by_id(request_id)
        
        if not request or request.cancel_token != token:
            return False
        
        if request.status != "pending":
            return False
        
        request.status = "cancelled"
        request.cancelled_at = datetime.utcnow()
        await self.db.save(request)
        
        # Reactivate account
        await self.reactivate_account(request.user_id)
        
        return True
    
    async def execute_deletion(self, user_id: str) -> Dict:
        """Execute account deletion (called by scheduled job)."""
        
        deletion_log = {
            "user_id": user_id,
            "executed_at": datetime.utcnow().isoformat(),
            "data_deleted": [],
            "data_retained": [],
            "data_anonymized": []
        }
        
        # 1. Delete account data
        await self.db.delete_user(user_id)
        deletion_log["data_deleted"].append("account_data")
        
        # 2. Delete simulation data
        await self.db.delete_simulations(user_id)
        deletion_log["data_deleted"].append("simulations")
        
        # 3. Delete usage logs
        await self.db.delete_usage_logs(user_id)
        deletion_log["data_deleted"].append("usage_logs")
        
        # 4. Revoke all API keys
        await self.db.revoke_api_keys(user_id)
        deletion_log["data_deleted"].append("api_keys")
        
        # 5. Delete consent records (after grace period for audit)
        await self.db.delete_consent_records(user_id)
        deletion_log["data_deleted"].append("consent_records")
        
        # 6. Anonymize support tickets (retain for service improvement)
        await self.db.anonymize_support_tickets(user_id)
        deletion_log["data_anonymized"].append("support_tickets")
        
        # 7. Anonymize security logs (legal obligation)
        await self.db.anonymize_security_logs(user_id)
        deletion_log["data_anonymized"].append("security_logs")
        deletion_log["data_retained"].append("security_logs (anonymized, 1 year)")
        
        # 8. Remove from analytics (already anonymized)
        # No action needed - analytics uses anonymous IDs
        
        # Log deletion for compliance
        await self._log_deletion(deletion_log)
        
        return deletion_log
    
    async def _log_deletion(self, log: Dict) -> None:
        """Log deletion for compliance audit."""
        # Store anonymized deletion record
        await self.db.save_deletion_log(
            log_id=generate_uuid(),
            deleted_at=log["executed_at"],
            data_deleted=log["data_deleted"],
            data_retained=log["data_retained"]
            # user_id NOT stored - already deleted
        )
```

**Section 4.4 Deletion Schedule Job**

```python
**Scheduled job to execute pending deletions**

from apscheduler.schedulers.asyncio import AsyncIOScheduler

async def process_pending_deletions():
    """Process deletion requests past grace period."""
    
    pending = await deletion_service.get_due_deletions()
    
    for request in pending:
        try:
            # Execute deletion
            result = await deletion_service.execute_deletion(request.user_id)
            
            # Update request status
            request.status = "completed"
            request.completed_at = datetime.utcnow()
            await db.save(request)
            
            logger.info(f"Deletion completed for request {request.request_id}")
            
        except Exception as e:
            logger.error(f"Deletion failed for {request.request_id}: {e}")
            request.status = "failed"
            request.error = str(e)
            await db.save(request)


**Schedule daily at 2 AM**
scheduler = AsyncIOScheduler()
scheduler.add_job(
    process_pending_deletions,
    'cron',
    hour=2,
    minute=0
)
```

---

**5. Right to Data Portability (Article 20)**

**Section 5.1 Implementation**

Data portability uses the same export mechanism as access requests but emphasizes machine-readable formats.

```python
**Data portability service**

class DataPortabilityService:
    """Service for Article 20 data portability."""
    
    PORTABLE_DATA = [
        "account_data",
        "simulations",
        "api_configurations",
        "preferences"
    ]
    
    async def export_portable_data(
        self,
        user_id: str,
        format: str = "json"
    ) -> bytes:
        """Export data in portable format."""
        
        data = {}
        
        for category in self.PORTABLE_DATA:
            data[category] = await self._get_data(user_id, category)
        
        if format == "json":
            return json.dumps(data, indent=2, default=str).encode()
        elif format == "csv":
            return self._to_csv_archive(data)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def transfer_to_controller(
        self,
        user_id: str,
        destination_controller: str,
        destination_api: str
    ) -> Dict:
        """
        Transfer data to another controller (Article 20(2)).
        
        Note: Requires technical feasibility and destination 
        controller's acceptance.
        """
        
        # This would require standard API integration
        # with other controllers - implementation depends
        # on industry standards adoption
        
        raise NotImplementedError(
            "Direct transfer requires destination controller API integration"
        )
```

---

**6. Right to Object (Article 21)**

**Section 6.1 Implementation**

Objection mechanisms for different processing types:

```python
**Processing objection service**

class ObjectionService:
    """Service for handling processing objections."""
    
    async def object_to_processing(
        self,
        user_id: str,
        processing_type: str,
        reason: Optional[str] = None
    ) -> Dict:
        """Handle objection to specific processing."""
        
        # Map processing types to actions
        handlers = {
            "direct_marketing": self._stop_direct_marketing,
            "analytics": self._stop_analytics,
            "profiling": self._stop_profiling,  # N/A for ThreatSimGPT
            "legitimate_interest": self._review_legitimate_interest
        }
        
        handler = handlers.get(processing_type)
        if not handler:
            raise ValueError(f"Unknown processing type: {processing_type}")
        
        result = await handler(user_id, reason)
        
        # Log objection
        await self._log_objection(user_id, processing_type, reason, result)
        
        return result
    
    async def _stop_direct_marketing(
        self,
        user_id: str,
        reason: str
    ) -> Dict:
        """Stop direct marketing - must be honored immediately."""
        
        # Withdraw marketing consent
        await consent_service.withdraw_consent(
            user_id=user_id,
            category=ConsentCategory.MARKETING_EMAIL,
            method="objection"
        )
        
        # Unsubscribe from all marketing lists
        await marketing_service.unsubscribe_all(user_id)
        
        return {
            "status": "honored",
            "processing_type": "direct_marketing",
            "effect": "immediate",
            "message": "All direct marketing stopped"
        }
    
    async def _stop_analytics(
        self,
        user_id: str,
        reason: str
    ) -> Dict:
        """Stop identified analytics."""
        
        await consent_service.withdraw_consent(
            user_id=user_id,
            category=ConsentCategory.ANALYTICS_IDENTIFIED,
            method="objection"
        )
        
        # Enable anonymous-only mode
        await user_service.set_anonymous_analytics(user_id, True)
        
        return {
            "status": "honored",
            "processing_type": "analytics",
            "effect": "immediate",
            "message": "Identified analytics disabled. Anonymous analytics continues."
        }
    
    async def _review_legitimate_interest(
        self,
        user_id: str,
        reason: str
    ) -> Dict:
        """
        Review legitimate interest objection.
        
        Note: Legitimate interest objections require assessment
        and may not always be honored.
        """
        
        # Create review ticket
        ticket = await support_service.create_ticket(
            user_id=user_id,
            type="gdpr_objection",
            subject="Legitimate Interest Objection Review",
            details={
                "reason": reason,
                "requires_assessment": True
            }
        )
        
        return {
            "status": "under_review",
            "processing_type": "legitimate_interest",
            "ticket_id": ticket.id,
            "message": "Your objection will be reviewed. We'll respond within 30 days.",
            "timeline": "30 days"
        }
```

---

**7. Request Handling Workflow**

**Section 7.1 Unified DSAR Handler**

```python
**Unified DSAR workflow**

class DSARHandler:
    """Unified handler for all Data Subject Access Requests."""
    
    REQUEST_TYPES = {
        "access": DataAccessService,
        "rectification": ProfileService,
        "erasure": AccountDeletionService,
        "restriction": RestrictionService,
        "portability": DataPortabilityService,
        "objection": ObjectionService
    }
    
    # SLA in days
    SLA = {
        "access": 30,
        "rectification": 30,
        "erasure": 30,
        "restriction": 30,
        "portability": 30,
        "objection": 30
    }
    
    async def handle_request(
        self,
        user_id: str,
        request_type: str,
        details: Dict = None
    ) -> Dict:
        """Handle any GDPR request."""
        
        # Validate request type
        if request_type not in self.REQUEST_TYPES:
            raise ValueError(f"Invalid request type: {request_type}")
        
        # Get appropriate service
        service_class = self.REQUEST_TYPES[request_type]
        service = service_class(self.db, self.storage, self.email)
        
        # Create audit record
        audit_id = await self._create_audit_record(
            user_id=user_id,
            request_type=request_type,
            sla_days=self.SLA[request_type]
        )
        
        try:
            # Execute request
            result = await service.handle(user_id, details)
            
            # Update audit record
            await self._complete_audit_record(audit_id, "completed", result)
            
            return result
            
        except Exception as e:
            await self._complete_audit_record(audit_id, "failed", str(e))
            raise
    
    async def _create_audit_record(
        self,
        user_id: str,
        request_type: str,
        sla_days: int
    ) -> str:
        """Create DSAR audit record."""
        
        record = {
            "audit_id": generate_uuid(),
            "user_id": user_id,
            "request_type": request_type,
            "received_at": datetime.utcnow().isoformat(),
            "sla_deadline": (datetime.utcnow() + timedelta(days=sla_days)).isoformat(),
            "status": "processing"
        }
        
        await self.db.save_audit_record(record)
        return record["audit_id"]
```

---

**8. Response Templates**

**Section 8.1 Email Templates**

```python
**DSAR email templates**

TEMPLATES = {
    "access_request_received": """
Subject: Your Data Access Request - ThreatSimGPT

Dear {user_name},

We received your request to access your personal data under Article 15 of the GDPR.

Request ID: {request_id}
Received: {received_date}
Expected completion: Within 30 days

To verify this request, please click the link below:
{verification_link}

If you did not make this request, please ignore this email.

Best regards,
ThreatSimGPT Privacy Team
privacy@threatsimgpt.io
    """,
    
    "access_request_ready": """
Subject: Your Data Export is Ready - ThreatSimGPT

Dear {user_name},

Your personal data export is ready for download.

Request ID: {request_id}
Download link: {download_link}
Link expires: {expiry_date}

The download includes:
- Personal data in JSON format
- Usage history (CSV)
- Simulation history (CSV)
- Consent records

For security, this link will expire in 7 days.

Best regards,
ThreatSimGPT Privacy Team
    """,
    
    "deletion_scheduled": """
Subject: Account Deletion Scheduled - ThreatSimGPT

Dear {user_name},

As requested, your account is scheduled for deletion.

Deletion date: {deletion_date}
Grace period: 30 days

During the grace period, you can cancel the deletion:
{cancel_link}

After {deletion_date}, all your data will be permanently deleted 
and cannot be recovered.

If you did not request this, please cancel immediately and 
contact us at security@threatsimgpt.io

Best regards,
ThreatSimGPT Privacy Team
    """
}
```

---

**Appendix: Compliance Checklist**

**Section Articles 12-23 Implementation Status**

| Article | Right | Status | Automation |
|---------|-------|--------|------------|
| 12 | Transparent information | | Full |
| 13 | Information at collection | | Full |
| 14 | Information not from subject | | Full |
| 15 | Right of access | | Full |
| 16 | Right to rectification | | Full |
| 17 | Right to erasure | | Full |
| 18 | Right to restriction | | Partial |
| 19 | Notification obligation | | Full |
| 20 | Right to portability | | Full |
| 21 | Right to object | | Full |
| 22 | Automated decisions | N/A | N/A |

---

*Document maintained by ThreatSimGPT Compliance Team*  
*Related: [GDPR Overview](README.md) | [Consent Management](consent-management.md)*
