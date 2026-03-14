**ThreatSimGPT GDPR Compliance**

**Version:** 1.1  
**Effective Date:** January 20, 2026  
**Last Updated:** January 20, 2026  
**Document Owner:** Compliance Team (Jerry - okino007)  
**Review Cycle:** Annual  

---

**Executive Summary**

This document outlines ThreatSimGPT's compliance with the General Data Protection Regulation (GDPR) (EU) 2016/679. It covers data processing activities, lawful bases, data subject rights, and technical/organizational measures implemented to ensure compliance.

**Compliance Status:** COMPLIANT

---

**GDPR Documentation Index**

| Document | GDPR Article | Status |
|----------|--------------|--------|
| [Data Mapping](data-mapping.md) | Article 30 | Complete |
| [Consent Management](consent-management.md) | Article 7 | Complete |
| [Data Subject Rights](data-subject-rights.md) | Articles 12-23 | Complete |
| [DPIA](dpia.md) | Article 35 | Complete |
| [Privacy Notice](privacy-notice.md) | Articles 13-14 | Complete |
| [Data Processing Agreement](data-processing-agreement.md) | Article 28 | Complete |
| [Breach Notification Templates](breach-notification-templates.md) | Articles 33-34 | Complete |
| [Records of Processing](records-of-processing.md) | Article 30 | Complete |

---

**Table of Contents**

1. [Scope and Applicability](#1-scope-and-applicability)
2. [Data Processing Activities](#2-data-processing-activities)
3. [Lawful Bases for Processing](#3-lawful-bases-for-processing)
4. [Data Subject Rights](#4-data-subject-rights)
5. [Consent Management](#5-consent-management)
6. [Data Protection Principles](#6-data-protection-principles)
7. [Technical Measures](#7-technical-measures)
8. [Organizational Measures](#8-organizational-measures)
9. [Data Transfers](#9-data-transfers)
10. [Data Breach Procedures](#10-data-breach-procedures)
11. [Records of Processing](#11-records-of-processing)
12. [Contact Information](#12-contact-information)

---

**1. Scope and Applicability**

**Section 1.1 When GDPR Applies**

ThreatSimGPT processes personal data subject to GDPR when:

| Scenario | GDPR Applies | Notes |
|----------|--------------|-------|
| EU/EEA users | Yes | Regardless of data location |
| EU/EEA data subjects in simulations | Yes | Content-based processing |
| Non-EU users, no EU data | No | Other regulations may apply |
| UK users | Yes | UK GDPR equivalent |

**Section 1.2 Data Controller vs Processor**

| Context | Role | Responsibilities |
|---------|------|------------------|
| Platform operation | Controller | Full GDPR compliance |
| Customer simulations | Processor | Per DPA agreements |
| API integrations | Processor | Per service agreements |

**Section 1.3 Legal Entity**

**Data Controller:**  
ThreatSimGPT Project  
Contact: compliance@threatsimgpt.io

---

**2. Data Processing Activities**

**Section 2.1 Personal Data Categories**

| Category | Examples | Sensitivity | Retention |
|----------|----------|-------------|-----------|
| Account Data | Email, name, username | Standard | Account lifetime + 30 days |
| Usage Data | API calls, timestamps | Standard | 90 days |
| Authentication | Tokens, sessions | Standard | Session duration |
| Simulation Content | User-provided scenarios | May be sensitive | Per user settings |
| Support Data | Tickets, communications | Standard | 2 years |

**Section 2.2 Data Mapping**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ThreatSimGPT Data Flow                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  User Input ──► API Gateway ──► Processing Engine ──► Output   │
│       │              │                │                 │       │
│       ▼              ▼                ▼                 ▼       │
│  [Account DB]   [Auth Logs]    [Temp Storage]    [User Output]  │
│                                                                 │
│  Retention:      Retention:      Retention:       Retention:    │
│  Account+30d     90 days         Processing only  User-defined  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Section 2.3 Processing Purposes**

| Purpose | Legal Basis | Data Categories |
|---------|-------------|-----------------|
| Service provision | Contract | Account, Usage |
| Security monitoring | Legitimate interest | Usage, Auth |
| Support | Contract | Support, Account |
| Analytics | Legitimate interest (anonymized) | Usage |
| Compliance | Legal obligation | All |

---

**3. Lawful Bases for Processing**

**Section 3.1 Article 6 Bases Used**

| Basis | Article | Use Cases |
|-------|---------|-----------|
| **Consent** | 6(1)(a) | Marketing, optional features |
| **Contract** | 6(1)(b) | Service delivery, support |
| **Legal Obligation** | 6(1)(c) | Audit logs, security |
| **Legitimate Interest** | 6(1)(f) | Security, fraud prevention |

**Section 3.2 Legitimate Interest Assessment (LIA)**

For security monitoring under legitimate interest:

| Factor | Assessment |
|--------|------------|
| **Purpose** | Platform security, fraud prevention |
| **Necessity** | Essential for secure operation |
| **Balancing** | User privacy protected via minimization |
| **Safeguards** | Encryption, access controls, retention limits |
| **Outcome** | Processing is justified |

---

**4. Data Subject Rights**

**Section 4.1 Rights Overview**

| Right | Article | Implementation | Response Time |
|-------|---------|----------------|---------------|
| **Access** | 15 | Self-service + request | 30 days |
| **Rectification** | 16 | Self-service + request | 30 days |
| **Erasure** | 17 | Account deletion flow | 30 days |
| **Restriction** | 18 | Manual request | 30 days |
| **Portability** | 20 | Export feature | 30 days |
| **Object** | 21 | Opt-out mechanisms | 30 days |

**Section 4.2 Right of Access (Article 15)**

**Implementation:**

```python
**API Endpoint: GET /api/v1/gdpr/data-export**
**Authentication: Required**
**Response: JSON data package**

{
  "data_subject": {
    "id": "user_123",
    "email": "user@example.com",
    "created_at": "2025-06-15T10:00:00Z"
  },
  "processing_purposes": ["service_delivery", "security"],
  "data_categories": ["account", "usage"],
  "recipients": ["internal_only"],
  "retention_period": "account_lifetime_plus_30_days",
  "data_export": {
    "account_data": {...},
    "usage_history": [...],
    "simulations": [...]
  },
  "export_date": "2026-01-20T12:00:00Z"
}
```

**Process:**
1. User requests via settings or email
2. Identity verification (2FA if enabled)
3. Data compilation (automated)
4. Delivery via secure download link
5. Link expires after 7 days

**Section 4.3 Right to Erasure (Article 17)**

**Implementation:**

```python
**API Endpoint: DELETE /api/v1/gdpr/account**
**Authentication: Required + Confirmation**
**Response: Deletion confirmation**

{
  "status": "deletion_scheduled",
  "deletion_date": "2026-02-19T00:00:00Z",
  "grace_period_days": 30,
  "data_to_delete": [
    "account_data",
    "usage_history", 
    "simulations",
    "api_keys"
  ],
  "data_retained": [
    "anonymized_analytics",
    "security_logs (90 days)"
  ],
  "cancellation_url": "https://..."
}
```

**Exceptions (Article 17(3)):**
- Legal obligation (security logs)
- Legal claims defense
- Public interest archiving (anonymized)

**Section 4.4 Right to Data Portability (Article 20)**

**Export Formats:**
- JSON (machine-readable)
- CSV (tabular data)
- ZIP archive (complete package)

**Included Data:**
- Account profile
- Simulation history
- API usage
- Settings and preferences

**Section 4.5 Right to Object (Article 21)**

**Objection Mechanisms:**

| Processing | Opt-out Method |
|------------|----------------|
| Marketing | Unsubscribe link |
| Analytics | Settings toggle |
| Profiling | Not applicable (no profiling) |

---

**5. Consent Management**

**Section 5.1 Consent Requirements**

Where consent is the legal basis:

| Requirement | Implementation |
|-------------|----------------|
| **Freely given** | No service denial for refusal |
| **Specific** | Granular consent options |
| **Informed** | Clear, plain language |
| **Unambiguous** | Affirmative action required |

**Section 5.2 Consent Records**

```json
{
  "consent_id": "consent_abc123",
  "user_id": "user_123",
  "purpose": "marketing_emails",
  "granted": true,
  "timestamp": "2026-01-20T10:30:00Z",
  "method": "checkbox_signup_form",
  "version": "consent_v1.2",
  "ip_address_hash": "sha256:...",
  "withdrawable": true
}
```

**Section 5.3 Consent Withdrawal**

- Available via account settings
- Immediate effect
- No service degradation for core features
- Logged for compliance

---

**6. Data Protection Principles**

**Section 6.1 Article 5 Compliance**

| Principle | Implementation |
|-----------|----------------|
| **Lawfulness, fairness, transparency** | Clear privacy policy, lawful bases documented |
| **Purpose limitation** | Data only used for stated purposes |
| **Data minimization** | Only necessary data collected |
| **Accuracy** | User self-service updates, regular cleanup |
| **Storage limitation** | Defined retention periods, auto-deletion |
| **Integrity & confidentiality** | Encryption, access controls, audits |
| **Accountability** | Documentation, DPO, audits |

**Section 6.2 Privacy by Design (Article 25)**

**Implemented Measures:**

1. **Default Privacy Settings**
   - Minimal data collection by default
   - Opt-in for additional features
   - Private by default for simulations

2. **Technical Measures**
   - Data encryption at rest and in transit
   - Pseudonymization where possible
   - Automatic data expiration

3. **Organizational Measures**
   - Privacy impact assessments
   - Regular privacy reviews
   - Staff training

---

**7. Technical Measures**

**Section 7.1 Security Controls (Article 32)**

| Control | Implementation | Status |
|---------|----------------|--------|
| **Encryption at Rest** | AES-256 | Active |
| **Encryption in Transit** | TLS 1.3 | Active |
| **Access Control** | RBAC + MFA | Active |
| **Audit Logging** | Comprehensive | Active |
| **Pseudonymization** | User IDs | Active |
| **Backup & Recovery** | Daily, encrypted | Active |

**Section 7.2 Data Protection Implementation**

```python
**Example: Data handling with GDPR compliance**

from threatsimgpt.gdpr import GDPRCompliance

class UserDataHandler:
    def __init__(self):
        self.gdpr = GDPRCompliance()
    
    def process_user_data(self, user_id: str, data: dict) -> dict:
        """Process user data with GDPR safeguards."""
        
        # Verify lawful basis
        self.gdpr.verify_lawful_basis(user_id, "contract")
        
        # Apply data minimization
        minimized_data = self.gdpr.minimize(data, required_fields=[
            "simulation_type",
            "parameters"
        ])
        
        # Pseudonymize where possible
        pseudonymized = self.gdpr.pseudonymize(minimized_data)
        
        # Log processing activity
        self.gdpr.log_processing(
            user_id=user_id,
            purpose="simulation_execution",
            data_categories=["usage"]
        )
        
        return pseudonymized
    
    def export_user_data(self, user_id: str) -> dict:
        """Article 15 - Right of Access implementation."""
        return self.gdpr.compile_data_export(user_id)
    
    def delete_user_data(self, user_id: str) -> bool:
        """Article 17 - Right to Erasure implementation."""
        return self.gdpr.execute_erasure(
            user_id=user_id,
            grace_period_days=30,
            exceptions=["security_logs"]
        )
```

**Section 7.3 Retention Implementation**

```yaml
**data_retention_config.yaml

retention_policies:
  account_data:
    duration: "account_lifetime + 30 days"
    deletion_method: "secure_delete"
    exceptions:
      - "legal_hold"
  
  usage_logs:
    duration: "90 days"
    deletion_method: "automatic"
    anonymization: true
  
  security_logs:
    duration: "1 year"
    deletion_method: "scheduled"
    legal_basis: "legal_obligation"
  
  simulation_data:
    duration: "user_defined"
    default: "30 days"
    deletion_method: "user_controlled"
```

---

**8. Organizational Measures**

**Section 8.1 Data Protection Officer**

| Field | Details |
|-------|---------|
| **Appointed** | Yes (voluntary) |
| **Contact** | dpo@threatsimgpt.io |
| **Independence** | Reports to leadership |
| **Tasks** | Monitoring, advice, contact point |

**Section 8.2 Staff Training**

| Training | Frequency | Audience |
|----------|-----------|----------|
| GDPR Fundamentals | Annual | All staff |
| Data Handling | Onboarding + Annual | Engineers |
| Incident Response | Quarterly | Security team |

**Section 8.3 Vendor Management**

**Data Processing Agreements (DPAs):**

| Vendor Type | DPA Required | Review Cycle |
|-------------|--------------|--------------|
| Cloud providers | Yes | Annual |
| Analytics | Yes | Annual |
| Support tools | Yes | Annual |

---

**9. Data Transfers**

**Section 9.1 Transfer Mechanisms**

| Destination | Mechanism | Status |
|-------------|-----------|--------|
| EU/EEA | N/A (adequate) | |
| UK | UK Adequacy | |
| US | SCCs + supplementary | |
| Other | Case-by-case SCCs | As needed |

**Section 9.2 Standard Contractual Clauses**

- EU Commission SCCs (2021 version)
- Supplementary measures per EDPB recommendations
- Transfer impact assessments completed

---

**10. Data Breach Procedures**

**Section 10.1 Breach Response (Articles 33-34)**

```
┌─────────────────────────────────────────────────────────────────┐
│                   Data Breach Response Flow                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Detection ──► Assessment ──► Notification ──► Remediation     │
│      │            │               │                │            │
│   0-1 hr      1-24 hr         ≤72 hr          Ongoing          │
│                                                                 │
│  Actions:     Actions:        Actions:         Actions:         │
│  - Contain    - Impact        - Authority      - Root cause     │
│  - Log        - Risk          - Subjects       - Prevention     │
│  - Escalate   - Classify      - Document       - Review         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Section 10.2 Notification Requirements**

| Notification | Trigger | Timeline |
|--------------|---------|----------|
| **Supervisory Authority** | Risk to rights/freedoms | 72 hours |
| **Data Subjects** | High risk | Without undue delay |
| **Internal** | Any breach | Immediate |

**Section 10.3 Breach Record**

All breaches logged with:
- Description and categories
- Approximate records affected
- Consequences assessment
- Measures taken
- Notification records

---

**11. Records of Processing**

**Section 11.1 Article 30 Records**

**Controller Records:**

| Field | Value |
|-------|-------|
| Controller name | ThreatSimGPT Project |
| Contact | compliance@threatsimgpt.io |
| DPO | dpo@threatsimgpt.io |
| Processing purposes | Service delivery, security, support |
| Data categories | Account, usage, simulations |
| Recipients | Internal, authorized processors |
| Transfers | EU, UK, US (SCCs) |
| Retention | Per retention policy |
| Security measures | See Section 7 |

**Section 11.2 Processing Register**

Maintained electronically with:
- All processing activities
- Legal bases
- Data categories
- Retention periods
- Last review date

---

**12. Contact Information**

**Section Data Protection Inquiries**

| Type | Contact |
|------|---------|
| General GDPR questions | gdpr@threatsimgpt.io |
| Data subject requests | privacy@threatsimgpt.io |
| DPO | dpo@threatsimgpt.io |
| Complaints | compliance@threatsimgpt.io |

**Section Supervisory Authority**

Users may lodge complaints with their local data protection authority.

**Lead Authority (if applicable):**  
To be determined based on main establishment location.

---

**Appendix A: GDPR Article Mapping**

| Article | Topic | Section |
|---------|-------|---------|
| 5 | Principles | 6 |
| 6 | Lawful bases | 3 |
| 7 | Consent | 5 |
| 12-23 | Data subject rights | 4 |
| 24 | Controller responsibility | 8 |
| 25 | Privacy by design | 6.2 |
| 28 | Processors | 8.3 |
| 30 | Records | 11 |
| 32 | Security | 7 |
| 33-34 | Breach notification | 10 |
| 35 | DPIA | Separate document |
| 37-39 | DPO | 8.1 |
| 44-49 | Transfers | 9 |

---

**Version History**

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 1.0 | 2026-01-20 | Initial release | Jerry (okino007) |

---

*This document is part of the ThreatSimGPT Compliance Documentation.*  
*Related: [Acceptable Use Policy](../policies/acceptable-use-policy.md)*
