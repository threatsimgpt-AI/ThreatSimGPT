**ThreatSimGPT GDPR Data Mapping**

**Version:** 1.0  
**Last Updated:** January 20, 2026  
**Owner:** Compliance Team  

---

**Overview**

This document provides a detailed mapping of all personal data processed by ThreatSimGPT, including data flows, storage locations, and processing purposes.

---

**1. Data Inventory**

**Section 1.1 Account Data**

| Data Element | Type | Sensitivity | Source | Storage | Retention |
|--------------|------|-------------|--------|---------|-----------|
| Email address | Personal | Standard | User input | PostgreSQL | Account + 30 days |
| Username | Personal | Standard | User input | PostgreSQL | Account + 30 days |
| Display name | Personal | Standard | User input | PostgreSQL | Account + 30 days |
| Password hash | Credential | High | User input | PostgreSQL | Account + 30 days |
| API keys | Credential | High | Generated | PostgreSQL | Until revoked |
| MFA secrets | Credential | High | Generated | PostgreSQL (encrypted) | Account lifetime |

**Section 1.2 Usage Data**

| Data Element | Type | Sensitivity | Source | Storage | Retention |
|--------------|------|-------------|--------|---------|-----------|
| API calls | Usage | Standard | System | TimescaleDB | 90 days |
| Request timestamps | Usage | Standard | System | TimescaleDB | 90 days |
| IP addresses | Personal | Standard | Network | Logs | 30 days |
| User agent | Technical | Low | HTTP | Logs | 30 days |
| Session IDs | Technical | Low | System | Redis | Session duration |

**Section 1.3 Simulation Data**

| Data Element | Type | Sensitivity | Source | Storage | Retention |
|--------------|------|-------------|--------|---------|-----------|
| Simulation inputs | Content | Variable* | User input | PostgreSQL | User-defined |
| Generated outputs | Content | Variable* | System | PostgreSQL | User-defined |
| Execution logs | Technical | Low | System | Elasticsearch | 30 days |

*May contain personal data depending on user input

**Section 1.4 Support Data**

| Data Element | Type | Sensitivity | Source | Storage | Retention |
|--------------|------|-------------|--------|---------|-----------|
| Support tickets | Communication | Standard | User input | Support system | 2 years |
| Chat logs | Communication | Standard | User input | Support system | 1 year |
| Feedback | Opinion | Standard | User input | PostgreSQL | Anonymized after 1 year |

---

**2. Data Flow Diagram**

```
                                    ThreatSimGPT Data Flows
┌──────────────────────────────────────────────────────────────────────────────────────┐
│                                                                                      │
│    ┌─────────┐         ┌──────────────┐         ┌─────────────┐                     │
│    │  User   │────────►│  API Gateway │────────►│  Auth Svc   │                     │
│    │ Browser │         │   (TLS 1.3)  │         │   (JWT)     │                     │
│    └─────────┘         └──────┬───────┘         └──────┬──────┘                     │
│         │                     │                        │                             │
│         │                     ▼                        ▼                             │
│         │              ┌──────────────┐         ┌─────────────┐                     │
│         │              │  Rate Limit  │         │  PostgreSQL │                     │
│         │              │   (Redis)    │         │ (Account DB)│                     │
│         │              └──────┬───────┘         └─────────────┘                     │
│         │                     │                                                      │
│         │                     ▼                                                      │
│         │              ┌──────────────┐         ┌─────────────┐                     │
│         │              │  Simulation  │────────►│  Vector DB  │                     │
│         │              │   Engine     │         │ (Embeddings)│                     │
│         └─────────────►│              │         └─────────────┘                     │
│                        └──────┬───────┘                                             │
│                               │                                                      │
│                               ▼                                                      │
│                        ┌──────────────┐         ┌─────────────┐                     │
│                        │   Output     │────────►│   Logs      │                     │
│                        │  Generation  │         │(Elasticsearch)                    │
│                        └──────────────┘         └─────────────┘                     │
│                                                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘

Legend:
────► Data flow
[   ] System component
```

---

**3. Processing Activities Register**

**Section 3.1 Core Processing Activities**

| Activity ID | Activity | Purpose | Legal Basis | Data Categories | Recipients |
|-------------|----------|---------|-------------|-----------------|------------|
| PA-001 | User registration | Account creation | Contract | Account | Internal |
| PA-002 | Authentication | Access control | Contract | Account, Auth | Internal |
| PA-003 | Simulation execution | Service delivery | Contract | Usage, Simulation | Internal |
| PA-004 | API logging | Security, debugging | Legitimate interest | Usage | Internal |
| PA-005 | Support handling | Customer support | Contract | Support, Account | Internal, Support vendor |
| PA-006 | Analytics | Service improvement | Legitimate interest | Usage (anonymized) | Internal |
| PA-007 | Security monitoring | Fraud prevention | Legitimate interest | Usage, Auth | Internal |
| PA-008 | Backup | Business continuity | Legitimate interest | All | Internal |

**Section 3.2 Third-Party Processing**

| Vendor | Purpose | Data Shared | DPA Status | Location |
|--------|---------|-------------|------------|----------|
| Cloud provider | Infrastructure | All (encrypted) | Signed | EU |
| CDN | Content delivery | IP, User agent | Signed | Global |
| Email service | Notifications | Email address | Signed | EU |
| Support platform | Tickets | Support data | Signed | EU |

---

**4. Data Subject Categories**

| Category | Description | Special Considerations |
|----------|-------------|------------------------|
| Registered users | Platform account holders | Full GDPR rights |
| API users | Programmatic access | May be organizations |
| Support contacts | Ticket submitters | Communication records |
| Website visitors | Non-authenticated | Cookie consent required |

---

**5. Special Category Data**

**Section 5.1 Assessment**

ThreatSimGPT does **not** intentionally collect special category data (Article 9).

However, user-provided simulation content **may** contain such data. Mitigations:

| Risk | Mitigation |
|------|------------|
| Users input sensitive data | Clear guidance in AUP |
| Simulation outputs | Not stored by default |
| Training data | Anonymized, reviewed |

**Section 5.2 Children's Data**

ThreatSimGPT is not intended for users under 16. Verification via terms acceptance.

---

**6. Cross-Border Transfers**

**Section 6.1 Transfer Map**

| Data | From | To | Mechanism | Risk Assessment |
|------|------|----|-----------|-----------------|
| Account data | EU | EU | N/A | Low |
| Backups | EU | EU | N/A | Low |
| CDN cache | EU | Global | SCCs | Medium - mitigated |
| Support tickets | EU | EU | N/A | Low |

**Section 6.2 Transfer Impact Assessment**

For US transfers (if applicable):

| Factor | Assessment |
|--------|------------|
| Data type | Non-sensitive usage data |
| Access risk | Low - encrypted, access controlled |
| Legal risk | Medium - mitigated by SCCs + supplementary measures |
| Overall | Acceptable with safeguards |

---

**7. Retention Schedule**

**Section 7.1 Standard Retention**

| Data Category | Active Retention | Archive | Deletion |
|---------------|------------------|---------|----------|
| Account data | Account lifetime | 30 days | Secure delete |
| Usage logs | 90 days | None | Auto-purge |
| Security logs | 1 year | None | Auto-purge |
| Simulation data | User-defined (default 30 days) | None | User action or auto |
| Support data | 2 years | None | Anonymize |
| Backups | 30 days | None | Rotation |

**Section 7.2 Deletion Procedures**

```python
**Automated retention enforcement**

from threatsimgpt.gdpr import RetentionManager

retention = RetentionManager()

**Daily job**
async def enforce_retention():
    # Delete expired usage logs
    await retention.purge_expired(
        table="usage_logs",
        retention_days=90
    )
    
    # Delete expired security logs
    await retention.purge_expired(
        table="security_logs",
        retention_days=365
    )
    
    # Process pending account deletions
    await retention.process_deletion_queue()
    
    # Anonymize old support data
    await retention.anonymize_support_data(
        older_than_years=2
    )
```

---

**8. Data Minimization**

**Section 8.1 Collection Minimization**

| Endpoint | Required Data | Optional Data | Rejected Data |
|----------|---------------|---------------|---------------|
| Registration | Email, password | Display name | Phone, address |
| Simulation | Type, parameters | Description | N/A |
| Support | Issue, email | Screenshot | Unrelated PII |

**Section 8.2 Processing Minimization**

- Only process data necessary for stated purpose
- Pseudonymize where identity not required
- Aggregate for analytics

---

**9. Technical Controls by Data Type**

| Data Type | Encryption at Rest | Encryption in Transit | Access Control | Audit Log |
|-----------|--------------------|-----------------------|----------------|-----------|
| Credentials | AES-256 + salt | TLS 1.3 | Admin only | Yes |
| Account data | AES-256 | TLS 1.3 | User + Admin | Yes |
| Usage data | AES-256 | TLS 1.3 | Internal | Yes |
| Simulation | AES-256 | TLS 1.3 | Owner only | Yes |
| Logs | AES-256 | TLS 1.3 | Security team | Yes |

---

**10. Data Subject Request Procedures**

**Section 10.1 Access Request (Article 15)**

```yaml
**Request handling workflow**

access_request:
  trigger: "User request via portal or email"
  verification: "Email confirmation + 2FA if enabled"
  
  data_compilation:
    - account_data: "Direct export from PostgreSQL"
    - usage_data: "Aggregated from TimescaleDB"
    - simulation_data: "User's simulation history"
    - support_data: "Ticket history"
  
  format: "JSON + human-readable summary"
  delivery: "Secure download link (7 day expiry)"
  timeline: "Within 30 days"
  
  logging:
    - request_id
    - timestamp
    - data_provided
    - delivery_confirmation
```

**Section 10.2 Erasure Request (Article 17)**

```yaml
**Erasure workflow**

erasure_request:
  trigger: "User request via portal"
  verification: "Password + 2FA confirmation"
  
  grace_period: 30 days
  cancellation: "Available during grace period"
  
  deletion_scope:
    immediate:
      - active_sessions
      - api_keys
    after_grace_period:
      - account_data
      - simulation_data
      - support_data (anonymized)
    retained:
      - security_logs (1 year, anonymized)
      - aggregated_analytics
  
  confirmation: "Email notification"
  
  logging:
    - request_id
    - deletion_date
    - data_deleted
    - data_retained_reason
```

---

**Appendix: Data Element Glossary**

| Element | Definition | GDPR Category |
|---------|------------|---------------|
| Email address | User's email for account | Personal data |
| Username | Unique account identifier | Personal data |
| IP address | Network address | Personal data |
| API key | Authentication token | Pseudonymous identifier |
| Session ID | Temporary session token | Pseudonymous identifier |
| Simulation content | User-provided scenarios | May be personal data |

---

*Document maintained by ThreatSimGPT Compliance Team*  
*Next review: July 2026*
