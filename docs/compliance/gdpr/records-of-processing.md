**ThreatSimGPT Records of Processing Activities (ROPA)**

**Version:** 1.0  
**Last Updated:** January 20, 2026  
**Legal Basis:** GDPR Article 30  
**Owner:** Data Protection Officer  

---

**Overview**

This document maintains the Records of Processing Activities as required by GDPR Article 30. It documents all processing activities involving personal data.

---

**Controller Information (Article 30(1))**

| Field | Value |
|-------|-------|
| **Controller Name** | ThreatSimGPT Project |
| **Controller Address** | [Address] |
| **Controller Contact** | privacy@threatsimgpt.io |
| **Joint Controller** | N/A |
| **Representative** | N/A (controller established in EU) |
| **Data Protection Officer** | dpo@threatsimgpt.io |

---

**Processing Activities Register**

**Section PA-001: User Account Management**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-001 |
| **Activity Name** | User Account Management |
| **Description** | Creation, maintenance, and deletion of user accounts |
| **Purpose** | Enable users to access and use ThreatSimGPT services |
| **Legal Basis** | Contract (Article 6(1)(b)) |
| **Data Categories** | Email address, username, display name, password (hashed) |
| **Data Subject Categories** | Platform users |
| **Recipients** | Internal: Engineering, Support |
| **Third Countries** | None (EU-only processing) |
| **Transfer Safeguards** | N/A |
| **Retention Period** | Account lifetime + 30 days |
| **Security Measures** | Encryption, access control, audit logging |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-002: Authentication and Access Control**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-002 |
| **Activity Name** | Authentication and Access Control |
| **Description** | User login, session management, MFA |
| **Purpose** | Secure access to platform services |
| **Legal Basis** | Contract (Article 6(1)(b)), Legitimate Interest (Article 6(1)(f)) |
| **Data Categories** | Session tokens, MFA secrets, login timestamps, IP addresses |
| **Data Subject Categories** | Platform users |
| **Recipients** | Internal: Security, Engineering |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | Session duration (tokens), 90 days (logs) |
| **Security Measures** | Encryption, secure token storage, rate limiting |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-003: Threat Simulation Execution**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-003 |
| **Activity Name** | Threat Simulation Execution |
| **Description** | Processing user-provided scenarios to generate threat simulations |
| **Purpose** | Core service delivery - threat simulation |
| **Legal Basis** | Contract (Article 6(1)(b)) |
| **Data Categories** | Simulation parameters, user inputs, generated outputs |
| **Data Subject Categories** | Platform users; potentially third parties in simulation content |
| **Recipients** | Internal: Processing engines |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | User-controlled (default 30 days) |
| **Security Measures** | Encryption, access control, content isolation |
| **DPIA Required** | Yes - See DPIA-TSG-001 |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-004: Batch Processing**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-004 |
| **Activity Name** | Batch Processing |
| **Description** | Processing multiple simulation requests concurrently |
| **Purpose** | Enable efficient bulk simulation execution |
| **Legal Basis** | Contract (Article 6(1)(b)) |
| **Data Categories** | Batch job metadata, simulation parameters, results |
| **Data Subject Categories** | Platform users |
| **Recipients** | Internal: Processing engines |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | User-controlled (default 30 days) |
| **Security Measures** | Encryption, queue isolation, access control |
| **DPIA Required** | Yes - See DPIA-TSG-001 |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-005: API Usage Logging**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-005 |
| **Activity Name** | API Usage Logging |
| **Description** | Recording API calls for billing, analytics, and troubleshooting |
| **Purpose** | Service delivery, usage analytics, debugging |
| **Legal Basis** | Contract (Article 6(1)(b)), Legitimate Interest (Article 6(1)(f)) |
| **Data Categories** | API endpoints, timestamps, user IDs, request metadata |
| **Data Subject Categories** | Platform users |
| **Recipients** | Internal: Engineering, Analytics |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | 90 days |
| **Security Measures** | Encryption, access control, pseudonymization |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-006: Security Monitoring**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-006 |
| **Activity Name** | Security Monitoring |
| **Description** | Monitoring for security threats, anomalies, and incidents |
| **Purpose** | Platform security, fraud prevention |
| **Legal Basis** | Legitimate Interest (Article 6(1)(f)) |
| **Data Categories** | IP addresses, user agents, access patterns, security events |
| **Data Subject Categories** | All platform users and visitors |
| **Recipients** | Internal: Security team |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | 1 year |
| **Security Measures** | Encryption, restricted access, audit logging |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

**Legitimate Interest Assessment:**
- Interest: Platform security and fraud prevention
- Necessity: Essential for protecting all users and systems
- Balance: Privacy impact minimal (security data only); significant security benefit
- Safeguards: Access restricted to security team, retention limited, no profiling

---

**Section PA-007: Customer Support**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-007 |
| **Activity Name** | Customer Support |
| **Description** | Handling support requests and communications |
| **Purpose** | Respond to user inquiries and issues |
| **Legal Basis** | Contract (Article 6(1)(b)) |
| **Data Categories** | Name, email, ticket content, communication history |
| **Data Subject Categories** | Platform users submitting support requests |
| **Recipients** | Internal: Support team; External: Support platform provider |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | 2 years |
| **Security Measures** | Encryption, access control, DPA with provider |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-008: Marketing Communications**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-008 |
| **Activity Name** | Marketing Communications |
| **Description** | Sending marketing emails to opted-in users |
| **Purpose** | Inform users of product updates, features, promotions |
| **Legal Basis** | Consent (Article 6(1)(a)) |
| **Data Categories** | Email address, name, consent records |
| **Data Subject Categories** | Users who have consented to marketing |
| **Recipients** | Internal: Marketing; External: Email service provider |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | Until consent withdrawn |
| **Security Measures** | Encryption, consent management, unsubscribe mechanism |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-009: Analytics (Anonymized)**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-009 |
| **Activity Name** | Analytics (Anonymized) |
| **Description** | Aggregated usage analytics for service improvement |
| **Purpose** | Understand usage patterns, improve service |
| **Legal Basis** | Legitimate Interest (Article 6(1)(f)) - anonymized data |
| **Data Categories** | Aggregated usage statistics (no personal data after anonymization) |
| **Data Subject Categories** | N/A (anonymized) |
| **Recipients** | Internal: Product, Engineering |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | Indefinite (anonymized) |
| **Security Measures** | Anonymization techniques ensure no re-identification |
| **DPIA Required** | No (anonymized data not personal data) |
| **Last Reviewed** | 2026-01-20 |

---

**Section PA-010: Data Subject Rights Handling**

| Field | Value |
|-------|-------|
| **Activity ID** | PA-010 |
| **Activity Name** | Data Subject Rights Handling |
| **Description** | Processing requests for access, deletion, portability, etc. |
| **Purpose** | Fulfill legal obligations under GDPR Articles 12-23 |
| **Legal Basis** | Legal Obligation (Article 6(1)(c)) |
| **Data Categories** | Request details, identity verification, audit records |
| **Data Subject Categories** | Platform users exercising their rights |
| **Recipients** | Internal: Compliance, DPO |
| **Third Countries** | None |
| **Transfer Safeguards** | N/A |
| **Retention Period** | 3 years (audit trail) |
| **Security Measures** | Identity verification, access control, audit logging |
| **DPIA Required** | No |
| **Last Reviewed** | 2026-01-20 |

---

**Summary Table**

| ID | Activity | Purpose | Legal Basis | Retention |
|----|----------|---------|-------------|-----------|
| PA-001 | User Account Management | Service delivery | Contract | Account + 30 days |
| PA-002 | Authentication | Security | Contract, LI | Session/90 days |
| PA-003 | Simulation Execution | Service delivery | Contract | User-controlled |
| PA-004 | Batch Processing | Service delivery | Contract | User-controlled |
| PA-005 | API Usage Logging | Analytics, debugging | Contract, LI | 90 days |
| PA-006 | Security Monitoring | Security | LI | 1 year |
| PA-007 | Customer Support | Support | Contract | 2 years |
| PA-008 | Marketing | Marketing | Consent | Until withdrawn |
| PA-009 | Analytics | Improvement | LI (anonymized) | Indefinite |
| PA-010 | DSAR Handling | Legal obligation | Legal Obligation | 3 years |

---

**Third-Party Recipients**

| Recipient Category | Purpose | Safeguards |
|--------------------|---------|------------|
| Cloud infrastructure | Hosting | DPA, EU data center |
| Email service | Transactional + marketing | DPA, encryption |
| Support platform | Customer support | DPA |

---

**Review Schedule**

| Review Type | Frequency | Next Review | Owner |
|-------------|-----------|-------------|-------|
| Full ROPA review | Annual | 2027-01-20 | DPO |
| New processing assessment | As needed | N/A | DPO |
| Recipient update | Quarterly | 2026-04-20 | Compliance |
| Retention validation | Annual | 2027-01-20 | Compliance |

---

**Change Log**

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-01-20 | 1.0 | Initial creation | Jerry (okino007) |

---

*This register is maintained in accordance with GDPR Article 30.*  
*It must be made available to the supervisory authority upon request.*
