**ThreatSimGPT Data Protection Impact Assessment (DPIA) Template**

**Version:** 1.0  
**Last Updated:** January 20, 2026  
**Owner:** Data Protection Officer  
**Legal Basis:** GDPR Article 35  

---

**Overview**

This document provides the Data Protection Impact Assessment framework for ThreatSimGPT. DPIAs are mandatory for processing likely to result in high risk to individuals' rights and freedoms.

---

**1. DPIA Screening Criteria**

**Section 1.1 When DPIA is Required**

A DPIA **MUST** be conducted when processing involves:

| Criterion | GDPR Reference | ThreatSimGPT Relevance |
|-----------|----------------|------------------------|
| Systematic and extensive profiling with significant effects | Article 35(3)(a) | Not applicable |
| Large-scale processing of special categories | Article 35(3)(b) | Possible in simulations |
| Systematic monitoring of publicly accessible areas | Article 35(3)(c) | Not applicable |
| New technologies | WP29 Guidelines | AI/ML threat simulation |
| Automated decision-making with legal effects | Article 22 | Not applicable |
| Large-scale processing | WP29 Guidelines | Batch processing |
| Matching or combining datasets | WP29 Guidelines | MITRE ATT&CK integration |
| Vulnerable data subjects | WP29 Guidelines | Possible |
| Innovative use of technology | WP29 Guidelines | LLM-based simulation |

**Section 1.2 DPIA Threshold Assessment**

**Result:** DPIA is **REQUIRED** for ThreatSimGPT due to:
1. New/innovative technology (AI-powered threat simulation)
2. Large-scale processing capability (batch processing)
3. Potential for special category data in user inputs

---

**2. DPIA: ThreatSimGPT Core Platform**

**Section 2.1 Project Information**

| Field | Value |
|-------|-------|
| **Assessment ID** | DPIA-TSG-001 |
| **Project Name** | ThreatSimGPT Core Platform |
| **Project Owner** | ThreatSimGPT Project Team |
| **DPO** | dpo@threatsimgpt.io |
| **Assessment Date** | January 20, 2026 |
| **Assessment Author** | Jeremiah Okino (okino007) |
| **Review Date** | January 20, 2027 |
| **Status** | Approved |

**Section 2.2 Processing Description**

**Section 2.2.1 Nature of Processing**

ThreatSimGPT processes data to:

1. **User Account Management**
   - Registration and authentication
   - Profile management
   - API key generation and management

2. **Threat Simulation Execution**
   - User-provided scenario parameters
   - AI-generated threat simulations
   - MITRE ATT&CK framework mapping

3. **Batch Processing**
   - Multiple scenario execution
   - Progress tracking
   - Result aggregation

4. **Support and Communication**
   - Customer support tickets
   - Transactional emails
   - Usage analytics (anonymized)

**Section 2.2.2 Scope of Processing**

| Dimension | Details |
|-----------|---------|
| **Data Subjects** | Platform users, potentially data subjects referenced in simulations |
| **Estimated Volume** | 1,000-10,000 users, 100,000+ simulations/month |
| **Geographic Scope** | Global, with EU/EEA focus |
| **Data Elements** | See Section 2.2.3 |
| **Processing Duration** | Continuous platform operation |
| **Retention Period** | Varies by data type (see data-mapping.md) |

**Section 2.2.3 Data Elements Processed**

| Category | Data Elements | Special Category |
|----------|---------------|------------------|
| Account | Email, username, display name | No |
| Authentication | Password hash, MFA tokens, sessions | No |
| Usage | API calls, timestamps, IP addresses | No |
| Simulation Input | User-provided scenarios | Potentially* |
| Simulation Output | Generated threat scenarios | No |
| Support | Ticket content, communications | No |

*User-provided simulation content may inadvertently contain special category data

**Section 2.2.4 Context**

| Factor | Assessment |
|--------|------------|
| **Data Subject Relationship** | Direct (users), Indirect (subjects in simulations) |
| **User Expectations** | Security testing tool, expects data protection |
| **Prior Processing** | N/A - new processing activity |
| **Vulnerable Subjects** | Not specifically targeted, but possible |

**Section 2.2.5 Purposes**

| Purpose | Description | Necessity |
|---------|-------------|-----------|
| Service Delivery | Enable threat simulation functionality | Essential |
| Security | Protect platform and users | Essential |
| Support | Respond to user inquiries | Essential |
| Improvement | Enhance service quality (anonymized) | Legitimate |

**Section 2.3 Consultation**

**Section 2.3.1 Data Subject Views**

| Method | Outcome |
|--------|---------|
| Privacy Policy Review | Clear disclosure of processing activities |
| Consent Mechanisms | Granular consent for optional processing |
| Transparency | Processing purposes clearly communicated |
| Feedback Channels | Support and privacy email available |

**Section 2.3.2 Internal Stakeholders**

| Stakeholder | Input |
|-------------|-------|
| Development Team | Technical feasibility of privacy controls |
| Security Team | Security measure adequacy |
| Legal | Regulatory compliance validation |
| Business | Operational impact assessment |

**Section 2.3.3 DPO Advice**

**DPO Opinion:** Processing may proceed with identified mitigations.

**Key Recommendations:**
1. Implement content filtering for special category data detection
2. Provide clear guidance on acceptable simulation content
3. Maintain robust breach detection and response
4. Regular review of processing activities

**Section 2.4 Necessity and Proportionality**

**Section 2.4.1 Legal Basis Assessment**

| Processing Activity | Legal Basis | Justification |
|---------------------|-------------|---------------|
| Account management | Contract (Art. 6(1)(b)) | Necessary for service delivery |
| Simulation execution | Contract (Art. 6(1)(b)) | Core service functionality |
| Security logging | Legitimate interest (Art. 6(1)(f)) | Platform protection |
| Marketing | Consent (Art. 6(1)(a)) | Optional, user choice |
| Analytics | Legitimate interest (Art. 6(1)(f)) | Service improvement, anonymized |

**Section 2.4.2 Purpose Limitation**

| Check | Assessment |
|-------|------------|
| Purposes clearly defined | Yes - documented in privacy policy |
| Processing limited to stated purposes | Yes - technical controls enforce |
| No incompatible processing | Yes - no secondary use without consent |

**Section 2.4.3 Data Minimization**

| Check | Assessment |
|-------|------------|
| Only necessary data collected | Yes - minimal registration data |
| Data reduced where possible | Yes - IP addresses hashed after 30 days |
| Pseudonymization applied | Yes - user IDs for internal processing |

**Section 2.4.4 Accuracy**

| Check | Assessment |
|-------|------------|
| Data kept accurate | Yes - user self-service updates |
| Inaccurate data corrected/deleted | Yes - rectification process |
| Accuracy verification | Yes - email verification |

**Section 2.4.5 Storage Limitation**

| Data Category | Retention | Justification |
|---------------|-----------|---------------|
| Account data | Account lifetime + 30 days | Service delivery, legal hold period |
| Usage logs | 90 days | Security monitoring |
| Security logs | 1 year | Legal obligation, incident investigation |
| Simulation data | User-defined (default 30 days) | User control |

**Section 2.4.6 Data Subject Rights**

| Right | Implementation | Status |
|-------|----------------|--------|
| Information | Privacy policy, in-app notices | Implemented |
| Access | Self-service export | Implemented |
| Rectification | Profile editing | Implemented |
| Erasure | Account deletion | Implemented |
| Restriction | Manual process | Implemented |
| Portability | Data export (JSON/CSV) | Implemented |
| Object | Opt-out mechanisms | Implemented |

**Section 2.5 Risk Assessment**

**Section 2.5.1 Risk Identification**

| Risk ID | Risk Description | Data Subjects Affected |
|---------|------------------|------------------------|
| R1 | Unauthorized access to user accounts | Platform users |
| R2 | Data breach exposing personal data | Platform users |
| R3 | Special category data in simulations | Third parties |
| R4 | Excessive data retention | All data subjects |
| R5 | Inadequate security measures | All data subjects |
| R6 | Cross-border transfer risks | EU/EEA users |
| R7 | Third-party processor breach | All data subjects |
| R8 | Inability to fulfill data subject rights | All data subjects |

**Section 2.5.2 Risk Evaluation**

| Risk ID | Likelihood | Severity | Overall Risk | Justification |
|---------|------------|----------|--------------|---------------|
| R1 | Medium | High | HIGH | Credential attacks common |
| R2 | Low | High | MEDIUM | Strong security controls |
| R3 | Medium | Medium | MEDIUM | User education needed |
| R4 | Low | Low | LOW | Automated retention |
| R5 | Low | High | MEDIUM | Regular security reviews |
| R6 | Low | Medium | LOW | SCCs in place |
| R7 | Low | Medium | LOW | Vendor due diligence |
| R8 | Low | Medium | LOW | Automated processes |

**Section 2.5.3 Risk Matrix**

```
              │ Negligible │   Minor   │  Moderate  │   Major   │  Severe   │
──────────────┼────────────┼───────────┼────────────┼───────────┼───────────┤
Almost Certain│            │           │            │           │           │
──────────────┼────────────┼───────────┼────────────┼───────────┼───────────┤
Likely        │            │           │            │           │           │
──────────────┼────────────┼───────────┼────────────┼───────────┼───────────┤
Possible      │            │           │    R3      │           │           │
──────────────┼────────────┼───────────┼────────────┼───────────┼───────────┤
Unlikely      │     R4     │  R6,R7,R8 │   R2,R5    │    R1     │           │
──────────────┼────────────┼───────────┼────────────┼───────────┼───────────┤
Rare          │            │           │            │           │           │
──────────────┴────────────┴───────────┴────────────┴───────────┴───────────┘
```

**Section 2.6 Risk Mitigation Measures**

**Section 2.6.1 Technical Measures**

| Risk | Measure | Status | Effectiveness |
|------|---------|--------|---------------|
| R1 | Multi-factor authentication | Implemented | High |
| R1 | Rate limiting on auth endpoints | Implemented | High |
| R1 | Account lockout after failed attempts | Implemented | High |
| R2 | Encryption at rest (AES-256) | Implemented | High |
| R2 | Encryption in transit (TLS 1.3) | Implemented | High |
| R2 | Intrusion detection system | Implemented | Medium |
| R3 | Content filtering (advisory) | Planned | Medium |
| R3 | Clear AUP prohibiting sensitive data | Implemented | Medium |
| R5 | Regular vulnerability scanning | Implemented | High |
| R5 | Penetration testing (annual) | Implemented | High |

**Section 2.6.2 Organizational Measures**

| Risk | Measure | Status | Effectiveness |
|------|---------|--------|---------------|
| R1 | Security awareness training | Implemented | Medium |
| R2 | Incident response procedure | Implemented | High |
| R2 | Breach notification process | Implemented | High |
| R3 | User guidance on acceptable content | Implemented | Medium |
| R4 | Automated retention enforcement | Implemented | High |
| R6 | Standard Contractual Clauses | Implemented | High |
| R7 | Vendor due diligence process | Implemented | High |
| R7 | Data Processing Agreements | Implemented | High |
| R8 | Documented DSAR procedures | Implemented | High |

**Section 2.6.3 Residual Risk Assessment**

| Risk ID | Initial Risk | Mitigation Effectiveness | Residual Risk |
|---------|--------------|--------------------------|---------------|
| R1 | HIGH | Strong | LOW |
| R2 | MEDIUM | Strong | LOW |
| R3 | MEDIUM | Moderate | LOW-MEDIUM |
| R4 | LOW | Strong | MINIMAL |
| R5 | MEDIUM | Strong | LOW |
| R6 | LOW | Strong | MINIMAL |
| R7 | LOW | Strong | MINIMAL |
| R8 | LOW | Strong | MINIMAL |

**Section 2.7 DPIA Outcome**

**Section 2.7.1 Decision**

| Outcome | Decision |
|---------|----------|
| **Processing Approved** | Yes |
| **Supervisory Authority Consultation Required** | No |
| **Conditions** | Implement planned content filtering within 6 months |

**Section 2.7.2 Justification**

Processing may proceed because:

1. **Necessity Demonstrated:** Processing is necessary for service delivery
2. **Proportionality Achieved:** Data minimization and purpose limitation in place
3. **Risks Mitigated:** Technical and organizational measures reduce risk to acceptable levels
4. **Rights Protected:** Full data subject rights implementation
5. **Transparency Ensured:** Clear privacy notices and consent mechanisms

**Section 2.7.3 Conditions and Recommendations**

| Item | Priority | Deadline | Owner |
|------|----------|----------|-------|
| Implement content filtering for special categories | High | July 2026 | Dev Team |
| Enhanced user guidance on simulation content | Medium | March 2026 | Docs Team |
| Annual DPIA review | Medium | January 2027 | DPO |
| Penetration test review | Medium | April 2026 | Security |

**Section 2.8 Approval**

| Role | Name | Date | Approval |
|------|------|------|----------|
| Project Owner | ThreatSimGPT Team | 2026-01-20 | Approved |
| DPO | dpo@threatsimgpt.io | 2026-01-20 | Approved |
| Security Lead | Lara (laradipupo) | 2026-01-20 | Approved |
| Compliance Lead | Jerry (okino007) | 2026-01-20 | Approved |

---

**3. DPIA Review Schedule**

| Trigger | Action Required |
|---------|-----------------|
| Annual review | Full DPIA reassessment |
| New processing activity | Threshold assessment |
| Significant change to processing | Impact reassessment |
| Data breach | Review affected processing |
| Regulatory guidance update | Compliance review |
| Technology change | Technical measures review |

---

**4. DPIA Template for New Processing**

Use this template for assessing new processing activities:

```markdown
**DPIA: [Processing Activity Name]**

**1. Threshold Assessment**
Is DPIA required? [Yes/No]
Criteria met: [List applicable criteria]

**2. Processing Description**
Nature: [What processing occurs]
Scope: [Data subjects, volume, geography]
Context: [Relationship, expectations]
Purpose: [Why processing is needed]

**3. Necessity & Proportionality**
Legal basis: [Article 6/9 basis]
Purpose limitation: [Assessment]
Data minimization: [Assessment]
Accuracy: [Assessment]
Storage limitation: [Assessment]

**4. Risk Assessment**
[Risk ID] | [Description] | [Likelihood] | [Severity] | [Overall]

**5. Mitigation Measures**
[Risk ID] | [Measure] | [Status] | [Effectiveness]

**6. Residual Risk**
[Risk ID] | [Initial] | [Residual]

**7. Outcome**
Decision: [Approved/Rejected/Consultation Required]
Conditions: [Any conditions]

**8. Approval**
[Signatures]
```

---

**Appendix A: DPIA Screening Checklist**

Use this checklist to determine if a DPIA is required:

| Question | Yes | No |
|----------|-----|-----|
| Does processing use new technologies? | ☐ | ☐ |
| Does processing involve profiling or automated decisions? | ☐ | ☐ |
| Does processing involve special category data at scale? | ☐ | ☐ |
| Does processing involve systematic monitoring? | ☐ | ☐ |
| Does processing involve vulnerable individuals? | ☐ | ☐ |
| Does processing involve large-scale data processing? | ☐ | ☐ |
| Does processing involve matching/combining datasets? | ☐ | ☐ |
| Does processing prevent data subjects from exercising rights? | ☐ | ☐ |
| Does processing involve cross-border transfers? | ☐ | ☐ |

**If 2+ boxes checked YES → DPIA Required**

---

*Document maintained by ThreatSimGPT Compliance Team*  
*Related: [GDPR Overview](README.md) | [Data Mapping](data-mapping.md)*
