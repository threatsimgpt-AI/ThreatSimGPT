**ThreatSimGPT Evidence Collection Procedures**

**Version:** 1.0
**Effective Date:** January 20, 2026
**Last Updated:** January 20, 2026
**Document Owner:** Compliance Team
**Purpose:** Define procedures for collecting, managing, and presenting audit evidence

---

**Overview**

This document establishes standardized procedures for collecting, preserving, and presenting evidence for compliance audits, regulatory examinations, and internal reviews of ThreatSimGPT.

---

**1. Evidence Framework**

**Section 1.1 Evidence Types**

| Type | Description | Examples |
|------|-------------|----------|
| Documentary | Written records and policies | Policies, procedures, meeting minutes |
| Electronic | System-generated records | Logs, configurations, screenshots |
| Testimonial | Statements from personnel | Interviews, attestations |
| Physical | Tangible items | Hardware security devices, access badges |
| Analytical | Derived from analysis | Reports, metrics, trend analysis |

**Section 1.2 Evidence Attributes**

All evidence must meet these quality criteria:

| Attribute | Description | Verification |
|-----------|-------------|--------------|
| Relevance | Directly relates to control | Auditor confirmation |
| Reliability | Accurate and trustworthy | Source verification |
| Sufficiency | Adequate to support conclusion | Sample size validation |
| Timeliness | Within audit period | Timestamp verification |
| Completeness | No gaps or omissions | Checklist verification |
| Integrity | Unaltered from source | Hash verification |

**Section 1.3 Chain of Custody**

| Element | Requirement |
|---------|-------------|
| Collection | Document who collected, when, from where |
| Storage | Secure location with access logging |
| Transfer | Document each handoff |
| Access | Log all evidence access |
| Retention | Maintain per retention schedule |

---

**2. Evidence Collection Process**

**Section 2.1 Collection Workflow**

```
1. Request Receipt
   - Receive evidence request from auditor
   - Log request in evidence tracker
   - Assign to evidence collector
   
2. Source Identification
   - Identify data sources
   - Determine collection method
   - Estimate collection effort
   
3. Collection Execution
   - Extract evidence from source
   - Apply appropriate format
   - Capture metadata
   
4. Quality Verification
   - Verify completeness
   - Check accuracy
   - Validate timestamps
   
5. Documentation
   - Complete evidence form
   - Record chain of custody
   - Link to request
   
6. Secure Storage
   - Upload to evidence repository
   - Set access permissions
   - Enable integrity monitoring
   
7. Delivery
   - Deliver to requestor
   - Obtain acknowledgment
   - Log delivery
```

**Section 2.2 Evidence Request Form**

| Field | Required | Description |
|-------|----------|-------------|
| Request ID | Yes | Unique identifier |
| Requestor | Yes | Name and role |
| Audit/Examination | Yes | Associated audit |
| Control Reference | Yes | Control being tested |
| Evidence Description | Yes | What is needed |
| Date Range | Yes | Time period covered |
| Format Required | No | Specific format needs |
| Deadline | Yes | When evidence is needed |
| Classification | Yes | Sensitivity level |

**Section 2.3 Evidence Collection Form**

| Field | Required | Description |
|-------|----------|-------------|
| Evidence ID | Yes | Unique identifier |
| Request ID | Yes | Link to request |
| Collector | Yes | Who collected |
| Collection Date | Yes | When collected |
| Source System | Yes | Where collected from |
| Collection Method | Yes | How collected |
| Evidence Type | Yes | Documentary, electronic, etc. |
| File Name(s) | Yes | Evidence file names |
| Hash Value(s) | Yes | SHA-256 of files |
| Period Covered | Yes | Date range of evidence |
| Notes | No | Additional context |

---

**3. Evidence by Control Area**

**Section 3.1 Access Control Evidence**

| Control | Evidence Type | Collection Method |
|---------|---------------|-------------------|
| User provisioning | User creation logs | Query IAM system |
| Access reviews | Review documentation | Export from GRC tool |
| Privilege management | Role assignment logs | Query access control |
| Termination | Offboarding records | HR system export |
| MFA enforcement | MFA configuration | System screenshot |

**Evidence Package Contents:**

```
access-control-evidence/
  user-provisioning/
    - new-user-request-samples.pdf
    - approval-workflow-screenshots.png
    - user-creation-logs.csv
  access-reviews/
    - quarterly-review-report.pdf
    - reviewer-attestations.pdf
    - remediation-evidence.pdf
  privilege-management/
    - role-definitions.json
    - admin-user-list.csv
    - privilege-change-logs.csv
  termination/
    - offboarding-checklist-samples.pdf
    - access-revocation-logs.csv
    - system-access-removal-screenshots.png
```

**Section 3.2 Change Management Evidence**

| Control | Evidence Type | Collection Method |
|---------|---------------|-------------------|
| Change requests | Ticket samples | Export from ticketing |
| Approvals | Approval records | Workflow screenshots |
| Testing | Test results | Test system export |
| Deployment | Deployment logs | CI/CD pipeline logs |
| Rollback capability | Rollback procedures | Documentation + test |

**Section 3.3 Incident Response Evidence**

| Control | Evidence Type | Collection Method |
|---------|---------------|-------------------|
| Incident detection | Alert logs | SIEM export |
| Response procedures | Incident tickets | Ticketing system |
| Communication | Notification records | Email/message logs |
| Resolution | Remediation evidence | System logs |
| Post-incident review | PIR documentation | Meeting minutes |

**Section 3.4 Data Protection Evidence**

| Control | Evidence Type | Collection Method |
|---------|---------------|-------------------|
| Encryption at rest | Configuration | System screenshots |
| Encryption in transit | TLS certificates | Certificate export |
| Key management | Key rotation logs | KMS audit logs |
| Data classification | Classification policy | Policy document |
| DLP controls | DLP rule configuration | DLP console export |

---

**4. Evidence Repository**

**Section 4.1 Repository Structure**

```
evidence-repository/
  [audit-year]/
    [audit-name]/
      requests/
        - request-001.json
        - request-002.json
      evidence/
        [control-domain]/
          [control-id]/
            - evidence-files
            - metadata.json
            - chain-of-custody.json
      deliveries/
        - delivery-log.csv
      reports/
        - final-evidence-package.pdf
```

**Section 4.2 Access Control**

| Role | Permissions |
|------|-------------|
| Evidence Administrator | Full access, configuration |
| Evidence Collector | Create, read own evidence |
| Auditor | Read assigned audit evidence |
| Compliance Lead | Read all, approve sensitive |
| Legal | Read all, legal hold management |

**Section 4.3 Integrity Controls**

| Control | Implementation |
|---------|----------------|
| Hash verification | SHA-256 calculated on upload |
| Version control | All changes versioned |
| Access logging | All access logged |
| Immutability | Write-once for finalized evidence |
| Backup | Daily backup with integrity check |

---

**5. Evidence Preservation**

**Section 5.1 Preservation Requirements**

| Requirement | Implementation |
|-------------|----------------|
| Legal hold | Suspend deletion for litigation |
| Regulatory retention | Minimum retention per regulation |
| Format preservation | Store in original format plus PDF |
| Metadata preservation | Capture all original metadata |
| Context preservation | Include collection documentation |

**Section 5.2 Legal Hold Process**

| Step | Action | Owner |
|------|--------|-------|
| 1 | Legal hold notice received | Legal |
| 2 | Identify relevant evidence | Compliance |
| 3 | Apply hold designation | Evidence Admin |
| 4 | Suspend deletion rules | Technical Team |
| 5 | Notify evidence custodians | Compliance |
| 6 | Monitor for new relevant evidence | Ongoing |
| 7 | Release hold when authorized | Legal |

**Section 5.3 Retention Schedule**

| Evidence Type | Minimum Retention | Regulation |
|---------------|-------------------|------------|
| Financial records | 7 years | SOX |
| Security logs | 1 year | PCI-DSS |
| Access records | 7 years | HIPAA |
| Audit reports | 7 years | SOC 2 |
| Incident records | 7 years | Multiple |
| Compliance evidence | 7 years | General |

---

**6. Evidence Presentation**

**Section 6.1 Presentation Formats**

| Format | Use Case | Considerations |
|--------|----------|----------------|
| PDF | Final documentation | Preserved formatting |
| CSV | Log extracts | Easy analysis |
| Screenshots | Configuration evidence | Include timestamps |
| Video | Process walkthroughs | Narrated preferred |
| Live demo | System capabilities | Backup with screenshots |

**Section 6.2 Evidence Package Assembly**

| Component | Content |
|-----------|---------|
| Cover page | Audit name, date range, preparer |
| Table of contents | Evidence index by control |
| Control matrix | Control to evidence mapping |
| Evidence sections | Organized by control domain |
| Appendices | Supporting documentation |

**Section 6.3 Auditor Walkthrough Preparation**

| Activity | Timing |
|----------|--------|
| Evidence review | 2 days before |
| Technical prep | 1 day before |
| System access setup | 1 day before |
| Dry run | Day before |
| Subject matter experts on standby | Day of |

---

**7. Common Evidence Requests**

**Section 7.1 SOC 2 Evidence Matrix**

| Control | Evidence Required |
|---------|-------------------|
| CC1.1 | Org chart, code of conduct attestations |
| CC2.1 | Internal communications samples |
| CC3.1 | Risk assessment documentation |
| CC4.1 | Monitoring dashboards, alert configurations |
| CC5.1 | Control test results |
| CC6.1 | Logical access controls, user lists |
| CC7.1 | Vulnerability scan reports |
| CC8.1 | Change management tickets |
| CC9.1 | Risk mitigation documentation |

**Section 7.2 GDPR Evidence Matrix**

| Requirement | Evidence Required |
|-------------|-------------------|
| Article 5 | Processing policies, minimization evidence |
| Article 6 | Legal basis documentation |
| Article 7 | Consent records, mechanisms |
| Article 12-23 | DSAR handling records |
| Article 28 | DPA agreements |
| Article 30 | ROPA documentation |
| Article 32 | Security measures documentation |
| Article 33-34 | Breach notification records |
| Article 35 | DPIA documentation |

---

**8. Quality Assurance**

**Section 8.1 Evidence Review Checklist**

| Check | Verified |
|-------|----------|
| Evidence matches request | [ ] |
| Date range is correct | [ ] |
| Source is documented | [ ] |
| Format is appropriate | [ ] |
| Sensitive data masked | [ ] |
| Hash value recorded | [ ] |
| Chain of custody complete | [ ] |
| Classification applied | [ ] |

**Section 8.2 Common Issues and Remediation**

| Issue | Remediation |
|-------|-------------|
| Wrong date range | Re-extract with correct dates |
| Missing metadata | Add collection form details |
| Unmasked PII | Apply masking, re-upload |
| Incomplete evidence | Collect additional samples |
| Format issues | Convert to required format |
| Integrity failure | Re-collect from source |

---

**Document Control**

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2026-01-20 | Jerry (okino007) | Initial release |

---

*Proper evidence collection is fundamental to successful audits and regulatory examinations.*
