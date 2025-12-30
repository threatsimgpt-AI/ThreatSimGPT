# ThreatSimGPT Security Guide

**Version:** 1.0.0  
**Last Updated:** November 2025

Comprehensive security guide for deploying, configuring, and using ThreatSimGPT safely in enterprise environments.

---

## Table of Contents

1. [Security Overview](#security-overview)
2. [Vulnerability Reporting](#vulnerability-reporting)
3. [Secure Deployment](#secure-deployment)
4. [API Key Management](#api-key-management)
5. [Content Safety](#content-safety)
6. [Compliance](#compliance)
7. [Best Practices](#best-practices)

---

## Security Overview

### Supported Versions

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 1.0.x   | Active             | TBD            |
| 0.1.x   | Limited            | 2026-06-01     |
| < 0.1   | Unsupported        | 2025-01-01     |

### Security Architecture

ThreatSimGPT implements defense-in-depth security:

```
┌─────────────────────────────────────────┐
│ Layer 1: Input Validation               │
│ - Schema validation                      │
│ - Type checking                          │
│ - Sanitization                           │
├─────────────────────────────────────────┤
│ Layer 2: Authentication & Authorization  │
│ - API key validation                     │
│ - Role-based access control              │
│ - Rate limiting                          │
├─────────────────────────────────────────┤
│ Layer 3: Content Safety                 │
│ - Safety filtering                       │
│ - Educational disclaimers                │
│ - Compliance checks                      │
├─────────────────────────────────────────┤
│ Layer 4: Data Protection                │
│ - Encryption at rest                     │
│ - Encryption in transit                  │
│ - Minimal data collection                │
├─────────────────────────────────────────┤
│ Layer 5: Monitoring & Auditing          │
│ - Comprehensive logging                  │
│ - Anomaly detection                      │
│ - Incident response                      │
└─────────────────────────────────────────┘
```

---

## Vulnerability Reporting

### How to Report

**IMPORTANT: Do NOT use GitHub Issues for security vulnerabilities**

**Contact Information:**
- **Email:** threatsimgpt@hotmail.com
- **Subject Line:** `[SECURITY] ThreatSimGPT Vulnerability Report`
- **PGP Key:** Available upon request

### What to Include

Comprehensive vulnerability reports should include:

1. **Summary**
   - Brief description (1-2 sentences)
   - Severity assessment (Critical/High/Medium/Low)

2. **Vulnerability Details**
   - Affected component/module
   - Attack vector (Local/Network/Physical)
   - Prerequisites for exploitation
   - Impact (Confidentiality/Integrity/Availability)

3. **Proof of Concept**
   - Detailed reproduction steps
   - Code snippets or screenshots
   - Test environment details
   - Expected vs actual behavior

4. **Suggested Mitigation**
   - Proposed fix (if applicable)
   - Workarounds
   - Compensating controls

5. **Researcher Information**
   - Name/handle for attribution
   - Affiliation (optional)
   - Contact method for follow-up

### Response Timeline

| Phase | Timeline | Description |
|-------|----------|-------------|
| **Acknowledgment** | 48 hours | Initial response confirming receipt |
| **Assessment** | 5-7 days | Vulnerability verification and severity rating |
| **Fix Development** | 1-4 weeks | Patch development based on severity |
| **Testing** | 3-5 days | Security testing and QA |
| **Release** | 1-2 days | Patch deployment and notification |
| **Disclosure** | 90 days max | Coordinated public disclosure |

### Severity Levels

#### Critical (CVSS 9.0-10.0)
- Remote code execution
- Authentication bypass
- Complete system compromise
- **Response:** Immediate (24-48 hours)

#### High (CVSS 7.0-8.9)
- SQL injection
- Cross-site scripting (XSS)
- Sensitive data exposure
- **Response:** 1 week

#### Medium (CVSS 4.0-6.9)
- CSRF attacks
- Information disclosure
- Privilege escalation
- **Response:** 2-3 weeks

#### Low (CVSS 0.1-3.9)
- Missing security headers
- Rate limiting issues
- Minor information leakage
- **Response:** 4 weeks

### Safe Harbor

Security research under this policy is:
- Authorized under Computer Fraud and Abuse Act
- Protected whistleblower activity
- Compliant with DMCA Section 1201

**Researchers must:**
- Act in good faith
- Follow responsible disclosure
- Not access/modify user data
- Not disrupt services
- Not violate privacy

### Recognition Program

**Hall of Fame:**
- Public recognition in security acknowledgments
- Listed in SECURITY.md
- Mentioned in release notes

**Rewards (Future):**
- Significant vulnerabilities: Monetary bounty (planned)
- All reports: ThreatSimGPT swag and merchandise

---

## Secure Deployment

### Production Deployment Checklist

#### Pre-Deployment

- [ ] Security audit completed
- [ ] Dependencies scanned for vulnerabilities
- [ ] Static code analysis passed
- [ ] Penetration testing completed
- [ ] Security documentation reviewed

#### Deployment Configuration

- [ ] HTTPS/TLS enabled (TLS 1.2+ only)
- [ ] API keys rotated and secured
- [ ] Rate limiting configured
- [ ] Monitoring and alerting active
- [ ] Backup and recovery tested
- [ ] Incident response plan documented

#### Post-Deployment

- [ ] Security monitoring active
- [ ] Log aggregation configured
- [ ] Alert thresholds set
- [ ] Regular security scans scheduled
- [ ] Update procedures documented

### Network Security

#### Firewall Configuration

```bash
# Allow only necessary ports
# API Server
iptables -A INPUT -p tcp --dport 8000 -j ACCEPT

# HTTPS
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block all other incoming
iptables -P INPUT DROP
```

#### TLS Configuration

```yaml
# config.yaml
api:
  ssl:
    enabled: true
    cert_file: "/path/to/cert.pem"
    key_file: "/path/to/key.pem"
    min_tls_version: "1.2"
    ciphers:
      - "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
      - "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### Container Security

#### Docker Security

```dockerfile
# Use specific version tags
FROM python:3.11.6-slim

# Run as non-root user
RUN useradd -m -u 1000 threatsimgpt
USER threatsimgpt

# Read-only root filesystem
VOLUME ["/app/logs", "/app/data"]

# Security options
LABEL security.scan="enabled"
```

```yaml
# docker-compose.yml
services:
  threatsimgpt:
    image: threatsimgpt:latest
    read_only: true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
```

---

## API Key Management

### Best Practices

#### Storage

**DO:**
```bash
# Use environment variables
export OPENROUTER_API_KEY="sk-or-v1-..."

# Use secrets management
# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id threatsimgpt/api-keys

# HashiCorp Vault
vault kv get secret/threatsimgpt/api-keys
```

**DON'T:**
```yaml
# config.yaml - NEVER store keys directly
llm:
  openrouter:
    api_key: "sk-or-v1-abc123..."  # BAD!
```

#### Rotation

```bash
# Rotate API keys quarterly
# 1. Generate new key
# 2. Update environment
export OPENROUTER_API_KEY="sk-or-v1-NEW_KEY"

# 3. Test
python3 -m threatsimgpt llm test-providers

# 4. Revoke old key
```

#### Monitoring

```python
# Monitor API key usage
from threatsimgpt.utils.audit import APIKeyAuditor

auditor = APIKeyAuditor()
auditor.track_usage(api_key, endpoint, timestamp)

# Alert on suspicious activity
if auditor.detect_anomaly(api_key):
    alert_security_team()
```

### Key Segregation

Use different keys per environment:

```bash
# Development
export OPENROUTER_API_KEY_DEV="sk-or-v1-dev..."

# Staging
export OPENROUTER_API_KEY_STAGING="sk-or-v1-staging..."

# Production
export OPENROUTER_API_KEY_PROD="sk-or-v1-prod..."
```

---

## Content Safety

### Safety Filters

ThreatSimGPT implements multi-layer content filtering:

#### Layer 1: Pre-Generation

```yaml
# config.yaml
simulation:
  compliance_mode: true          # Enable safety checks
  content_filtering: true        # Filter harmful content
  prohibited_topics:
    - "real_malware"
    - "illegal_activities"
    - "personal_attacks"
```

#### Layer 2: Post-Generation

```python
from threatsimgpt.llm.validation import ContentValidator

validator = ContentValidator(safety_level="STRICT")
result = validator.validate_content(generated_content)

if not result.is_safe:
    # Block unsafe content
    raise ContentSafetyViolation(result.violations)
```

#### Layer 3: Human Review

```bash
# Always review generated content
python3 -m threatsimgpt simulate -s template.yaml --preview

# Manual approval before use
python3 -m threatsimgpt simulate -s template.yaml --require-approval
```

### Educational Disclaimers

All generated content includes disclaimers:

```
EDUCATIONAL CONTENT - SIMULATION ONLY

This is simulated threat content for security training purposes.
- Do NOT use for malicious purposes
- Use only in authorized training
- Compliant with applicable laws
- Educational use disclaimer
```

### Usage Policies

**Authorized Uses:**
- Security awareness training
- Red team exercises (authorized)
- Penetration testing (authorized)
- Security research
- Educational purposes

**Prohibited Uses:**
- Actual phishing attacks
- Unauthorized system access
- Harassment or harm
- Illegal activities
- Unethical research

---

## Compliance

### GDPR Compliance

ThreatSimGPT minimizes data collection:

```python
# Data minimization
class DataProtection:
    def collect_data(self):
        # Only collect necessary data
        return {
            "simulation_id": uuid4(),
            "timestamp": datetime.utcnow(),
            # NO personal data collected
        }
    
    def retention_policy(self):
        # Auto-delete after 90 days
        delete_data_older_than(days=90)
```

### CCPA Compliance

User rights implementation:

```bash
# Right to know
python3 -m threatsimgpt data export-user-data --user-id USER_ID

# Right to delete
python3 -m threatsimgpt data delete-user-data --user-id USER_ID

# Right to opt-out
python3 -m threatsimgpt data opt-out --user-id USER_ID
```

### SOC 2 Controls

| Control | Implementation |
|---------|----------------|
| **Access Control** | Role-based access, API key authentication |
| **Encryption** | TLS in transit, AES-256 at rest |
| **Monitoring** | Comprehensive logging, real-time alerts |
| **Incident Response** | Documented procedures, 24/7 monitoring |
| **Change Management** | Version control, approval workflows |

### Industry-Specific

#### Healthcare (HIPAA)

```yaml
# config.yaml
compliance:
  hipaa:
    enabled: true
    phi_detection: true
    audit_logging: "comprehensive"
    retention_period: 7  # years
```

#### Finance (PCI DSS)

```yaml
compliance:
  pci:
    enabled: true
    sensitive_data_masking: true
    quarterly_scans: true
```

---

## Best Practices

### Development

```python
# 1. Input validation
def validate_input(user_input: str) -> str:
    # Sanitize inputs
    return bleach.clean(user_input)

# 2. Parameterized queries
cursor.execute(
    "SELECT * FROM scenarios WHERE id = ?",
    (scenario_id,)
)

# 3. Error handling
try:
    result = execute_simulation(scenario)
except Exception as e:
    logger.error(f"Simulation failed: {e}")
    # Don't expose internal details
    return "Simulation failed. Please contact support."
```

### Infrastructure

```bash
# 1. Keep software updated
pip install --upgrade threatsimgpt

# 2. Regular security scans
bandit -r src/
safety check

# 3. Dependency auditing
pip-audit

# 4. Container scanning
trivy image threatsimgpt:latest
```

### Monitoring

```yaml
# config.yaml
monitoring:
  alerts:
    - type: "failed_authentication"
      threshold: 5
      window: "5m"
      action: "block_ip"
    
    - type: "rate_limit_exceeded"
      threshold: 1000
      window: "1h"
      action: "alert_admin"
    
    - type: "content_safety_violation"
      threshold: 1
      action: "immediate_alert"
```

---

## Incident Response

### Response Plan

#### Phase 1: Detection
- Automated monitoring alerts
- User reports
- Security scan findings

#### Phase 2: Containment
```bash
# Immediate actions
# 1. Rotate compromised API keys
python3 -m threatsimgpt security rotate-keys --emergency

# 2. Block malicious IPs
python3 -m threatsimgpt security block-ip 192.168.1.100

# 3. Isolate affected systems
docker-compose down threatsimgpt-api
```

#### Phase 3: Investigation
- Review logs
- Identify attack vector
- Assess damage
- Document findings

#### Phase 4: Recovery
- Apply patches
- Restore from backup
- Verify system integrity
- Resume operations

#### Phase 5: Post-Incident
- Root cause analysis
- Update procedures
- Implement improvements
- Notify stakeholders

---

## Security Auditing

### Automated Scans

```bash
# Run weekly security audits
#!/bin/bash

# Code security
bandit -r src/ -o bandit-report.html

# Dependency vulnerabilities
safety check --json > safety-report.json

# Container scanning
trivy image threatsimgpt:latest

# License compliance
pip-licenses --format=html > licenses.html
```

### Manual Reviews

- **Quarterly:** Code security review
- **Bi-annual:** Architecture review
- **Annual:** Penetration testing
- **Continuous:** Pull request reviews

---

## Additional Resources

- **User Guide:** USER_GUIDE.md
- **Developer Guide:** DEVELOPER_GUIDE.md
- **API Documentation:** API_DOCUMENTATION.md
- **Configuration:** CONFIGURATION_REFERENCE.md

---

## Contact

**Security Team:**
- **Email:** threatsimgpt@hotmail.com
- **PGP Key:** Available upon request
- **Response Time:** 48 hours maximum

**General Support:**
- **GitHub Issues:** https://github.com/threatsimgpt-AI/ThreatSimGPT/issues
- **Discussions:** https://github.com/threatsimgpt-AI/ThreatSimGPT/discussions
