# Security Policy

> **For comprehensive security documentation, see [SECURITY_GUIDE.md](SECURITY_GUIDE.md)**

## Supported Versions

We provide security updates for the following versions of ThreatSimGPT:

| Version | Supported          | End of Support |
| ------- | ------------------ | -------------- |
| 1.0.x   | Active             | TBD            |
| 0.1.x   | Limited            | 2026-06-01     |
| < 0.1   | Unsupported        | 2025-01-01     |

## Reporting a Vulnerability

The ThreatSimGPT team takes security seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**IMPORTANT: Do NOT use GitHub Issues for security vulnerabilities**

Instead, please report security vulnerabilities to:
- **Email**: threatsimgpt@hotmail.com
- **Subject**: `[SECURITY] ThreatSimGPT Vulnerability Report`

### What to Include

Please include the following information in your security report:

1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential impact of the vulnerability
3. **Steps to Reproduce**: Detailed steps to reproduce the issue
4. **Proof of Concept**: Code or screenshots demonstrating the issue
5. **Suggested Fix**: If you have ideas for fixing the issue
6. **Your Information**: How you'd like to be credited (optional)

### Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Depending on severity (1-4 weeks)
- **Public Disclosure**: After fix is released

### Security Measures

ThreatSimGPT implements several security measures:

#### Code Security
- Static code analysis with Bandit
- Dependency vulnerability scanning
- Automated security testing in CI/CD
- Regular dependency updates

#### API Security
- API key protection and rotation
- Input validation and sanitization
- Rate limiting and request throttling
- Secure environment variable handling

#### Content Safety
- Content filtering for generated material
- Educational use disclaimers
- Ethical use guidelines
- User consent and opt-out mechanisms

#### Data Protection
- Minimal data collection
- Secure storage practices
- Data retention policies
- GDPR/CCPA compliance considerations

### Vulnerability Types

We are particularly interested in reports of:

#### High Priority
- Code injection vulnerabilities
- Authentication/authorization bypasses
- Sensitive data exposure
- Remote code execution
- Cross-site scripting (XSS)
- SQL injection

#### Medium Priority
- Cross-site request forgery (CSRF)
- Information disclosure
- Denial of service (DoS)
- Privilege escalation
- Input validation issues

#### Low Priority
- Missing security headers
- SSL/TLS configuration issues
- Rate limiting bypasses
- Information leakage

### Safe Harbor

We consider security research conducted under this policy to be:
- Authorized under the Computer Fraud and Abuse Act
- Compliant with DMCA Section 1201
- Protected activity under applicable whistleblower laws

We will not pursue legal action against security researchers who:
- Follow responsible disclosure practices
- Act in good faith
- Don't access or modify user data
- Don't disrupt services
- Don't violate privacy

### Recognition

We believe in recognizing security researchers who help improve ThreatSimGPT:

- **Hall of Fame**: Recognition in our security acknowledgments
- **Credits**: Listed in release notes and documentation
- **Swag**: ThreatSimGPT merchandise for significant findings

### Security Updates

When security updates are released:

1. **Security Advisory**: Published on GitHub Security Advisories
2. **Release Notes**: Included in CHANGELOG.md
3. **Notification**: Users notified through GitHub releases
4. **Documentation**: Security documentation updated

### Best Practices for Users

To use ThreatSimGPT securely:

#### API Keys
- Store API keys in environment variables
- Never commit API keys to version control
- Rotate API keys regularly
- Use different keys for different environments

#### Content Generation
- Review all generated content before use
- Ensure compliance with local laws and policies
- Use content only for authorized purposes
- Implement proper content filtering

#### Infrastructure
- Keep ThreatSimGPT updated to latest version
- Monitor for security advisories
- Use secure hosting environments
- Implement proper access controls

#### Development
- Follow secure coding practices
- Validate all inputs
- Use parameterized queries
- Implement proper error handling

### Compliance

ThreatSimGPT is designed to comply with:
- GDPR (General Data Protection Regulation)
- CCPA (California Consumer Privacy Act)
- SOC 2 principles
- OWASP security guidelines

### Contact Information

For security-related questions:
- **Security Email**: security@threatsimgpt.com
- **General Issues**: [GitHub Issues](https://github.com/threatsimgpt-AI/ThreatSimGPT/issues)
- **Discussions**: [GitHub Discussions](https://github.com/threatsimgpt-AI/ThreatSimGPT/discussions)

---

**Note**: This security policy applies only to the ThreatSimGPT codebase. For security issues with dependencies or third-party services, please report to the respective maintainers.
