# ThreatSimGPT Configuration Reference

**Version:** 1.0.0  
**Last Updated:** November 2025

Complete reference for ThreatSimGPT configuration including system settings and template schemas.

---

## Table of Contents

1. [System Configuration](#system-configuration)
2. [Template Schema](#template-schema)
3. [Environment Variables](#environment-variables)
4. [Content Types](#content-types)
5. [Validation Rules](#validation-rules)

---

## System Configuration

### Configuration File: `config.yaml`

Main system configuration file controlling LLM providers, logging, and output settings.

```yaml
llm:
  # Default LLM provider to use
  default_provider: "openrouter"  # Options: openrouter, openai, anthropic
  
  # OpenRouter configuration (recommended)
  openrouter:
    base_url: "https://openrouter.ai/api/v1"
    model: "openai/gpt-5.1-chat"  # Or: anthropic/claude-3-haiku, etc.
    max_tokens: 1000
    temperature: 0.7
    timeout: 60
    retry_attempts: 3
  
  # OpenAI configuration
  openai:
    model: "gpt-4"
    max_tokens: 1000
    temperature: 0.7
    timeout: 60
    
  # Anthropic Claude configuration
  anthropic:
    model: "claude-3-haiku-20240307"
    max_tokens: 1000
    temperature: 0.7
    timeout: 60

logging:
  level: "INFO"  # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
  file: "logs/threatsimgpt.log"
  rotation: "daily"  # daily, weekly, size
  max_bytes: 10485760  # 10MB
  backup_count: 5

content:
  output_directory: "generated_content"
  save_format: "markdown"  # markdown, json, yaml
  include_metadata: true
  auto_save: true
  
simulation:
  max_stages: 10
  default_timeout: 300  # seconds
  compliance_mode: true
  content_filtering: true
  audit_logging: true
```

### LLM Provider Configuration

#### OpenRouter (Recommended)

```yaml
llm:
  default_provider: "openrouter"
  openrouter:
    base_url: "https://openrouter.ai/api/v1"
    model: "openai/gpt-5.1-chat"
    max_tokens: 1000
    temperature: 0.7
    timeout: 60
    retry_attempts: 3
```

**Available Models:**
- `openai/gpt-5.1-chat` - Latest GPT model
- `openai/gpt-4-turbo` - GPT-4 Turbo
- `anthropic/claude-3-haiku` - Fast Claude model
- `anthropic/claude-3-sonnet` - Balanced Claude model
- `meta-llama/llama-3.1-70b` - Open source Llama
- `google/gemini-pro` - Google Gemini

#### OpenAI

```yaml
llm:
  default_provider: "openai"
  openai:
    model: "gpt-4"  # or gpt-3.5-turbo
    max_tokens: 1000
    temperature: 0.7
```

#### Anthropic Claude

```yaml
llm:
  default_provider: "anthropic"
  anthropic:
    model: "claude-3-haiku-20240307"
    max_tokens: 1000
    temperature: 0.7
```

---

## Template Schema

### Complete Template Structure

```yaml
# =============================================================================
# METADATA (Required)
# =============================================================================
metadata:
  name: "Scenario Name"                    # Required: Clear, descriptive name
  description: "Detailed description"      # Required: What this scenario does
  version: "1.0.0"                        # Required: Semantic versioning
  author: "Your Team"                     # Required: Creator identification
  created_at: "2025-11-23T10:00:00Z"     # Required: ISO 8601 timestamp
  updated_at: "2025-11-23T10:00:00Z"     # Required: Last modification
  tags: ["tag1", "tag2"]                  # Required: Searchable tags (array)
  references:                             # Optional: Documentation links
    - "https://attack.mitre.org/techniques/T1566/"

# =============================================================================
# THREAT CLASSIFICATION (Required)
# =============================================================================
threat_type: "phishing"                   # Required: See threat types below
delivery_vector: "email"                  # Required: See delivery vectors below
difficulty_level: 5                       # Required: Integer 1-10
estimated_duration: 30                    # Required: Minutes (integer)

# =============================================================================
# TARGET PROFILE (Required)
# =============================================================================
target_profile:
  # Core identification (all required)
  role: "Employee"                        # Required: Job role/title
  department: "general"                   # Required: Department name (max 50 chars)
  seniority: "mid"                        # Required: junior|mid|senior
  technical_level: "moderate"             # Required: low|moderate|high
  security_awareness_level: 5             # Required: Integer 1-10
  industry: "technology"                  # Required: Industry type
  
  # Optional extended profile
  company_size: "medium"                  # Optional: small|medium|large|enterprise
  typical_working_hours: "9:00-17:00"    # Optional: Time range
  communication_style: "professional"     # Optional: Style description
  
  # Optional interests/context
  interests:                              # Optional: Array of interests
    - "business_strategy"
    - "technology"
  
  # Optional social media presence
  social_media_presence:                  # Optional: Object
    linkedin: "active_professional"
    twitter: "moderate"
    facebook: "minimal"

# =============================================================================
# BEHAVIORAL PATTERN (Required)
# =============================================================================
behavioral_pattern:
  # MITRE ATT&CK mappings (optional but recommended)
  mitre_attack_techniques:                # Optional: Array of technique IDs
    - "T1566.001"  # Phishing: Spearphishing Attachment
    - "T1566.002"  # Phishing: Spearphishing Link
  
  mitre_attack_tactics:                   # Optional: Array of tactic names
    - "Initial Access"
    - "Collection"
  
  # Required attack characteristics
  psychological_triggers:                 # Required: Array (min 1)
    - "urgency"
    - "authority"
    - "curiosity"
    - "fear"
  
  social_engineering_tactics:             # Required: Array (min 1)
    - "impersonation"
    - "pretexting"
    - "time_pressure"
  
  # Optional technical methods
  technical_methods:                      # Optional: Array
    - "email_spoofing"
    - "credential_harvesting"
    - "url_shortening"
  
  # Optional evasion techniques
  evasion_techniques:                     # Optional: Array
    - "legitimate_service_abuse"
    - "typosquatting"

# =============================================================================
# SIMULATION PARAMETERS (Optional)
# =============================================================================
simulation_parameters:
  max_iterations: 3                       # Optional: Integer (default: 3)
  max_duration_minutes: 60                # Optional: Integer (default: 60)
  escalation_enabled: true                # Optional: Boolean (default: true)
  response_adaptation: true               # Optional: Boolean (default: true)
  time_pressure_simulation: true          # Optional: Boolean (default: false)
  multi_stage_attack: false               # Optional: Boolean (default: false)
  persistence_simulation: false           # Optional: Boolean (default: false)
  language: "en-US"                       # Optional: String (default: en-US)
  tone: "professional"                    # Optional: String
  urgency_level: 5                        # Optional: Integer 1-10 (default: 5)
  compliance_mode: true                   # Optional: Boolean (default: true)
  content_filtering: true                 # Optional: Boolean (default: true)
  audit_logging: true                     # Optional: Boolean (default: true)

# =============================================================================
# CUSTOM PARAMETERS (Optional)
# =============================================================================
custom_parameters:
  # Any custom fields for scenario-specific configuration
  email_templates:
    subject_patterns:
      - "Pattern 1"
      - "Pattern 2"
  
  impersonation_details:
    fake_personas:
      - name: "John Doe"
        title: "IT Manager"
```

### Field Specifications

#### Metadata Fields

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| `name` | string | Yes | 1-200 characters |
| `description` | string | Yes | 1-1000 characters |
| `version` | string | Yes | Semantic version (X.Y.Z) |
| `author` | string | Yes | 1-100 characters |
| `created_at` | string | Yes | ISO 8601 timestamp |
| `updated_at` | string | Yes | ISO 8601 timestamp |
| `tags` | array[string] | Yes | 1-20 tags, each 1-50 chars |
| `references` | array[string] | No | Valid URLs |

#### Threat Type Values

Valid `threat_type` values:

- `phishing` - Email phishing attacks
- `spear_phishing` - Targeted phishing
- `sms_phishing` - SMS/text phishing (smishing)
- `social_engineering` - General social engineering
- `bec` - Business Email Compromise
- `vishing` - Voice phishing (phone calls)
- `pretexting` - Pretext-based attacks
- `impersonation` - Identity impersonation
- `credential_harvesting` - Credential theft
- `malware_delivery` - Malware distribution

#### Delivery Vector Values

Valid `delivery_vector` values:

- `email` - Email delivery
- `sms` - SMS/text message
- `phone_call` - Voice call
- `social_media` - Social media platforms
- `instant_message` - Chat/IM platforms
- `website` - Malicious website
- `usb_device` - Physical USB device
- `qr_code` - QR code scanning

#### Seniority Levels

Valid `seniority` values:

- `junior` - Entry-level employees (0-2 years)
- `mid` - Mid-level employees (2-5 years)
- `senior` - Senior employees (5+ years)

#### Technical Levels

Valid `technical_level` values:

- `low` - Limited technical knowledge
- `moderate` - Average technical understanding
- `high` - Advanced technical expertise

---

## Environment Variables

### Required Variables

```bash
# LLM Provider API Keys (at least one required)
export OPENROUTER_API_KEY="sk-or-v1-..."
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Optional Variables

```bash
# System configuration overrides
export THREATSIMGPT_CONFIG_PATH="/path/to/config.yaml"
export THREATSIMGPT_LOG_LEVEL="DEBUG"
export THREATSIMGPT_OUTPUT_DIR="./my_output"

# LLM configuration overrides
export THREATSIMGPT_LLM_PROVIDER="openrouter"
export THREATSIMGPT_LLM_MODEL="openai/gpt-5.1-chat"
export THREATSIMGPT_MAX_TOKENS="1500"

# Feature flags
export THREATSIMGPT_COMPLIANCE_MODE="true"
export THREATSIMGPT_CONTENT_FILTERING="true"
export THREATSIMGPT_DEBUG_MODE="false"
```

---

## Content Types

### Email Content Type

```yaml
# Generates professional phishing emails
content_type: "email"
max_tokens: 2000  # Sufficient for full email

# Example output:
# - Email headers (From, To, Subject)
# - Email body with formatting
# - Call-to-action
# - Signature block
```

### SMS Content Type

```yaml
# Generates SMS/text messages
content_type: "sms"
max_tokens: 500  # Short messages

# Example output:
# - 160-300 character text message
# - Shortened URLs
# - Urgent language
```

### Phone Script Content Type

```yaml
# Generates phone call scripts
content_type: "phone_script"
max_tokens: 2000  # Complete conversation

# Example output:
# - Opening greeting
# - Conversation flow
# - Objection handling
# - Information extraction
```

### Document Content Type

```yaml
# Generates document lures
content_type: "document"
max_tokens: 3000  # Full document

# Example output:
# - Document structure
# - Realistic content
# - Malicious elements (safe simulation)
```

### Social Media Content Type

```yaml
# Generates social media posts
content_type: "social_media"
max_tokens: 500  # Brief posts

# Example output:
# - Platform-appropriate content
# - Hashtags
# - Links
# - Engagement hooks
```

---

## Validation Rules

### Template Validation

Templates are validated against JSON schema:

```bash
# Validate template
python3 -m threatsimgpt templates show my_template --validate
```

**Common Validation Errors:**

1. **Missing Required Fields**
   ```
   Error: Missing required field 'metadata.name'
   Fix: Add name field to metadata section
   ```

2. **Invalid Enum Value**
   ```
   Error: Invalid threat_type 'hacking'
   Fix: Use valid value like 'phishing' or 'social_engineering'
   ```

3. **Type Mismatch**
   ```
   Error: difficulty_level must be integer, got string
   Fix: Change "5" to 5 (remove quotes)
   ```

4. **Array Validation**
   ```
   Error: psychological_triggers must be array
   Fix: Use YAML array syntax with dashes
   ```

### Content Validation

Generated content is validated for:

1. **Safety** - No harmful content
2. **Completeness** - Not truncated
3. **Relevance** - Matches scenario
4. **Format** - Proper structure

```yaml
# Enable validation in config.yaml
simulation:
  compliance_mode: true      # Safety validation
  content_filtering: true    # Content filtering
  audit_logging: true        # Log all generation
```

---

## Custom Scenarios

### Creating Custom Scenarios

1. **Start with template:**
   ```bash
   cp templates/executive_phishing.yaml templates/my_scenario.yaml
   ```

2. **Modify key fields:**
   - Update metadata (name, description, author)
   - Adjust target_profile
   - Set appropriate difficulty_level
   - Customize behavioral_pattern

3. **Validate:**
   ```bash
   python3 -m threatsimgpt templates show my_scenario --validate
   ```

4. **Test:**
   ```bash
   python3 -m threatsimgpt simulate -s templates/my_scenario.yaml --dry-run
   ```

### Advanced Customization

Use `custom_parameters` for scenario-specific configuration:

```yaml
custom_parameters:
  # Industry-specific terms
  industry_terminology:
    - "HIPAA compliance"
    - "patient data"
    - "medical records"
  
  # Custom templates
  email_templates:
    urgent_request:
      subject: "URGENT: {topic}"
      sender_pattern: "{name}@{domain}.com"
  
  # Timing strategies
  optimal_timing:
    - "07:00-09:00"  # Morning rush
    - "17:00-19:00"  # End of day
```

---

## Best Practices

### Configuration Management

1. **Version Control:** Track config.yaml changes
2. **Environment-Specific:** Use separate configs for dev/prod
3. **Secret Management:** Use environment variables for API keys
4. **Documentation:** Comment complex configurations

### Template Development

1. **Semantic Versioning:** Use X.Y.Z format
2. **MITRE Mapping:** Include ATT&CK technique references
3. **Clear Naming:** Descriptive, searchable names
4. **Comprehensive Tags:** Multiple relevant tags
5. **Validation:** Always validate before use

### Security

1. **API Key Security:** Never commit API keys
2. **Compliance Mode:** Enable for production
3. **Content Filtering:** Always enable
4. **Audit Logging:** Enable for compliance tracking

---

## Additional Resources

- **User Guide:** USER_GUIDE.md
- **Developer Guide:** DEVELOPER_GUIDE.md
- **API Documentation:** API_DOCUMENTATION.md
- **Security Guide:** SECURITY_GUIDE.md

---

## Support

- **GitHub Issues:** https://github.com/threatsimgpt-AI/ThreatSimGPT/issues
- **Email:** threatsimgpt@hotmail.com
