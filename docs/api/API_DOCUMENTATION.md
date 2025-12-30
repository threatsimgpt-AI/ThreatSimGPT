# ThreatSimGPT API Documentation

**Version:** 1.0.0  
**Last Updated:** November 2025

## Overview

ThreatSimGPT provides a RESTful API for programmatic access to threat simulation capabilities. The API enables enterprises to integrate threat scenario generation, content validation, and simulation orchestration into their security workflows.

## Base Configuration

### Base URL
```
Production: https://api.threatsimgpt.io/v1
Development: http://localhost:8000
```

### Authentication

Production deployments require API key authentication:

```bash
curl -X GET "https://api.threatsimgpt.io/v1/health" \
     -H "Authorization: Bearer YOUR_API_KEY"
```

For local development, authentication is optional.

## API Endpoints

### Health Check

Check API health and component status.

**Endpoint:** `GET /health`

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2025-11-23T10:30:00Z",
  "version": "1.0.0",
  "components": {
    "api": "healthy",
    "simulator": "healthy",
    "llm_manager": "healthy",
    "validation": "healthy"
  }
}
```

---

### LLM Content Generation

Generate threat simulation content using LLM providers.

**Endpoint:** `POST /llm/generate`

**Request Body:**
```json
{
  "prompt": "Create a realistic phishing email targeting IT administrators",
  "scenario_type": "phishing",
  "max_tokens": 500,
  "temperature": 0.7,
  "provider": "openrouter"
}
```

**Response:**
```json
{
  "content": "Subject: Critical Security Update Required...",
  "provider_used": "openrouter",
  "model": "openai/gpt-5.1-chat",
  "tokens_used": 245,
  "generation_time_seconds": 2.3,
  "safety_score": 0.95,
  "finish_reason": "stop",
  "metadata": {
    "scenario_type": "phishing",
    "validated": true,
    "content_type": "email"
  }
}
```

**Parameters:**
- `prompt` (required): The generation prompt
- `scenario_type` (required): Type of scenario (`phishing`, `bec`, `social_engineering`, etc.)
- `max_tokens` (optional): Maximum tokens (default: 1000)
- `temperature` (optional): Generation temperature 0.0-1.0 (default: 0.7)
- `provider` (optional): LLM provider to use (default: configured default)

---

### Scenario Management

#### Create Scenario

**Endpoint:** `POST /scenarios`

**Request Body:**
```json
{
  "name": "Executive Phishing Campaign",
  "threat_type": "phishing",
  "description": "Advanced spear-phishing targeting C-level executives",
  "difficulty_level": 8,
  "target_profile": {
    "role": "CEO",
    "department": "executive",
    "seniority": "senior",
    "industry": "technology"
  },
  "behavioral_pattern": {
    "psychological_triggers": ["authority", "urgency"],
    "social_engineering_tactics": ["impersonation", "pretexting"]
  }
}
```

**Response:**
```json
{
  "scenario_id": "abc123-def456-ghi789",
  "name": "Executive Phishing Campaign",
  "threat_type": "phishing",
  "status": "created",
  "created_at": "2025-11-23T10:30:00Z",
  "metadata": {
    "difficulty_level": 8,
    "estimated_duration": 45
  }
}
```

#### Get Scenario

**Endpoint:** `GET /scenarios/{scenario_id}`

**Response:**
```json
{
  "scenario_id": "abc123-def456-ghi789",
  "name": "Executive Phishing Campaign",
  "threat_type": "phishing",
  "description": "Advanced spear-phishing targeting C-level executives",
  "status": "ready",
  "created_at": "2025-11-23T10:30:00Z",
  "target_profile": {...},
  "behavioral_pattern": {...}
}
```

#### List Scenarios

**Endpoint:** `GET /scenarios`

**Query Parameters:**
- `threat_type`: Filter by threat type
- `difficulty_level`: Filter by difficulty (1-10)
- `limit`: Maximum results (default: 50)
- `offset`: Pagination offset

**Response:**
```json
{
  "scenarios": [
    {
      "scenario_id": "abc123",
      "name": "Executive Phishing Campaign",
      "threat_type": "phishing",
      "difficulty_level": 8
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

---

### Simulation Execution

#### Run Simulation

**Endpoint:** `POST /simulations/run`

**Request Body:**
```json
{
  "scenario_id": "abc123-def456-ghi789",
  "max_stages": 5,
  "compliance_mode": true,
  "content_filtering": true
}
```

**Response:**
```json
{
  "simulation_id": "sim-xyz789",
  "scenario_id": "abc123-def456-ghi789",
  "status": "running",
  "started_at": "2025-11-23T10:35:00Z",
  "estimated_completion": "2025-11-23T11:20:00Z"
}
```

#### Get Simulation Status

**Endpoint:** `GET /simulations/{simulation_id}`

**Response:**
```json
{
  "simulation_id": "sim-xyz789",
  "scenario_id": "abc123-def456-ghi789",
  "status": "completed",
  "started_at": "2025-11-23T10:35:00Z",
  "completed_at": "2025-11-23T11:18:00Z",
  "stages_completed": 5,
  "stages_total": 5,
  "results": {
    "success": true,
    "content_generated": 5,
    "safety_violations": 0
  }
}
```

#### Get Simulation Results

**Endpoint:** `GET /simulations/{simulation_id}/results`

**Response:**
```json
{
  "simulation_id": "sim-xyz789",
  "scenario_name": "Executive Phishing Campaign",
  "stages": [
    {
      "stage_number": 1,
      "stage_type": "reconnaissance",
      "content": "...",
      "metadata": {...}
    }
  ],
  "summary": {
    "total_stages": 5,
    "successful_stages": 5,
    "total_duration_seconds": 2580
  }
}
```

---

### Template Management

#### Validate Template

**Endpoint:** `POST /templates/validate`

**Request Body:**
```yaml
metadata:
  name: "Test Scenario"
  version: "1.0.0"
threat_type: "phishing"
# ... rest of template
```

**Response:**
```json
{
  "valid": true,
  "errors": [],
  "warnings": [
    "Consider adding MITRE ATT&CK mappings for better context"
  ],
  "score": 95
}
```

---

## Error Handling

The API uses standard HTTP status codes:

- `200 OK`: Successful request
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request parameters
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `422 Unprocessable Entity`: Validation error
- `500 Internal Server Error`: Server error
- `503 Service Unavailable`: Service temporarily unavailable

**Error Response Format:**
```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid scenario configuration",
    "details": {
      "field": "difficulty_level",
      "reason": "Must be between 1 and 10"
    }
  }
}
```

---

## Rate Limiting

Production API enforces rate limits:

- **Free Tier:** 100 requests/hour
- **Professional:** 1,000 requests/hour
- **Enterprise:** Custom limits

Rate limit headers:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 995
X-RateLimit-Reset: 1637765400
```

---

## Webhooks

Configure webhooks to receive real-time notifications:

**Event Types:**
- `simulation.started`: Simulation execution began
- `simulation.completed`: Simulation finished
- `simulation.failed`: Simulation encountered error
- `content.generated`: New content generated
- `validation.failed`: Content failed safety validation

**Webhook Payload:**
```json
{
  "event": "simulation.completed",
  "timestamp": "2025-11-23T11:18:00Z",
  "data": {
    "simulation_id": "sim-xyz789",
    "scenario_id": "abc123",
    "status": "completed"
  }
}
```

---

## SDKs and Client Libraries

Official SDKs available:

- **Python:** `pip install threatsimgpt-sdk`
- **Node.js:** `npm install @threatsimgpt/sdk`
- **Go:** `go get github.com/threatsimgpt/go-sdk`

---

## Support

- **Documentation:** https://docs.threatsimgpt.io
- **API Status:** https://status.threatsimgpt.io
- **Support Email:** support@threatsimgpt.io
