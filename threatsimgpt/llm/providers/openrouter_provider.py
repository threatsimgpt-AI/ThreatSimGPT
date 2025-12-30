"""OpenRouter LLM provider for ThreatSimGPT.

This provider integrates with OpenRouter API to access multiple LLM models
through a single API interface, providing flexibility and cost-effectiveness.
"""

import logging
import asyncio
import aiohttp
from typing import Optional, Dict, Any, List

from ..base import BaseLLMProvider, LLMResponse

logger = logging.getLogger(__name__)


class OpenRouterProvider(BaseLLMProvider):
    """OpenRouter API provider for multiple LLM models."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize OpenRouter provider.

        Args:
            config: Configuration dict with api_key, model, etc.
        """
        super().__init__(config)
        self.api_key = config.get('api_key')
        self.model = config.get('model', 'qwen/qwen3-vl-235b-a22b-thinking')  # Default to working Qwen model
        self.base_url = config.get('base_url', 'https://openrouter.ai/api/v1')
        self.app_name = config.get('app_name', 'ThreatSimGPT')
        self.site_url = config.get('site_url', 'https://github.com/threatsimgpt-AI/ThreatSimGPT')

        # Popular model options for ThreatSimGPT (including user's working Qwen model)
        self.recommended_models = {
            'qwen-3l-235b': 'qwen/qwen3-vl-235b-a22b-thinking',  # User's preferred working model
            'qwen-2.5-72b': 'qwen/qwen-2.5-72b-instruct',
            'qwen-2.5-7b': 'qwen/qwen-2.5-7b-instruct',
            'claude-3-haiku': 'anthropic/claude-3-haiku',
            'claude-3-sonnet': 'anthropic/claude-3-sonnet',
            'gpt-4o-mini': 'openai/gpt-4o-mini',
            'gpt-4o': 'openai/gpt-4o',
            'llama-3.1-70b': 'meta-llama/llama-3.1-70b-instruct',
            'llama-3.1-8b': 'meta-llama/llama-3.1-8b-instruct',
            'mixtral-8x7b': 'mistralai/mixtral-8x7b-instruct',
            'gemini-pro': 'google/gemini-pro'
        }

        if not self.api_key:
            logger.warning("OpenRouter API key not provided")

        # Session management
        self._session: Optional[aiohttp.ClientSession] = None
        self._ssl_context = None

    def _get_ssl_context(self):
        """Get or create SSL context for OpenRouter API."""
        if self._ssl_context is None:
            try:
                import ssl
                self._ssl_context = ssl.create_default_context()
                # Disable SSL verification on macOS due to certificate issues with aiohttp
                self._ssl_context.check_hostname = False
                self._ssl_context.verify_mode = ssl.CERT_NONE
                logger.debug("SSL verification disabled for aiohttp (macOS compatibility)")
            except Exception as e:
                logger.warning(f"Could not configure SSL context: {e}")
        return self._ssl_context

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with connection pooling."""
        if self._session is None or self._session.closed:
            ssl_context = self._get_ssl_context()
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(connector=connector)
        return self._session

    async def cleanup(self):
        """Clean up resources."""
        if self._session and not self._session.closed:
            await self._session.close()

    def is_available(self) -> bool:
        """Check if OpenRouter provider is available."""
        return bool(self.api_key)

    async def generate(self, prompt: str) -> LLMResponse:
        """Generate response from prompt (required by base class)."""
        result = await self.generate_content(prompt)
        if result is None:
            return LLMResponse("Error: Failed to generate content")
        return result

    async def generate_content(
        self,
        prompt: str,
        scenario_type: str = "general",
        max_tokens: int = 800,  # Reduced from 1000 for faster generation
        temperature: float = 0.7,
        **kwargs
    ) -> Optional[LLMResponse]:
        """Generate content using OpenRouter API.

        Args:
            prompt: The input prompt
            scenario_type: Type of scenario for context
            max_tokens: Maximum tokens to generate
            temperature: Sampling temperature
            **kwargs: Additional parameters

        Returns:
            LLMResponse with generated content or None if failed
        """
        if not self.is_available():
            logger.error("OpenRouter provider not available - missing API key")
            return None

        try:
            # Prepare request headers
            headers = {
                'Authorization': f'Bearer {self.api_key}',
                'Content-Type': 'application/json',
                'HTTP-Referer': self.site_url,
                'X-Title': self.app_name
            }

            # Prepare request payload
            payload = {
                'model': self.model,
                'messages': [
                    {
                        'role': 'system',
                        'content': self._get_system_prompt(scenario_type)
                    },
                    {
                        'role': 'user',
                        'content': prompt
                    }
                ],
                'max_tokens': max_tokens,
                'temperature': temperature,
                'stream': False
            }

            # Add any additional parameters
            for key, value in kwargs.items():
                if key not in ['prompt', 'scenario_type']:
                    payload[key] = value

            # Make API request with retry logic
            max_retries = 1  # Reduced retries to avoid long waits
            retry_delay = 2.0

            # Use connection pooling with session management
            for attempt in range(max_retries + 1):
                try:
                    session = await self._get_session()
                    timeout = aiohttp.ClientTimeout(total=120)  # Increased for better reliability
                    async with session.post(
                        f'{self.base_url}/chat/completions',
                        headers=headers,
                        json=payload,
                        timeout=timeout
                    ) as response:

                            if response.status == 200:
                                data = await response.json()

                                # Extract content from response
                                if 'choices' in data and len(data['choices']) > 0:
                                    content = data['choices'][0]['message']['content']

                                    # Extract usage information if available
                                    usage = data.get('usage', {})

                                    # Create LLMResponse with real AI content
                                    response = LLMResponse(content, provider='openrouter', model=self.model)

                                    # Mark as real AI response from API
                                    response.is_real_ai = True
                                    response.usage = usage
                                    response.response_id = data.get('id')
                                    response.model_used = data.get('model', self.model)

                                    logger.info(f"Real OpenRouter API response received: {len(content)} chars")
                                    return response
                                else:
                                    logger.error("No content in OpenRouter response")
                                    return None
                            else:
                                error_text = await response.text()
                                logger.warning(f"OpenRouter API error {response.status} (attempt {attempt + 1}): {error_text}")
                                if attempt == max_retries:
                                    logger.error(f"OpenRouter API failed after {max_retries + 1} attempts")
                                    return None
                                await asyncio.sleep(retry_delay * (attempt + 1))
                                continue

                except asyncio.TimeoutError:
                    logger.warning(f"OpenRouter API timeout (attempt {attempt + 1})")
                    if attempt == max_retries:
                        logger.error(f"OpenRouter API timed out after {max_retries + 1} attempts")
                        return None
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue
                except aiohttp.ClientError as e:
                    logger.warning(f"OpenRouter client error (attempt {attempt + 1}): {str(e)}")
                    if attempt == max_retries:
                        logger.error(f"OpenRouter client error after {max_retries + 1} attempts: {str(e)}")
                        return None
                    await asyncio.sleep(retry_delay * (attempt + 1))
                    continue

                break  # Success, exit retry loop

        except Exception as e:
            logger.error(f"Unexpected error in OpenRouter provider: {str(e)}")
            return None

    def _get_system_prompt(self, scenario_type: str) -> str:
        """Get system prompt based on scenario type."""
        base_prompt = """You are ThreatSimGPT, an AI assistant specialized in generating realistic threat scenario samples for cybersecurity training and agent development.

Your role is to create actual threat scenario content that demonstrates how real attacks work, which will be used to:
1. Train security professionals to recognize threats
2. Develop AI agents to detect and respond to attacks
3. Build comprehensive threat intelligence databases
4. Test security awareness and response capabilities

IMPORTANT GUIDELINES:
- Generate realistic, actionable threat content that could actually be used in attacks
- Create actual samples (emails, scripts, plans, messages) rather than just descriptions
- Use believable but fictional data (fake companies, emails, URLs with example.com domains)
- Make content specific to target profiles and scenarios
- Include psychological triggers, social engineering tactics, and attack methodologies
- Focus on creating diverse variations to train robust detection systems
- All content is for defensive training purposes and authorized security research only"""

        scenario_prompts = {
            'threat_simulation_reconnaissance': base_prompt + """

For reconnaissance scenarios, generate:
- Actual OSINT research examples with specific data gathering techniques
- Real-world information sources and target profiling methods
- Sample data that would be collected about targets
- Specific tools, techniques, and procedures used in reconnaissance""",

            'threat_simulation_delivery': base_prompt + """

For delivery scenarios, generate:
- Actual phishing emails, SMS messages, or social engineering scripts
- Realistic attack vectors with specific implementation details
- Authentic-looking lures and communication samples
- Concrete delivery mechanisms and timing strategies""",

            'threat_simulation_exploitation': base_prompt + """

For exploitation scenarios, generate:
- Specific exploitation techniques and payload samples
- Actual attack chains and execution methods
- Real-world persistence and evasion techniques
- Concrete post-exploitation activities and objectives""",

            'threat_simulation_persistence': base_prompt + """

For persistence scenarios, focus on:
- Persistence mechanism detection methods
- System monitoring and anomaly detection
- Threat hunting techniques and indicators
- Recovery and remediation procedures"""
        }

        return scenario_prompts.get(scenario_type, base_prompt)

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the current model."""
        return {
            'provider': 'openrouter',
            'model': self.model,
            'base_url': self.base_url,
            'available': self.is_available(),
            'recommended_models': self.recommended_models
        }

    def list_available_models(self) -> List[str]:
        """List recommended models available through OpenRouter."""
        return list(self.recommended_models.keys())

    async def test_connection(self) -> bool:
        """Test connection to OpenRouter API."""
        if not self.is_available():
            return False

        try:
            test_response = await self.generate_content(
                prompt="Test connection. Please respond with 'Connection successful.'",
                scenario_type="general",
                max_tokens=50,
                temperature=0.1
            )

            return test_response is not None and "successful" in test_response.content.lower()

        except Exception as e:
            logger.error(f"OpenRouter connection test failed: {str(e)}")
            return False
