
import os
import logging
import time

from urllib.parse import urlparse

from openai import OpenAI
from dotenv import load_dotenv


# =================================
# Load Environment Variables
# =================================
load_dotenv()

logger = logging.getLogger(__name__)


def get_required_env(name):

    value = os.getenv(name)

    if not value or not value.strip():
        raise ValueError(
            f"Environment variable {name} is not configured"
        )

    return value.strip()


# =================================
# AI Service
# =================================
class AIService:

    def __init__(self):

        self.base_url = get_required_env("AVALAI_BASE_URL")
        self.api_key = get_required_env("AVALAI_API_KEY")
        self.model = get_required_env("AVALAI_MODEL")

        self.temperature = float(
            get_required_env("AVALAI_TEMPERATURE")
        )

        self.timeout = int(
            os.getenv("AVALAI_TIMEOUT", "180").strip()
        )
        self.max_retries = int(
            os.getenv("AVALAI_MAX_RETRIES", "1").strip()
        )

        self.system_prompt = get_required_env(
            "AVALAI_SYSTEM_PROMPT"
        )

        # Validate API URL
        parsed_url = urlparse(self.base_url)

        if (
            parsed_url.scheme not in ("http", "https")
            or not parsed_url.hostname
        ):
            raise ValueError("Invalid AVALAI_BASE_URL")

        # Validate temperature
        if not 0 <= self.temperature <= 2:
            raise ValueError(
                "AVALAI_TEMPERATURE must be between 0 and 2"
            )

        # Validate timeout
        if self.timeout <= 0:
            raise ValueError(
                "AVALAI_TIMEOUT must be greater than zero"
            )

        if self.max_retries < 0 or self.max_retries > 5:
            raise ValueError(
                "AVALAI_MAX_RETRIES must be between 0 and 5"
            )

        # Initialize OpenAI-compatible client. Keep retries limited because
        # a timeout on a large prompt should not trigger several long waits.
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=self.max_retries
        )

    # =================================
    # AI Analysis
    # =================================
    def analyze(self, prompt: str) -> str:

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("AI prompt cannot be empty")

        started_at = time.monotonic()
        prompt_chars = len(prompt)

        logger.info(
            "AvalAI request started: model=%s prompt_chars=%s timeout=%ss retries=%s",
            self.model,
            prompt_chars,
            self.timeout,
            self.max_retries
        )

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": self.system_prompt
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=self.temperature
            )
        except Exception as error:
            elapsed = round(time.monotonic() - started_at, 2)
            logger.exception(
                "AvalAI request failed: model=%s prompt_chars=%s elapsed_seconds=%s error_type=%s",
                self.model,
                prompt_chars,
                elapsed,
                type(error).__name__
            )
            raise

        elapsed = round(time.monotonic() - started_at, 2)
        logger.info(
            "AvalAI request completed: model=%s prompt_chars=%s elapsed_seconds=%s",
            self.model,
            prompt_chars,
            elapsed
        )

        if not response.choices:
            raise RuntimeError(
                "AI service returned no response choices"
            )

        message = response.choices[0].message
        content = message.content

        if isinstance(content, list):
            content = "".join(
                item.text
                for item in content
                if getattr(item, "text", None)
            )

        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(
                "AI service returned an empty response"
            )

        return content.strip()


# =================================
# Service Initialization
# =================================
ai_service = AIService()
