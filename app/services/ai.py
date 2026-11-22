
import os

from urllib.parse import urlparse

from openai import OpenAI
from dotenv import load_dotenv


# =================================
# Load Environment Variables
# =================================
load_dotenv()


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
            get_required_env("AVALAI_TIMEOUT")
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

        # Initialize OpenAI-compatible client
        self.client = OpenAI(
            api_key=self.api_key,
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=2
        )

    # =================================
    # AI Analysis
    # =================================
    def analyze(self, prompt: str) -> str:

        if not isinstance(prompt, str) or not prompt.strip():
            raise ValueError("AI prompt cannot be empty")

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
