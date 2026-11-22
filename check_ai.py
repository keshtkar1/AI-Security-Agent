
import os

from dotenv import load_dotenv
from app.services.ai import ai_service


# Load environment variables
load_dotenv()


def get_required_env(name):

    value = os.getenv(name)

    if not value:
        raise ValueError(
            f"Environment variable {name} is not configured"
        )

    return value.strip()


def main():

    try:

        prompt = get_required_env("AI_TEST_PROMPT")

        print("[INFO] Connecting to AvalAI...")

        result = ai_service.analyze(prompt)

        print("\n[SUCCESS] AI connection is working")
        print("AI Response:")
        print(result)

    except Exception as error:

        print("\n[ERROR] AI connection failed")
        print("Details:", str(error))


if __name__ == "__main__":
    main()
