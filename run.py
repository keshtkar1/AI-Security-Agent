
import os

from dotenv import load_dotenv
import uvicorn


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
# Application Server Configuration
# =================================
APP_HOST = get_required_env("APP_HOST")
APP_PORT = int(get_required_env("APP_PORT"))


# =================================
# Configuration Validation
# =================================
def validate_configuration():

    if not 1 <= APP_PORT <= 65535:
        raise ValueError(
            "APP_PORT must be between 1 and 65535"
        )

    if any(char.isspace() for char in APP_HOST):
        raise ValueError("Invalid APP_HOST")

    if "/" in APP_HOST or "\\" in APP_HOST:
        raise ValueError("Invalid APP_HOST")


# =================================
# Start Application
# =================================
def main():

    validate_configuration()

    print("=================================")
    print("AI Security Agent")
    print("=================================")
    print(f"Host: {APP_HOST}")
    print(f"Port: {APP_PORT}")
    print(f"URL: http://{APP_HOST}:{APP_PORT}")
    print("=================================")

    uvicorn.run(
        "app.main:app",
        host=APP_HOST,
        port=APP_PORT,
        reload=False
    )


if __name__ == "__main__":
    main()
