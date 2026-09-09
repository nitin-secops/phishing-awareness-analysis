"""
config.py
---------
A minimal, dependency-free .env file loader.

Popular libraries like `python-dotenv` do this same job with more
features, but writing a small version ourselves is a good way to
actually understand what "loading environment variables from a file"
means, instead of treating it as magic.

The .env file is never committed to Git (see .gitignore) - it only
exists on your local machine, so your API key never becomes public.
"""

import os

ENV_FILE_PATH = os.path.join(os.path.dirname(__file__), ".env")


def load_env_file(path: str = ENV_FILE_PATH) -> None:
    """
    Read KEY=VALUE pairs from a .env file and load them into
    os.environ, so the rest of the program can access them with
    os.getenv("KEY") just like a real environment variable.

    Lines starting with '#' are treated as comments and skipped.
    """
    if not os.path.exists(path):
        return  # No .env file - that's fine, we'll just run in offline mode

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ[key.strip()] = value.strip()


def get_virustotal_api_key() -> str:
    """
    Return the VirusTotal API key from the environment, or an empty
    string if it isn't set. Callers should treat an empty string as
    "no key available - run in offline mode".
    """
    load_env_file()
    return os.getenv("VT_API_KEY", "").strip()
