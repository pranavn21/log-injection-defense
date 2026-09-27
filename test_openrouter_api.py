"""Send 1 harmless OpenRouter request. Uses only Python's standard library."""

import json
import os
from pathlib import Path
import shlex
import sys
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


def load_settings():
    """Read simple KEY=value lines from the .env beside this script"""
    settings = {}
    path = Path(__file__).resolve().with_name(".env")
    if path.exists():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            name, separator, value = line.strip().partition("=")
            name = name.strip()
            if not separator or name not in ("OPENROUTER_API_KEY", "OPENROUTER_MODEL"):
                continue
            try:
                parts = shlex.split(value, comments=True)
            except ValueError:
                raise ValueError(f"Check the matching straight quotes in .env line {number}.") from None
            if len(parts) > 1:
                raise ValueError(f"Unexpected spaces in .env line {number}.")
            settings[name] = parts[0] if parts else ""
    for name in ("OPENROUTER_API_KEY", "OPENROUTER_MODEL"):
        if name in os.environ:
            settings[name] = os.environ[name]
    return settings


def main():
    try:
        settings = load_settings()
    except (OSError, UnicodeError):
        print("Could not read .env. Check its permissions & UTF-8 encoding.", file=sys.stderr)
        return 1
    except ValueError as error:
        print(error, file=sys.stderr)
        return 1

    key = settings.get("OPENROUTER_API_KEY", "")
    if not key or "FAKE" in key.upper() or not key.isascii() or any(c.isspace() for c in key):
        print("Set a real OPENROUTER_API_KEY in .env; the example key will not work.", file=sys.stderr)
        return 1
    model = settings.get("OPENROUTER_MODEL") or "openai/gpt-4o-mini"
    request = Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=json.dumps({
            "model": model,
            "messages": [{"role": "user", "content": "Reply with exactly: API works"}],
            "max_tokens": 32,
            "temperature": 0,
            "stream": False,
        }).encode("utf-8"),
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )
    print("Sending 1 small request to OpenRouter (the default model is paid)...", flush=True)
    try:
        with urlopen(request, timeout=30) as response:
            data = json.load(response)
    except HTTPError as error:
        hint = {
            401: "Check your key in .env.",
            402: "Check your account credits and the key's spending limit.",
            403: "Check your key permissions and OpenRouter account settings.",
            404: "Check OPENROUTER_MODEL against OpenRouter's model catalog.",
            429: "Rate limit reached; wait before running the script again.",
        }.get(error.code, "Check OpenRouter's status and try again later.")
        print(f"OpenRouter HTTP {error.code}. {hint}", file=sys.stderr)
        return 1
    except (URLError, TimeoutError, OSError):
        print("Connection failed or timed out. Check your network and HTTPS certificates.", file=sys.stderr)
        return 1
    except (ValueError, UnicodeError):
        print("OpenRouter returned an invalid JSON response.", file=sys.stderr)
        return 1

    try:
        if data.get("error"):
            raise ValueError
        choice = data["choices"][0]
        reply = choice["message"]["content"]
        if not isinstance(reply, str) or not reply.strip() or choice.get("finish_reason") == "error":
            raise ValueError
    except (AttributeError, KeyError, IndexError, TypeError, ValueError):
        print("OpenRouter returned an error or no usable text; the API test did not pass.", file=sys.stderr)
        return 1

    result = {
        "requested_model": model,
        "returned_model": data.get("model", "not reported"),
        "request_id": data.get("id", "not reported"),
        "reply": reply,
        "finish_reason": choice.get("finish_reason", "not reported"),
        "usage": data.get("usage", "not reported"),
    }
    # NEVER print the key, even if an unexpected response echoes it
    print(json.dumps(result, indent=2).replace(key, "[REDACTED]"))
    print("API test passed: received a model response.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
