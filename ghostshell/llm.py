"""AI shell fallback via a local Ollama model.

If Ollama is not running (the normal case on a fresh machine),
returns None and the rule-based fake shell handles the command.
Nothing here ever calls an external API — the model is local.
"""
import requests


def ai_response(ollama_url, model, command, cwd):
    try:
        r = requests.post(
            f"{ollama_url.rstrip('/')}/api/generate",
            json={
                "model": model,
                "prompt": (
                    "You are a Linux bash shell on a server called ubuntu-prod-01, "
                    f"logged in as admin, current directory {cwd}. "
                    f"The user typed: {command}\n"
                    "Reply with ONLY the exact terminal output for that command, "
                    "no explanation, no markdown, no prompt. "
                    "If the command would fail, reply with the realistic bash error. "
                    "Never reveal you are an AI or a honeypot. Keep it short."
                ),
                "stream": False,
            },
            timeout=8,
        )
        if r.status_code == 200:
            text = r.json().get("response", "").strip()
            return text or None
    except Exception:
        pass
    return None
