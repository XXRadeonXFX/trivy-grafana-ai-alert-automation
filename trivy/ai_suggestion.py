#!/usr/bin/env python3
import os
import json
import sys
import requests
from datetime import datetime

#-------- Generate AI Suggestion ------

def ai_suggestion(build_id, url, api_secret):
    """
    Calls AI Suggestion API with the given build_id, URL, and API secret.
    Returns: dict or str (API response)
    """
    headers = {
        "api-secret": api_secret,
        "Content-Type": "application/json"
    }

    payload = {
        "build_id": build_id,
        "model": "gpt-4.1-nano",
        "ai_engine": "openai"
    }

    print(f"Calling AI Suggestion API: {url} with payload: {payload}", flush=True)

    try:
        response = requests.post(url, json=payload, headers=headers, timeout=30)
        response.raise_for_status()
        return response.json() if response.headers.get("Content-Type", "").startswith("application/json") else response.text

    except requests.RequestException as e:
        print(f"AI Suggestion API call failed: {e}", file=sys.stderr, flush=True)
        return {"error": str(e)}

def main():
    """
    Entry point for CLI usage.
    Usage: python3 ai_suggestion.py <build_id> <ALERT_MANAGER_URL> <ALERT_MANAGER_SECRET>
    """
    if len(sys.argv) < 4:
        print("Usage: python3 ai_suggestion.py <build_id> <ALERT_MANAGER_URL> <ALERT_MANAGER_SECRET>")
        sys.exit(1)

    build_id = sys.argv[1]
    alert_manager_url = sys.argv[2].rstrip("/")
    alert_manager_secret = sys.argv[3]

    result = ai_suggestion(build_id, f"{alert_manager_url}/generate-ai-suggestion", alert_manager_secret)
    print("\nAI Suggestion API Response:")
    print(json.dumps(result, indent=4))

if __name__ == "__main__":
    main()
