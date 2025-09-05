#!/usr/bin/env python3
"""
Call an AI Suggestion service endpoint that supports multiple AI providers
(OpenAI or Gemini).

Example:
  python3 ai_suggestion.py 52 https://alerts.thakurprince.com yourapisecret \
      --engine gemini --model gemini-2.0-flash --timeout 60 --retries 3 --log-level INFO
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


DEFAULT_MODELS: Dict[str, str] = {
    "openai": "gpt-4.1-nano",
    "gemini": "gemini-2.0-flash",
}

STATUS_RETRY: tuple[int, ...] = (429, 500, 502, 503, 504)


@dataclass(frozen=True)
class Config:
    build_number: int
    base_url: str
    api_secret: str
    engine: str
    model: str
    timeout: int
    retries: int
    backoff: float
    verify_tls: bool
    log_level: str
    json_only: bool
    send_as_string: bool


def _mask_secret(s: str) -> str:
    if not s:
        return ""
    if len(s) <= 6:
        return "*" * len(s)
    return f"{s[:3]}***{s[-3:]}"


def normalize_and_validate_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid base URL (scheme/host required): {base_url!r}")
    return base_url.rstrip("/")


def resolve_model(engine: str, model: Optional[str]) -> str:
    engine_l = engine.lower()
    if engine_l not in DEFAULT_MODELS:
        raise ValueError(f"Unsupported engine {engine!r}. Choose from: {', '.join(DEFAULT_MODELS)}")
    return model or DEFAULT_MODELS[engine_l]


def build_payload(build_number: int, engine: str, model: str, send_as_string: bool = False) -> Dict[str, Any]:
    if send_as_string:
        # Send as "build-52" string format to match database tag column
        build_id = f"build-{build_number}"
    else:
        # Send as integer - server should handle the tag formatting
        build_id = build_number

    return {
        "build_id": build_id,
        "ai_engine": engine.lower(),
        "model": model,
    }


def create_session(retries: int, backoff: float) -> requests.Session:
    """Create a requests Session with retry logic for transient errors."""
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        status=retries,
        backoff_factor=backoff,
        status_forcelist=STATUS_RETRY,
        allowed_methods=frozenset({"POST"}),
        raise_on_status=False,
        respect_retry_after_header=True,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def call_api(
    session: requests.Session,
    base_url: str,
    api_secret: str,
    payload: Dict[str, Any],
    timeout: int,
    verify_tls: bool,
    logger: logging.Logger,
) -> Dict[str, Any] | str:
    endpoint = f"{base_url}/generate-ai-suggestion"
    headers = {
        "api-secret": api_secret,
        "Content-Type": "application/json",
        # handy for tracing in server logs
        "X-Request-Id": str(uuid.uuid4()),
    }

    logger.info("POST %s (engine=%s model=%s build_id=%s)",
                endpoint, payload.get("ai_engine"), payload.get("model"), payload.get("build_id"))
    logger.debug("Request headers: %s", {**headers, "api-secret": _mask_secret(api_secret)})
    logger.debug("Request payload: %s", payload)

    try:
        resp = session.post(endpoint, json=payload, headers=headers, timeout=timeout, verify=verify_tls)
    except requests.RequestException as e:
        logger.error("Request failed: %s", e)
        return {"error": str(e)}

    ct = (resp.headers.get("content-type") or "").lower()
    body: Dict[str, Any] | str

    # Prefer JSON when available (even on error)
    if "application/json" in ct:
        try:
            body = resp.json()
        except ValueError:
            body = {"error": "Invalid JSON in response", "raw": resp.text}
    else:
        body = resp.text

    if 200 <= resp.status_code < 300:
        logger.info("Success %s %s", resp.status_code, resp.reason)
        return body

    # surface more detail on non-2xx
    logger.warning("Non-success %s %s", resp.status_code, resp.reason)
    return {
        "error": f"{resp.status_code} {resp.reason}",
        "body": body,
    }


def parse_args() -> Config:
    p = argparse.ArgumentParser(description="Call /generate-ai-suggestion (OpenAI or Gemini).")
    p.add_argument("build_number", help="Build number to analyze (integer, will be formatted as needed).")
    p.add_argument("base_url", help="Service base URL, e.g. https://alerts.example.com")
    p.add_argument("api_secret", help="Value for 'api-secret' header")

    p.add_argument("-e", "--engine",
                   choices=sorted(DEFAULT_MODELS.keys()),
                   default=os.getenv("AI_ENGINE", "openai"),
                   help="AI provider (default: %(default)s)")
    p.add_argument("-m", "--model",
                   default=os.getenv("AI_MODEL"),
                   help="Model name (default depends on engine)")

    p.add_argument("--timeout", type=int, default=int(os.getenv("AI_TIMEOUT", "60")),
                   help="HTTP timeout seconds (default: %(default)s)")
    p.add_argument("--retries", type=int, default=int(os.getenv("AI_RETRIES", "3")),
                   help="Retry count for transient errors (default: %(default)s)")
    p.add_argument("--backoff", type=float, default=float(os.getenv("AI_BACKOFF", "0.5")),
                   help="Exponential backoff factor (default: %(default)s)")
    p.add_argument("--no-verify-tls", action="store_true",
                   help="Disable TLS certificate verification (NOT recommended in prod).")
    p.add_argument("--log-level",
                   choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"],
                   default=os.getenv("LOG_LEVEL", "INFO"),
                   help="Log verbosity (default: %(default)s)")
    p.add_argument("--json-only", action="store_true",
                   help="Print JSON only (no extra logs to stdout).")
    p.add_argument("--send-as-string", action="store_true",
                   help="Send build_id as 'build-{number}' string instead of integer.")

    args = p.parse_args()

    # Convert and validate types/values
    try:
        build_number = int(str(args.build_number))
    except ValueError:
        raise SystemExit("build_number must be an integer.")

    base_url = normalize_and_validate_url(args.base_url)
    engine = args.engine.lower()
    model = resolve_model(engine, args.model)

    return Config(
        build_number=build_number,
        base_url=base_url,
        api_secret=args.api_secret,
        engine=engine,
        model=model,
        timeout=args.timeout,
        retries=args.retries,
        backoff=args.backoff,
        verify_tls=not args.no_verify_tls,
        log_level=args.log_level,
        json_only=args.json_only,
        send_as_string=args.send_as_string,
    )


def setup_logging(level: str, json_only: bool) -> logging.Logger:
    logger = logging.getLogger("ai_suggestion")
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr if json_only else sys.stdout)
    fmt = "%(asctime)s | %(levelname)s | %(message)s"
    handler.setFormatter(logging.Formatter(fmt))
    logger.handlers[:] = [handler]
    return logger


def main() -> int:
    cfg = parse_args()
    logger = setup_logging(cfg.log_level, cfg.json_only)

    if cfg.json_only:
        # keep stdout clean for JSON; put logs on stderr
        for h in logger.handlers:
            h.stream = sys.stderr

    session = create_session(cfg.retries, cfg.backoff)
    payload = build_payload(cfg.build_number, cfg.engine, cfg.model, cfg.send_as_string)

    result = call_api(
        session=session,
        base_url=cfg.base_url,
        api_secret=cfg.api_secret,
        payload=payload,
        timeout=cfg.timeout,
        verify_tls=cfg.verify_tls,
        logger=logger,
    )

    # Print the final response to stdout (JSON if dict/list)
    if isinstance(result, (dict, list)):
        print(json.dumps(result, indent=2))
        # exit codes: 0 ok; 2 client error; 3 server or unknown error
        if isinstance(result, dict) and "error" in result:
            status_text = str(result["error"])
            try:
                status_code = int(status_text.split()[0])
            except Exception:
                return 3
            return 2 if 400 <= status_code < 500 else 3
        return 0
    else:
        # non-JSON body
        print(result)
        return 0

if __name__ == "__main__":
    sys.exit(main())
