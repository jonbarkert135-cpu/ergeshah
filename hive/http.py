"""Blocking JSON HTTP over ``urllib`` — no third-party HTTP client.

Only what an LLM API needs: POST/GET JSON, honest error surfacing, ``Retry-After`` support.
Retry policy lives in the provider layer; this module just reports what happened.
"""

from __future__ import annotations

import json
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass


@dataclass
class HttpResult:
    status: int
    body: dict | list | None
    text: str
    headers: dict[str, str]

    def retry_after(self) -> float | None:
        raw = self.headers.get("retry-after") or self.headers.get("Retry-After")
        if not raw:
            return None
        try:
            return float(raw)
        except ValueError:
            return None


class HttpFailure(Exception):
    """Transport-level failure (DNS, TLS, timeout, connection reset)."""


def request_json(
    url: str,
    *,
    method: str = "POST",
    payload: dict | None = None,
    headers: dict[str, str] | None = None,
    timeout: int = 300,
) -> HttpResult:
    data = None
    hdrs = {"content-type": "application/json", "accept": "application/json"}
    hdrs.update({k.lower(): v for k, v in (headers or {}).items()})
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed API hosts
            raw = resp.read().decode("utf-8", "replace")
            return HttpResult(resp.status, _maybe_json(raw), raw, dict(resp.headers))
    except urllib.error.HTTPError as exc:  # 4xx / 5xx still carry a useful body
        raw = exc.read().decode("utf-8", "replace") if exc.fp else ""
        return HttpResult(exc.code, _maybe_json(raw), raw, dict(exc.headers or {}))
    except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
        raise HttpFailure(f"{type(exc).__name__}: {exc}") from exc


def _maybe_json(raw: str) -> dict | list | None:
    try:
        return json.loads(raw)
    except Exception:
        return None


def post_text(url: str, text_payload: dict, timeout: int = 20) -> int:
    """Fire-and-forget JSON POST used for notifications (Slack webhooks)."""
    try:
        result = request_json(url, payload=text_payload, timeout=timeout)
        return result.status
    except HttpFailure:
        return 0
