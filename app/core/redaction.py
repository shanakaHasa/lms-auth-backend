"""Secret scrubbing for logs.

This service handles credentials, not student records, so the thing that must
never reach a log line is a password, a token, or a client secret. The scrubber
runs as a structlog processor, which means it applies to every log call rather
than depending on each caller remembering.
"""

from __future__ import annotations

import re
from collections.abc import MutableMapping
from typing import Any

# Keys whose value is replaced wholesale, matched case-insensitively and as a
# substring -- so `new_password`, `refresh_token` and `X-CSRF-Token` all hit.
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "cookie",
    "credential",
    "private_key",
    "code",
    "otp",
)

REDACTED = "[REDACTED]"
MAX_VALUE_CHARS = 2000

# Catches a credential that arrived inside a free-text string rather than as a
# structured field -- a bearer header echoed into an error message, say.
_BEARER = re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._\-+/=]{8,}")
_BASIC = re.compile(r"(?i)\b(basic)\s+[A-Za-z0-9+/=]{8,}")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")
_REFRESH = re.compile(r"\brt1_[A-Za-z0-9._-]{8,}")


def is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def scrub_text(value: str) -> str:
    value = _BEARER.sub(r"\1 " + REDACTED, value)
    value = _BASIC.sub(r"\1 " + REDACTED, value)
    value = _JWT.sub(REDACTED, value)
    value = _REFRESH.sub(REDACTED, value)
    return value[:MAX_VALUE_CHARS]


def scrub(value: Any, *, _depth: int = 0) -> Any:
    """Recursively redact a value. Depth-capped so a cyclic-ish structure
    cannot turn a log call into a hang."""
    if _depth > 6:
        return REDACTED
    if isinstance(value, str):
        return scrub_text(value)
    if isinstance(value, dict):
        return {
            k: REDACTED if is_sensitive_key(str(k)) else scrub(v, _depth=_depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, list | tuple):
        return [scrub(v, _depth=_depth + 1) for v in value]
    return value


def redact_processor(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """structlog processor. Applied to every event, so nothing depends on a
    caller remembering to redact."""
    return {k: REDACTED if is_sensitive_key(k) else scrub(v) for k, v in event_dict.items()}
