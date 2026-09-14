"""Structured JSON logging with request correlation.

Every line carries `request_id` and, once a token is verified, `tenant_id` and
`actor_id` — so one login attempt can be followed across the app, and an audit
row can be tied back to the request that produced it.

The redaction processor runs on every event, so a credential cannot reach a log
line by someone forgetting to strip it.
"""

from __future__ import annotations

import logging
import sys
from collections.abc import MutableMapping
from contextvars import ContextVar
from typing import Any

import structlog

from app.core.redaction import redact_processor

request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
tenant_id_ctx: ContextVar[str | None] = ContextVar("tenant_id", default=None)
actor_id_ctx: ContextVar[str | None] = ContextVar("actor_id", default=None)


def _inject_context(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    # structlog types processors against MutableMapping, not dict. Parameters are
    # contravariant, so annotating dict here makes the list of processors fail to
    # type-check even though it works at runtime.
    if rid := request_id_ctx.get():
        event_dict["request_id"] = rid
    if tid := tenant_id_ctx.get():
        event_dict["tenant_id"] = tid
    if aid := actor_id_ctx.get():
        event_dict["actor_id"] = aid
    return event_dict


def configure_logging(level: str = "INFO", json_output: bool = True) -> None:
    logging.basicConfig(format="%(message)s", stream=sys.stdout, level=level.upper())
    renderer: Any = (
        structlog.processors.JSONRenderer()
        if json_output
        else structlog.dev.ConsoleRenderer(colors=True)
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            _inject_context,
            # Redaction goes LAST before rendering, so it also covers fields
            # added by the processors above.
            redact_processor,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.getLevelName(level.upper())),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> Any:
    return structlog.get_logger(name)


def clear_request_context() -> None:
    request_id_ctx.set(None)
    tenant_id_ctx.set(None)
    actor_id_ctx.set(None)
