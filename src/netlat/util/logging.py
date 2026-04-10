"""Structured logging configuration for netlat."""

from __future__ import annotations

import logging
import os
import sys

import structlog


def configure_logging() -> structlog.BoundLogger:
    """Configure structlog with JSON or human-readable output.

    Uses environment variables:
        NETLAT_LOG_FORMAT: "json" for JSON output, anything else for console.
        NETLAT_LOG_LEVEL: Standard Python log level name (default: INFO).

    Returns:
        Configured structlog bound logger.
    """
    log_format = os.environ.get("NETLAT_LOG_FORMAT", "console").lower()
    log_level_name = os.environ.get("NETLAT_LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.dev.set_exc_info,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if log_format == "json":
        renderer: structlog.types.Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )

    return structlog.get_logger()


def get_logger(name: str | None = None) -> structlog.BoundLogger:
    """Get a named logger instance."""
    logger: structlog.BoundLogger = structlog.get_logger()
    if name:
        logger = logger.bind(component=name)
    return logger
