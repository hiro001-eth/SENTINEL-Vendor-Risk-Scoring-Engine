"""
Vendor Risk Scoring Engine (SENTINEL)
Package initialization.
"""

VERSION = "1.0.0-PRODUCTION"

def get_version() -> str:
    return VERSION

def healthcheck() -> bool:
    """Basic healthcheck function for Docker."""
    return True

def configure_logging() -> None:
    """Configure structlog."""
    import structlog
    import logging
    
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso", utc=True),
            structlog.processors.JSONRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False
    )
