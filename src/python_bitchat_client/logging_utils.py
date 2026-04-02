import logging
from typing import Final

LOGGER_NAME: Final[str] = "python_bitchat_client"


def get_logger() -> logging.Logger:
    return logging.getLogger(LOGGER_NAME)


def configure_logging(level: str | int = "INFO") -> logging.Logger:
    logger = get_logger()
    if isinstance(level, str):
        resolved_level = getattr(logging, level.upper(), logging.INFO)
    else:
        resolved_level = int(level)
    logger.setLevel(resolved_level)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("[%(name)s][%(levelname)s] %(message)s"))
        logger.addHandler(handler)
    return logger
