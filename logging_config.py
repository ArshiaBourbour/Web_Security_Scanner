import logging
import sys

_CONFIGURED = False


def configure_logging(level: int = logging.WARNING) -> None:
    """Configure the root '4eyez' logger once. Safe to call multiple times."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    logger = logging.getLogger("4eyez")
    logger.setLevel(level)

    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(name)s: %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False

    _CONFIGURED = True


def get_logger(name: str) -> logging.Logger:
    """Return a namespaced logger under the '4eyez' hierarchy."""
    configure_logging()
    return logging.getLogger(f"4eyez.{name}")
