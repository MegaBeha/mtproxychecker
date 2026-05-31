import logging as py_logging

from .checker import check_proxy
from .logging import LOGGER_NAME
from .models import (
    AttemptResult,
    CheckOptions,
    CheckResult,
    ErrorCode,
    Mode,
    ParsedSecret,
    ProxyTarget,
    SecretKind,
)
from .parser import decode_secret, parse_proxy_url

_logger = py_logging.getLogger(LOGGER_NAME)
_logger.addHandler(py_logging.NullHandler())
_logger.propagate = False

__all__ = [
    "AttemptResult",
    "CheckOptions",
    "CheckResult",
    "ErrorCode",
    "Mode",
    "ParsedSecret",
    "ProxyTarget",
    "SecretKind",
    "check_proxy",
    "decode_secret",
    "parse_proxy_url",
]
