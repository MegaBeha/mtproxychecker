from __future__ import annotations

from .models import ERROR_MESSAGES, ErrorCode


class MTProxyCheckerError(Exception):
    code: ErrorCode = ErrorCode.INTERNAL_ERROR

    def __init__(self, detail: str | None = None):
        self.detail = detail
        super().__init__(detail or ERROR_MESSAGES[self.code])


class InvalidInputError(MTProxyCheckerError):
    code = ErrorCode.INVALID_INPUT


class InvalidSecretError(MTProxyCheckerError):
    code = ErrorCode.INVALID_SECRET


class UnsupportedModeError(MTProxyCheckerError):
    code = ErrorCode.UNSUPPORTED_MODE


class ProtocolError(MTProxyCheckerError):
    code = ErrorCode.PROTOCOL_ERROR


class NetworkCheckError(MTProxyCheckerError):
    def __init__(self, code: ErrorCode, detail: str | None = None):
        self.code = code
        super().__init__(detail)


def public_message(code: ErrorCode) -> str:
    return ERROR_MESSAGES[code]


def classify_exception(exc: BaseException) -> tuple[ErrorCode, str, str]:
    if isinstance(exc, MTProxyCheckerError):
        return exc.code, public_message(exc.code), str(exc)

    if isinstance(exc, TimeoutError):
        return (
            ErrorCode.RESPONSE_TIMEOUT,
            public_message(ErrorCode.RESPONSE_TIMEOUT),
            str(exc) or "timed out",
        )

    if isinstance(exc, OSError):
        return (
            ErrorCode.NETWORK_ERROR,
            public_message(ErrorCode.NETWORK_ERROR),
            str(exc),
        )

    return ErrorCode.INTERNAL_ERROR, public_message(ErrorCode.INTERNAL_ERROR), str(exc)
