from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Mode(str, Enum):
    SECURE = "secure"
    ABRIDGED = "abridged"
    INTERMEDIATE = "intermediate"
    FAKETLS = "faketls"


class SecretKind(str, Enum):
    RAW = "raw"
    DD_SECURE = "dd-secure"
    FAKETLS = "faketls"
    EXTENDED_RAW = "extended-raw"


class ErrorCode(str, Enum):
    INVALID_INPUT = "INVALID_INPUT"
    INVALID_SECRET = "INVALID_SECRET"
    UNSUPPORTED_MODE = "UNSUPPORTED_MODE"
    CONNECT_TIMEOUT = "CONNECT_TIMEOUT"
    RESPONSE_TIMEOUT = "RESPONSE_TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"


ERROR_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INVALID_INPUT: (
        "Invalid proxy input. Provide a Telegram MTProxy URL or host, port, and secret."
    ),
    ErrorCode.INVALID_SECRET: "Invalid MTProxy secret.",
    ErrorCode.UNSUPPORTED_MODE: (
        "The requested mode is not compatible with this secret."
    ),
    ErrorCode.CONNECT_TIMEOUT: "Connection timed out.",
    ErrorCode.RESPONSE_TIMEOUT: (
        "Proxy did not return a valid Telegram response in time."
    ),
    ErrorCode.NETWORK_ERROR: "Network error while checking proxy.",
    ErrorCode.PROTOCOL_ERROR: (
        "Proxy response did not match the expected MTProxy protocol."
    ),
    ErrorCode.INTERNAL_ERROR: "Unexpected checker error.",
}


@dataclass(frozen=True)
class ParsedSecret:
    raw_secret: bytes
    display: str
    is_faketls: bool = False
    faketls_domain: str = ""
    kind: SecretKind = SecretKind.RAW


@dataclass(frozen=True)
class ProxyTarget:
    host: str
    port: int
    secret: ParsedSecret


@dataclass(frozen=True)
class CheckOptions:
    mode: Mode | str = "auto"
    dc: int | None = None
    dcs: tuple[int, ...] | None = None
    exhaustive: bool = False
    connect_timeout: float = 2.0
    response_timeout: float = 2.0


@dataclass(frozen=True)
class AttemptResult:
    dc: int
    mode: Mode
    ok: bool = False
    rtt_ms: float | None = None
    server_nonce: str | None = None
    error_code: ErrorCode | None = None
    error_message: str | None = None
    detail: str | None = None


@dataclass(frozen=True)
class CheckResult:
    ok: bool
    target: ProxyTarget | None = None
    mode: Mode | None = None
    dc: int | None = None
    rtt_ms: float | None = None
    server_nonce: str | None = None
    attempts: tuple[AttemptResult, ...] = field(default_factory=tuple)
    error_code: ErrorCode | None = None
    error_message: str | None = None
