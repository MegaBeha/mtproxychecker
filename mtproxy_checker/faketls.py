from __future__ import annotations

import hashlib
import hmac
import os
import struct
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from .errors import ProtocolError
from .logging import get_logger
from .parser import FAKETLS_DEFAULT_DOMAIN

FAKETLS_CLIENT_HELLO_LEN = 517
FAKETLS_MAX_APP_DATA = 1425
FAKETLS_CCS = b"\x14\x03\x03\x00\x01\x01"
FAKETLS_APP_DATA_PREFIX = b"\x17\x03\x03"

logger = get_logger(__name__)


def generate_x25519_public_key() -> bytes:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def make_grease_values() -> list[int]:
    greases = [(value & 0xF0) + 0x0A for value in os.urandom(7)]

    for i in range(1, len(greases), 2):
        if greases[i] == greases[i - 1]:
            greases[i] = 0x10 ^ greases[i]

    return greases


def add_grease(out: bytearray, greases: list[int], index: int) -> None:
    value = greases[index]
    out += bytes([value, value])


def add_u16(out: bytearray, value: int) -> None:
    out += struct.pack(">H", value)


def make_faketls_client_hello(
    secret: bytes,
    domain: str,
    timestamp: int | None = None,
) -> tuple[bytes, bytes]:
    if len(secret) != 16:
        raise ProtocolError(f"FakeTLS secret must be 16 bytes, got {len(secret)}")

    domain_ascii = domain.encode("ascii", "ignore").decode("ascii")
    domain_ascii = domain_ascii or FAKETLS_DEFAULT_DOMAIN
    domain_bytes = domain_ascii.encode("ascii")
    greases = make_grease_values()
    out = bytearray()

    out += b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
    random_offset = len(out)
    out += b"\x00" * 32
    out += b"\x20"
    out += os.urandom(32)
    out += b"\x00\x22"
    add_grease(out, greases, 0)
    out += (
        b"\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30"
        b"\xcc\xa9\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f"
        b"\x00\x35\x00\x0a\x01\x00\x01\x91"
    )
    add_grease(out, greases, 2)
    out += b"\x00\x00\x00\x00"
    add_u16(out, len(domain_bytes) + 5)
    add_u16(out, len(domain_bytes) + 3)
    out += b"\x00"
    add_u16(out, len(domain_bytes))
    out += domain_bytes
    out += b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08"
    add_grease(out, greases, 4)
    out += (
        b"\x00\x1d\x00\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00"
        b"\x00\x10\x00\x0e\x00\x0c\x02\x68\x32\x08\x68\x74\x74\x70\x2f\x31"
        b"\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00\x00\x0d\x00\x14\x00"
        b"\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06\x06"
        b"\x01\x02\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29"
    )
    add_grease(out, greases, 4)
    out += b"\x00\x01\x00\x00\x1d\x00\x20"
    out += generate_x25519_public_key()
    out += b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a"
    add_grease(out, greases, 6)
    out += b"\x03\x04\x03\x03\x03\x02\x03\x01\x00\x1b\x00\x03\x02\x00\x02"
    add_grease(out, greases, 3)
    out += b"\x00\x01\x00\x00\x15"

    padding_length = FAKETLS_CLIENT_HELLO_LEN - 2 - len(out)

    if padding_length < 0:
        raise ProtocolError("FakeTLS ClientHello is too long for the fixed profile")

    add_u16(out, padding_length)
    out += b"\x00" * padding_length

    if len(out) != FAKETLS_CLIENT_HELLO_LEN:  # pragma: no cover
        raise ProtocolError(f"bad FakeTLS ClientHello length: {len(out)}")

    digest = hmac.new(secret, bytes(out), hashlib.sha256).digest()

    if timestamp is None:
        timestamp = int(time.time())

    digest_tail = struct.unpack("<I", digest[28:32])[0]
    client_random = digest[:28] + struct.pack("<I", digest_tail ^ timestamp)
    out[random_offset : random_offset + 32] = client_random

    return bytes(out), client_random


def validate_faketls_server_response(
    secret: bytes,
    client_random: bytes,
    response: bytes,
) -> None:
    if len(response) < 43:
        raise ProtocolError("short FakeTLS server response")

    server_random = response[11:43]
    zeroed = bytearray(response)
    zeroed[11:43] = b"\x00" * 32
    expected = hmac.new(secret, client_random + bytes(zeroed), hashlib.sha256).digest()

    if not hmac.compare_digest(server_random, expected):
        raise ProtocolError("FakeTLS server random HMAC mismatch")


def log_faketls_client_hello(domain: str, length: int) -> None:
    logger.debug(
        "faketls client hello created",
        extra={
            "event": "faketls_client_hello_created",
            "domain": domain,
            "clienthello_len": length,
        },
    )
