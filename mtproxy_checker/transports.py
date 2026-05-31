from __future__ import annotations

import socket
import struct

from .errors import ProtocolError
from .faketls import (
    FAKETLS_APP_DATA_PREFIX,
    FAKETLS_CCS,
    FAKETLS_MAX_APP_DATA,
    log_faketls_client_hello,
    make_faketls_client_hello,
    validate_faketls_server_response,
)
from .logging import get_logger
from .parser import FAKETLS_DEFAULT_DOMAIN

logger = get_logger(__name__)


def recv_exact(sock: socket.socket, n: int) -> bytes:
    out = bytearray()

    while len(out) < n:
        chunk = sock.recv(n - len(out))

        if not chunk:
            raise ProtocolError(
                f"connection closed while reading {n} bytes, got {len(out)}"
            )

        out += chunk

    return bytes(out)


class PlainTransport:
    def __init__(self, sock: socket.socket):
        self.sock = sock

    def write(self, data: bytes) -> None:
        self.sock.sendall(data)

    def read_exact(self, n: int) -> bytes:
        return recv_exact(self.sock, n)


class FakeTlsTransport:
    def __init__(self, sock: socket.socket, secret: bytes, domain: str):
        self.sock = sock
        self.secret = secret
        self.domain = domain or FAKETLS_DEFAULT_DOMAIN
        self.read_buffer = bytearray()
        self.did_first_write = False

    def handshake(self) -> None:
        client_hello, client_random = make_faketls_client_hello(
            self.secret,
            self.domain,
        )
        log_faketls_client_hello(self.domain, len(client_hello))
        self.sock.sendall(client_hello)

        first_header = self._read_plain(5)
        record_type, payload_len = self._parse_tls_header(first_header)

        if record_type != 0x16:
            raise ProtocolError(
                f"expected FakeTLS ServerHello, got record 0x{record_type:02x}"
            )

        first_payload = self._read_plain(payload_len)
        ccs = self._read_plain(len(FAKETLS_CCS))

        if ccs != FAKETLS_CCS:
            raise ProtocolError("bad FakeTLS server dummy ChangeCipherSpec")

        app_header = self._read_plain(5)
        app_record_type, app_payload_len = self._parse_tls_header(app_header)

        if app_record_type != 0x17:
            raise ProtocolError(
                "expected FakeTLS server application data, "
                f"got record 0x{app_record_type:02x}"
            )

        app_payload = self._read_plain(app_payload_len)
        response = first_header + first_payload + ccs + app_header + app_payload
        validate_faketls_server_response(self.secret, client_random, response)
        logger.debug(
            "faketls server response validated",
            extra={
                "event": "faketls_server_response_validated",
                "serverhello_len": len(first_header) + len(first_payload),
                "appdata_len": app_payload_len,
            },
        )

    def write(self, data: bytes) -> None:
        out = bytearray()

        if not self.did_first_write:
            out += FAKETLS_CCS
            self.did_first_write = True

        for offset in range(0, len(data), FAKETLS_MAX_APP_DATA):
            chunk = data[offset : offset + FAKETLS_MAX_APP_DATA]
            out += FAKETLS_APP_DATA_PREFIX
            out += struct.pack(">H", len(chunk))
            out += chunk
            logger.debug(
                "faketls appdata record written",
                extra={
                    "event": "faketls_appdata_record_written",
                    "appdata_len": len(chunk),
                },
            )

        self.sock.sendall(bytes(out))

    def read_exact(self, n: int) -> bytes:
        while len(self.read_buffer) < n:
            header = self._read_plain(5)
            record_type, payload_len = self._parse_tls_header(header)
            payload = self._read_plain(payload_len)

            if record_type == 0x14 and payload == b"\x01":
                continue

            if record_type != 0x17:
                raise ProtocolError(
                    f"expected FakeTLS application data, got record 0x{record_type:02x}"
                )

            logger.debug(
                "faketls appdata record read",
                extra={
                    "event": "faketls_appdata_record_read",
                    "appdata_len": payload_len,
                },
            )
            self.read_buffer += payload

        out = bytes(self.read_buffer[:n])
        del self.read_buffer[:n]
        return out

    def _read_plain(self, n: int) -> bytes:
        return recv_exact(self.sock, n)

    @staticmethod
    def _parse_tls_header(header: bytes) -> tuple[int, int]:
        if len(header) != 5:
            raise ProtocolError(f"short FakeTLS record header: {len(header)} bytes")

        record_type = header[0]
        version = header[1:3]

        if version not in (b"\x03\x01", b"\x03\x03"):
            raise ProtocolError(f"unexpected FakeTLS record version: {version.hex()}")

        return record_type, struct.unpack(">H", header[3:5])[0]
