import hmac
import struct
import unittest
from hashlib import sha256
from unittest.mock import patch

from mtproxy_checker.errors import ProtocolError
from mtproxy_checker.faketls import (
    FAKETLS_APP_DATA_PREFIX,
    FAKETLS_CCS,
    FAKETLS_CLIENT_HELLO_LEN,
    log_faketls_client_hello,
    make_faketls_client_hello,
    make_grease_values,
    validate_faketls_server_response,
)
from mtproxy_checker.models import Mode
from mtproxy_checker.protocol import (
    frame_message,
    make_obfuscated2_handshake,
    parse_res_pq,
)
from mtproxy_checker.transports import FakeTlsTransport, PlainTransport, recv_exact


class FakeSocket:
    def __init__(self, incoming: bytes = b"", chunk_size: int | None = None):
        self.incoming = bytearray(incoming)
        self.sent = bytearray()
        self.chunk_size = chunk_size

    def recv(self, n: int) -> bytes:
        if not self.incoming:
            return b""

        if self.chunk_size is not None:
            n = min(n, self.chunk_size)

        out = bytes(self.incoming[:n])
        del self.incoming[:n]
        return out

    def sendall(self, data: bytes) -> None:
        self.sent += data


def make_valid_faketls_response(secret: bytes, client_random: bytes) -> bytes:
    response = bytearray(
        b"\x16\x03\x03\x00\x26" + b"\x00" * 38 + FAKETLS_CCS + b"\x17\x03\x03\x00\x01x"
    )
    zeroed = bytearray(response)
    zeroed[11:43] = b"\x00" * 32
    response[11:43] = hmac.new(secret, client_random + bytes(zeroed), sha256).digest()
    return bytes(response)


class FakeTlsTests(unittest.TestCase):
    def test_client_hello_hmac_random(self) -> None:
        secret = bytes.fromhex("c96b6d60154b353e16b514651c87f15b")
        hello, client_random = make_faketls_client_hello(
            secret,
            "googleapis.com",
            timestamp=123456,
        )

        self.assertEqual(len(hello), FAKETLS_CLIENT_HELLO_LEN)
        self.assertEqual(hello[11:43], client_random)

        zeroed = bytearray(hello)
        zeroed[11:43] = b"\x00" * 32
        digest = hmac.new(secret, bytes(zeroed), sha256).digest()
        expected_tail = struct.unpack("<I", digest[28:32])[0] ^ 123456

        self.assertEqual(client_random[:28], digest[:28])
        self.assertEqual(client_random[28:32], struct.pack("<I", expected_tail))

    def test_client_hello_rejects_bad_secret_length_and_uses_default_domain(
        self,
    ) -> None:
        with self.assertRaises(ProtocolError):
            make_faketls_client_hello(b"short", "example.com")

        hello, _random = make_faketls_client_hello(
            b"1" * 16,
            "тест",
            timestamp=1,
        )

        self.assertIn(b"www.google.com", hello)

    def test_client_hello_uses_current_time_and_rejects_too_long_profile(
        self,
    ) -> None:
        with patch("mtproxy_checker.faketls.time.time", return_value=123.0):
            hello, client_random = make_faketls_client_hello(b"1" * 16, "example.com")

        self.assertEqual(hello[11:43], client_random)

        with (
            patch("mtproxy_checker.faketls.FAKETLS_CLIENT_HELLO_LEN", 10),
            self.assertRaises(ProtocolError),
        ):
            make_faketls_client_hello(b"1" * 16, "example.com")

    def test_grease_values_avoid_adjacent_duplicates(self) -> None:
        with patch("mtproxy_checker.faketls.os.urandom", return_value=b"\x00" * 7):
            greases = make_grease_values()

        self.assertEqual(greases[0], 0x0A)
        self.assertEqual(greases[1], 0x1A)

    def test_validate_faketls_server_response(self) -> None:
        secret = b"1" * 16
        client_random = b"r" * 32
        response = make_valid_faketls_response(secret, client_random)

        validate_faketls_server_response(secret, client_random, response)

        with self.assertRaises(ProtocolError):
            validate_faketls_server_response(secret, client_random, b"short")

        with self.assertRaises(ProtocolError):
            validate_faketls_server_response(
                secret, client_random, response[:-1] + b"!"
            )

    def test_log_client_hello_helper(self) -> None:
        log_faketls_client_hello("example.com", 517)

    def test_first_write_prefixes_ccs_and_splits_records(self) -> None:
        fake_socket = FakeSocket()
        transport = FakeTlsTransport(fake_socket, b"1" * 16, "example.com")

        transport.write(b"a" * 1500)
        sent = bytes(fake_socket.sent)

        self.assertTrue(sent.startswith(FAKETLS_CCS))
        self.assertEqual(sent[6:9], FAKETLS_APP_DATA_PREFIX)
        self.assertEqual(struct.unpack(">H", sent[9:11])[0], 1425)
        second_header = 6 + 5 + 1425
        self.assertEqual(
            sent[second_header : second_header + 3],
            FAKETLS_APP_DATA_PREFIX,
        )
        self.assertEqual(
            struct.unpack(">H", sent[second_header + 3 : second_header + 5])[0],
            75,
        )

    def test_read_exact_across_appdata_records(self) -> None:
        incoming = b"\x17\x03\x03\x00\x02ab\x17\x03\x03\x00\x04cdef"
        transport = FakeTlsTransport(
            FakeSocket(incoming, chunk_size=2),
            b"1" * 16,
            "example.com",
        )

        self.assertEqual(transport.read_exact(5), b"abcde")
        self.assertEqual(transport.read_exact(1), b"f")

    def test_read_exact_skips_ccs_and_rejects_bad_record_type(self) -> None:
        transport = FakeTlsTransport(
            FakeSocket(b"\x14\x03\x03\x00\x01\x01\x17\x03\x03\x00\x02ok"),
            b"1" * 16,
            "",
        )

        self.assertEqual(transport.domain, "www.google.com")
        self.assertEqual(transport.read_exact(2), b"ok")

        bad_transport = FakeTlsTransport(
            FakeSocket(b"\x16\x03\x03\x00\x01x"),
            b"1" * 16,
            "example.com",
        )

        with self.assertRaises(ProtocolError):
            bad_transport.read_exact(1)

    def test_second_write_does_not_repeat_ccs(self) -> None:
        fake_socket = FakeSocket()
        transport = FakeTlsTransport(fake_socket, b"1" * 16, "example.com")

        transport.write(b"one")
        transport.write(b"two")

        self.assertEqual(bytes(fake_socket.sent).count(FAKETLS_CCS), 1)

    def test_handshake_success_and_failures(self) -> None:
        secret = b"1" * 16
        client_random = b"r" * 32
        incoming = make_valid_faketls_response(secret, client_random)

        with patch(
            "mtproxy_checker.transports.make_faketls_client_hello",
            return_value=(b"hello", client_random),
        ):
            transport = FakeTlsTransport(FakeSocket(incoming), secret, "example.com")
            transport.handshake()

        self.assertEqual(bytes(transport.sock.sent), b"hello")

        cases = (
            b"\x17\x03\x03\x00\x01x",
            b"\x16\x03\x03\x00\x01x" + b"badccs",
            b"\x16\x03\x03\x00\x01x" + FAKETLS_CCS + b"\x16\x03\x03\x00\x01x",
        )

        for case in cases:
            with (
                patch(
                    "mtproxy_checker.transports.make_faketls_client_hello",
                    return_value=(b"hello", client_random),
                ),
                self.assertRaises(ProtocolError),
            ):
                FakeTlsTransport(FakeSocket(case), secret, "example.com").handshake()

    def test_plain_transport_and_recv_exact(self) -> None:
        fake_socket = FakeSocket(b"hello", chunk_size=2)
        transport = PlainTransport(fake_socket)

        transport.write(b"out")
        self.assertEqual(bytes(fake_socket.sent), b"out")
        self.assertEqual(transport.read_exact(5), b"hello")

        with self.assertRaises(ProtocolError):
            recv_exact(FakeSocket(b"a"), 2)

    def test_parse_tls_header_validation(self) -> None:
        self.assertEqual(
            FakeTlsTransport._parse_tls_header(b"\x17\x03\x03\x00\x05"),
            (0x17, 5),
        )

        with self.assertRaises(ProtocolError):
            FakeTlsTransport._parse_tls_header(b"bad")

        with self.assertRaises(ProtocolError):
            FakeTlsTransport._parse_tls_header(b"\x17\x01\x01\x00\x00")


class ProtocolTests(unittest.TestCase):
    def test_frame_message_secure(self) -> None:
        data = b"abcd"
        frame = frame_message(data, Mode.SECURE)
        frame_len = struct.unpack("<I", frame[:4])[0]

        self.assertGreaterEqual(frame_len, len(data))
        self.assertEqual(frame[4 : 4 + len(data)], data)

    def test_obfuscated2_handshake_has_expected_shape(self) -> None:
        init, _enc, _dec = make_obfuscated2_handshake(b"1" * 16, Mode.SECURE, 2)

        self.assertEqual(len(init), 64)

    def test_parse_res_pq_validates_nonce(self) -> None:
        nonce = b"n" * 16
        server_nonce = b"s" * 16
        body = struct.pack("<I", 0x05162463) + nonce + server_nonce
        frame = b"\x00" * 8 + struct.pack("<Q", 4) + struct.pack("<I", len(body)) + body

        self.assertEqual(parse_res_pq(frame, nonce), server_nonce.hex())

    def test_parse_res_pq_nonce_mismatch(self) -> None:
        nonce = b"n" * 16
        body = struct.pack("<I", 0x05162463) + (b"x" * 16) + (b"s" * 16)
        frame = b"\x00" * 8 + struct.pack("<Q", 4) + struct.pack("<I", len(body)) + body

        with self.assertRaises(ProtocolError):
            parse_res_pq(frame, nonce)
