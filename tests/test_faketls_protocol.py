import hmac
import struct
import unittest
from hashlib import sha256

from mtproxy_checker.errors import ProtocolError
from mtproxy_checker.faketls import (
    FAKETLS_APP_DATA_PREFIX,
    FAKETLS_CCS,
    FAKETLS_CLIENT_HELLO_LEN,
    make_faketls_client_hello,
)
from mtproxy_checker.models import Mode
from mtproxy_checker.protocol import (
    frame_message,
    make_obfuscated2_handshake,
    parse_res_pq,
)
from mtproxy_checker.transports import FakeTlsTransport


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
