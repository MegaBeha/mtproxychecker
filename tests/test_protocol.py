import struct
import unittest
from unittest.mock import patch

from mtproxy_checker.errors import ProtocolError
from mtproxy_checker.models import Mode
from mtproxy_checker.protocol import (
    MAX_FRAME,
    REQ_PQ_MULTI,
    RES_PQ,
    frame_message,
    make_obfuscated2_handshake,
    make_unencrypted_req_pq_multi,
    protocol_tag_for_mode,
    read_frame,
)


class IdentityCipher:
    def update(self, data: bytes) -> bytes:
        return data


class BytesTransport:
    def __init__(self, data: bytes):
        self.data = bytearray(data)

    def read_exact(self, n: int) -> bytes:
        out = bytes(self.data[:n])
        del self.data[:n]
        return out


class ProtocolMoreTests(unittest.TestCase):
    def test_protocol_tags_cover_all_modes(self) -> None:
        self.assertEqual(protocol_tag_for_mode(Mode.FAKETLS), b"\xdd" * 4)
        self.assertEqual(protocol_tag_for_mode(Mode.INTERMEDIATE), b"\xee" * 4)
        self.assertEqual(protocol_tag_for_mode(Mode.ABRIDGED), b"\xef" * 4)

    def test_protocol_tag_rejects_unknown_mode(self) -> None:
        with self.assertRaises(ProtocolError):
            protocol_tag_for_mode("nope")  # type: ignore[arg-type]

    def test_make_obfuscated2_handshake_retries_forbidden_randoms(self) -> None:
        randoms = [
            b"\xef" + b"a" * 63,
            b"GET " + b"a" * 60,
            b"abcd" + b"\x00" * 4 + b"a" * 56,
            b"\x01" * 64,
        ]

        with patch("mtproxy_checker.protocol.os.urandom", side_effect=randoms):
            init, _enc, _dec = make_obfuscated2_handshake(b"1" * 16, Mode.SECURE, 2)

        self.assertEqual(len(init), 64)

    def test_make_unencrypted_req_pq_multi_shape(self) -> None:
        with (
            patch("mtproxy_checker.protocol.os.urandom", return_value=b"n" * 16),
            patch("mtproxy_checker.protocol.time.time", return_value=10.0),
        ):
            nonce, packet = make_unencrypted_req_pq_multi()

        self.assertEqual(nonce, b"n" * 16)
        self.assertEqual(packet[:8], b"\x00" * 8)
        self.assertEqual(struct.unpack("<I", packet[16:20])[0], 20)
        self.assertEqual(struct.unpack("<I", packet[20:24])[0], REQ_PQ_MULTI)

    def test_frame_message_intermediate_and_abridged(self) -> None:
        self.assertEqual(
            frame_message(b"abc", Mode.INTERMEDIATE),
            b"\x03\x00\x00\x00abc",
        )
        self.assertEqual(frame_message(b"abcd", Mode.ABRIDGED), b"\x01abcd")

        large = b"a" * (127 * 4)
        frame = frame_message(large, Mode.ABRIDGED)

        self.assertEqual(frame[:4], b"\x7f\x7f\x00\x00")
        self.assertEqual(frame[4:], large)

    def test_frame_message_rejects_invalid_abridged_length_and_mode(self) -> None:
        with self.assertRaises(ProtocolError):
            frame_message(b"abc", Mode.ABRIDGED)

        with self.assertRaises(ProtocolError):
            frame_message(b"abc", "nope")  # type: ignore[arg-type]

    def test_read_frame_secure_and_high_bit_adjustment(self) -> None:
        payload = read_frame(
            BytesTransport(struct.pack("<I", 4) + b"data"),
            IdentityCipher(),
            Mode.SECURE,
        )
        self.assertEqual(payload, b"data")

        high_bit_payload = read_frame(
            BytesTransport(struct.pack("<I", 0x80000004) + b"more"),
            IdentityCipher(),
            Mode.INTERMEDIATE,
        )
        self.assertEqual(high_bit_payload, b"more")

    def test_read_frame_rejects_bad_secure_lengths(self) -> None:
        for frame_len in (0, MAX_FRAME + 1):
            with self.assertRaises(ProtocolError):
                read_frame(
                    BytesTransport(struct.pack("<I", frame_len)),
                    IdentityCipher(),
                    Mode.SECURE,
                )

    def test_read_frame_abridged_short_and_long_lengths(self) -> None:
        self.assertEqual(
            read_frame(BytesTransport(b"\x01data"), IdentityCipher(), Mode.ABRIDGED),
            b"data",
        )
        self.assertEqual(
            read_frame(
                BytesTransport(b"\x7f\x02\x00\x00abcdefgh"),
                IdentityCipher(),
                Mode.ABRIDGED,
            ),
            b"abcdefgh",
        )

    def test_read_frame_abridged_rejects_bad_length_and_mode(self) -> None:
        with self.assertRaises(ProtocolError):
            read_frame(BytesTransport(b"\x00"), IdentityCipher(), Mode.ABRIDGED)

        with self.assertRaises(ProtocolError):
            read_frame(BytesTransport(b""), IdentityCipher(), "nope")  # type: ignore[arg-type]

    def test_parse_res_pq_error_shapes(self) -> None:
        from mtproxy_checker.protocol import parse_res_pq

        nonce = b"n" * 16

        with self.assertRaises(ProtocolError):
            parse_res_pq(b"short", nonce)

        with self.assertRaises(ProtocolError):
            parse_res_pq(b"bad-auth" + b"\x00" * 40, nonce)

        with self.assertRaises(ProtocolError):
            parse_res_pq(
                b"\x00" * 8 + b"\x01" * 8 + struct.pack("<I", 9999) + b"x" * 20,
                nonce,
            )

        short_body = (
            b"\x00" * 8 + b"\x01" * 8 + struct.pack("<I", 20) + b"abcd" + b"x" * 16
        )
        with self.assertRaises(ProtocolError):
            parse_res_pq(short_body, nonce)

        bad_constructor = (
            b"\x00" * 8
            + b"\x01" * 8
            + struct.pack("<I", 36)
            + struct.pack("<I", 0)
            + nonce
            + b"s" * 16
        )
        with self.assertRaises(ProtocolError):
            parse_res_pq(bad_constructor, nonce)

    def test_parse_res_pq_accepts_valid_frame(self) -> None:
        from mtproxy_checker.protocol import parse_res_pq

        nonce = b"n" * 16
        server_nonce = b"s" * 16
        body = struct.pack("<I", RES_PQ) + nonce + server_nonce
        frame = b"\x00" * 8 + b"\x01" * 8 + struct.pack("<I", len(body)) + body

        self.assertEqual(parse_res_pq(frame, nonce), server_nonce.hex())
