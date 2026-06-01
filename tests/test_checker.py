import unittest
from unittest.mock import patch

from mtproxy_checker import CheckOptions, ErrorCode, Mode, check_proxy
from mtproxy_checker.checker import check_once, require_target
from mtproxy_checker.errors import InvalidInputError, NetworkCheckError
from mtproxy_checker.parser import decode_secret, make_target


class FakeCipher:
    def update(self, data: bytes) -> bytes:
        return data


class FakeSocket:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.timeout: float | None = None

    def __enter__(self) -> "FakeSocket":
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def sendall(self, data: bytes) -> None:
        self.sent.append(data)


class FakeTransport:
    def __init__(self, sock: FakeSocket, *_args: object) -> None:
        self.sock = sock
        self.handshake_done = False
        self.writes: list[bytes] = []

    def handshake(self) -> None:
        self.handshake_done = True

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    def read_exact(self, _n: int) -> bytes:
        return b""


class CheckerMoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.target = make_target(
            "example.com",
            443,
            "4fc30d1222972a04067e805a5134cb57",
        )

    def test_check_proxy_success_records_attempt(self) -> None:
        with patch("mtproxy_checker.checker.check_once", return_value=(12.5, "abc")):
            result = check_proxy(self.target, CheckOptions(dc=4))

        self.assertTrue(result.ok)
        self.assertEqual(result.dc, 4)
        self.assertEqual(result.mode, Mode.SECURE)
        self.assertEqual(result.server_nonce, "abc")
        self.assertEqual(len(result.attempts), 1)
        self.assertTrue(result.attempts[0].ok)

    def test_check_proxy_failure_uses_last_error_code(self) -> None:
        def fail_once(*_args: object, **_kwargs: object) -> None:
            raise NetworkCheckError(ErrorCode.RESPONSE_TIMEOUT, "slow")

        with patch("mtproxy_checker.checker.check_once", side_effect=fail_once):
            result = check_proxy(self.target, CheckOptions(dc=2))

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, ErrorCode.RESPONSE_TIMEOUT)
        self.assertEqual(len(result.attempts), 1)
        self.assertEqual(result.attempts[0].detail, "slow")

    def test_check_proxy_internal_exception_is_stable(self) -> None:
        with patch(
            "mtproxy_checker.checker.build_attempts",
            side_effect=RuntimeError("boom"),
        ):
            result = check_proxy(self.target)

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, ErrorCode.INTERNAL_ERROR)
        self.assertEqual(result.error_message, "Unexpected checker error.")

    def test_check_once_secure_success_uses_protocol_pipeline(self) -> None:
        fake_socket = FakeSocket()
        nonce = b"n" * 16

        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                return_value=fake_socket,
            ),
            patch(
                "mtproxy_checker.checker.make_obfuscated2_handshake",
                return_value=(b"init", FakeCipher(), FakeCipher()),
            ),
            patch(
                "mtproxy_checker.checker.make_unencrypted_req_pq_multi",
                return_value=(nonce, b"req"),
            ),
            patch("mtproxy_checker.checker.frame_message", return_value=b"framed"),
            patch("mtproxy_checker.checker.read_frame", return_value=b"response"),
            patch("mtproxy_checker.checker.parse_res_pq", return_value="server-nonce"),
        ):
            elapsed_ms, server_nonce = check_once(
                self.target,
                dc_id=2,
                connect_timeout=1.0,
                response_timeout=1.5,
                mode=Mode.SECURE,
            )

        self.assertGreaterEqual(elapsed_ms, 0)
        self.assertEqual(server_nonce, "server-nonce")
        self.assertEqual(fake_socket.timeout, 1.5)
        self.assertEqual(fake_socket.sent, [b"init", b"framed"])

    def test_check_once_faketls_success_uses_faketls_transport(self) -> None:
        target = make_target(
            "example.com",
            443,
            decode_secret(
                "eec96b6d60154b353e16b514651c87f15b676f6f676c65617069732e636f6d"
            ),
        )
        fake_socket = FakeSocket()

        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                return_value=fake_socket,
            ),
            patch("mtproxy_checker.checker.FakeTlsTransport", FakeTransport),
            patch(
                "mtproxy_checker.checker.make_obfuscated2_handshake",
                return_value=(b"init", FakeCipher(), FakeCipher()),
            ),
            patch(
                "mtproxy_checker.checker.make_unencrypted_req_pq_multi",
                return_value=(b"n" * 16, b"req"),
            ),
            patch("mtproxy_checker.checker.frame_message", return_value=b"framed"),
            patch("mtproxy_checker.checker.read_frame", return_value=b"response"),
            patch("mtproxy_checker.checker.parse_res_pq", return_value="server-nonce"),
        ):
            _elapsed_ms, server_nonce = check_once(
                target,
                dc_id=2,
                connect_timeout=1.0,
                response_timeout=1.0,
                mode=Mode.FAKETLS,
            )

        self.assertEqual(server_nonce, "server-nonce")

    def test_check_once_connect_timeout_maps_error_code(self) -> None:
        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                side_effect=TimeoutError("connect slow"),
            ),
            self.assertRaises(NetworkCheckError) as caught,
        ):
            check_once(self.target, 2, 1.0, 1.0, Mode.SECURE)

        self.assertEqual(caught.exception.code, ErrorCode.CONNECT_TIMEOUT)

    def test_check_once_connect_oserror_maps_network_error(self) -> None:
        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                side_effect=OSError("no route"),
            ),
            self.assertRaises(NetworkCheckError) as caught,
        ):
            check_once(self.target, 2, 1.0, 1.0, Mode.SECURE)

        self.assertEqual(caught.exception.code, ErrorCode.NETWORK_ERROR)

    def test_check_once_response_timeout_maps_error_code(self) -> None:
        fake_socket = FakeSocket()

        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                return_value=fake_socket,
            ),
            patch(
                "mtproxy_checker.checker.make_obfuscated2_handshake",
                return_value=(b"init", FakeCipher(), FakeCipher()),
            ),
            patch(
                "mtproxy_checker.checker.make_unencrypted_req_pq_multi",
                return_value=(b"n" * 16, b"req"),
            ),
            patch("mtproxy_checker.checker.frame_message", return_value=b"framed"),
            patch(
                "mtproxy_checker.checker.read_frame",
                side_effect=TimeoutError("read slow"),
            ),
            self.assertRaises(NetworkCheckError) as caught,
        ):
            check_once(self.target, 2, 1.0, 1.0, Mode.SECURE)

        self.assertEqual(caught.exception.code, ErrorCode.RESPONSE_TIMEOUT)

    def test_check_once_response_oserror_maps_network_error(self) -> None:
        fake_socket = FakeSocket()

        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                return_value=fake_socket,
            ),
            patch(
                "mtproxy_checker.checker.make_obfuscated2_handshake",
                return_value=(b"init", FakeCipher(), FakeCipher()),
            ),
            patch(
                "mtproxy_checker.checker.PlainTransport",
                side_effect=OSError("socket gone"),
            ),
            self.assertRaises(NetworkCheckError) as caught,
        ):
            check_once(self.target, 2, 1.0, 1.0, Mode.SECURE)

        self.assertEqual(caught.exception.code, ErrorCode.NETWORK_ERROR)

    def test_require_target(self) -> None:
        self.assertIs(require_target(self.target), self.target)

        with self.assertRaises(InvalidInputError):
            require_target(None)

    def test_timeout_error_without_message_gets_default_detail(self) -> None:
        with (
            patch(
                "mtproxy_checker.checker.socket.create_connection",
                side_effect=TimeoutError(),
            ),
            self.assertRaises(NetworkCheckError) as caught,
        ):
            check_once(self.target, 2, 1.0, 1.0, Mode.SECURE)

        self.assertEqual(caught.exception.detail, "timed out")
