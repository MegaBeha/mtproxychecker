import io
import logging
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from mtproxy_checker import CheckOptions, ErrorCode, Mode, check_proxy
from mtproxy_checker.cli import main, print_result, setup_logging
from mtproxy_checker.models import AttemptResult, CheckResult
from mtproxy_checker.parser import decode_secret, make_target


class ApiTests(unittest.TestCase):
    def test_check_proxy_invalid_url_returns_stable_error(self) -> None:
        result = check_proxy("https://t.me/proxy?server=example.com")

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, ErrorCode.INVALID_INPUT)
        self.assertEqual(
            result.error_message,
            "Invalid proxy input. Provide a Telegram MTProxy URL or host, port, "
            "and secret.",
        )

    def test_check_proxy_unsupported_mode_returns_stable_error(self) -> None:
        target = make_target(
            "example.com",
            443,
            decode_secret(
                "eec96b6d60154b353e16b514651c87f15b676f6f676c65617069732e636f6d"
            ),
        )
        result = check_proxy(target, CheckOptions(mode="secure"))

        self.assertFalse(result.ok)
        self.assertEqual(result.error_code, ErrorCode.UNSUPPORTED_MODE)
        self.assertEqual(
            result.error_message,
            "The requested mode is not compatible with this secret.",
        )


class CliTests(unittest.TestCase):
    def test_setup_logging_trace_uses_debug_level(self) -> None:
        setup_logging(debug=False, trace=True)

        self.assertEqual(logging.getLogger("mtproxy_checker").level, logging.DEBUG)

    def test_cli_success_output(self) -> None:
        target = make_target(
            "example.com",
            443,
            "4fc30d1222972a04067e805a5134cb57",
        )
        result = CheckResult(
            ok=True,
            target=target,
            mode=Mode.SECURE,
            dc=2,
            rtt_ms=12.3,
            server_nonce="abc",
        )

        with patch("mtproxy_checker.cli.check_proxy", return_value=result):
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main(
                    ["example.com", "443", "4fc30d1222972a04067e805a5134cb57"]
                )

        self.assertEqual(exit_code, 0)
        self.assertIn("UP: host=example.com port=443 mode=secure dc=2", out.getvalue())

    def test_cli_down_output(self) -> None:
        result = CheckResult(
            ok=False,
            attempts=(
                AttemptResult(
                    dc=2,
                    mode=Mode.SECURE,
                    error_code=ErrorCode.RESPONSE_TIMEOUT,
                    error_message=(
                        "Proxy did not return a valid Telegram response in time."
                    ),
                    detail="timed out",
                ),
            ),
            error_code=ErrorCode.RESPONSE_TIMEOUT,
            error_message="Proxy did not return a valid Telegram response in time.",
        )

        with patch("mtproxy_checker.cli.check_proxy", return_value=result):
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main(
                    ["example.com", "443", "4fc30d1222972a04067e805a5134cb57"]
                )

        self.assertEqual(exit_code, 2)
        self.assertIn("DOWN: no working mode/DC combination", out.getvalue())

    def test_cli_url_path_and_invalid_positional_input(self) -> None:
        target = make_target(
            "example.com",
            443,
            "4fc30d1222972a04067e805a5134cb57",
        )
        result = CheckResult(ok=True, target=target, mode=Mode.SECURE, dc=2, rtt_ms=1)

        with patch("mtproxy_checker.cli.check_proxy", return_value=result) as checked:
            out = io.StringIO()
            with redirect_stdout(out):
                exit_code = main(
                    [
                        "--url",
                        "https://t.me/proxy?server=example.com&port=443&secret=x",
                        "--timeout",
                        "3",
                    ]
                )

        self.assertEqual(exit_code, 0)
        self.assertEqual(checked.call_args.args[1].connect_timeout, 3)
        self.assertIn("UP:", out.getvalue())

        out = io.StringIO()
        with redirect_stdout(out):
            exit_code = main(["example.com"])

        self.assertEqual(exit_code, 2)
        self.assertIn("DOWN: Invalid proxy input.", out.getvalue())

    def test_print_result_faketls_and_trace_details(self) -> None:
        target = make_target(
            "example.com",
            443,
            decode_secret(
                "eec96b6d60154b353e16b514651c87f15b676f6f676c65617069732e636f6d"
            ),
        )
        ok_result = CheckResult(
            ok=True,
            target=target,
            mode=Mode.FAKETLS,
            dc=2,
            rtt_ms=1.2,
            server_nonce="nonce",
        )

        out = io.StringIO()
        with redirect_stdout(out):
            print_result(ok_result)

        self.assertIn("domain=googleapis.com", out.getvalue())

        down_result = CheckResult(
            ok=False,
            attempts=(
                AttemptResult(dc=2, mode=Mode.SECURE, ok=True),
                AttemptResult(
                    dc=3,
                    mode=Mode.ABRIDGED,
                    error_code=ErrorCode.PROTOCOL_ERROR,
                    error_message="public",
                    detail="private detail",
                ),
            ),
        )

        out = io.StringIO()
        with redirect_stdout(out):
            print_result(down_result, trace=True)

        self.assertIn("private detail", out.getvalue())
