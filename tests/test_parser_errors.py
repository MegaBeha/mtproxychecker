import argparse
import base64
import unittest

from mtproxy_checker.attempts import (
    build_attempts,
    describe_secret,
    effective_inner_mode,
    format_attempts,
    normalize_mode,
)
from mtproxy_checker.errors import (
    InvalidInputError,
    InvalidSecretError,
    NetworkCheckError,
    UnsupportedModeError,
    classify_exception,
    public_message,
)
from mtproxy_checker.models import ErrorCode, Mode, ParsedSecret, SecretKind
from mtproxy_checker.parser import (
    FAKETLS_DEFAULT_DOMAIN,
    decode_secret,
    extract_first_domain,
    make_target,
    parse_dcs,
    short_hex,
)


class ParserErrorsMoreTests(unittest.TestCase):
    def test_extract_first_domain_fallbacks_and_cleanup(self) -> None:
        self.assertEqual(extract_first_domain(b"\x00\x00"), FAKETLS_DEFAULT_DOMAIN)
        self.assertEqual(
            extract_first_domain(b"\x01-foo.example.com\x00xxx"),
            "foo.example.com",
        )
        self.assertEqual(extract_first_domain(b"hello@@example"), "helloexample")

    def test_decode_secret_rejects_empty_and_short_prefixed_values(self) -> None:
        for secret in ("", "ee00", "dd00", "abc", "abcd"):
            with self.assertRaises(InvalidSecretError):
                decode_secret(secret)

        with self.assertRaises(InvalidSecretError):
            decode_secret("a")

    def test_decode_secret_base64_short_and_prefixed_defaults(self) -> None:
        with self.assertRaises(InvalidSecretError):
            decode_secret(base64.b64encode(b"short").decode("ascii"))

        prefixed = decode_secret(base64.b64encode(b"\xee" + b"1" * 16).decode("ascii"))
        self.assertTrue(prefixed.is_faketls)
        self.assertEqual(prefixed.faketls_domain, FAKETLS_DEFAULT_DOMAIN)

    def test_make_target_validation_and_preserves_parsed_secret(self) -> None:
        parsed = ParsedSecret(raw_secret=b"1" * 16, display="1" * 32)
        target = make_target("example.com", "443", parsed)

        self.assertIs(target.secret, parsed)

        for args in (
            (None, 443, parsed),
            ("example.com", None, parsed),
            ("example.com", 443, None),
            ("example.com", "nope", parsed),
            ("example.com", 0, parsed),
            ("example.com", 70000, parsed),
        ):
            with self.assertRaises(InvalidInputError):
                make_target(*args)

    def test_parse_dcs(self) -> None:
        self.assertEqual(parse_dcs(""), (2, 1, 3, 4, 5))
        self.assertEqual(parse_dcs("2, 4,,1"), (2, 4, 1))

        for value in ("nope", ",,,"):
            with self.assertRaises(argparse.ArgumentTypeError):
                parse_dcs(value)

    def test_short_hex_truncates(self) -> None:
        self.assertEqual(short_hex(b"\x01\x02", limit=4), "0102")
        self.assertEqual(short_hex(b"a" * 5, limit=2), "6161...(5 bytes)")

    def test_attempt_helpers(self) -> None:
        raw = ParsedSecret(raw_secret=b"1" * 16, display="1" * 32)
        faketls = ParsedSecret(
            raw_secret=b"1" * 16,
            display="ee" + "1" * 32,
            is_faketls=True,
            faketls_domain="example.com",
            kind=SecretKind.FAKETLS,
        )

        self.assertEqual(normalize_mode(Mode.SECURE), Mode.SECURE)
        self.assertEqual(
            build_attempts(raw, Mode.ABRIDGED, None, None, False),
            ((2, Mode.ABRIDGED),),
        )
        self.assertEqual(
            build_attempts(faketls, Mode.FAKETLS, 5, None, False),
            ((5, Mode.FAKETLS),),
        )
        self.assertEqual(describe_secret(faketls), "faketls domain='example.com'")
        self.assertEqual(
            format_attempts(((2, Mode.SECURE), (4, Mode.ABRIDGED))),
            "dc=2/secure,dc=4/abridged",
        )
        self.assertEqual(effective_inner_mode(Mode.FAKETLS), Mode.SECURE)
        self.assertEqual(effective_inner_mode(Mode.INTERMEDIATE), Mode.INTERMEDIATE)

        with self.assertRaises(UnsupportedModeError):
            normalize_mode("made-up")

    def test_error_classification(self) -> None:
        self.assertEqual(
            public_message(ErrorCode.INVALID_SECRET),
            "Invalid MTProxy secret.",
        )

        code, message, detail = classify_exception(
            NetworkCheckError(ErrorCode.CONNECT_TIMEOUT)
        )
        self.assertEqual(code, ErrorCode.CONNECT_TIMEOUT)
        self.assertEqual(message, "Connection timed out.")
        self.assertEqual(detail, "Connection timed out.")

        code, _message, detail = classify_exception(TimeoutError())
        self.assertEqual(code, ErrorCode.RESPONSE_TIMEOUT)
        self.assertEqual(detail, "timed out")

        code, _message, detail = classify_exception(OSError("offline"))
        self.assertEqual(code, ErrorCode.NETWORK_ERROR)
        self.assertEqual(detail, "offline")

        code, message, detail = classify_exception(RuntimeError("boom"))
        self.assertEqual(code, ErrorCode.INTERNAL_ERROR)
        self.assertEqual(message, "Unexpected checker error.")
        self.assertEqual(detail, "boom")
