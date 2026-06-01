import base64
import unittest

from mtproxy_checker.attempts import build_attempts
from mtproxy_checker.errors import InvalidInputError, UnsupportedModeError
from mtproxy_checker.models import Mode, SecretKind
from mtproxy_checker.parser import (
    decode_secret,
    parse_proxy_url,
    parse_query_preserve_plus,
)


class ParserTests(unittest.TestCase):
    def test_raw_hex_secret(self) -> None:
        parsed = decode_secret("4fc30d1222972a04067e805a5134cb57")

        self.assertEqual(parsed.raw_secret.hex(), "4fc30d1222972a04067e805a5134cb57")
        self.assertFalse(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.RAW)

    def test_dd_secret(self) -> None:
        parsed = decode_secret("dd104462821249bd7ac519130220c25d09")

        self.assertEqual(parsed.raw_secret.hex(), "104462821249bd7ac519130220c25d09")
        self.assertFalse(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.DD_SECURE)

    def test_ee_secret_with_domain(self) -> None:
        parsed = decode_secret(
            "eec96b6d60154b353e16b514651c87f15b676f6f676c65617069732e636f6d"
        )

        self.assertEqual(parsed.raw_secret.hex(), "c96b6d60154b353e16b514651c87f15b")
        self.assertTrue(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.FAKETLS)
        self.assertEqual(parsed.faketls_domain, "googleapis.com")

    def test_base64_raw_secret(self) -> None:
        encoded = base64.b64encode(bytes.fromhex("104462821249bd7ac519130220c25d09"))
        parsed = decode_secret(encoded.decode("ascii"))

        self.assertEqual(parsed.raw_secret.hex(), "104462821249bd7ac519130220c25d09")
        self.assertEqual(parsed.kind, SecretKind.RAW)

    def test_long_hex_extended_raw_secret(self) -> None:
        parsed = decode_secret(
            "79e344818749bd7ac519130220c25d09"
            "79e344818749bd7ac519130220c25d09"
            "79e344818749bd7ac519130220c25d09"
            "79e344818749bd7ac519130220c25d09"
        )

        self.assertEqual(parsed.raw_secret.hex(), "79e344818749bd7ac519130220c25d09")
        self.assertFalse(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.EXTENDED_RAW)

    def test_base64_dd_secret(self) -> None:
        payload = bytes.fromhex("dd104462821249bd7ac519130220c25d09")
        parsed = decode_secret(base64.b64encode(payload).decode("ascii"))

        self.assertEqual(parsed.raw_secret.hex(), "104462821249bd7ac519130220c25d09")
        self.assertFalse(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.DD_SECURE)

    def test_base64_ee_faketls_secret(self) -> None:
        payload = (
            bytes.fromhex("eec96b6d60154b353e16b514651c87f15b") + b"googleapis.com"
        )
        parsed = decode_secret(base64.b64encode(payload).decode("ascii"))

        self.assertEqual(parsed.raw_secret.hex(), "c96b6d60154b353e16b514651c87f15b")
        self.assertTrue(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.FAKETLS)
        self.assertEqual(parsed.faketls_domain, "googleapis.com")

    def test_long_base64_extended_raw_secret(self) -> None:
        parsed = decode_secret(
            "EERighJJvXrFGRMCIMJdCQRueWVrdGFuZXQuY29tZmFyYWthdi5jb212YW4ubmFqdmEuY29t"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAAAAAAAA"
        )

        self.assertEqual(parsed.raw_secret.hex(), "104462821249bd7ac519130220c25d09")
        self.assertFalse(parsed.is_faketls)
        self.assertEqual(parsed.kind, SecretKind.EXTENDED_RAW)

    def test_query_parser_preserves_plus(self) -> None:
        parsed = parse_query_preserve_plus(
            "tg://proxy?server=example.com&&flag&port=443&secret=abc+def%2Bghi"
        )

        self.assertEqual(parsed["secret"], "abc+def+ghi")
        self.assertEqual(parsed["flag"], "")

    def test_parse_proxy_url(self) -> None:
        target = parse_proxy_url(
            "https://t.me/proxy?server=example.com&port=443"
            "&secret=4fc30d1222972a04067e805a5134cb57"
        )

        self.assertEqual(target.host, "example.com")
        self.assertEqual(target.port, 443)

    def test_parse_proxy_url_missing_fields(self) -> None:
        with self.assertRaises(InvalidInputError):
            parse_proxy_url("https://t.me/proxy?server=example.com")

    def test_parse_proxy_url_invalid_port(self) -> None:
        with self.assertRaises(InvalidInputError):
            parse_proxy_url(
                "https://t.me/proxy?server=example.com&port=nope"
                "&secret=4fc30d1222972a04067e805a5134cb57"
            )


class AttemptBuilderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = decode_secret("4fc30d1222972a04067e805a5134cb57")
        self.faketls = decode_secret(
            "eec96b6d60154b353e16b514651c87f15b676f6f676c65617069732e636f6d"
        )

    def test_default_fast_attempts(self) -> None:
        attempts = build_attempts(self.raw, "auto", None, None, False)

        self.assertEqual(attempts, ((2, Mode.SECURE),))

    def test_exhaustive_attempts(self) -> None:
        attempts = build_attempts(self.raw, "auto", None, None, True)

        self.assertEqual(len(attempts), 15)
        self.assertEqual(attempts[0], (2, Mode.SECURE))
        self.assertEqual(attempts[-1], (5, Mode.INTERMEDIATE))

    def test_dc_and_dcs_override(self) -> None:
        self.assertEqual(
            build_attempts(self.raw, "auto", 4, (1, 2), False),
            ((4, Mode.SECURE),),
        )
        self.assertEqual(
            build_attempts(self.raw, "auto", None, (4, 1), False),
            ((4, Mode.SECURE), (1, Mode.SECURE)),
        )

    def test_faketls_attempts(self) -> None:
        self.assertEqual(
            build_attempts(self.faketls, "auto", None, None, False),
            ((2, Mode.FAKETLS),),
        )

    def test_invalid_mode_combinations(self) -> None:
        with self.assertRaises(UnsupportedModeError):
            build_attempts(self.faketls, "secure", None, None, False)

        with self.assertRaises(UnsupportedModeError):
            build_attempts(self.raw, "faketls", None, None, False)
