from __future__ import annotations

import argparse
import logging as py_logging
from collections.abc import Sequence

from .checker import check_proxy
from .errors import classify_exception
from .logging import configure_cli_logging, get_logger
from .models import CheckOptions, CheckResult, Mode
from .parser import make_target, parse_dcs

logger = get_logger(__name__)


def setup_logging(debug: bool, trace: bool) -> None:
    level = py_logging.WARNING

    if debug:
        level = py_logging.INFO

    if trace:
        level = py_logging.DEBUG

    configure_cli_logging(level)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check whether an MTProto proxy is reachable by doing an MTProxy "
            "obfuscated handshake and Telegram req_pq_multi relay test."
        )
    )

    parser.add_argument("host", nargs="?")
    parser.add_argument("port", nargs="?")
    parser.add_argument("secret", nargs="?")
    parser.add_argument(
        "--url",
        help=(
            "Proxy URL, for example: "
            "https://t.me/proxy?server=1.2.3.4&port=443&secret=..."
        ),
    )
    parser.add_argument(
        "--dc",
        type=int,
        default=None,
        help="Test a single Telegram DC id. If omitted, fast mode tries 2.",
    )
    parser.add_argument(
        "--dcs",
        type=parse_dcs,
        default=None,
        help="Comma-separated DC ids to try, for example: --dcs 2,4,1",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=None,
        help="Compatibility alias for setting both connect and response timeouts.",
    )
    parser.add_argument(
        "--connect-timeout",
        type=float,
        default=None,
        help="TCP connect timeout in seconds, default: 2",
    )
    parser.add_argument(
        "--response-timeout",
        type=float,
        default=None,
        help="Read/response timeout in seconds, default: 2",
    )
    parser.add_argument(
        "--exhaustive",
        action="store_true",
        help="Try all default DC/mode combinations. Slower, useful for debugging.",
    )
    parser.add_argument(
        "--mode",
        choices=["auto", "secure", "abridged", "intermediate", "faketls"],
        default="auto",
        help=(
            "Transport mode to try. Default: auto, which uses a fast mode "
            "unless --exhaustive is set."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable progress logging.",
    )
    parser.add_argument(
        "--trace",
        action="store_true",
        help="Enable very verbose hex-level debug logging.",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    setup_logging(args.verbose, args.trace)

    connect_timeout = (
        args.connect_timeout
        if args.connect_timeout is not None
        else args.timeout
        if args.timeout is not None
        else 2.0
    )
    response_timeout = (
        args.response_timeout
        if args.response_timeout is not None
        else args.timeout
        if args.timeout is not None
        else 2.0
    )

    options = CheckOptions(
        mode=args.mode,
        dc=args.dc,
        dcs=args.dcs,
        exhaustive=args.exhaustive,
        connect_timeout=connect_timeout,
        response_timeout=response_timeout,
    )

    if args.url:
        result = check_proxy(args.url, options)
    else:
        try:
            target = make_target(args.host, args.port, args.secret)
        except Exception as exc:
            code, message, detail = classify_exception(exc)
            result = CheckResult(ok=False, error_code=code, error_message=message)
            logger.debug(
                "invalid CLI target",
                extra={
                    "event": "cli_invalid_target",
                    "error": str(exc),
                    "detail": detail,
                },
            )
        else:
            result = check_proxy(target, options)

    print_result(result, trace=args.trace)
    return 0 if result.ok else 2


def print_result(result: CheckResult, trace: bool = False) -> None:
    if result.ok and result.target is not None:
        domain_part = (
            f" domain={result.target.secret.faketls_domain}"
            if result.mode == Mode.FAKETLS
            else ""
        )
        print(
            f"UP: host={result.target.host} port={result.target.port} "
            f"mode={result.mode.value if result.mode else ''} dc={result.dc}"
            f"{domain_part} rtt_ms={result.rtt_ms:.1f} "
            f"server_nonce={result.server_nonce}"
        )
        return

    if result.attempts:
        print("DOWN: no working mode/DC combination")

        for attempt in result.attempts:
            if attempt.ok:
                continue

            message = (
                attempt.detail if trace and attempt.detail else attempt.error_message
            )
            print(f"  - dc={attempt.dc} mode={attempt.mode.value}: {message}")
        return

    print(f"DOWN: {result.error_message or 'Invalid proxy input.'}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
