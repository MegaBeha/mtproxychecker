from __future__ import annotations

import argparse
import json
import math
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn

from .checker import check_proxy
from .logging import key_fingerprint
from .models import CheckOptions, ErrorCode
from .parser import make_target

STATUS = ("OK", "WARNING", "CRITICAL", "UNKNOWN")
_WORKER = "from mtproxy_checker.nagios import _worker; _worker()"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        # argparse's default message may contain supplied credentials.
        raise ValueError("Invalid arguments")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(description="Check one MTProxy through one Telegram DC.")
    parser.add_argument("-H", "--hostname", required=True)
    parser.add_argument("-p", "--port", type=int, default=443)
    parser.add_argument("--secret-file", required=True)
    parser.add_argument("-t", "--timeout", type=float, default=10.0)
    parser.add_argument("-w", "--warning", type=float, default=2.0)
    parser.add_argument("-c", "--critical", type=float, default=5.0)
    parser.add_argument("--dc", type=int, default=2)
    return parser


def _worker() -> None:
    """Read the secret only in the process covered by the overall timeout."""
    try:
        config = json.load(sys.stdin)
        secret = Path(config["secret_file"]).read_text(encoding="utf-8").strip()
        target = make_target(config["hostname"], config["port"], secret)
    except Exception:
        print(json.dumps({"status": 3, "message": "Cannot read or parse secret file"}))
        return

    try:
        result = check_proxy(
            target,
            CheckOptions(
                dc=config["dc"],
                connect_timeout=config["timeout"],
                response_timeout=config["timeout"],
            ),
        )
        mode = "FakeTLS" if target.secret.is_faketls else "secure"
        if result.ok:
            seconds = result.rtt_ms
            if seconds is None or not math.isfinite(seconds) or seconds < 0:
                raise ValueError("Invalid elapsed time")
            print(
                json.dumps(
                    {
                        "status": 0,
                        "seconds": seconds / 1000,
                        "mode": mode,
                        "key_id": key_fingerprint(target.secret.raw_secret),
                    }
                )
            )
        else:
            network_failure = result.error_code in (
                ErrorCode.CONNECT_TIMEOUT,
                ErrorCode.RESPONSE_TIMEOUT,
                ErrorCode.NETWORK_ERROR,
                ErrorCode.PROTOCOL_ERROR,
            )
            print(
                json.dumps(
                    {
                        "status": 2 if network_failure else 3,
                        "message": (
                            "Proxy connection or Telegram exchange failed"
                            if network_failure
                            else "Checker could not perform the check"
                        ),
                        "key_id": key_fingerprint(target.secret.raw_secret),
                    }
                )
            )
    except Exception:
        print(json.dumps({"status": 3, "message": "Internal checker error"}))


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
        if (
            not args.hostname.strip()
            or not 1 <= args.port <= 65535
            or not 1 <= args.dc <= 5
            or not all(
                math.isfinite(value)
                for value in (args.timeout, args.warning, args.critical)
            )
            or args.timeout <= 0
            or not 0 <= args.warning <= args.critical
        ):
            raise ValueError("Invalid arguments")
    except ValueError:
        print("UNKNOWN - Invalid arguments; see --help")
        return 3

    try:
        # No secret or proxy URL is passed in process arguments. The watchdog
        # also bounds DNS, file reads and a peer that keeps individual reads alive.
        process = subprocess.run(
            [sys.executable, "-c", _WORKER],
            input=json.dumps(vars(args)),
            capture_output=True,
            text=True,
            timeout=args.timeout,
            check=False,
        )
        if process.returncode:
            raise ValueError("Worker failed")
        result = json.loads(process.stdout)
        code = result["status"]
        if type(code) is not int or code not in (0, 2, 3):
            raise ValueError("Invalid worker status")
        key_id = result.get("key_id")
        if key_id is not None and not re.fullmatch(r"[0-9a-f]{12}", key_id):
            raise ValueError("Invalid key identifier")
        if code == 0:
            seconds = float(result["seconds"])
            if (
                not math.isfinite(seconds)
                or seconds < 0
                or result["mode"] not in ("FakeTLS", "secure")
                or key_id is None
            ):
                raise ValueError("Invalid worker result")
            code = 2 if seconds > args.critical else 1 if seconds > args.warning else 0
            print(
                f"{STATUS[code]} - MTProxy {result['mode']}, DC{args.dc}, "
                f"key_id={result['key_id']}, exchange {seconds:.3f}s "
                f"| time={seconds:.3f}s;{args.warning:g};{args.critical:g};0;"
            )
        else:
            message = (
                "Proxy connection or Telegram exchange failed"
                if code == 2
                else "Cannot perform check; verify configuration and secret file"
            )
            suffix = f", key_id={key_id}" if key_id else ""
            print(f"{STATUS[code]} - {message}{suffix}")
        return int(code)
    except subprocess.TimeoutExpired:
        print(f"CRITICAL - Overall check timeout after {args.timeout:g}s")
        return 2
    except Exception:
        # Never forward a traceback or worker stdout/stderr containing a secret.
        print("UNKNOWN - Internal plugin error")
        return 3
