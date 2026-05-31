# MTProxy Checker

MTProxy Checker validates Telegram MTProxy endpoints by doing the real relay
health check: TCP connect, MTProxy obfuscated2 handshake, unauthenticated
MTProto `req_pq_multi`, and verified `resPQ` nonce response.

It supports raw 16-byte secrets, `dd` secure secrets, `ee` FakeTLS secrets, and
extended hex/base64 proxy secrets used by Telegram clients.

For a full code walkthrough, including the cryptography and protocol background,
read [docs/architecture-and-cryptography.md](docs/architecture-and-cryptography.md).

## Install

From a GitHub repository:

```bash
pip install "git+https://github.com/alimghmi/mtproxychecker.git"
```

For local development:

```bash
pip install -e ".[dev]"
```

## CLI

```bash
mtproxy-check --url 'https://t.me/proxy?server=1.2.3.4&port=443&secret=...'
```

Positional form:

```bash
mtproxy-check 1.2.3.4 443 4fc30d1222972a04067e805a5134cb57
```

Fast mode is the default. It checks DC 2 with `secure` for normal secrets, and
DC 2 with `faketls` for FakeTLS secrets.

```bash
mtproxy-check --url '...' --connect-timeout 2 --response-timeout 2 -v
mtproxy-check --url '...' --exhaustive -v
mtproxy-check --url '...' --trace
```

Exit codes:

- `0`: proxy is up and returned a valid Telegram `resPQ`.
- `2`: proxy is down, invalid input, or no compatible mode/DC worked.

## Library

```python
from mtproxy_checker import CheckOptions, check_proxy

result = check_proxy(
    "https://t.me/proxy?server=1.2.3.4&port=443&secret=...",
    CheckOptions(connect_timeout=2.0, response_timeout=2.0),
)

if result.ok:
    print(result.mode, result.dc, result.rtt_ms, result.server_nonce)
else:
    print(result.error_code, result.error_message)
```

The public `check_proxy()` API returns a `CheckResult` for normal misuse and
network/protocol failures. It does not leak stack traces or raw secrets through
the public error message.

The library is silent by default. It installs a package `NullHandler` and never
configures root logging. Applications that want checker logs can attach their
own handler to the `mtproxy_checker` logger:

```python
import logging

from mtproxy_checker.logging import StructuredFormatter, get_logger

handler = logging.StreamHandler()
handler.setFormatter(StructuredFormatter())

logger = get_logger()
logger.addHandler(handler)
logger.setLevel(logging.INFO)
```

Stable public error messages include:

- `INVALID_INPUT`: invalid proxy URL or missing host/port/secret.
- `INVALID_SECRET`: invalid MTProxy secret.
- `UNSUPPORTED_MODE`: requested mode does not match the secret.
- `CONNECT_TIMEOUT`: TCP connection timed out.
- `RESPONSE_TIMEOUT`: no valid Telegram response before timeout.
- `NETWORK_ERROR`: socket or network failure.
- `PROTOCOL_ERROR`: response did not match MTProxy/MTProto expectations.
- `INTERNAL_ERROR`: unexpected checker error.

## Development

```bash
python3 -m py_compile mtproxy_checker/*.py
python3 -m pytest -q
python3 -m ruff check .
python3 -m ruff format --check .
python3 -m mypy mtproxy_checker
python3 -m build
```

Live proxy checks are intentionally not part of the default tests.

## License

MIT
