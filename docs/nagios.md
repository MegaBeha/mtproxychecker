# Nagios: check_mtproxy

Checks a Telegram request/response through one MTProxy and one DC. Run it on the
Nagios server, using the account that executes service checks.

## Install

Requires Python 3.10+, venv/pip and Git. `cryptography` is installed automatically.
These examples use the `nagios` account; adjust paths and account names as needed.
Install from this fork's plugin branch:

```bash
sudo python3 -m venv /opt/check-mtproxy
sudo /opt/check-mtproxy/bin/pip install 'git+https://github.com/MegaBeha/mtproxychecker.git@feat/nagios-plugin'
sudo install -d -o nagios -g nagios -m 700 /etc/nagios/mtproxy
sudo install -o nagios -g nagios -m 600 /dev/null /etc/nagios/mtproxy/proxy.secret
sudoedit /etc/nagios/mtproxy/proxy.secret
```

Paste only the proxy secret, in hex or base64, into the file. For FakeTLS, use
the complete `ee` secret including its encoded domain, not the full proxy URL.

## Check manually

```bash
sudo -u nagios /opt/check-mtproxy/bin/check_mtproxy \
  -H proxy.example.com --secret-file /etc/nagios/mtproxy/proxy.secret
```

Example output (exit code 0):

```text
OK - MTProxy FakeTLS, DC2, key_id=7c93a2b084ef, exchange 0.318s | time=0.318s;2;5;0;
```

## Configure Nagios

Copy [commands.cfg](../examples/nagios/commands.cfg) and
[services.cfg](../examples/nagios/services.cfg) into your Nagios object directory.
Replace the example host/address and key path; adapt the `linux-server` and
`generic-service` template names if necessary. Use an existing host instead of
the example host definition if the proxy is already monitored.

Validate with `nagios -v /path/to/nagios.cfg`, then reload or restart your Nagios
service. The example checks every 3 minutes, with 3 attempts; notifications follow
your existing templates and contacts.

## Options and results

| Option | Default | Meaning |
|---|---|---|
| `-H`, `--hostname` | required | Proxy IP or hostname |
| `-p`, `--port` | 443 | TCP port |
| `--secret-file` | required | File containing the proxy secret |
| `-t`, `--timeout` | 10 | Overall timeout, seconds, including file reads and DNS |
| `-w`, `--warning` | 2 | WARNING above this exchange time, seconds |
| `-c`, `--critical` | 5 | CRITICAL above this exchange time, seconds |
| `--dc` | 2 | One Telegram DC, 1–5 |

Exit codes: **0 OK**, **1 WARNING**, **2 CRITICAL** (slow exchange, connection/protocol
failure or timeout), **3 UNKNOWN** (invalid arguments, secret-file or internal error).
Thresholds use strict `>`: exactly 2s is OK; exactly 5s is WARNING with the defaults.
Time covers connection and MTProto exchange. Perfdata is returned on successful
exchanges; graphing requires a configured Nagios performance-data backend.

If the check fails, first repeat the manual command as the Nagios account.
For UNKNOWN, check the file permissions, secret format and arguments. For CRITICAL,
check connectivity, the proxy key and the selected DC. Logs use a key fingerprint,
not the secret. Nagios handles retries and notifications.

## Tested and limitations

Live-tested on **TeleMT 3.5.5, FakeTLS, DC2**, with **Nagios Core 4.5.14,
Debian 13 and Python 3.13.5**. Other proxy implementations have not been live-tested.
A successful reply does not verify all Telegram functions or reachability from
other client networks. No Telegram account or message sending is required.

For Docker, install inside the Nagios container or its image. Keep the key and
installation persistent through image configuration or mounts. Recreate the
virtual environment when changing the container's Python version.
