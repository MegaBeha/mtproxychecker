import io
import json
import logging
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from mtproxy_checker import CheckResult, ErrorCode
from mtproxy_checker.logging import get_logger, key_fingerprint
from mtproxy_checker.nagios import _worker, main


class NagiosTests(unittest.TestCase):
    secret = "00112233445566778899aabbccddeeff"

    def setUp(self) -> None:
        self.arguments = ["-H", "127.0.0.1", "--secret-file", "secret.txt"]
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "secret.txt"
        self.path.write_text(self.secret + "\n", encoding="utf-8")
        self.key_id = key_fingerprint(bytes.fromhex(self.secret))

    def tearDown(self) -> None:
        logger = get_logger()
        logger.handlers = [logging.NullHandler()]
        logger.setLevel(logging.NOTSET)

    def run_main(self, arguments: list[str]) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(arguments)
        self.assertEqual(err.getvalue(), "")
        self.assertNotIn(self.secret, out.getvalue())
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        return code, out.getvalue()

    def worker_result(self, result: CheckResult) -> tuple[dict, object]:
        config = {
            "hostname": "127.0.0.1",
            "port": 443,
            "secret_file": str(self.path),
            "dc": 4,
            "timeout": 10,
        }
        out = io.StringIO()
        with (
            patch("sys.stdin", io.StringIO(json.dumps(config))),
            redirect_stdout(out),
            patch("mtproxy_checker.nagios.check_proxy", return_value=result) as check,
        ):
            _worker()
        self.assertNotIn(self.secret, out.getvalue())
        return json.loads(out.getvalue()), check

    def successful_process(self, seconds: float = 0.318) -> subprocess.CompletedProcess:
        return subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {
                    "status": 0,
                    "seconds": seconds,
                    "mode": "FakeTLS",
                    "key_id": self.key_id,
                }
            ),
            "",
        )

    def test_defaults_and_single_check(self) -> None:
        with patch(
            "mtproxy_checker.nagios.subprocess.run",
            return_value=self.successful_process(),
        ) as run:
            code, output = self.run_main(self.arguments)
        self.assertEqual(code, 0)
        self.assertIn("MTProxy FakeTLS, DC2", output)
        self.assertIn(f"key_id={self.key_id}", output)
        self.assertIn("| time=0.318s;2;5;0;", output)
        run.assert_called_once()
        config = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(
            (config["port"], config["dc"], config["timeout"]), (443, 2, 10)
        )
        self.assertEqual(run.call_args.kwargs["timeout"], 10)
        self.assertNotIn(self.secret, repr(run.call_args))

    def test_thresholds_and_boundaries(self) -> None:
        for seconds, expected in ((0, 0), (2, 0), (2.001, 1), (5, 1), (5.001, 2)):
            with self.subTest(seconds=seconds):
                with patch(
                    "mtproxy_checker.nagios.subprocess.run",
                    return_value=self.successful_process(seconds),
                ):
                    code, _ = self.run_main(self.arguments)
                self.assertEqual(code, expected)

    def test_custom_options(self) -> None:
        with patch(
            "mtproxy_checker.nagios.subprocess.run",
            return_value=self.successful_process(0.5),
        ) as run:
            code, output = self.run_main(
                [
                    *self.arguments,
                    "-p",
                    "8443",
                    "--dc",
                    "4",
                    "-t",
                    "3",
                    "-w",
                    "0.2",
                    "-c",
                    "0.4",
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn("DC4", output)
        self.assertIn(";0.2;0.4;", output)
        config = json.loads(run.call_args.kwargs["input"])
        self.assertEqual(
            (config["port"], config["dc"], config["timeout"]), (8443, 4, 3)
        )

    def test_invalid_arguments_are_unknown_and_do_not_start_worker(self) -> None:
        cases = [[], ["--secret", self.secret]]
        cases += [
            self.arguments + extra
            for extra in (
                ["-H", " "],
                ["-p", "0"],
                ["-p", "65536"],
                ["-p", "bad"],
                ["--dc", "0"],
                ["--dc", "6"],
                ["-t", "0"],
                ["-t", "-1"],
                ["-t", "nan"],
                ["-w", "inf"],
                ["-c", "nan"],
                ["-w", "-1"],
                ["-w", "6", "-c", "5"],
            )
        ]
        with patch("mtproxy_checker.nagios.subprocess.run") as run:
            for arguments in cases:
                with self.subTest(arguments=arguments):
                    code, output = self.run_main(arguments)
                    self.assertEqual(code, 3)
                    self.assertTrue(output.startswith("UNKNOWN -"))
            run.assert_not_called()

    def test_help(self) -> None:
        with (
            redirect_stdout(io.StringIO()) as out,
            self.assertRaises(SystemExit) as raised,
        ):
            main(["--help"])
        self.assertEqual(raised.exception.code, 0)
        self.assertIn("--secret-file", out.getvalue())

    def test_worker_reads_raw_and_faketls_secret_and_checks_one_dc(self) -> None:
        for secret, mode in (
            (self.secret, "secure"),
            ("ee" + self.secret + b"example.com".hex(), "FakeTLS"),
        ):
            with self.subTest(mode=mode):
                self.path.write_text(secret + "\n", encoding="utf-8")
                result, check = self.worker_result(CheckResult(ok=True, rtt_ms=318))
                self.assertEqual(result["status"], 0)
                self.assertEqual(result["mode"], mode)
                self.assertEqual(result["seconds"], 0.318)
                self.assertEqual(result["key_id"], self.key_id)
                check.assert_called_once()
                target, options = check.call_args.args
                self.assertEqual(target.secret.raw_secret.hex(), self.secret)
                self.assertEqual(options.dc, 4)
                self.assertIsNone(options.dcs)
                self.assertFalse(options.exhaustive)

    def test_worker_maps_network_and_protocol_errors_to_critical(self) -> None:
        for error in ErrorCode:
            with self.subTest(error=error):
                result, _ = self.worker_result(
                    CheckResult(ok=False, error_code=error, error_message=self.secret)
                )
                expected = (
                    2
                    if error
                    in (
                        ErrorCode.CONNECT_TIMEOUT,
                        ErrorCode.RESPONSE_TIMEOUT,
                        ErrorCode.NETWORK_ERROR,
                        ErrorCode.PROTOCOL_ERROR,
                    )
                    else 3
                )
                self.assertEqual(result["status"], expected)

    def test_worker_invalid_duration_is_unknown(self) -> None:
        for milliseconds in (None, -1, float("nan"), float("inf")):
            with self.subTest(milliseconds=milliseconds):
                result, _ = self.worker_result(
                    CheckResult(ok=True, rtt_ms=milliseconds)
                )
                self.assertEqual(result["status"], 3)

    def test_worker_exception_does_not_disclose_secret(self) -> None:
        with patch(
            "mtproxy_checker.nagios.make_target", side_effect=ValueError(self.secret)
        ):
            result, _ = self.worker_result(CheckResult(ok=True))
        self.assertEqual(result["status"], 3)
        with patch(
            "mtproxy_checker.nagios.CheckOptions", side_effect=RuntimeError(self.secret)
        ):
            result, _ = self.worker_result(CheckResult(ok=True))
        self.assertEqual(result["status"], 3)

    def test_unreadable_empty_and_invalid_file_are_unknown(self) -> None:
        for contents in (None, "", "not a key"):
            with self.subTest(contents=contents):
                if contents is None:
                    self.path.unlink()
                else:
                    self.path.write_text(contents, encoding="utf-8")
                result, check = self.worker_result(CheckResult(ok=True))
                self.assertEqual(result["status"], 3)
                check.assert_not_called()
        self.path.write_text(self.secret, encoding="utf-8")
        with patch("pathlib.Path.read_text", side_effect=PermissionError(self.secret)):
            result, _ = self.worker_result(CheckResult(ok=True))
        self.assertEqual(result["status"], 3)

    def test_failed_worker_and_invalid_output_are_unknown(self) -> None:
        for process in (
            subprocess.CompletedProcess([], 1, self.secret, self.secret),
            subprocess.CompletedProcess([], 0, self.secret, self.secret),
            subprocess.CompletedProcess([], 0, "{}", ""),
            subprocess.CompletedProcess([], 0, '{"status": 9}', ""),
            subprocess.CompletedProcess([], 0, '{"status": true}', ""),
        ):
            with self.subTest(process=process):
                with patch(
                    "mtproxy_checker.nagios.subprocess.run", return_value=process
                ):
                    code, _ = self.run_main(self.arguments)
                self.assertEqual(code, 3)
        with patch(
            "mtproxy_checker.nagios.subprocess.run", side_effect=OSError(self.secret)
        ):
            code, _ = self.run_main(self.arguments)
        self.assertEqual(code, 3)

    def test_invalid_success_payload_is_unknown(self) -> None:
        cases = (
            {"seconds": -1},
            {"seconds": "nan"},
            {"mode": self.secret},
            {"key_id": None},
            {"key_id": self.secret},
        )
        for change in cases:
            with self.subTest(change=change):
                process = self.successful_process()
                result = json.loads(process.stdout)
                result.update(change)
                process.stdout = json.dumps(result)
                with patch(
                    "mtproxy_checker.nagios.subprocess.run", return_value=process
                ):
                    code, _ = self.run_main(self.arguments)
                self.assertEqual(code, 3)

    def test_failure_output_and_unknown_have_correct_exit_codes(self) -> None:
        for status, key_id in ((2, self.key_id), (3, None)):
            with self.subTest(status=status):
                result = {"status": status, "message": self.secret, "key_id": key_id}
                process = subprocess.CompletedProcess([], 0, json.dumps(result), "")
                with patch(
                    "mtproxy_checker.nagios.subprocess.run", return_value=process
                ):
                    code, output = self.run_main(self.arguments)
                self.assertEqual(code, status)
                if key_id:
                    self.assertIn(key_id, output)

    def test_timeout_exception_is_critical(self) -> None:
        with patch(
            "mtproxy_checker.nagios.subprocess.run",
            side_effect=subprocess.TimeoutExpired([], 10, output=self.secret),
        ):
            code, output = self.run_main(self.arguments)
        self.assertEqual(code, 2)
        self.assertIn("Overall check timeout after 10s", output)

    def test_real_worker_timeout_is_enforced(self) -> None:
        started = time.monotonic()
        with patch("mtproxy_checker.nagios._WORKER", "import time; time.sleep(30)"):
            code, output = self.run_main([*self.arguments, "-t", "0.2"])
        self.assertEqual(code, 2)
        self.assertIn("timeout", output)
        self.assertLess(time.monotonic() - started, 3)

    def test_real_worker_file_error(self) -> None:
        code, _ = self.run_main(
            [
                "-H",
                "127.0.0.1",
                "--secret-file",
                str(self.path.with_name("absent")),
            ]
        )
        self.assertEqual(code, 3)

    def test_real_worker_connection_refused(self) -> None:
        # The bound but non-listening local socket reserves a closed port.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            code, output = self.run_main(
                [
                    "-H",
                    "127.0.0.1",
                    "-p",
                    str(port),
                    "--secret-file",
                    str(self.path),
                ]
            )
        self.assertEqual(code, 2)
        self.assertIn(self.key_id, output)

    @contextmanager
    def local_proxy(self, delay: float):
        """A one-request secure MTProxy fixture, using only synthetic keys."""
        import hashlib
        import struct

        received = []

        def read_exact(sock, length):
            data = b""
            while len(data) < length:
                chunk = sock.recv(length - len(data))
                if not chunk:
                    raise ConnectionError("test connection closed")
                data += chunk
            return data

        def serve(listener):
            try:
                with listener.accept()[0] as client:
                    client.settimeout(2)
                    init = read_exact(client, 64)
                    secret = bytes.fromhex(self.secret)
                    decrypt = Cipher(
                        algorithms.AES(hashlib.sha256(init[8:40] + secret).digest()),
                        modes.CTR(init[40:56]),
                    ).decryptor()
                    header = decrypt.update(init)
                    if header[56:60] != b"\xdd" * 4:
                        return
                    length = struct.unpack("<I", decrypt.update(read_exact(client, 4)))[
                        0
                    ]
                    request = decrypt.update(read_exact(client, length))
                    if request[20:24] != struct.pack("<I", 0xBE7E8EF1):
                        return
                    received.append(header[60])
                    body = struct.pack("<I", 0x05162463) + request[24:40] + b"s" * 16
                    reply = b"\x00" * 8 + struct.pack("<QI", 4, len(body)) + body
                    encrypt = Cipher(
                        algorithms.AES(
                            hashlib.sha256(init[55:23:-1] + secret).digest()
                        ),
                        modes.CTR(init[23:7:-1]),
                    ).encryptor()
                    time.sleep(delay)
                    client.sendall(
                        encrypt.update(struct.pack("<I", len(reply)) + reply)
                    )
            except OSError:
                pass

        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            listener.settimeout(3)
            thread = threading.Thread(target=serve, args=(listener,), daemon=True)
            thread.start()
            try:
                yield listener.getsockname()[1], received
            finally:
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())

    def test_real_worker_success_delay_and_wrong_key(self) -> None:
        for delay, wrong_key, expected in (
            (0, False, 0),
            (0.15, False, 1),
            (0.4, False, 2),
            (0, True, 2),
        ):
            with self.subTest(delay=delay, wrong_key=wrong_key):
                self.path.write_text(
                    "ab" * 16 if wrong_key else self.secret, encoding="utf-8"
                )
                with self.local_proxy(delay) as (port, received):
                    code, output = self.run_main(
                        [
                            "-H",
                            "127.0.0.1",
                            "-p",
                            str(port),
                            "--dc",
                            "4",
                            "--secret-file",
                            str(self.path),
                            "-w",
                            "0.1",
                            "-c",
                            "0.3",
                        ]
                    )
                self.assertEqual(code, expected)
                self.assertNotIn("ab" * 16, output)
                if not wrong_key:
                    self.assertEqual(received, [4])
                    self.assertIn("| time=", output)
