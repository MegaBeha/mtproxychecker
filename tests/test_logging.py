import io
import logging
import unittest
from logging import LogRecord

from mtproxy_checker import check_proxy
from mtproxy_checker.cli import setup_logging
from mtproxy_checker.logging import (
    LOGGER_NAME,
    StructuredFormatter,
    configure_cli_logging,
    get_logger,
)


class LoggingTests(unittest.TestCase):
    def tearDown(self) -> None:
        package_logger = get_logger()
        package_logger.handlers.clear()
        package_logger.addHandler(logging.NullHandler())
        package_logger.propagate = False
        package_logger.setLevel(logging.NOTSET)

    def test_library_call_does_not_configure_root_logging(self) -> None:
        root = logging.getLogger()
        before_handlers = list(root.handlers)
        before_level = root.level

        result = check_proxy("https://t.me/proxy?server=example.com")

        self.assertFalse(result.ok)
        self.assertEqual(list(root.handlers), before_handlers)
        self.assertEqual(root.level, before_level)

    def test_cli_setup_configures_only_package_logger(self) -> None:
        setup_logging(debug=True, trace=False)
        package_logger = get_logger()

        self.assertEqual(package_logger.name, LOGGER_NAME)
        self.assertEqual(package_logger.level, logging.INFO)
        self.assertFalse(package_logger.propagate)
        self.assertEqual(len(package_logger.handlers), 1)

    def test_structured_text_logs_include_event_fields(self) -> None:
        stream = io.StringIO()
        configure_cli_logging(logging.INFO, stream=stream)

        get_logger("tests").info(
            "hello",
            extra={"event": "unit_test_event", "target_host": "example.com"},
        )

        output = stream.getvalue()
        self.assertIn("event=unit_test_event", output)
        self.assertIn("target_host=example.com", output)
        self.assertIn("message=hello", output)

    def test_json_logs_and_value_formatting(self) -> None:
        stream = io.StringIO()
        configure_cli_logging(logging.INFO, json_logs=True, stream=stream)

        get_logger("json").info(
            "hello world",
            extra={"event": "json_event", "count": 3},
        )

        output = stream.getvalue()
        self.assertIn('"event": "json_event"', output)
        self.assertIn('"count": 3', output)

        formatter = StructuredFormatter()

        self.assertEqual(formatter._format_value(""), '""')
        self.assertEqual(formatter._format_value("hello world"), '"hello world"')
        self.assertEqual(formatter._format_value(3), "3")

    def test_structured_formatter_without_extra_fields(self) -> None:
        formatter = StructuredFormatter()
        record = LogRecord(
            name="mtproxy_checker.test",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="plain",
            args=(),
            exc_info=None,
        )

        self.assertIn("message=plain", formatter.format(record))

    def test_get_logger_accepts_full_package_name(self) -> None:
        logger = get_logger("mtproxy_checker.already_qualified")

        self.assertEqual(logger.name, "mtproxy_checker.already_qualified")
