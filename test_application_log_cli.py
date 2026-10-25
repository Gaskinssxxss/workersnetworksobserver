import contextlib
import io
import json
import tempfile
import unittest
from unittest import mock
from pathlib import Path

import application_log_collectors
import application_object_log_source as object_logs
from telemetry_common import CollectionFailure


class ApplicationLogCliTests(unittest.TestCase):
    def test_journald_json_message_is_whitelisted_and_bounded(self):
        native = json.dumps({"MESSAGE": json.dumps({"method": "GET", "status": 204,
                                                        "protocol": "HTTP/1.1", "body": "secret"}),
                             "__REALTIME_TIMESTAMP": "1792945745626168", "__CURSOR": "cursor-1"})
        with mock.patch.object(application_log_collectors, "LOG_PATHS", ()), \
             mock.patch.object(object_logs, "run_readonly", return_value=native) as run_mock:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = application_log_collectors.main(["17", "--journal-identifier", "nginx",
                                                        "--since=-5m"])
        records = [json.loads(line) for line in out.getvalue().splitlines()]
        status = json.loads(err.getvalue().splitlines()[-1])
        self.assertEqual(code, 0)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["application_data"], {"method": "GET", "status": 204,
                                                           "protocol": "HTTP/1.1"})
        self.assertEqual(records[0]["event_cursor"], "cursor-1")
        self.assertEqual(status["status"], "AVAILABLE")
        command = run_mock.call_args.args[0]
        self.assertIn("--identifier=nginx", command)
        self.assertIn("--since=-5m", command)

    def test_explicit_empty_journal_source_reports_empty(self):
        with mock.patch.object(application_log_collectors, "LOG_PATHS", ()), \
             mock.patch.object(object_logs, "run_readonly", return_value=""):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = application_log_collectors.main(["17", "--journal-identifier", "nginx"])
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(json.loads(err.getvalue())["status"], "EMPTY")

    def test_journal_permission_failure_is_reported_without_execution_failure(self):
        with mock.patch.object(application_log_collectors, "LOG_PATHS", ()), \
             mock.patch.object(object_logs, "run_readonly",
                               side_effect=CollectionFailure("PERMISSION_DENIED", "journal access denied")):
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = application_log_collectors.main(["17", "--journal-unit", "nginx.service"])
        status = json.loads(err.getvalue())
        self.assertEqual(code, 0)
        self.assertEqual(status["status"], "PERMISSION_DENIED")
        self.assertEqual(status["source_status"][0]["status"], "PERMISSION_DENIED")

    def test_explicit_native_jsonl_source_for_tls_http_and_rpc(self):
        rows = [
            {"method": "GET", "status": 200, "protocol": "HTTP/1.1", "ssl_protocol": "TLSv1.3",
             "ssl_cipher": "TLS_AES_128_GCM_SHA256", "timestamp": "2026-10-25T00:00:00Z"},
            {"grpc_method": "/health.v1.Health/Check", "grpc_status": 0, "duration_ms": 2},
        ]
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "access.jsonl"
            source.write_text("".join(json.dumps(row) + "\n" for row in rows))
            for task, expected_type, count in (("15", "tls_metadata", 1), ("17", "http_request_response", 1),
                                                ("18", "api_rpc_telemetry", 1)):
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = application_log_collectors.main([task, "--log", str(source)])
                self.assertEqual(code, 0)
                records = [json.loads(line) for line in out.getvalue().splitlines()]
                status = json.loads(err.getvalue().splitlines()[-1])
                self.assertEqual(len(records), count)
                self.assertEqual(records[0]["object_type"], expected_type)
                self.assertEqual(status["status"], "AVAILABLE")
                self.assertEqual(status["source_status"][0]["source"], str(source))

    def test_explicit_missing_source_is_unavailable_not_execution_failure(self):
        with tempfile.TemporaryDirectory() as td:
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = application_log_collectors.main(["17", "--log", str(Path(td) / "absent.jsonl")])
            self.assertEqual(code, 0)
            self.assertEqual(out.getvalue(), "")
            self.assertEqual(json.loads(err.getvalue())["status"], "UNAVAILABLE")

    def test_empty_tls_columns_do_not_classify_plain_http_rows_as_tls(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td) / "access.jsonl"
            source.write_text(
                '{"method":"GET","status":200,"ssl_protocol":"","ssl_cipher":""}\n'
                '{"method":"GET","status":200,"ssl_protocol":"TLSv1.3","ssl_cipher":"AES"}\n'
            )
            out, err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = application_log_collectors.main(["15", "--log", str(source)])
            self.assertEqual(code, 0)
            records = [json.loads(line) for line in out.getvalue().splitlines()]
            self.assertEqual(len(records), 1)
            self.assertEqual(records[0]["application_data"]["ssl_protocol"], "TLSv1.3")


if __name__ == "__main__":
    unittest.main()
