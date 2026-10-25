import subprocess
import unittest
from unittest.mock import patch

import tcp_connection_collector as tcp
import transport_endpoint_collector as endpoints
import udp_quic_collector as udp


class EndpointParsingTests(unittest.TestCase):
    def test_tcp_listeners_have_local_and_peer_fields(self):
        raw = "tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:*\ntcp LISTEN 0 64 [::]:443 [::]:*"
        records = endpoints.parse(raw, "host", "time")
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["object_type"], "transport_endpoint")
        self.assertEqual(records[0]["local_address"], "0.0.0.0")
        self.assertEqual(records[0]["local_port"], "22")
        self.assertEqual(records[1]["local_address"], "::")
        self.assertEqual(records[1]["remote_port"], "*")
        self.assertEqual(records[0]["raw_record"], raw.splitlines()[0])

    def test_command_is_bounded_and_failures_reported(self):
        with patch.object(endpoints.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            self.assertEqual(endpoints.collect()[1], [])
            self.assertEqual(run.call_args.kwargs["timeout"], 10)
        with patch.object(endpoints.subprocess, "run", side_effect=FileNotFoundError("ss missing")):
            with self.assertRaisesRegex(RuntimeError, "ss missing"):
                endpoints.collect()


class TcpParsingTests(unittest.TestCase):
    def test_listener_partition_avoids_endpoint_duplicate(self):
        raw = "tcp LISTEN 0 128 127.0.0.1:8080 0.0.0.0:*\ntcp ESTAB 0 0 192.0.2.1:5000 198.51.100.2:443"
        records = tcp.parse(raw, "host", "time")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["object_type"], "tcp_connection")
        self.assertEqual(records[0]["state"], "ESTAB")
        self.assertEqual(records[0]["remote_address"], "198.51.100.2")
        self.assertEqual(records[0]["remote_port"], "443")


class UdpParsingTests(unittest.TestCase):
    def test_udp_keeps_socket_state_and_does_not_infer_quic(self):
        raw = "udp UNCONN 0 0 0.0.0.0:443 0.0.0.0:*"
        records = udp.parse(raw, "host", "time")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["object_type"], "udp_socket")
        self.assertEqual(records[0]["local_port"], "443")
        self.assertNotIn("quic", records[0])
        self.assertEqual(records[0]["state"], "UNCONN")

    def test_udp_command_failure_is_reported(self):
        with patch.object(udp.subprocess, "run", side_effect=subprocess.CalledProcessError(1, udp.COMMAND, stderr="not supported")):
            with self.assertRaisesRegex(RuntimeError, "not supported"):
                udp.collect()


if __name__ == "__main__":
    unittest.main()
