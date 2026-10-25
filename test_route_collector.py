import json
import subprocess
import unittest
from unittest.mock import call, patch

import route_collector as collector


class ParseRoutesTests(unittest.TestCase):
    def test_ipv4_default_and_regular_route(self):
        raw = json.dumps([
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "protocol": "static", "metric": 10, "table": "main"},
            {"dst": "198.51.100.0/24", "dev": "eth1", "proto": "kernel", "metric": 50},
        ])
        records = collector.parse_routes(raw, "IPv4", "host-a", "time", "ip -4 -j route show table all")
        self.assertEqual(records[0]["routing_data"], {
            "destination": "default", "table": "main", "gateway": "192.0.2.1",
            "interface": "eth0", "metric": 10, "protocol": "static",
        })
        self.assertEqual(records[1]["routing_data"], {
            "destination": "198.51.100.0/24", "interface": "eth1",
            "protocol": "kernel", "metric": 50,
        })
        self.assertEqual(records[0]["layer"], "L3")
        self.assertEqual(records[0]["object_type"], "route")
        self.assertEqual(records[0]["host"], "host-a")
        self.assertEqual(records[0]["timestamp"], "time")

    def test_ipv6_and_absent_optional_fields(self):
        records = collector.parse_routes(
            '[{"dst":"default","nexthops":[{"gateway":"2001:db8::1","dev":"eth0"}]}]',
            "IPv6", "host-b", "time", "ip -6 -j route show table all",
        )
        self.assertEqual(records[0]["family"], "IPv6")
        self.assertEqual(records[0]["routing_data"], {
            "destination": "default",
            "next_hops": [{"gateway": "2001:db8::1", "dev": "eth0"}],
        })
        self.assertEqual(records[0]["source"], "ip -6 -j route show table all")


class CollectTests(unittest.TestCase):
    @patch.object(collector.socket, "gethostname", return_value="mock-host")
    @patch.object(collector.subprocess, "run")
    def test_runs_both_family_commands(self, run, _hostname):
        run.side_effect = [
            subprocess.CompletedProcess([], 0, '[{"dst":"default","dev":"eth0"}]', ""),
            subprocess.CompletedProcess([], 0, '[{"dst":"default","dev":"eth1"}]', ""),
        ]
        evidence, records = collector.collect()
        self.assertEqual(run.call_args_list, [
            call(collector.COMMANDS["IPv4"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10),
            call(collector.COMMANDS["IPv6"], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=10),
        ])
        self.assertEqual(len(records), 2)
        self.assertEqual(records[1]["host"], "mock-host")
        self.assertIn("IPv4", evidence)
        self.assertIn("IPv6", evidence)

    @patch.object(collector.subprocess, "run")
    def test_reports_command_failure_with_per_source_status(self, run):
        run.side_effect = [
            subprocess.CalledProcessError(2, collector.COMMANDS["IPv4"], stderr="permission denied"),
            subprocess.CompletedProcess([], 0, "[]", ""),
        ]
        _, records, sources, status, detail = collector.collect_detailed()
        self.assertEqual(records, [])
        self.assertEqual(status, "PERMISSION_DENIED")
        self.assertEqual([item["status"] for item in sources], ["PERMISSION_DENIED", "EMPTY"])
        self.assertIn("permission denied", detail)


if __name__ == "__main__":
    unittest.main()
