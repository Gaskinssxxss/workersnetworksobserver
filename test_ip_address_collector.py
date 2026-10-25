import json
import unittest
from unittest.mock import patch

import ip_address_collector as collector


class ParseSnapshotTests(unittest.TestCase):
    def test_emits_ipv4_and_ipv6_records_and_skips_other_families(self):
        raw = json.dumps([
            {"ifname": "eth0", "addr_info": [
                {"family": "inet", "local": "192.0.2.10", "prefixlen": 24},
                {"family": "inet6", "local": "2001:db8::10", "prefixlen": 64},
                {"family": "link", "local": "00:11:22:33:44:55", "prefixlen": 48},
            ]},
            {"ifname": "lo", "addr_info": []},
        ])
        records = collector.parse_snapshot(raw, "host-a", "2026-10-25T00:00:00+00:00")
        self.assertEqual([r["address"] for r in records], ["192.0.2.10", "2001:db8::10"])
        self.assertEqual([r["family"] for r in records], ["IPv4", "IPv6"])
        for record in records:
            self.assertEqual(record["layer"], "L3")
            self.assertEqual(record["object_type"], "ip_address")
            self.assertEqual(record["interface"], "eth0")
            self.assertEqual(record["host"], "host-a")
            self.assertEqual(record["source"], "ip -j address show")
            self.assertEqual(record["timestamp"], "2026-10-25T00:00:00+00:00")

    def test_missing_address_fields_are_skipped(self):
        raw = '[{"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.1"}]}]'
        self.assertEqual(collector.parse_snapshot(raw, "h", "t"), [])


class CollectTests(unittest.TestCase):
    @patch.object(collector.socket, "gethostname", return_value="mock-host")
    @patch.object(collector.subprocess, "run")
    def test_collect_uses_existing_read_only_command(self, run, _hostname):
        run.return_value.stdout = '[{"ifname":"eth0","addr_info":[{"family":"inet","local":"198.51.100.3","prefixlen":25}]}]'
        raw, records = collector.collect()
        run.assert_called_once_with(
            ["ip", "-j", "address", "show"], check=True,
            stdout=collector.subprocess.PIPE, stderr=collector.subprocess.PIPE, text=True, timeout=10,
        )
        self.assertEqual(json.loads(raw)[0]["ifname"], "eth0")
        self.assertEqual(records[0]["address"], "198.51.100.3")
        self.assertEqual(records[0]["host"], "mock-host")
        self.assertTrue(records[0]["timestamp"].endswith("+00:00"))


if __name__ == "__main__":
    unittest.main()
