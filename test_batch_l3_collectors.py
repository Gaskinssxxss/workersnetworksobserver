import json
import subprocess
import unittest
from unittest.mock import patch

import ip_protocol_metric_collector as metrics
import network_tunnel_collector as tunnels
import routing_policy_collector as policy


def completed(stdout):
    return subprocess.CompletedProcess([], 0, stdout, "")


class PolicyTests(unittest.TestCase):
    @patch.object(policy.socket, "gethostname", return_value="host-x")
    @patch.object(policy.subprocess, "run")
    def test_ipv4_ipv6_rules_and_native_vrf_marker(self, run, _host):
        run.side_effect = [completed('[{"priority":100,"fwmark":"0x1","table":100,"l3mdev":true}]'),
                           completed('[{"priority":200,"src":"2001:db8::/32","table":200}]')]
        evidence, records = policy.collect()
        self.assertEqual(len(records), 2)
        self.assertEqual(records[0]["routing_policy_data"]["l3mdev"], True)
        self.assertEqual(records[1]["family"], "IPv6")
        self.assertEqual(records[0]["host"], "host-x")
        self.assertEqual(len(evidence), 2)
        self.assertEqual(run.call_args_list[0].args[0], policy.COMMANDS["IPv4"])
        self.assertEqual(run.call_args_list[1].args[0], policy.COMMANDS["IPv6"])

    @patch.object(policy.subprocess, "run", side_effect=FileNotFoundError("ip missing"))
    def test_missing_ip_fails_explicitly(self, _run):
        with self.assertRaisesRegex(RuntimeError, "ip missing"):
            policy.collect()


class TunnelTests(unittest.TestCase):
    @patch.object(tunnels.socket, "gethostname", return_value="host-t")
    @patch.object(tunnels.subprocess, "run")
    def test_discovery_preserves_native_tunnel_attributes_and_ignores_other_links(self, run, _host):
        raw = json.dumps([
            {"ifname": "gre0", "linkinfo": {"info_kind": "gre", "info_data": {"local": "192.0.2.1", "ttl": 64}}},
            {"ifname": "eth0", "linkinfo": {"info_kind": "bridge"}},
        ])
        run.return_value = completed(raw)
        evidence, records = tunnels.collect()
        self.assertEqual(evidence, raw)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["object_type"], "network_tunnel")
        self.assertEqual(records[0]["tunnel_type"], "gre")
        self.assertEqual(records[0]["tunnel_data"]["linkinfo"]["info_data"]["ttl"], 64)
        self.assertEqual(run.call_args.kwargs["timeout"], 10)

    @patch.object(tunnels.subprocess, "run", return_value=completed('[{"ifname":"eth0"}]'))
    def test_success_with_no_tunnel_types_is_empty_snapshot(self, _run):
        _, records = tunnels.collect()
        self.assertEqual(records, [])

    @patch.object(tunnels.subprocess, "run", side_effect=subprocess.CalledProcessError(1, tunnels.COMMAND, stderr="unsupported"))
    def test_tunnel_command_failure_is_explicit(self, _run):
        with self.assertRaisesRegex(RuntimeError, "unsupported"):
            tunnels.collect()


class MetricTests(unittest.TestCase):
    def test_keeps_ip_and_icmp_names_and_values_only(self):
        records = metrics.parse_counters(
            '{"kernel":{"IpInReceives":123,"Ip6InReceives":45,"IcmpInMsgs":6,"Icmp6InMsgs":7,"TcpInSegs":999}}',
            "host-m", "time",
        )
        self.assertEqual([item["counter_name"] for item in records],
                         ["IpInReceives", "Ip6InReceives", "IcmpInMsgs", "Icmp6InMsgs"])
        self.assertEqual([item["value"] for item in records], [123, 45, 6, 7])
        self.assertEqual([item["family"] for item in records], ["IPv4", "IPv6", "IPv4", "IPv6"])
        self.assertEqual([item["protocol"] for item in records], ["IP", "IP", "ICMP", "ICMP"])

    @patch.object(metrics.socket, "gethostname", return_value="host-m")
    @patch.object(metrics.subprocess, "run")
    def test_absolute_json_command_and_missing_utility(self, run, _host):
        run.return_value = completed('{"kernel":{"IpInReceives":123}}')
        raw, records = metrics.collect()
        self.assertEqual(raw, '{"kernel":{"IpInReceives":123}}')
        self.assertEqual(records[0]["value"], 123)
        self.assertEqual(run.call_args.args[0], metrics.COMMAND)
        self.assertTrue(run.call_args.kwargs["check"])
        self.assertTrue(run.call_args.kwargs["timeout"] <= 10)
        run.side_effect = FileNotFoundError("nstat missing")
        with self.assertRaisesRegex(RuntimeError, "nstat missing"):
            metrics.collect()


if __name__ == "__main__":
    unittest.main()
