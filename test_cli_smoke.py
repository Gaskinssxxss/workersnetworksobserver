"""Smoke-test public collector entry points retained in this release."""
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ENTRYPOINTS = ['application_resilience_collector.py', 'application_session_collector.py', 'collection_health_collector.py', 'collection_target_collector.py', 'conntrack_collector.py', 'container_network_collector.py', 'ip_address_collector.py', 'ip_protocol_metric_collector.py', 'kubernetes_network_collector.py', 'kubernetes_network_policy_collector.py', 'kubernetes_networking_collector.py', 'load_balancing_collector.py', 'network_namespace_collector.py', 'network_services_collector.py', 'network_tunnel_collector.py', 'nftables_snapshot_collector.py', 'process_networking_collector.py', 'proxy_networking_collector.py', 'route_collector.py', 'routing_policy_collector.py', 'service_discovery_collector.py', 'service_mesh_collector.py', 'tcp_connection_collector.py', 'telemetry_context_collector.py', 'telemetry_source_collector.py', 'transport_endpoint_collector.py', 'transport_performance_collector.py', 'udp_quic_collector.py', 'virtual_machine_network_collector.py']

class CliSmokeTests(unittest.TestCase):
    def test_all_collector_entrypoints_show_help(self):
        for entrypoint in ENTRYPOINTS:
            with self.subTest(entrypoint=entrypoint):
                result = subprocess.run([sys.executable, str(ROOT / entrypoint), "--help"],
                                        capture_output=True, text=True, timeout=5)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("usage:", result.stdout.lower())

if __name__ == "__main__":
    unittest.main()
