# Workers’ Network Observatory

The project is a set of independently executable Python modules. Each module writes telemetry JSONL to stdout and one task-status JSONL record to stderr; source failures are reported as `UNAVAILABLE` or `PERMISSION_DENIED`, successful empty snapshots as `EMPTY`. There is no master collector or scheduler.

## Modules by object scope

| Task | Object | Independent entry point | Source/limit |
| 01 | IP addressing | `ip_address_collector.py` | `ip -j address show` |
| 02 | Routing | `route_collector.py` | `ip -4/-6 -j route show table all` |
| 03 | Policy routing | `routing_policy_collector.py` | `ip -4/-6 -j rule show` |
| 04 | Network tunneling | `network_tunnel_collector.py` | `ip -d -j link show` |
| 05 | IP protocol operations | `ip_protocol_metric_collector.py` | `nstat -a -s -j` |
| 06 | Transport endpoints | `transport_endpoint_collector.py` | `ss` snapshots |
| 07 | TCP connections | `tcp_connection_collector.py` | `ss` snapshots; no lifecycle inference |
| 08 | UDP and QUIC | `udp_quic_collector.py` | `ss` UDP; QUIC only with explicit native source |
| 09 | Connection tracking | `conntrack_collector.py` | `conntrack -L`; unavailable when utility/permission is missing |
| 10–12 | NAT, firewall, enforcement | `nftables_snapshot_collector.py` | One read-only nftables JSON snapshot |
| 13 | Transport performance | `transport_performance_collector.py` | `ss` and `nstat` snapshots/counters |
| 15, 17, 18 | TLS, HTTP, API/RPC | `application_log_collectors.py` | Structured JSONL via `--log` or JSON `MESSAGE` in journald via `--journal-unit` / `--journal-identifier`; whitelist prevents payload capture |
| 19 | Network services | `network_services_collector.py` | `systemctl`, `journalctl`, and `ss` |
| 20 | Service discovery | `service_discovery_collector.py` | Explicit JSONL `--log`, structured journald `--journal-unit` / `--journal-identifier`, or opt-in local `--avahi` browse |
| 21 | Application sessions | `application_session_collector.py` | Explicit structured JSONL or structured journald; only session identity/state/event fields |
| 24 | Proxy networking | `proxy_networking_collector.py` | Explicit structured JSONL or structured journald; native Envoy admin GET via `--admin-url` |
| 25 | Load balancing | `load_balancing_collector.py` | Explicit structured JSONL or structured journald; native Envoy admin GET via `--admin-url` |
| 27 | Application resilience | `application_resilience_collector.py` | Explicit structured JSONL or structured journald |
| 28 | Network namespaces | `network_namespace_collector.py` | `ip -j netns list`, `/proc/<pid>/ns/net`; snapshots only |
| 29 | Process networking | `process_networking_collector.py` | `ss -H -n -tup -e -p`; process association only when `ss` exposes it |
| 30 | VM networking | `virtual_machine_network_collector.py` | Read-only local `virsh --connect qemu:///system` domain/interface inventory |
| 31 | Container networking | `container_network_collector.py` | Docker list/inspect through the local Unix socket; reports daemon permission failures |
| 32 | Kubernetes networking | `kubernetes_networking_collector.py` | `kubectl` JSON for pods, Services, EndpointSlices; namespace required |
| 33 | Kubernetes network security | `kubernetes_network_policy_collector.py` | `kubectl` JSON for NetworkPolicies; namespace required |
| 34 | Service mesh | `service_mesh_collector.py` | Explicit loopback Envoy admin URL; only GET `/config_dump`, whitelisted summaries |
| 36 | Telemetry sources | `telemetry_source_collector.py` | Local module, executable, and candidate source-path inventory |
| 37 | Collection targets | `collection_target_collector.py` | Explicit `--target TYPE:IDENTIFIER`; validates namespace/PID/unit/container/VM identities |
| 39 | Telemetry context | `telemetry_context_collector.py` | Host, machine, process, cgroup, and namespace identity snapshot |
| 40 | Collection health | `collection_health_collector.py` | Summarizes caller-supplied task-status JSONL; runs no other collectors |
