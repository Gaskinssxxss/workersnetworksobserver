# Workers’ Network Observatory

### Modular Network Telemetry Collection & Classification

A portfolio of small, read-only Python automations for collecting server network telemetry from Linux and existing application sources.

Workers’ Network Observatory organizes observations by network object and layer. Each task can be run from the command line and emits structured JSONL for downstream tools.

## What’s inside

The release contains 33 task scopes, grouped by domain:

| Domain | Tasks | Coverage |
|---|---|---|
| **L3 · IP networking** | 01–05 | Addresses, routes, policy rules, tunnels, IP protocol counters |
| **L4 · Transport** | 06–13 | Endpoints, TCP connections, UDP sockets, conntrack, nftables, transport performance |
| **L5–L7 · Application networking** | 15, 17–21, 24–25, 27 | TLS, HTTP, API/RPC, services, discovery, application sessions, proxy and upstream observations, resilience |
| **Runtime & virtualization** | 28–34 | Namespaces, process sockets, VMs, containers, Kubernetes, service mesh |
| **Observability context** | 36–37, 39–40 | Telemetry sources, collection targets, host context, collection status |

For the exact task-to-module mapping and source requirements, see [Automation Coverage](AUTOMATION_COVERAGE.md).

## Run a task

**Requirements:** Linux and Python 3.11 or newer. Collectors use the Python standard library; each task may also need its native Linux utility, application source, or read-only permission.

```bash
python3 ip_address_collector.py --help
python3 ip_address_collector.py
```

Other examples:

```bash
python3 route_collector.py
python3 nftables_snapshot_collector.py --help
python3 kubernetes_networking_collector.py --namespace payments
```

There is no master collector or scheduler. Run the task you need; use `--help` to see its inputs and optional evidence output.

## Output

- **stdout:** one telemetry record per JSONL line
- **stderr:** structured collection status, including source outcomes
- **Raw evidence:** optional and controlled by task-specific arguments

Collection outcomes distinguish `AVAILABLE`, `EMPTY`, `UNAVAILABLE`, and `PERMISSION_DENIED`. Missing tools or access are reported by the collector; the project does not require `sudo` or change host network configuration.

## Validation

The 33 included task scopes are marked `VALIDATED` in [the validation summary](VALIDATION_STATUS.json). That label refers to the named sources and scenarios recorded for this project; it is not a universal guarantee across all Linux distributions, kernels, applications, cloud providers, or production configurations.

Collectors that read snapshots report the source state at collection time; they do not create a complete lifecycle history. Task 33 collects Kubernetes NetworkPolicy objects. Its validation does not cover dataplane enforcement.

Raw scenario evidence is maintained separately from this code release. The summary preserves the evidence references; review the referenced artifacts and remove environment-specific details before publishing them.

## License

MIT. See [LICENSE](LICENSE).
