"""Bounded reader for task-specific native structured application JSONL sources."""

import argparse
import datetime as dt
import ipaddress
import json
import socket
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from telemetry_common import CollectionFailure, aggregate_status, execution_failure, finish, run_readonly


SPECS = {
    "20": ("service_discovery_observation", ("service", "service_id", "instance", "registration_id", "endpoint", "address", "host", "port", "protocol", "event", "action", "timestamp", "ttl", "namespace"), (("service", "service_id", "instance", "registration_id"), ("endpoint", "address", "event", "action"))),
    "21": ("application_session_event", ("session_id", "session_type", "session_state", "session_event", "event", "service", "state", "timestamp", "duration_ms", "idle_seconds"), (("session_id", "session_type"), ("session_state", "session_event", "event", "state"))),
    "24": ("proxy_network_observation", ("proxy", "listener", "virtual_host", "route", "upstream", "backend", "local_endpoint", "remote_endpoint", "state", "event", "status", "duration_ms", "timestamp"), (("proxy", "listener", "virtual_host", "route", "upstream", "backend"), ("state", "event", "status"))),
    "25": ("load_balancer_observation", ("cluster", "upstream", "backend", "endpoint", "address", "health_state", "healthy", "status", "check_time", "event", "timestamp"), (("cluster", "upstream", "backend", "endpoint", "address"), ("health_state", "healthy", "status", "event"))),
    "27": ("application_resilience_observation", ("service", "policy", "operation", "retry_count", "attempt", "timeout_ms", "deadline_ms", "circuit_breaker", "circuit_state", "state", "event", "result", "status_code", "timestamp", "duration_ms"), (("service", "policy", "operation", "circuit_breaker"), ("retry_count", "attempt", "timeout_ms", "deadline_ms", "circuit_state", "state", "event", "result", "status_code"))),
}

JOURNAL_SPECS = {
    "15": ("tls_metadata", ("tls_version", "ssl_protocol", "tls_cipher", "ssl_cipher"),
           (("tls_version", "ssl_protocol", "tls_cipher", "ssl_cipher"),)),
    "17": ("http_request_response", ("method", "request_method", "status", "status_code", "protocol",
                                       "duration", "duration_ms", "request_time", "bytes_sent", "body_bytes_sent"),
           (("method", "request_method"), ("status", "status_code"))),
    "18": ("api_rpc_telemetry", ("rpc_method", "grpc_method", "service", "grpc_service", "grpc_status",
                                   "rpc_status", "status_code", "duration", "duration_ms"),
           (("rpc_method", "grpc_method", "service", "grpc_service"),)),
    **{task: (spec[0], spec[1], spec[2]) for task, spec in SPECS.items()},
}


def collect_journal_logs(task_id, units=(), identifiers=(), since="-1h", line_limit=500,
                         raw_path=None, append_raw=False):
    """Read only bounded systemd journal JSON and emit allowlisted application fields."""
    task_id = str(task_id)
    if task_id not in JOURNAL_SPECS:
        raise ValueError(f"journal application source is unsupported for task {task_id}")
    units, identifiers = tuple(units), tuple(identifiers)
    if not units and not identifiers:
        return [], [{"source": "journalctl application filter", "status": "UNAVAILABLE",
                     "detail": "supply --journal-unit or --journal-identifier"}], ""
    if not 1 <= int(line_limit) <= 500:
        raise ValueError("journal line limit must be between 1 and 500")
    object_type, fields, required_groups = JOURNAL_SPECS[task_id]
    host, timestamp = socket.gethostname(), dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records, statuses, safe_lines, details = [], [], [], []
    selectors = [("unit", value) for value in units] + [("identifier", value) for value in identifiers]
    for selector, value in selectors:
        if not value or len(value) > 256 or "\x00" in value:
            statuses.append({"source": f"journalctl {selector}", "status": "UNAVAILABLE",
                             "detail": "invalid or empty journal filter"})
            continue
        command = ["journalctl", f"--{selector}={value}", f"--since={since}", "--output=json",
                   "--no-pager", "--lines", str(int(line_limit))]
        source = " ".join(command)
        try:
            output = run_readonly(command, timeout=10)
        except CollectionFailure as exc:
            statuses.append({"source": source, "status": exc.status, "detail": str(exc)})
            details.append(f"{source} {exc.status}: {exc}")
            continue
        valid, matched = 0, 0
        for line in output.splitlines():
            try:
                journal_row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(journal_row, dict):
                continue
            valid += 1
            message = journal_row.get("MESSAGE")
            if not isinstance(message, str):
                continue
            try:
                item = json.loads(message)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            data = {key: item[key] for key in fields if key in item and
                    isinstance(item[key], (str, int, float, bool)) and item[key] not in ("", None)}
            if not all(any(key in data for key in group) for group in required_groups):
                continue
            event_time = next((item[key] for key in ("@timestamp", "timestamp", "time")
                               if key in item and isinstance(item[key], (str, int, float))),
                              journal_row.get("__REALTIME_TIMESTAMP"))
            record = {"layer": "L6" if task_id == "15" else "L7", "object_type": object_type,
                      "host": host, "timestamp": timestamp, "source": source,
                      "signal_type": "systemd_journal_application_log", "event_time": event_time,
                      "application_data": data}
            if "__CURSOR" in journal_row:
                record["event_cursor"] = journal_row["__CURSOR"]
            records.append(record)
            safe_lines.append(json.dumps({"source": source, "event_time": event_time,
                                          "safe_fields": data}, separators=(",", ":")))
            matched += 1
        statuses.append({"source": source, "status": "AVAILABLE" if matched else "EMPTY",
                         **({"detail": "journal rows had no matching structured application fields"}
                            if valid and not matched else {})})
    if raw_path and safe_lines:
        path = Path(raw_path)
        prior = path.read_text(encoding="utf-8") if append_raw and path.exists() else ""
        path.write_text(prior + "\n".join(safe_lines) + "\n", encoding="utf-8")
    return records, statuses, "; ".join(details) or None


def _loopback_base(value):
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme != "http" or not parsed.hostname or not parsed.port:
        raise ValueError("Envoy admin URL must be explicit http://localhost:<port> or loopback IP")
    if parsed.hostname.lower() != "localhost":
        try:
            if not ipaddress.ip_address(parsed.hostname).is_loopback:
                raise ValueError("non-loopback Envoy admin endpoint rejected")
        except ValueError as exc:
            if str(exc) == "non-loopback Envoy admin endpoint rejected":
                raise
            raise ValueError("Envoy admin URL must use localhost or a loopback IP") from exc
    return value.rstrip("/")


def _extract_safe(value, names=None, endpoints=None):
    names = names if names is not None else set()
    endpoints = endpoints if endpoints is not None else set()
    if isinstance(value, dict):
        for key, item in value.items():
            if key in ("name", "cluster_name", "route_config_name") and isinstance(item, str):
                names.add(item)
            if key == "socket_address" and isinstance(item, dict):
                address, port = item.get("address"), item.get("port_value")
                if address is not None:
                    endpoints.add((address, port))
            _extract_safe(item, names, endpoints)
    elif isinstance(value, list):
        for item in value:
            _extract_safe(item, names, endpoints)
    return sorted(names), sorted(endpoints, key=lambda item: (item[0], item[1] or 0))


def collect_envoy(task_id, admin_url, raw_path=None):
    path = {"24": "/config_dump", "25": "/clusters?format=json"}[str(task_id)]
    base = _loopback_base(admin_url)
    url = base + path
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            raw = response.read(4_194_305)
            if len(raw) > 4_194_304:
                raise ValueError("Envoy admin response exceeds 4 MiB bound")
        document = json.loads(raw)
    except urllib.error.HTTPError as exc:
        status = "PERMISSION_DENIED" if exc.code in (401, 403) else "UNAVAILABLE"
        return [], status, [{"source": url, "status": status, "detail": f"HTTP {exc.code}"}], None
    except (OSError, urllib.error.URLError, ValueError, json.JSONDecodeError) as exc:
        detail = str(exc)
        status = "PERMISSION_DENIED" if "permission denied" in detail.lower() or "forbidden" in detail.lower() else "UNAVAILABLE"
        return [], status, [{"source": url, "status": status, "detail": detail}], None

    host = socket.gethostname()
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records = []
    if str(task_id) == "24":
        for section in document.get("configs", []):
            section_type = section.get("@type", "unknown")
            if "Listener" in section_type:
                object_type, item_kind = "proxy_listener", "listener"
            elif "Route" in section_type:
                object_type, item_kind = "proxy_route", "route"
            elif "Cluster" in section_type:
                object_type, item_kind = "proxy_upstream_configuration", "cluster"
            else:
                continue
            names, endpoints = _extract_safe(section)
            records.append({"layer": "L7", "object_type": object_type, "host": host, "timestamp": timestamp,
                            "source": url, "signal_type": "native_proxy_configuration_snapshot",
                            "native_data": {"section_type": section_type, "resource_names": names,
                                            "socket_endpoints": endpoints, "configuration_kind": item_kind}})
    elif str(task_id) == "25":
        for cluster in document.get("cluster_statuses", []):
            name = cluster.get("name")
            hosts = cluster.get("host_statuses", [])
            if not hosts:
                records.append({"layer": "L7", "object_type": "load_balancer_observation", "host": host,
                                "timestamp": timestamp, "source": url, "signal_type": "native_upstream_health_snapshot",
                                "upstream_data": {"cluster": name}})
            for endpoint in hosts:
                address = endpoint.get("address")
                health = endpoint.get("health_status")
                upstream_data = {"cluster": name, "endpoint": address}
                if "health_status" in endpoint:
                    upstream_data["health_state"] = health
                for field in ("weight", "priority"):
                    if field in endpoint:
                        upstream_data[field] = endpoint[field]
                records.append({"layer": "L7", "object_type": "load_balancer_observation", "host": host,
                                "timestamp": timestamp, "source": url, "signal_type": "native_upstream_health_snapshot",
                                "upstream_data": upstream_data})
    else:
        raise ValueError("unsupported native Envoy task")
    status = "AVAILABLE" if records else "EMPTY"
    source_status = [{"source": url, "status": status}]
    safe_evidence = json.dumps(records, indent=2) + "\n" if raw_path else None
    return records, status, source_status, safe_evidence


def collect_object_logs(task_id, paths, raw_path=None):
    obj_type, fields, required_groups = SPECS[str(task_id)]
    host = socket.gethostname()
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records, raw_rows, source_status = [], [], []
    paths = tuple(Path(p) for p in paths)
    if not paths:
        source_status.append({"source": "native-structured-JSONL (--log)", "status": "UNAVAILABLE",
                              "detail": "no native structured source path supplied"})
    for path in paths:
        if not path.is_file():
            source_status.append({"source": str(path), "status": "UNAVAILABLE", "detail": "source file absent"})
            continue
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                end = stream.tell()
                stream.seek(max(0, end - 1_048_576))
                lines = stream.read(1_048_576).decode("utf-8", errors="replace").splitlines()[-500:]
        except PermissionError as exc:
            source_status.append({"source": str(path), "status": "PERMISSION_DENIED", "detail": str(exc)})
            continue
        except OSError as exc:
            source_status.append({"source": str(path), "status": "UNAVAILABLE", "detail": str(exc)})
            continue
        parsed = matched = 0
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(item, dict):
                continue
            parsed += 1
            data = {key: item[key] for key in fields if key in item and isinstance(item[key], (str, int, float, bool))}
            if not all(any(key in data for key in group) for group in required_groups):
                continue
            matched += 1
            event_time = next((item[k] for k in ("@timestamp", "timestamp", "time") if isinstance(item.get(k), (str, int, float))), None)
            records.append({"layer": "L7", "object_type": obj_type, "host": host, "timestamp": timestamp,
                            "source": str(path), "signal_type": "native_application_log", "event_time": event_time,
                            "application_data": data})
            raw_rows.append(json.dumps({"source": str(path), "safe_fields": data}, separators=(",", ":")))
        if matched:
            state = "AVAILABLE"
        elif parsed or not lines:
            state = "EMPTY"
        else:
            state = "UNAVAILABLE"
        source_status.append({"source": str(path), "status": state,
                              **({"detail": "source contained no matching object fields"} if state == "EMPTY" and parsed else {}),
                              **({"detail": "no valid structured JSON lines"} if state == "UNAVAILABLE" else {})})
    if raw_path:
        Path(raw_path).write_text("\n".join(raw_rows) + ("\n" if raw_rows else ""), encoding="utf-8")
    status = aggregate_status(records, source_status)
    return records, status, source_status


def main_for_task(task_id, argv=None):
    parser = argparse.ArgumentParser(description=f"Collect Task {task_id} native structured application observations.")
    parser.add_argument("--log", action="append", default=[], help="native JSONL log or metric file (repeatable)")
    parser.add_argument("--admin-url", help="explicit loopback Envoy admin URL for Tasks 24-25")
    parser.add_argument("--raw-evidence")
    parser.add_argument("--journal-unit", action="append", default=[],
                        help="read structured MESSAGE JSON from this systemd unit (repeatable)")
    parser.add_argument("--journal-identifier", action="append", default=[],
                        help="read structured MESSAGE JSON by SYSLOG_IDENTIFIER (repeatable)")
    parser.add_argument("--since", default="-1h", help="bounded journal time filter (default: -1h)")
    args = parser.parse_args(argv)
    try:
        if args.admin_url:
            if str(task_id) not in ("24", "25"):
                return finish(task_id, [], "UNAVAILABLE", "--admin-url is supported for Tasks 24-25 only",
                              [{"source": "--admin-url", "status": "UNAVAILABLE"}])
            records, status, sources, raw = collect_envoy(task_id, args.admin_url, args.raw_evidence)
            if args.raw_evidence and raw is not None:
                Path(args.raw_evidence).write_text(raw, encoding="utf-8")
            return finish(task_id, records, status, source_status=sources)
        if args.journal_unit or args.journal_identifier:
            if args.log:
                records, status, sources = collect_object_logs(task_id, args.log, args.raw_evidence)
            else:
                records, status, sources = [], "EMPTY", []
        else:
            records, status, sources = collect_object_logs(task_id, args.log, args.raw_evidence)
        if args.journal_unit or args.journal_identifier:
            journal_records, journal_sources, detail = collect_journal_logs(
                task_id, args.journal_unit, args.journal_identifier, args.since,
                raw_path=args.raw_evidence, append_raw=bool(args.log))
            records.extend(journal_records)
            sources.extend(journal_sources)
            status = aggregate_status(records, sources)
            if detail:
                sources.append({"source": "journalctl", "status": "UNAVAILABLE", "detail": detail})
    except OSError as exc:
        return execution_failure(task_id, exc, "raw-evidence")
    return finish(task_id, records, status, source_status=sources)
