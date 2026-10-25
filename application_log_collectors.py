#!/usr/bin/env python3
"""Read existing structured web/application logs without collecting payloads or secrets."""

import argparse
import json
from pathlib import Path
from telemetry_common import aggregate_status, context, execution_failure, finish, make_record, save_raw
from application_object_log_source import collect_journal_logs


LOG_PATHS = ("/var/log/nginx/access.log", "/var/log/apache2/access.log", "/var/log/haproxy.log",
             "/var/log/caddy/access.log", "/var/log/envoy/access.log")
SAFE_HTTP = ("method", "request_method", "status", "status_code", "protocol", "duration", "duration_ms",
             "request_time", "bytes_sent", "body_bytes_sent")
SAFE_TLS = ("tls_version", "ssl_protocol", "tls_cipher", "ssl_cipher")
SAFE_RPC = ("rpc_method", "grpc_method", "service", "grpc_service", "grpc_status", "rpc_status", "status_code",
            "duration", "duration_ms")


def collect_logs(task_id, object_type, kind, paths=LOG_PATHS, raw_path=None, source_status=None):
    host, timestamp = context()
    paths = tuple(paths)
    source_status = source_status if source_status is not None else []
    candidates = [Path(path) for path in paths if Path(path).is_file()]
    for path in paths:
        if not Path(path).is_file():
            source_status.append({"source": str(path), "status": "UNAVAILABLE", "detail": "source file absent"})
    if not candidates:
        return [], "UNAVAILABLE", "no configured structured application log source exists"
    records, safe_evidence, failures = [], [], []
    keys = SAFE_TLS if kind == "tls" else SAFE_RPC if kind == "rpc" else SAFE_HTTP
    for path in candidates:
        try:
            with path.open("rb") as stream:
                stream.seek(0, 2)
                end = stream.tell()
                stream.seek(max(0, end - 1_048_576))
                bounded = stream.read(1_048_576).decode("utf-8", errors="replace")
                lines = bounded.splitlines()[-500:]
        except PermissionError as exc:
            source_status.append({"source": str(path), "status": "PERMISSION_DENIED", "detail": str(exc)})
            failures.append(str(exc))
            continue
        except OSError as exc:
            source_status.append({"source": str(path), "status": "UNAVAILABLE", "detail": str(exc)})
            failures.append(str(exc))
            continue
        path_records, parsed_lines = [], 0
        for line in lines:
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            parsed_lines += 1
            data = {key: item[key] for key in keys if key in item
                    and isinstance(item[key], (str, int, float, bool))
                    and item[key] != "" and item[key] is not None}
            if kind == "http" and not ("method" in data or "request_method" in data) and not ("status" in data or "status_code" in data):
                continue
            if kind == "tls" and not any(key in data for key in SAFE_TLS):
                continue
            if kind == "rpc" and not any(key in data for key in ("rpc_method", "grpc_method", "service", "grpc_service")):
                continue
            layer = "L6" if kind == "tls" else "L7"
            path_records.append(make_record(layer, object_type,
                                       str(path), host, timestamp, signal_type="structured_application_log",
                                       event_time=next((item[key] for key in ("@timestamp", "timestamp", "time")
                                                        if key in item and isinstance(item[key], (str, int, float))), None),
                                       application_data=data))
            safe_evidence.append(json.dumps({"source": str(path), "safe_fields": data}, separators=(",", ":")))
        records.extend(path_records)
        state = "AVAILABLE" if path_records else ("EMPTY" if parsed_lines else "UNAVAILABLE")
        source_status.append({"source": str(path), "status": state,
                              **({"detail": "structured JSON log format unavailable"} if state == "UNAVAILABLE" else {})})
    if raw_path:
        # Evidence is deliberately field-whitelisted so queries, headers, bodies, and credentials cannot leak.
        save_raw(raw_path, "\n".join(safe_evidence) + ("\n" if safe_evidence else ""))
    status = aggregate_status(records, source_status)
    detail = "; ".join(failures) if failures else ("structured log files expose no matching fields" if status == "EMPTY" else None)
    return records, status, detail


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task", choices=("15", "17", "18"))
    parser.add_argument("--log", action="append", help="native structured JSONL source (repeatable; overrides default paths)")
    parser.add_argument("--raw-evidence")
    parser.add_argument("--journal-unit", action="append", default=[], help="read structured JSON MESSAGE from a systemd unit")
    parser.add_argument("--journal-identifier", action="append", default=[], help="read structured JSON MESSAGE by SYSLOG_IDENTIFIER")
    parser.add_argument("--since", default="-1h", help="journal time filter (default: -1h)")
    args = parser.parse_args(argv)
    configuration = {
        "15": ("tls_metadata", "tls"),
        "17": ("http_request_response", "http"),
        "18": ("api_rpc_telemetry", "rpc"),
    }
    object_type, kind = configuration[args.task]
    try:
        source_status = []
        if args.log:
            records, status, detail = collect_logs(args.task, object_type, kind, paths=tuple(args.log),
                                                   raw_path=args.raw_evidence, source_status=source_status)
        elif args.journal_unit or args.journal_identifier:
            records, status, detail = [], "EMPTY", None
        else:
            records, status, detail = collect_logs(args.task, object_type, kind, paths=LOG_PATHS,
                                                   raw_path=args.raw_evidence, source_status=source_status)
        if args.journal_unit or args.journal_identifier:
            journal_records, journal_sources, journal_detail = collect_journal_logs(
                args.task, args.journal_unit, args.journal_identifier, since=args.since,
                raw_path=args.raw_evidence, append_raw=bool(args.log))
            records.extend(journal_records)
            source_status.extend(journal_sources)
            status = aggregate_status(records, source_status)
            if journal_detail:
                detail = "; ".join(value for value in (detail, journal_detail) if value)
    except OSError as exc:
        return execution_failure(args.task, exc, "raw-evidence")
    return finish(args.task, records, status, detail, source_status)


if __name__ == "__main__":
    raise SystemExit(main())
