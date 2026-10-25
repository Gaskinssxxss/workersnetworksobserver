#!/usr/bin/env python3
"""Read-only IPv4/IPv6 route snapshot collector using iproute2 JSON."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import aggregate_status, command_status, execution_failure, finish


COMMANDS = {
    "IPv4": ["ip", "-4", "-j", "route", "show", "table", "all"],
    "IPv6": ["ip", "-6", "-j", "route", "show", "table", "all"],
}


class RouteCollectionError(Exception):
    pass


def parse_routes(raw, family, host, timestamp, source):
    """Map available iproute2 route attributes without filling absent fields."""
    routes = json.loads(raw)
    records = []
    for route in routes:
        data = {}
        for source_key, output_key in (
            ("dst", "destination"),
            ("table", "table"),
            ("gateway", "gateway"),
            ("dev", "interface"),
            ("metric", "metric"),
            ("nexthops", "next_hops"),
        ):
            if source_key in route:
                data[output_key] = route[source_key]
        if "protocol" in route:
            data["protocol"] = route["protocol"]
        elif "proto" in route:
            data["protocol"] = route["proto"]
        records.append({
            "layer": "L3",
            "object_type": "route",
            "family": family,
            "host": host,
            "timestamp": timestamp,
            "source": source,
            "routing_data": data,
        })
    return records


def collect_detailed():
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    host = socket.gethostname()
    evidence = {}
    records = []
    source_status = []
    details = []
    for family, command in COMMANDS.items():
        source = " ".join(command)
        try:
            result = subprocess.run(
                command, check=True, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, timeout=10,
            )
        except (subprocess.CalledProcessError, OSError, subprocess.TimeoutExpired) as exc:
            state = command_status(exc)
            reason = str(getattr(exc, "stderr", None) or exc)
            source_status.append({"source": source, "status": state, "detail": reason})
            details.append(f"{source}: {reason}")
            continue
        evidence[family] = result.stdout
        try:
            parsed = parse_routes(result.stdout, family, host, timestamp, source)
        except json.JSONDecodeError as exc:
            source_status.append({"source": source, "status": "UNAVAILABLE", "detail": f"invalid JSON: {exc}"})
            details.append(f"{source}: invalid JSON: {exc}")
            continue
        records.extend(parsed)
        source_status.append({"source": source, "status": "AVAILABLE" if parsed else "EMPTY"})
    return evidence, records, source_status, aggregate_status(records, source_status), "; ".join(details) or None


def collect():
    """Backward-compatible two-value API; CLI uses collect_detailed for partial statuses."""
    evidence, records, _, _, detail = collect_detailed()
    if detail:
        raise RouteCollectionError(detail)
    return evidence, records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-ipv4", type=Path, help="save raw IPv4 command JSON stdout")
    parser.add_argument("--raw-ipv6", type=Path, help="save raw IPv6 command JSON stdout")
    args = parser.parse_args(argv)
    try:
        evidence, records, sources, status, detail = collect_detailed()
    except Exception as exc:
        return execution_failure("02", exc)
    try:
        if args.raw_ipv4 and "IPv4" in evidence:
            args.raw_ipv4.write_text(evidence["IPv4"], encoding="utf-8")
        if args.raw_ipv6 and "IPv6" in evidence:
            args.raw_ipv6.write_text(evidence["IPv6"], encoding="utf-8")
    except OSError as exc:
        return execution_failure("02", exc, "raw-evidence")
    return finish("02", records, status, detail, sources)


if __name__ == "__main__":
    raise SystemExit(main())
