#!/usr/bin/env python3
"""Read-only policy-routing rule snapshot collector."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import aggregate_status, command_status, execution_failure, finish


COMMANDS = {
    "IPv4": ["ip", "-4", "-j", "rule", "show"],
    "IPv6": ["ip", "-6", "-j", "rule", "show"],
}


def collect_detailed():
    timestamp, host = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), socket.gethostname()
    evidence, records = {}, []
    source_status, details = [], []
    for family, command in COMMANDS.items():
        source = " ".join(command)
        try:
            result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=10)
        except (OSError, subprocess.SubprocessError) as exc:
            state = command_status(exc)
            source_status.append({"source": source, "status": state, "detail": str(getattr(exc, "stderr", None) or exc)})
            details.append(f"{source}: {getattr(exc, 'stderr', None) or exc}")
            continue
        evidence[family] = result.stdout
        try:
            rules = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            source_status.append({"source": source, "status": "UNAVAILABLE", "detail": f"invalid JSON: {exc}"})
            details.append(f"{source}: invalid JSON: {exc}")
            continue
        parsed = []
        for rule in rules:
            parsed.append({"layer": "L3", "object_type": "routing_policy", "family": family,
                           "host": host, "timestamp": timestamp, "source": source,
                           "routing_policy_data": rule})
        records.extend(parsed)
        source_status.append({"source": source, "status": "AVAILABLE" if parsed else "EMPTY"})
    return evidence, records, source_status, aggregate_status(records, source_status), "; ".join(details) or None


def collect():
    """Backward-compatible two-value API; CLI uses collect_detailed for partial statuses."""
    evidence, records, _, _, detail = collect_detailed()
    if detail:
        raise RuntimeError(detail)
    return evidence, records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-ipv4", type=Path)
    parser.add_argument("--raw-ipv6", type=Path)
    args = parser.parse_args(argv)
    try:
        evidence, records, sources, status, detail = collect_detailed()
    except Exception as exc:
        return execution_failure("03", exc)
    try:
        if args.raw_ipv4 and "IPv4" in evidence:
            args.raw_ipv4.write_text(evidence["IPv4"], encoding="utf-8")
        if args.raw_ipv6 and "IPv6" in evidence:
            args.raw_ipv6.write_text(evidence["IPv6"], encoding="utf-8")
    except OSError as exc:
        return execution_failure("03", exc, "raw-evidence")
    return finish("03", records, status, detail, sources)


if __name__ == "__main__":
    raise SystemExit(main())
