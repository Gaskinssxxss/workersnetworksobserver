#!/usr/bin/env python3
"""Read-only IPv4/IPv6 snapshot collector using `ip -j address show`."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import aggregate_status, command_status, execution_failure, finish


SOURCE = "ip -j address show"


def parse_snapshot(raw, host, timestamp):
    """Convert iproute2 JSON into one L3/ip_address record per address."""
    interfaces = json.loads(raw)
    records = []
    for interface in interfaces:
        name = interface.get("ifname")
        for info in interface.get("addr_info", []):
            family = info.get("family")
            if family not in ("inet", "inet6"):
                continue
            address = info.get("local")
            prefix = info.get("prefixlen")
            if address is None or prefix is None:
                continue
            records.append({
                "layer": "L3",
                "object_type": "ip_address",
                "family": "IPv4" if family == "inet" else "IPv6",
                "address": address,
                "prefix": prefix,
                "host": host,
                "interface": name,
                "timestamp": timestamp,
                "source": SOURCE,
            })
    return records


def collect():
    result = subprocess.run(
        ["ip", "-j", "address", "show"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return result.stdout, parse_snapshot(result.stdout, socket.gethostname(), timestamp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence", type=Path, help="write raw ip command JSON stdout to this file")
    args = parser.parse_args(argv)
    try:
        raw, records = collect()
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        state = command_status(exc)
        return finish("01", [], state, exc,
                      [{"source": SOURCE, "status": state, "detail": str(exc)}])
    except json.JSONDecodeError as exc:
        return finish("01", [], "UNAVAILABLE", f"unsupported iproute2 JSON: {exc}",
                      [{"source": SOURCE, "status": "UNAVAILABLE", "detail": str(exc)}])
    try:
        if args.raw_evidence:
            args.raw_evidence.write_text(raw, encoding="utf-8")
    except OSError as exc:
        return execution_failure("01", exc, "raw-evidence")
    state = "AVAILABLE" if records else "EMPTY"
    return finish("01", records, state,
                  source_status=[{"source": SOURCE, "status": state}])


if __name__ == "__main__":
    raise SystemExit(main())
