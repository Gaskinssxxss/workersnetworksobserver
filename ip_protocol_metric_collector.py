#!/usr/bin/env python3
"""Read-only absolute IPv4/IPv6 and ICMP counter snapshot using nstat."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import command_status, execution_failure, finish


COMMAND = ["nstat", "-a", "-s", "-j"]


def parse_counters(raw, host, timestamp):
    document = json.loads(raw)
    counters = document.get("kernel", document)
    records = []
    for name, value in counters.items():
        if name.startswith(("Ip6", "Icmp6")):
            family = "IPv6"
        elif name.startswith(("Ip", "Icmp")):
            family = "IPv4"
        else:
            continue
        protocol = "ICMP" if name.startswith(("Icmp", "Icmp6")) else "IP"
        records.append({"layer": "L3", "object_type": "ip_protocol_metric", "family": family,
                        "protocol": protocol, "host": host, "timestamp": timestamp,
                        "source": " ".join(COMMAND), "counter_name": name, "value": value})
    return records


def collect():
    try:
        result = subprocess.run(COMMAND, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", None)
        raise RuntimeError(f"command failed ({' '.join(COMMAND)}): {detail or exc}") from exc
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return result.stdout, parse_counters(result.stdout, socket.gethostname(), timestamp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        raw, records = collect()
    except RuntimeError as exc:
        state = command_status(exc)
        return finish("05", [], state, exc,
                      [{"source": " ".join(COMMAND), "status": state, "detail": str(exc)}])
    except json.JSONDecodeError as exc:
        return finish("05", [], "UNAVAILABLE", f"unsupported nstat JSON: {exc}",
                      [{"source": " ".join(COMMAND), "status": "UNAVAILABLE", "detail": str(exc)}])
    try:
        if args.raw_evidence:
            args.raw_evidence.write_text(raw, encoding="utf-8")
    except OSError as exc:
        return execution_failure("05", exc, "raw-evidence")
    state = "AVAILABLE" if records else "EMPTY"
    return finish("05", records, state, source_status=[{"source": " ".join(COMMAND), "status": state}])


if __name__ == "__main__":
    raise SystemExit(main())
