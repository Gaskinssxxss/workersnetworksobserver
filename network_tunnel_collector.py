#!/usr/bin/env python3
"""Discover L3 tunnel links using native detailed iproute2 JSON."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import command_status, execution_failure, finish


COMMAND = ["ip", "-d", "-j", "link", "show"]
TUNNEL_TYPES = {"gre", "gretap", "ipip", "sit", "ip6tnl", "ip6gre", "vti", "vti6", "erspan"}


def collect():
    try:
        result = subprocess.run(COMMAND, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", None)
        raise RuntimeError(f"command failed ({' '.join(COMMAND)}): {detail or exc}") from exc
    links = json.loads(result.stdout)
    timestamp, host = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"), socket.gethostname()
    records = []
    for link in links:
        info = link.get("linkinfo")
        if not isinstance(info, dict) or info.get("info_kind") not in TUNNEL_TYPES:
            continue
        records.append({"layer": "L3", "object_type": "network_tunnel", "tunnel_type": info["info_kind"],
                        "host": host, "timestamp": timestamp, "source": " ".join(COMMAND),
                        "tunnel_data": link})
    return result.stdout, records


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        raw, records = collect()
    except RuntimeError as exc:
        state = command_status(exc)
        return finish("04", [], state, exc,
                      [{"source": " ".join(COMMAND), "status": state, "detail": str(exc)}])
    except json.JSONDecodeError as exc:
        return finish("04", [], "UNAVAILABLE", f"unsupported iproute2 JSON: {exc}",
                      [{"source": " ".join(COMMAND), "status": "UNAVAILABLE", "detail": str(exc)}])
    try:
        if args.raw_evidence:
            args.raw_evidence.write_text(raw, encoding="utf-8")
    except OSError as exc:
        return execution_failure("04", exc, "raw-evidence")
    state = "AVAILABLE" if records else "EMPTY"
    detail = "No recognized L3 tunnel interfaces were present in this snapshot." if not records else None
    return finish("04", records, state, detail, [{"source": " ".join(COMMAND), "status": state}])


if __name__ == "__main__":
    raise SystemExit(main())
