#!/usr/bin/env python3
"""Collect TCP listening endpoints; TCP connection and UDP snapshots are separate tasks."""

import argparse
import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path
from telemetry_common import command_status, execution_failure, finish


COMMAND = ["ss", "-H", "-n", "-l", "-t"]


def endpoint(token):
    if ":" not in token:
        return None
    address, port = token.rsplit(":", 1)
    if address.startswith("[") and address.endswith("]"):
        address = address[1:-1]
    return {"address": address, "port": port}


def parse(raw, host, timestamp):
    records = []
    for line in raw.splitlines():
        fields = line.split(None, 5)
        if len(fields) == 5:
            netid, state, recvq, sendq, local, peer = "tcp", *fields
        elif len(fields) == 6:
            netid, state, recvq, sendq, local, peer = fields
        else:
            continue
        local_parts, peer_parts = endpoint(local), endpoint(peer)
        record = {"layer": "L4", "object_type": "transport_endpoint", "transport": netid.upper(),
                  "host": host, "timestamp": timestamp, "source": " ".join(COMMAND),
                  "state": state, "local_endpoint": local, "remote_endpoint": peer,
                  "raw_record": line}
        if recvq.isdigit():
            record["receive_queue"] = int(recvq)
        if sendq.isdigit():
            record["send_queue"] = int(sendq)
        if local_parts:
            record["local_address"], record["local_port"] = local_parts["address"], local_parts["port"]
        if peer_parts:
            record["remote_address"], record["remote_port"] = peer_parts["address"], peer_parts["port"]
        records.append(record)
    return records


def collect():
    try:
        result = subprocess.run(COMMAND, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"command failed ({' '.join(COMMAND)}): {getattr(exc, 'stderr', None) or exc}") from exc
    timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    return result.stdout, parse(result.stdout, socket.gethostname(), timestamp)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence", type=Path)
    args = parser.parse_args(argv)
    try:
        raw, records = collect()
    except RuntimeError as exc:
        state = command_status(exc)
        return finish("06", [], state, exc,
                      [{"source": " ".join(COMMAND), "status": state, "detail": str(exc)}])
    try:
        if args.raw_evidence:
            args.raw_evidence.write_text(raw, encoding="utf-8")
    except OSError as exc:
        return execution_failure("06", exc, "raw-evidence")
    state = "AVAILABLE" if records else "EMPTY"
    return finish("06", records, state, source_status=[{"source": " ".join(COMMAND), "status": state}])


if __name__ == "__main__":
    raise SystemExit(main())
