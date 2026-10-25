#!/usr/bin/env python3
"""Collect TCP socket diagnostics and native TCP absolute counters."""

import argparse
import json
import re
import sys
from telemetry_common import CollectionFailure, aggregate_status, context, execution_failure, finish, make_record, run_readonly, save_raw


SS_COMMAND = ["ss", "-H", "-n", "-t", "-i", "-m"]
NSTAT_COMMAND = ["nstat", "-a", "-s", "-j"]
TCP_STATES = {"ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2", "TIME-WAIT",
              "CLOSE-WAIT", "LAST-ACK", "LISTEN", "CLOSING", "CLOSED", "UNCONN"}
STAT_KEYS = ("rtt", "rto", "cwnd", "retrans", "skmem", "delivery_rate", "bytes_sent",
             "bytes_acked", "bytes_received", "rcv_space", "snd_wnd", "send")


def parse_ss(raw, host, timestamp):
    blocks, current = [], []
    for line in raw.splitlines():
        fields = line.split()
        if fields and fields[0].upper() in TCP_STATES:
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    records = []
    for block in blocks:
        first = block.splitlines()[0]
        fields = first.split(None, 4)
        data = {"native_socket_output": block}
        if len(fields) >= 5:
            data.update({"state": fields[0], "receive_queue": fields[1], "send_queue": fields[2],
                         "local_endpoint": fields[3], "remote_endpoint": fields[4]})
        detail_text = " ".join(block.splitlines()[1:])
        congestion = re.search(r"^\s*([A-Za-z0-9_-]+)\s+wscale:", block.splitlines()[1] if len(block.splitlines()) > 1 else "")
        if congestion:
            data["congestion_control"] = congestion.group(1)
        for key in STAT_KEYS:
            sep = r":" if key not in ("delivery_rate", "send") else r"(?::|\s+)"
            match = re.search(r"(?:^|\s)" + re.escape(key) + sep + r"([^\s]+)", detail_text)
            if match:
                data[key] = match.group(1)
        records.append(make_record("L4", "tcp_transport_performance", " ".join(SS_COMMAND),
                                   host, timestamp, task_id="13", signal_type="snapshot", performance_data=data))
    return records


def parse_nstat(raw, host, timestamp):
    document = json.loads(raw)
    counters = document.get("kernel", document)
    records = []
    for name, value in counters.items():
        if name.startswith("Tcp"):
            records.append(make_record("L4", "tcp_transport_performance", " ".join(NSTAT_COMMAND),
                                       host, timestamp, task_id="13", signal_type="absolute_counter",
                                       counter_name=name, value=value))
    return records


def collect_detailed(raw_ss=None, raw_nstat=None):
    host, timestamp = context()
    records, errors, source_status = [], [], []
    ss_text = nstat_text = None
    try:
        ss_text = run_readonly(SS_COMMAND)
        save_raw(raw_ss, ss_text)
        parsed = parse_ss(ss_text, host, timestamp)
        records.extend(parsed)
        source_status.append({"source": " ".join(SS_COMMAND), "status": "AVAILABLE" if parsed else "EMPTY"})
    except (CollectionFailure, ValueError) as exc:
        errors.append(str(exc))
        state = exc.status if isinstance(exc, CollectionFailure) else "UNAVAILABLE"
        source_status.append({"source": " ".join(SS_COMMAND), "status": state, "detail": str(exc)})
    try:
        nstat_text = run_readonly(NSTAT_COMMAND)
        save_raw(raw_nstat, nstat_text)
        parsed = parse_nstat(nstat_text, host, timestamp)
        records.extend(parsed)
        source_status.append({"source": " ".join(NSTAT_COMMAND), "status": "AVAILABLE" if parsed else "EMPTY"})
    except (CollectionFailure, ValueError) as exc:
        errors.append(str(exc))
        state = exc.status if isinstance(exc, CollectionFailure) else "UNAVAILABLE"
        source_status.append({"source": " ".join(NSTAT_COMMAND), "status": state, "detail": str(exc)})
    return records, aggregate_status(records, source_status), "; ".join(errors) or None, source_status


def collect(raw_ss=None, raw_nstat=None):
    """Backward-compatible three-value API; CLI also reports per-source states."""
    records, status, detail, _ = collect_detailed(raw_ss, raw_nstat)
    return records, status, detail


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-ss")
    parser.add_argument("--raw-nstat")
    args = parser.parse_args(argv)
    try:
        records, status, detail, sources = collect_detailed(args.raw_ss, args.raw_nstat)
        return finish("13", records, status, detail, sources)
    except OSError as exc:
        return execution_failure("13", exc, "raw-evidence")


if __name__ == "__main__":
    raise SystemExit(main())
