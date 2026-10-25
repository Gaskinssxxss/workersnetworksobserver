#!/usr/bin/env python3
"""Collect service discovery observations from structured logs or explicit Avahi browse."""

import argparse
import datetime as dt
import json
import socket
from pathlib import Path

from application_object_log_source import collect_journal_logs, collect_object_logs
from telemetry_common import CollectionFailure, aggregate_status, command_status, execution_failure, finish, run_readonly

AVAHI_COMMAND = ["avahi-browse", "--all", "--resolve", "--terminate", "--parsable"]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", action="append", default=[], help="native discovery JSONL source (repeatable)")
    parser.add_argument("--avahi", action="store_true", help="perform explicit local mDNS service browse")
    parser.add_argument("--journal-unit", action="append", default=[], help="read structured discovery JSON from a systemd unit")
    parser.add_argument("--journal-identifier", action="append", default=[], help="read structured discovery JSON by SYSLOG_IDENTIFIER")
    parser.add_argument("--since", default="-1h", help="journal time filter (default: -1h)")
    parser.add_argument("--raw-evidence")
    args = parser.parse_args(argv)
    records, sources, raw = [], [], []
    if args.log:
        try:
            found, _, log_sources = collect_object_logs("20", args.log)
            records.extend(found); sources.extend(log_sources)
            raw.extend(json.dumps({"source": r["source"], "safe_fields": r["application_data"]}, separators=(",", ":")) for r in found)
        except OSError as exc:
            return execution_failure("20", exc, "raw-evidence")
    elif not args.avahi and not (args.journal_unit or args.journal_identifier):
        sources.append({"source": "native discovery source (--log or --avahi)", "status": "UNAVAILABLE",
                        "detail": "no discovery source selected"})
    if args.avahi:
        source = " ".join(AVAHI_COMMAND)
        try:
            output = run_readonly(AVAHI_COMMAND, timeout=10)
            entries = [line for line in output.splitlines() if line.startswith("=")]
            host = socket.gethostname(); timestamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
            for entry in entries:
                records.append({"layer": "L7", "object_type": "service_discovery_endpoint", "host": host,
                                "timestamp": timestamp, "source": source, "signal_type": "native_discovery_snapshot",
                                "native_entry": entry})
            sources.append({"source": source, "status": "AVAILABLE" if entries else "EMPTY"})
            raw.append(output)
        except CollectionFailure as exc:
            sources.append({"source": source, "status": exc.status, "detail": str(exc)})
    if args.journal_unit or args.journal_identifier:
        try:
            found, journal_sources, detail = collect_journal_logs(
                "20", args.journal_unit, args.journal_identifier, since=args.since)
            records.extend(found)
            sources.extend(journal_sources)
            raw.extend(json.dumps({"source": r["source"], "safe_fields": r["application_data"]}, separators=(",", ":"))
                       for r in found)
            if detail:
                sources.append({"source": "journalctl", "status": "UNAVAILABLE", "detail": detail})
        except (ValueError, OSError) as exc:
            return execution_failure("20", exc, "journalctl")
    if args.raw_evidence:
        try: Path(args.raw_evidence).write_text("\n".join(raw) + ("\n" if raw else ""), encoding="utf-8")
        except OSError as exc: return execution_failure("20", exc, "raw-evidence")
    status = aggregate_status(records, sources)
    return finish("20", records, status, source_status=sources)


if __name__ == "__main__":
    raise SystemExit(main())
