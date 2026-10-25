#!/usr/bin/env python3
"""Collect running service state, socket activation associations, listeners, and safe journal metadata."""

import argparse
import json
import re
from telemetry_common import CollectionFailure, aggregate_status, context, execution_failure, finish, make_record, run_readonly, save_raw


UNIT_COMMAND = ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"]
SOCKET_COMMAND = ["systemctl", "list-sockets", "--all", "--no-legend", "--no-pager"]
SS_COMMANDS = {"TCP": ["ss", "-H", "-n", "-l", "-t", "-p"],
               "UDP": ["ss", "-H", "-n", "-l", "-u", "-p"]}
JOURNAL_COMMAND = ["journalctl", "--since=-1h", "--priority=warning", "--output=json", "--no-pager", "-n", "50"]


def parse_services(units, sockets, listeners, journal, host, timestamp):
    records = []
    for line in units.splitlines():
        fields = line.split(None, 4)
        if len(fields) >= 4:
            records.append(make_record("L7", "network_service", " ".join(UNIT_COMMAND), host, timestamp,
                                       signal_type="service_snapshot", unit=fields[0], load=fields[1],
                                       active=fields[2], substate=fields[3], description=fields[4] if len(fields) > 4 else ""))
    socket_map = {}
    for line in sockets.splitlines():
        fields = line.split()
        if len(fields) >= 3 and ":" in fields[0]:
            socket_map[fields[0]] = {"socket_unit": fields[1], "activates": fields[2]}
            records.append(make_record("L7", "network_service_socket_association", " ".join(SOCKET_COMMAND),
                                       host, timestamp, signal_type="socket_activation_configuration",
                                       address=fields[0], socket_unit=fields[1], activates=fields[2]))
    for transport, output in listeners.items() if isinstance(listeners, dict) else (("TCP/UDP", listeners),):
        for line in output.splitlines():
            fields = line.split(None, 5)
            if len(fields) == 5:
                state, recvq, sendq, local, peer = fields
                process = ""
            elif len(fields) == 6:
                state, recvq, sendq, local, peer, process = fields
            else:
                continue
            pid_match = re.search(r"pid=(\d+)", process)
            association = socket_map.get(local, {})
            command = SS_COMMANDS.get(transport, list(SS_COMMANDS.values())[0])
            records.append(make_record("L7", "network_service_listener", " ".join(command), host, timestamp,
                                       signal_type="listener_snapshot", transport=transport, state=state,
                                       local_endpoint=local, remote_endpoint=peer, process=process or None,
                                       pid=int(pid_match.group(1)) if pid_match else None,
                                       socket_unit=association.get("socket_unit"), activates=association.get("activates")))
    safe_journal = []
    for line in journal.splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        safe = {key: entry[key] for key in ("__REALTIME_TIMESTAMP", "__CURSOR", "_SYSTEMD_UNIT", "PRIORITY") if key in entry}
        if safe:
            safe_journal.append(safe)
            records.append(make_record("L7", "network_service_journal_event", " ".join(JOURNAL_COMMAND), host,
                                       timestamp, signal_type="native_journal_event_metadata", event_metadata=safe))
    return records, safe_journal


def collect(raw_units=None, raw_sockets=None, raw_ss=None, raw_journal=None,
            units_text=None, sockets_text=None, ss_text=None, journal_text=None, source_status=None):
    host, timestamp = context()
    source_status = source_status if source_status is not None else []
    commands = (("units", UNIT_COMMAND, raw_units, units_text), ("sockets", SOCKET_COMMAND, raw_sockets, sockets_text),
                ("journal", JOURNAL_COMMAND, raw_journal, journal_text))
    outputs, errors = {}, []
    for name, command, path, supplied in commands:
        try:
            outputs[name] = supplied if supplied is not None else run_readonly(command)
            if name != "journal":
                save_raw(path, outputs[name])
            source_status.append({"source": " ".join(command), "status": "AVAILABLE" if outputs[name] else "EMPTY"})
        except CollectionFailure as exc:
            outputs[name] = ""
            errors.append(f"{name} {exc.status}: {exc}")
            source_status.append({"source": " ".join(command), "status": exc.status, "detail": str(exc)})
    outputs["ss"] = {}
    for transport, command in SS_COMMANDS.items():
        try:
            outputs["ss"][transport] = run_readonly(command)
            source_status.append({"source": " ".join(command),
                                  "status": "AVAILABLE" if outputs["ss"][transport] else "EMPTY"})
        except CollectionFailure as exc:
            outputs["ss"][transport] = ""
            errors.append(f"ss {transport} {exc.status}: {exc}")
            source_status.append({"source": " ".join(command), "status": exc.status, "detail": str(exc)})
    save_raw(raw_ss, "".join(f"# {kind} { ' '.join(SS_COMMANDS[kind]) }\n{text}" for kind, text in outputs["ss"].items()))
    journal_parse_error = None
    for line in outputs["journal"].splitlines():
        try:
            json.loads(line)
        except json.JSONDecodeError as exc:
            journal_parse_error = exc
            break
    if journal_parse_error:
        for item in source_status:
            if item["source"] == " ".join(JOURNAL_COMMAND):
                item.update({"status": "UNAVAILABLE", "detail": f"unsupported journal JSON: {journal_parse_error}"})
                break
        errors.append(f"journal UNAVAILABLE: unsupported JSON: {journal_parse_error}")
    records, safe_journal = parse_services(outputs["units"], outputs["sockets"], outputs["ss"],
                                           outputs["journal"], host, timestamp)
    if raw_journal:
        # Journal messages are deliberately excluded from evidence; only safe event metadata is retained.
        save_raw(raw_journal, "\n".join(json.dumps(e, separators=(",", ":")) for e in safe_journal))
    status = aggregate_status(records, source_status)
    return records, status, "; ".join(errors) or None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-systemctl")
    parser.add_argument("--raw-sockets")
    parser.add_argument("--raw-ss")
    parser.add_argument("--raw-journal")
    args = parser.parse_args(argv)
    sources = []
    try:
        records, status, detail = collect(args.raw_systemctl, args.raw_sockets, args.raw_ss,
                                          args.raw_journal, source_status=sources)
    except OSError as exc:
        return execution_failure("19", exc, "raw-evidence")
    return finish("19", records, status, detail, sources)


if __name__ == "__main__":
    raise SystemExit(main())
