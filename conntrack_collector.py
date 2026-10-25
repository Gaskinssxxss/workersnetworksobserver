#!/usr/bin/env python3
"""Snapshot available conntrack entries without modifying kernel state."""

import argparse
import sys
from telemetry_common import CollectionFailure, context, execution_failure, finish, make_record, run_readonly, save_raw


COMMAND = ["conntrack", "-L"]


def collect(raw=None):
    host, timestamp = context()
    output = run_readonly(COMMAND)
    save_raw(raw, output)
    lines = [line for line in output.splitlines() if line.strip()]
    records = [make_record("L4", "conntrack_entry", " ".join(COMMAND), host, timestamp,
                           signal_type="snapshot", native_entry=line) for line in lines]
    return output, records, "AVAILABLE" if records else "EMPTY"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence")
    args = parser.parse_args(argv)
    try:
        _, records, status = collect(args.raw_evidence)
        finish("09", records, status,
               source_status=[{"source": " ".join(COMMAND), "status": status}])
    except CollectionFailure as exc:
        try:
            save_raw(args.raw_evidence, f"collection {exc.status}: {exc}\n")
        except OSError as write_error:
            return execution_failure("09", write_error, "raw-evidence")
        return finish("09", [], exc.status, exc,
                      [{"source": " ".join(COMMAND), "status": exc.status, "detail": str(exc)}])
    except OSError as exc:
        return execution_failure("09", exc, "raw-evidence")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
