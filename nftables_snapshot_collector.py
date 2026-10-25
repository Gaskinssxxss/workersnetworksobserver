#!/usr/bin/env python3
"""One read-only nftables JSON snapshot classified for Tasks 10, 11 and 12."""

import argparse
import json
import sys
from telemetry_common import CollectionFailure, context, execution_failure, finish, make_record, run_readonly, save_raw


COMMAND = ["nft", "-j", "list", "ruleset"]
NAT_OPS = {"snat", "dnat", "masquerade", "redirect", "nat"}


def contains_operator(value, operators):
    if isinstance(value, dict):
        return any(key in operators or contains_operator(item, operators) for key, item in value.items())
    if isinstance(value, list):
        return any(contains_operator(item, operators) for item in value)
    return False


def contains_connection_limit(value):
    if isinstance(value, dict):
        return any(key in ("connlimit", "limit", "quota", "meter")
                   or (key == "ct" and isinstance(item, dict) and any(k in ("count", "connlimit") for k in item))
                   or contains_connection_limit(item) for key, item in value.items())
    if isinstance(value, list):
        return any(contains_connection_limit(item) for item in value)
    return False


def collect(raw_path=None, raw_text=None):
    host, timestamp = context()
    output = raw_text if raw_text is not None else run_readonly(COMMAND)
    save_raw(raw_path, output)
    document = json.loads(output)
    entries = document.get("nftables", [])
    firewall, nat, enforcement = [], [], []
    source = " ".join(COMMAND)
    nat_chains = {(item["chain"].get("family"), item["chain"].get("table"), item["chain"].get("name"))
                  for item in entries if isinstance(item, dict) and isinstance(item.get("chain"), dict)
                  and item["chain"].get("type") == "nat"}
    for item in entries:
        if not isinstance(item, dict) or "metainfo" in item:
            continue
        kind = next((key for key in ("table", "chain", "rule") if key in item), None)
        if kind:
            native = item[kind]
            firewall.append(make_record("L4", "firewall_" + kind, source, host, timestamp,
                                        task_id="11", signal_type="snapshot", native_data=native))
            if kind == "rule":
                if contains_operator(native.get("expr", []), NAT_OPS) or (
                        native.get("family"), native.get("table"), native.get("chain")) in nat_chains:
                    nat.append(make_record("L4", "nat_rule", source, host, timestamp,
                                           task_id="10", signal_type="configuration", native_data=native))
                if contains_connection_limit(native.get("expr", [])):
                    enforcement.append(make_record("L4", "traffic_enforcement_rule", source, host, timestamp,
                                                   task_id="12", signal_type="configuration", native_data=native))
    return output, nat, firewall, enforcement


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--raw-evidence")
    args = parser.parse_args(argv)
    try:
        _, nat, firewall, enforcement = collect(args.raw_evidence)
    except CollectionFailure as exc:
        try:
            save_raw(args.raw_evidence, f"collection {exc.status}: {exc}\n")
        except OSError as write_error:
            for task in ("10", "11", "12"):
                finish(task, [], "EXECUTION_FAILURE", write_error,
                       [{"source": "raw-evidence", "status": "EXECUTION_FAILURE", "detail": str(write_error)}])
            return 1
        for task in ("10", "11", "12"):
            finish(task, [], exc.status, exc,
                   [{"source": " ".join(COMMAND), "status": exc.status, "detail": str(exc)}])
        return 0
    except (json.JSONDecodeError, AttributeError) as exc:
        for task in ("10", "11", "12"):
            finish(task, [], "UNAVAILABLE", f"unsupported nft JSON output: {exc}",
                   [{"source": " ".join(COMMAND), "status": "UNAVAILABLE", "detail": str(exc)}])
        return 0
    except OSError as exc:
        for task in ("10", "11", "12"):
            finish(task, [], "EXECUTION_FAILURE", exc,
                   [{"source": "raw-evidence", "status": "EXECUTION_FAILURE", "detail": str(exc)}])
        return 1
    for task, records in (("10", nat), ("11", firewall), ("12", enforcement)):
        state = "AVAILABLE" if records else "EMPTY"
        finish(task, records, state, source_status=[{"source": " ".join(COMMAND), "status": state}])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
