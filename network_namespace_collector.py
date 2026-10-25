#!/usr/bin/env python3
"""Snapshot named and process-visible Linux network namespaces."""

import argparse
import datetime as dt
import json
import os
import pathlib
import socket

from telemetry_common import aggregate_status, execution_failure, finish, run_readonly, CollectionFailure

IP_NETNS = ["ip", "-j", "netns", "list"]


def collect():
    host=socket.gethostname(); timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records=[]; sources=[]
    try:
        text=run_readonly(IP_NETNS)
        rows=json.loads(text)
        for row in rows:
            records.append({"layer":"runtime","object_type":"network_namespace","host":host,"timestamp":timestamp,
                            "source":" ".join(IP_NETNS),"signal_type":"namespace_snapshot","namespace_data":row})
        sources.append({"source":" ".join(IP_NETNS),"status":"AVAILABLE" if rows else "EMPTY"})
    except (CollectionFailure,json.JSONDecodeError) as exc:
        state=exc.status if isinstance(exc,CollectionFailure) else "UNAVAILABLE"
        sources.append({"source":" ".join(IP_NETNS),"status":state,"detail":str(exc)})
    groups={}; inaccessible=0
    for entry in pathlib.Path("/proc").iterdir():
        if not entry.name.isdigit():continue
        try:
            namespace=os.readlink(entry/"ns/net")
            try:name=(entry/"comm").read_text().strip()
            except OSError:name=""
        except (OSError,PermissionError):
            inaccessible+=1;continue
        current=groups.setdefault(namespace,{"process_count":0,"processes":[]})
        current["process_count"]+=1
        if len(current["processes"])<5:current["processes"].append({"pid":int(entry.name),"name":name})
    for namespace,data in sorted(groups.items()):
        records.append({"layer":"runtime","object_type":"network_namespace","host":host,"timestamp":timestamp,
                        "source":"/proc/<pid>/ns/net and /proc/<pid>/comm","signal_type":"namespace_snapshot",
                        "namespace_id":namespace,"process_count":data["process_count"],"representative_processes":data["processes"]})
    sources.append({"source":"/proc/<pid>/ns/net","status":"AVAILABLE" if groups else "EMPTY",
                    **({"detail":f"skipped {inaccessible} inaccessible process entries"} if inaccessible else {})})
    return records,aggregate_status(records,sources),sources


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--raw-evidence");args=parser.parse_args(argv)
    try:
        records,status,sources=collect()
        if args.raw_evidence:pathlib.Path(args.raw_evidence).write_text(json.dumps(records,indent=2)+"\n")
    except OSError as exc:return execution_failure("28",exc,"raw-evidence")
    return finish("28",records,status,source_status=sources)

if __name__=="__main__":raise SystemExit(main())
