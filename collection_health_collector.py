#!/usr/bin/env python3
"""Summarize caller-supplied standalone collector status JSONL; runs no other collectors."""

import argparse
import collections
import datetime as dt
import json
import pathlib
import socket

from telemetry_common import aggregate_status, execution_failure, finish

VALID={"AVAILABLE","EMPTY","UNAVAILABLE","PERMISSION_DENIED","EXECUTION_FAILURE"}

def read_status(path):
    with pathlib.Path(path).open("rb") as stream:
        stream.seek(0,2);end=stream.tell();stream.seek(max(0,end-1_048_576))
        text=stream.read(1_048_576).decode("utf-8",errors="replace")
    rows=[]
    for line in text.splitlines()[-500:]:
        try:item=json.loads(line)
        except json.JSONDecodeError:continue
        if isinstance(item,dict) and item.get("record_type")=="collection_status" and item.get("status") in VALID:
            rows.append({"task_id":str(item.get("task_id","")),"status":item["status"],
                         "record_count":item.get("record_count"),
                         "source_status":[{"source":x.get("source"),"status":x.get("status")} for x in item.get("source_status",[]) if isinstance(x,dict)]})
    return rows,bool(text.strip())

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--status-file",action="append",default=[])
    parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[];sources=[]
    if not args.status_file:return finish("40",[],"UNAVAILABLE","no external collection status file supplied",[{"source":"--status-file","status":"UNAVAILABLE"}])
    for filename in args.status_file:
        path=pathlib.Path(filename)
        try:rows,nonempty=read_status(path)
        except PermissionError as exc:sources.append({"source":str(path),"status":"PERMISSION_DENIED","detail":str(exc)});continue
        except OSError as exc:sources.append({"source":str(path),"status":"UNAVAILABLE","detail":str(exc)});continue
        if not rows:
            sources.append({"source":str(path),"status":"UNAVAILABLE" if nonempty else "EMPTY",
                            **({"detail":"no collection_status JSONL rows"} if nonempty else {})});continue
        counts=collections.Counter(row["status"] for row in rows)
        records.append({"layer":"observability","object_type":"collection_health_summary","host":host,"timestamp":ts,
            "source":str(path),"signal_type":"external_collection_status_snapshot","status_rows":len(rows),
            "status_counts":dict(counts),"task_statuses":rows})
        sources.append({"source":str(path),"status":"AVAILABLE"})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(records,indent=2)+"\n")
        except OSError as exc:return execution_failure("40",exc,"raw-evidence")
    state=aggregate_status(records,sources)
    return finish("40",records,state,source_status=sources)

if __name__=="__main__":raise SystemExit(main())
