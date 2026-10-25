#!/usr/bin/env python3
"""Validate explicit network collection targets against their native local source."""

import argparse
import datetime as dt
import json
import os
import pathlib
import socket

from telemetry_common import CollectionFailure, execution_failure, finish, run_readonly

def inspect_target(value):
    if ":" not in value:raise ValueError("target must be TYPE:IDENTIFIER")
    kind,identity=value.split(":",1)
    if not identity:raise ValueError("target identifier is empty")
    if kind=="namespace":
        if identity=="host":return "AVAILABLE","ACTIVE",{"namespace_id":os.readlink("/proc/self/ns/net")},"/proc/self/ns/net"
        command=["ip","-j","netns","list"]
        output=run_readonly(command);found=any(x.get("name")==identity for x in json.loads(output))
        return "AVAILABLE","ACTIVE" if found else "NOT_FOUND",{"name":identity}," ".join(command)
    if kind=="pid":
        path=pathlib.Path("/proc",identity)
        if not identity.isdigit():raise ValueError("pid target must be numeric")
        if not path.exists():return "AVAILABLE","NOT_FOUND",{"pid":int(identity)},"/proc/<pid>"
        return "AVAILABLE","ACTIVE",{"pid":int(identity),"name":(path/"comm").read_text().strip()},"/proc/<pid>/comm"
    if kind=="unit":
        command=["systemctl","show",identity,"-p","Id","-p","LoadState","-p","ActiveState","-p","SubState","--no-pager"]
        text=run_readonly(command);fields=dict(line.split("=",1) for line in text.splitlines() if "=" in line)
        state="NOT_FOUND" if fields.get("LoadState")=="not-found" else fields.get("ActiveState","UNKNOWN").upper()
        return "AVAILABLE",state,fields," ".join(command)
    if kind=="container":
        command=["docker","--host","unix:///var/run/docker.sock","inspect","--format","{{json .State}}",identity]
        state=json.loads(run_readonly(command));return "AVAILABLE",str(state.get("Status","UNKNOWN")).upper(),state," ".join(command)
    if kind=="vm":
        command=["virsh","--connect","qemu:///system","domstate",identity];state=run_readonly(command).strip()
        return "AVAILABLE",state.upper(),{"state":state}," ".join(command)
    raise ValueError("supported target types: namespace, pid, unit, container, vm")

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--target",action="append",default=[],help="TYPE:IDENTIFIER; repeatable")
    parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[];sources=[]
    if not args.target:return finish("37",[],"UNAVAILABLE","no explicit collection targets supplied",[{"source":"--target","status":"UNAVAILABLE"}])
    for value in args.target:
        try:
            state,lifecycle,data,source=inspect_target(value)
            records.append({"layer":"observability","object_type":"collection_target","host":host,"timestamp":ts,
                "source":source,"signal_type":"target_identity_snapshot","target_type":value.split(":",1)[0],
                "target_id":value.split(":",1)[1],"target_state":lifecycle,"target_data":data})
            sources.append({"source":source,"status":state})
        except CollectionFailure as exc:sources.append({"source":value,"status":exc.status,"detail":str(exc)})
        except (OSError,ValueError,json.JSONDecodeError) as exc:sources.append({"source":value,"status":"UNAVAILABLE","detail":str(exc)})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(records,indent=2)+"\n")
        except OSError as exc:return execution_failure("37",exc,"raw-evidence")
    status="AVAILABLE" if records else next((x["status"] for x in sources if x["status"] in ("PERMISSION_DENIED","UNAVAILABLE")),"EMPTY")
    return finish("37",records,status,source_status=sources)

if __name__=="__main__":raise SystemExit(main())
