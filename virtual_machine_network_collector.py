#!/usr/bin/env python3
"""Collect libvirt VM network interface configuration and native domain states."""

import argparse
import datetime as dt
import json
import pathlib
import socket

from telemetry_common import CollectionFailure, aggregate_status, execution_failure, finish, run_readonly

LIBVIRT=["virsh","--connect","qemu:///system"]
LIST=[*LIBVIRT,"list","--all","--name"]

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[];sources=[];raw={}
    try:
        names_text=run_readonly(LIST);names=[x.strip() for x in names_text.splitlines() if x.strip()]
        raw["list"]=names_text;sources.append({"source":" ".join(LIST),"status":"AVAILABLE" if names else "EMPTY"})
    except CollectionFailure as exc:
        return finish("30",[],exc.status,str(exc),[{"source":" ".join(LIST),"status":exc.status,"detail":str(exc)}])
    errors=[]
    for name in names:
        state_cmd=[*LIBVIRT,"domstate",name];if_cmd=[*LIBVIRT,"domiflist",name]
        try:state=run_readonly(state_cmd).strip();sources.append({"source":" ".join(state_cmd),"status":"AVAILABLE"})
        except CollectionFailure as exc:state=None;errors.append(str(exc));sources.append({"source":" ".join(state_cmd),"status":exc.status,"detail":str(exc)})
        try:table=run_readonly(if_cmd);raw[name]=table;sources.append({"source":" ".join(if_cmd),"status":"AVAILABLE" if table.strip() else "EMPTY"})
        except CollectionFailure as exc:errors.append(str(exc));sources.append({"source":" ".join(if_cmd),"status":exc.status,"detail":str(exc)});continue
        for line in table.splitlines():
            fields=line.split()
            if len(fields)>=5 and fields[0]!="Interface" and not set(fields[0])<={"-"}:
                records.append({"layer":"runtime","object_type":"virtual_machine_network_interface","host":host,"timestamp":ts,
                    "source":" ".join(if_cmd),"signal_type":"vm_network_snapshot","vm":name,"vm_state":state,
                    "interface":fields[0],"interface_type":fields[1],"source_network":fields[2],"model":fields[3],"mac_address":fields[4]})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(raw,indent=2)+"\n")
        except OSError as exc:return execution_failure("30",exc,"raw-evidence")
    status=aggregate_status(records,sources)
    return finish("30",records,status,"; ".join(errors) or None,sources)

if __name__=="__main__":raise SystemExit(main())
