#!/usr/bin/env python3
"""Snapshot host, namespace, process, and service identity for telemetry context."""

import argparse
import datetime as dt
import json
import os
import pathlib
import socket

from telemetry_common import execution_failure, finish

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    try:process_name=pathlib.Path("/proc/self/comm").read_text().strip()
    except OSError as exc:return finish("39",[],"UNAVAILABLE",str(exc),[{"source":"/proc/self","status":"UNAVAILABLE","detail":str(exc)}])
    namespaces={}
    for name in ("net","pid","mnt","user","uts","ipc","cgroup"):
        try:namespaces[name]=os.readlink(f"/proc/self/ns/{name}")
        except OSError:continue
    cgroups=[]
    try:
        for line in pathlib.Path("/proc/self/cgroup").read_text().splitlines():
            if ":" in line:
                _,controllers,path=line.split(":",2)
                cgroups.append({"controllers":controllers,"path":path})
    except OSError:pass
    try:machine_id=pathlib.Path("/etc/machine-id").read_text().strip() or None
    except OSError:machine_id=None
    data={"host":host,"hostname":host,"pid":os.getpid(),"ppid":os.getppid(),"uid":os.getuid(),"gid":os.getgid(),
          "machine_id":machine_id,"process_name":process_name,"namespace_ids":namespaces,"cgroups":cgroups,
          "systemd_unit":os.environ.get("SYSTEMD_UNIT"),"invocation_id_present":bool(os.environ.get("INVOCATION_ID"))}
    record={"layer":"observability","object_type":"telemetry_context","host":host,"timestamp":ts,
            "source":"/proc/self, /proc/self/ns, process environment","signal_type":"identity_snapshot","context_data":data}
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(data,indent=2)+"\n")
        except OSError as exc:return execution_failure("39",exc,"raw-evidence")
    return finish("39",[record],"AVAILABLE",source_status=[{"source":"/proc/self and /proc/self/ns","status":"AVAILABLE"}])

if __name__=="__main__":raise SystemExit(main())
