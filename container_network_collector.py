#!/usr/bin/env python3
"""Collect Docker container network attachments using read-only inspect commands."""

import argparse
import datetime as dt
import json
import pathlib
import socket

from telemetry_common import CollectionFailure, aggregate_status, execution_failure, finish, run_readonly

LIST=["docker","--host","unix:///var/run/docker.sock","ps","--all","--format","{{json .}}"]
MAX_CONTAINERS=500

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--container",action="append",default=[],help="limit collection to named container(s); repeatable")
    parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[];sources=[];raw={};errors=[]
    if args.container:
        items=[{"ID":name,"Names":name,"State":None} for name in args.container[:MAX_CONTAINERS]]
        if len(args.container)>MAX_CONTAINERS:
            sources.append({"source":"--container","status":"AVAILABLE","detail":f"capped at {MAX_CONTAINERS} containers"})
    else:
        try:
            listing=run_readonly(LIST);items=[]
            for line in listing.splitlines():
                try:items.append(json.loads(line))
                except json.JSONDecodeError:continue
            truncated=len(items)>MAX_CONTAINERS
            items=items[:MAX_CONTAINERS]
            sources.append({"source":" ".join(LIST),"status":"AVAILABLE" if items else "EMPTY",
                            **({"detail":f"capped at {MAX_CONTAINERS} containers"} if truncated else {})})
        except CollectionFailure as exc:return finish("31",[],exc.status,str(exc),[{"source":" ".join(LIST),"status":exc.status,"detail":str(exc)}])
    for item in items:
        cid=item.get("ID") or item.get("Id")
        if not cid:continue
        if args.container and item.get("State") is None:
            state_command=["docker","--host","unix:///var/run/docker.sock","inspect","--format","{{.State.Status}}",cid]
            try:
                item["State"]=run_readonly(state_command).strip()
                sources.append({"source":" ".join(state_command),"status":"AVAILABLE"})
            except CollectionFailure as exc:
                errors.append(str(exc));sources.append({"source":" ".join(state_command),"status":exc.status,"detail":str(exc)})
        command=["docker","--host","unix:///var/run/docker.sock","inspect","--format","{{json .NetworkSettings}}",cid]
        try:document=json.loads(run_readonly(command));raw[cid]=document;sources.append({"source":" ".join(command),"status":"AVAILABLE"})
        except CollectionFailure as exc:errors.append(str(exc));sources.append({"source":" ".join(command),"status":exc.status,"detail":str(exc)});continue
        except json.JSONDecodeError as exc:errors.append(str(exc));sources.append({"source":" ".join(command),"status":"UNAVAILABLE","detail":str(exc)});continue
        for network,endpoint in (document.get("Networks") or {}).items():
            records.append({"layer":"runtime","object_type":"container_network_endpoint","host":host,"timestamp":ts,
                "source":" ".join(command),"signal_type":"container_network_snapshot","container_id":cid,
                "container_name":item.get("Names"),"container_state":item.get("State"),"network":network,
                "endpoint_id":endpoint.get("EndpointID"),"ipv4_address":endpoint.get("IPAddress"),
                "ipv6_address":endpoint.get("GlobalIPv6Address"),"gateway":endpoint.get("Gateway"),
                "mac_address":endpoint.get("MacAddress"),"aliases":endpoint.get("Aliases"),
                "ports":document.get("Ports")})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(raw,indent=2)+"\n")
        except OSError as exc:return execution_failure("31",exc,"raw-evidence")
    return finish("31",records,aggregate_status(records,sources),"; ".join(errors) or None,sources)

if __name__=="__main__":raise SystemExit(main())
