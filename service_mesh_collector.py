#!/usr/bin/env python3
"""Read an explicitly supplied loopback Envoy admin config_dump endpoint."""

import argparse
import datetime as dt
import ipaddress
import json
import pathlib
import socket
import urllib.error
import urllib.parse
import urllib.request

from telemetry_common import execution_failure, finish


def loopback_url(value):
    parsed=urllib.parse.urlparse(value)
    if parsed.scheme!="http" or not parsed.hostname or not parsed.port:
        raise ValueError("admin URL must be explicit http://localhost:<port> or loopback IP")
    if parsed.hostname.lower()!="localhost":
        try:address=ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:raise ValueError("admin URL must use localhost or a loopback IP") from exc
        if not address.is_loopback:raise ValueError("non-loopback Envoy endpoint rejected")
    return value.rstrip("/")


def extract(value,names=None,endpoints=None):
    names=names if names is not None else set();endpoints=endpoints if endpoints is not None else set()
    if isinstance(value,dict):
        for key,item in value.items():
            if key in ("name","cluster_name","route_config_name") and isinstance(item,str):names.add(item)
            if key=="socket_address" and isinstance(item,dict):
                address=item.get("address");port=item.get("port_value")
                if address is not None:endpoints.add((address,port))
            extract(item,names,endpoints)
    elif isinstance(value,list):
        for item in value:extract(item,names,endpoints)
    return sorted(names),sorted(endpoints,key=lambda x:(x[0],x[1] or 0))


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--admin-url",required=True,
        help="explicit loopback Envoy admin base URL; collector requests only /config_dump")
    parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    source=args.admin_url.rstrip("/")+"/config_dump"
    try:
        url=loopback_url(args.admin_url)+"/config_dump"
        request=urllib.request.Request(url,headers={"Accept":"application/json"},method="GET")
        with urllib.request.urlopen(request,timeout=5) as response:
            raw=response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024:raise ValueError("Envoy config dump exceeds 4 MiB bound")
        doc=json.loads(raw)
    except (OSError,urllib.error.URLError,ValueError,json.JSONDecodeError) as exc:
        detail=str(exc);state="PERMISSION_DENIED" if "permission denied" in detail.lower() or "forbidden" in detail.lower() else "UNAVAILABLE"
        return finish("34",[],state,detail,[{"source":source,"status":state,"detail":detail}])
    host=socket.gethostname();timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[]
    for section in doc.get("configs",[]):
        section_type=section.get("@type","unknown")
        names,endpoints=extract(section)
        if "Listener" in section_type:obj="service_mesh_listener"
        elif "Route" in section_type:obj="service_mesh_route"
        elif "Cluster" in section_type:obj="service_mesh_upstream"
        elif "Endpoint" in section_type:obj="service_mesh_endpoint"
        else:obj="service_mesh_configuration"
        native_data={"section_type":section_type,"resource_names":names,"socket_endpoints":endpoints}
        if "version_info" in section:native_data["version_info"]=section["version_info"]
        records.append({"layer":"runtime","object_type":obj,"host":host,"timestamp":timestamp,"source":source,
                       "signal_type":"native_admin_snapshot","native_data":native_data})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(records,indent=2)+"\n")
        except OSError as exc:return execution_failure("34",exc,"raw-evidence")
    state="AVAILABLE" if records else "EMPTY"
    return finish("34",records,state,source_status=[{"source":source,"status":state}])


if __name__=="__main__":raise SystemExit(main())
