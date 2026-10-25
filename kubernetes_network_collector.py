#!/usr/bin/env python3
"""Collect Kubernetes network objects or NetworkPolicy using read-only kubectl JSON."""

import argparse
import datetime as dt
import json
import pathlib
import socket

from telemetry_common import CollectionFailure, execution_failure, finish, run_readonly


def task32_records(document,namespace,host,timestamp,source):
    records=[]
    for item in document.get("items",[]):
        kind=item.get("kind","");meta=item.get("metadata",{});spec=item.get("spec",{});status=item.get("status",{})
        common={"namespace":meta.get("namespace",namespace),"name":meta.get("name"),"uid":meta.get("uid"),"resource_kind":kind}
        if kind=="Pod":
            data={**common,"node_name":spec.get("nodeName"),"pod_ip":status.get("podIP"),"pod_ips":status.get("podIPs"),
                  "host_ip":status.get("hostIP"),"phase":status.get("phase"),
                  "container_ports":[p for c in spec.get("containers",[]) for p in c.get("ports",[])]}
        elif kind=="Service":
            data={**common,"service_type":spec.get("type"),"cluster_ip":spec.get("clusterIP"),"cluster_ips":spec.get("clusterIPs"),
                  "external_ips":spec.get("externalIPs"),"ports":spec.get("ports"),"selector":spec.get("selector"),
                  "load_balancer_ingress":status.get("loadBalancer",{}).get("ingress",[])}
        elif kind=="EndpointSlice":
            data={**common,"address_type":item.get("addressType"),"service_name":meta.get("labels",{}).get("kubernetes.io/service-name"),
                  "ports":item.get("ports"),"endpoints":[{"addresses":e.get("addresses"),"conditions":e.get("conditions"),
                      "target_ref":({k:e.get("targetRef",{}).get(k) for k in ("kind","namespace","name","uid")} if e.get("targetRef") else None)}
                      for e in item.get("endpoints",[])]}
        else:
            continue
        records.append({"layer":"runtime","object_type":"kubernetes_network_object","host":host,"timestamp":timestamp,
                        "source":source,"signal_type":"control_plane_snapshot","network_data":data})
    return records


def task33_records(document,namespace,host,timestamp,source):
    records=[]
    for item in document.get("items",[]):
        meta=item.get("metadata",{});spec=item.get("spec",{})
        data={"namespace":meta.get("namespace",namespace),"name":meta.get("name"),"uid":meta.get("uid"),
              "pod_selector":spec.get("podSelector"),"policy_types":spec.get("policyTypes"),
              "ingress":spec.get("ingress"),"egress":spec.get("egress")}
        records.append({"layer":"runtime","object_type":"kubernetes_network_policy","host":host,"timestamp":timestamp,
                        "source":source,"signal_type":"control_plane_snapshot","policy_data":data})
    return records


def main_for_task(task,argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--namespace",required=True)
    parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    resources="pods,services,endpointslices" if task=="32" else "networkpolicies"
    command=["kubectl","get",resources,"--namespace",args.namespace,"--output","json"]
    source=" ".join(command)
    try:
        raw=run_readonly(command,timeout=15);doc=json.loads(raw)
    except CollectionFailure as exc:return finish(task,[],exc.status,str(exc),[{"source":source,"status":exc.status,"detail":str(exc)}])
    except (json.JSONDecodeError,AttributeError) as exc:return finish(task,[],"UNAVAILABLE",str(exc),[{"source":source,"status":"UNAVAILABLE","detail":str(exc)}])
    host=socket.gethostname();timestamp=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
    records=task32_records(doc,args.namespace,host,timestamp,source) if task=="32" else task33_records(doc,args.namespace,host,timestamp,source)
    if args.raw_evidence:
        safe=[r.get("network_data",r.get("policy_data")) for r in records]
        try:args.raw_evidence.write_text(json.dumps(safe,indent=2)+"\n")
        except OSError as exc:return execution_failure(task,exc,"raw-evidence")
    state="AVAILABLE" if records else "EMPTY"
    return finish(task,records,state,source_status=[{"source":source,"status":state}])


if __name__=="__main__":
    p=argparse.ArgumentParser(description="Dispatch one read-only Kubernetes network object collector.")
    p.add_argument("task",choices=("32","33"),help="32=network objects, 33=NetworkPolicy objects")
    known,rest=p.parse_known_args()
    raise SystemExit(main_for_task(known.task,rest))
