#!/usr/bin/env python3
"""Inventory project collector modules and the presence of their native source tools."""

import argparse
import datetime as dt
import json
import pathlib
import shutil
import socket

from telemetry_common import execution_failure, finish

ROOT=pathlib.Path(__file__).resolve().parent
MODULES={
    "01": "ip_address_collector.py",
    "02": "route_collector.py",
    "03": "routing_policy_collector.py",
    "04": "network_tunnel_collector.py",
    "05": "ip_protocol_metric_collector.py",
    "06": "transport_endpoint_collector.py",
    "07": "tcp_connection_collector.py",
    "08": "udp_quic_collector.py",
    "09": "conntrack_collector.py",
    "10": "nftables_snapshot_collector.py",
    "11": "nftables_snapshot_collector.py",
    "12": "nftables_snapshot_collector.py",
    "13": "transport_performance_collector.py",
    "19": "network_services_collector.py",
    "20": "service_discovery_collector.py",
    "21": "application_session_collector.py",
    "24": "proxy_networking_collector.py",
    "25": "load_balancing_collector.py",
    "27": "application_resilience_collector.py",
    "28": "network_namespace_collector.py",
    "29": "process_networking_collector.py",
    "30": "virtual_machine_network_collector.py",
    "31": "container_network_collector.py",
    "32": "kubernetes_network_collector.py",
    "32": "kubernetes_networking_collector.py",
    "33": "kubernetes_network_collector.py",
    "33": "kubernetes_network_policy_collector.py",
    "34": "service_mesh_collector.py",
    "36": "telemetry_source_collector.py",
    "37": "collection_target_collector.py",
    "39": "telemetry_context_collector.py",
    "40": "collection_health_collector.py",
}
TOOLS=("ip","ss","nstat","nft","conntrack","systemctl","journalctl","resolvectl","avahi-browse","docker","virsh",
       "kubectl","istioctl","linkerd","aws","gcloud","az","openstack")
APP_PATHS=("/var/log/nginx/access.log","/var/log/apache2/access.log","/var/log/haproxy.log","/var/log/caddy/access.log","/var/log/envoy/access.log")

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--raw-evidence",type=pathlib.Path);args=parser.parse_args(argv)
    host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds");records=[];sources=[]
    for scope,module in MODULES.items():
        path=ROOT/module;present=path.is_file()
        records.append({"layer":"observability","object_type":"telemetry_source","host":host,"timestamp":ts,
            "source":str(path),"signal_type":"collector_module_inventory","scope":scope,"module":module,
            "module_present":present,"capability_state":"AVAILABLE" if present else "UNAVAILABLE"})
    for tool in TOOLS:
        path=shutil.which(tool)
        records.append({"layer":"observability","object_type":"telemetry_source","host":host,"timestamp":ts,
            "source":f"PATH:{tool}","signal_type":"native_tool_inventory","tool":tool,"executable":path,
            "capability_state":"AVAILABLE" if path else "UNAVAILABLE",
            "detail":"binary presence only; does not assert service state or data availability"})
        sources.append({"source":f"PATH:{tool}","status":"AVAILABLE" if path else "UNAVAILABLE"})
    for value in APP_PATHS:
        present=pathlib.Path(value).is_file()
        records.append({"layer":"observability","object_type":"telemetry_source","host":host,"timestamp":ts,
            "source":value,"signal_type":"application_log_source_inventory","capability_state":"AVAILABLE" if present else "UNAVAILABLE"})
        sources.append({"source":value,"status":"AVAILABLE" if present else "UNAVAILABLE"})
    if args.raw_evidence:
        try:args.raw_evidence.write_text(json.dumps(records,indent=2)+"\n")
        except OSError as exc:return execution_failure("36",exc,"raw-evidence")
    return finish("36",records,"AVAILABLE",source_status=[{"source":"local module/tool/path inventory","status":"AVAILABLE"},*sources])

if __name__=="__main__":raise SystemExit(main())
