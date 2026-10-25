#!/usr/bin/env python3
"""Snapshot native ss process/socket associations without reading payloads."""

import argparse
import datetime as dt
import json
import pathlib
import re
import socket

from telemetry_common import CollectionFailure, aggregate_status, execution_failure, finish, run_readonly

COMMAND=["ss","-H","-n","-tup","-e","-p"]
PROCESS_RE=re.compile(r'"([^"\n]+)",pid=(\d+),fd=(\d+)')


def parse(raw,host,timestamp):
    records=[]
    for line in raw.splitlines():
        fields=line.split()
        if len(fields)<5:continue
        transport=fields[0].lower()
        if transport not in ("tcp","udp","tcp6","udp6"):continue
        state=fields[1];rxq=fields[2];txq=fields[3];local=fields[4];peer=fields[5] if len(fields)>5 else None
        processes=[{"name":m.group(1),"pid":int(m.group(2)),"fd":int(m.group(3))} for m in PROCESS_RE.finditer(line)]
        inode_match=re.search(r"\bino:(\d+)",line)
        data={"transport":transport,"state":state,"receive_queue":rxq,"send_queue":txq,
              "local_endpoint":local,"remote_endpoint":peer,"processes":processes or None,
              "inode":int(inode_match.group(1)) if inode_match else None,"native_line":line}
        records.append({"layer":"runtime","object_type":"process_socket_association","host":host,
                        "timestamp":timestamp,"source":" ".join(COMMAND),"signal_type":"socket_snapshot",
                        "process_network_data":data})
    return records


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--raw-evidence");args=parser.parse_args(argv)
    source=" ".join(COMMAND)
    try:
        raw=run_readonly(COMMAND,timeout=10);host=socket.gethostname();ts=dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        records=parse(raw,host,ts)
        if args.raw_evidence:pathlib.Path(args.raw_evidence).write_text(raw,encoding="utf-8")
    except CollectionFailure as exc:return finish("29",[],exc.status,str(exc),[{"source":source,"status":exc.status,"detail":str(exc)}])
    except OSError as exc:return execution_failure("29",exc,"raw-evidence")
    state="AVAILABLE" if records else "EMPTY"
    return finish("29",records,state,source_status=[{"source":source,"status":state}])

if __name__=="__main__":raise SystemExit(main())
