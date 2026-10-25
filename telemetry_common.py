"""Small shared helpers for bounded, read-only host telemetry commands."""

import datetime as dt
import json
import socket
import subprocess
import sys
from pathlib import Path


class CollectionFailure(Exception):
    def __init__(self, status, detail):
        super().__init__(detail)
        self.status = status


def run_readonly(command, timeout=10):
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, timeout=timeout)
        return result.stdout
    except FileNotFoundError as exc:
        raise CollectionFailure("UNAVAILABLE", f"utility not found: {command[0]}") from exc
    except PermissionError as exc:
        raise CollectionFailure("PERMISSION_DENIED", str(exc)) from exc
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or str(exc)).strip()
        denied = any(word in detail.lower() for word in ("permission denied", "operation not permitted", "access denied",
                                                          "must be root", "requires cap_net_admin", "requires root"))
        raise CollectionFailure("PERMISSION_DENIED" if denied else "UNAVAILABLE", detail) from exc
    except subprocess.TimeoutExpired as exc:
        raise CollectionFailure("UNAVAILABLE", f"command timed out after {timeout}s: {' '.join(command)}") from exc
    except OSError as exc:
        raise CollectionFailure("UNAVAILABLE", str(exc)) from exc


def context():
    return socket.gethostname(), dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def make_record(layer, object_type, source, host, timestamp, **fields):
    return {"layer": layer, "object_type": object_type, "host": host,
            "timestamp": timestamp, "source": source, **fields}


def save_raw(path, raw):
    if path:
        Path(path).write_text(raw, encoding="utf-8")


def finish(task_id, records, status, detail=None, source_status=None):
    """Emit telemetry only on stdout and one machine-readable status row on stderr."""
    records = list(records)
    for record in records:
        print(json.dumps(record, separators=(",", ":"), ensure_ascii=False))
    if source_status is None:
        sources = []
        for record in records:
            source = record.get("source")
            if source and source not in [item["source"] for item in sources]:
                sources.append({"source": source, "status": "AVAILABLE"})
        if not sources:
            sources = [{"source": "unspecified", "status": status}]
    else:
        sources = list(source_status)
    payload = {"record_type": "collection_status", "task_id": str(task_id).zfill(2),
               "status": status, "record_count": len(records), "source_status": sources}
    if detail:
        payload["detail"] = str(detail)
    print(json.dumps(payload, separators=(",", ":")), file=sys.stderr)
    return 0


def execution_failure(task_id, detail, source="collector"):
    """Report an execution failure and return the shared nonzero exit code."""
    finish(task_id, [], "EXECUTION_FAILURE", detail,
           [{"source": source, "status": "EXECUTION_FAILURE", "detail": str(detail)}])
    return 1


def command_status(error):
    """Map command errors into a reportable source state."""
    if isinstance(error, CollectionFailure):
        return error.status
    detail = str(getattr(error, "stderr", "") or error).lower()
    return "PERMISSION_DENIED" if any(word in detail for word in
                                       ("permission denied", "operation not permitted", "access denied")) else "UNAVAILABLE"


def aggregate_status(records, source_status):
    if records:
        return "AVAILABLE"
    states = [item["status"] for item in source_status]
    if states and all(state == "EMPTY" for state in states):
        return "EMPTY"
    if "UNAVAILABLE" in states or "EXECUTION_FAILURE" in states:
        return "UNAVAILABLE"
    if "PERMISSION_DENIED" in states:
        return "PERMISSION_DENIED"
    return "EMPTY"
