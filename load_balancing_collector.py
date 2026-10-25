#!/usr/bin/env python3
"""Collect explicit load-balancer endpoint/health fields from native JSONL logs."""
from application_object_log_source import main_for_task

if __name__ == "__main__":
    raise SystemExit(main_for_task("25"))
