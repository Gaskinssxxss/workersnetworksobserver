#!/usr/bin/env python3
"""Collect pod, Service, and EndpointSlice network context from one namespace."""
from kubernetes_network_collector import main_for_task

if __name__ == "__main__":
    raise SystemExit(main_for_task("32"))
