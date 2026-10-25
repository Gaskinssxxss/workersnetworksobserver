#!/usr/bin/env python3
"""Collect Kubernetes NetworkPolicy selectors and allow rules for one namespace."""
from kubernetes_network_collector import main_for_task

if __name__ == "__main__":
    raise SystemExit(main_for_task("33"))
