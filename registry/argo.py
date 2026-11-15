"""Telling Argo CD to look at the gateway-models Helm repository now.

Argo CD polls a Helm repository every few minutes; once the publisher has published a
chart version it asks Argo CD to refresh that one Application (the annotation Argo CD's
UI sets). Its Kubernetes role may patch only that Application. A refresh that fails
costs only the wait for Argo CD's own poll.
"""
from __future__ import annotations

import logging
from pathlib import Path

import requests

log = logging.getLogger("argo")

SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def refresh(app: str, sa: Path = SA, api: str = "https://kubernetes.default.svc") -> bool:
    """app: "<namespace>/<name>" of an Argo CD Application. Never raises."""
    try:
        ns, name = app.split("/", 1)
        r = requests.patch(f"{api}/apis/argoproj.io/v1alpha1/namespaces/{ns}/applications/{name}",
                           json={"metadata": {"annotations": {"argocd.argoproj.io/refresh": "normal"}}},
                           headers={"Authorization": f"Bearer {(sa / 'token').read_text()}",
                                    "Content-Type": "application/merge-patch+json"},
                           verify=str(sa / "ca.crt"), timeout=5)
        r.raise_for_status()
        return True
    except (OSError, ValueError, requests.RequestException) as e:
        log.warning("asking Argo CD to refresh %s: %s (it polls on its own)", app, e)
        return False
