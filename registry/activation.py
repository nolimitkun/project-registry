"""When is a published change active? Once every OPA that serves the gateway has
loaded its bundle revision.

"Every OPA" is the ready pods behind the OPA Service, read from the Kubernetes API
(EndpointSlices), matched to the status reports by the pod name each OPA puts in
its status labels (opa-policy config: labels.pod). A pod that is gone stops
counting at once, a pod not ready yet doesn't count until it is. Without access
to the API, the fallback is every OPA that reported in the last few minutes,
which keeps a replaced pod counting until its last report ages out.

OPA reports only when something changes, so this is evaluated on every report
and also on every round of the publisher's loop.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import requests
from psycopg.types.json import Jsonb

from . import db as dbm

log = logging.getLogger("activation")
SA = Path("/var/run/secrets/kubernetes.io/serviceaccount")


def ready_opa_pods(namespace: str | None = None, service: str | None = None) -> set[str] | None:
    """Names of the ready pods behind the OPA Service, or None if the API can't be read."""
    namespace = namespace or os.environ.get("OPA_NAMESPACE", "mini-platform")
    service = service or os.environ.get("OPA_SERVICE", "opa")
    try:
        token = (SA / "token").read_text()
        r = requests.get(f"https://kubernetes.default.svc/apis/discovery.k8s.io/v1/namespaces/{namespace}/endpointslices",
                         params={"labelSelector": f"kubernetes.io/service-name={service}"},
                         headers={"Authorization": f"Bearer {token}"}, verify=str(SA / "ca.crt"), timeout=5)
        r.raise_for_status()
    except (OSError, requests.RequestException) as e:
        log.warning("can't list the OPA pods (%s); falling back to recent status reports", e)
        return None
    return {ep["targetRef"]["name"] for s in r.json().get("items", []) for ep in s.get("endpoints") or []
            if (ep.get("conditions") or {}).get("ready") and (ep.get("targetRef") or {}).get("kind") == "Pod"}


def record(c, report: dict) -> None:
    labels = report.get("labels") or {}
    if not labels.get("id"):
        return
    bundles = {name: b.get("active_revision") for name, b in (report.get("bundles") or {}).items()}
    c.execute("""insert into opa_status (instance_id, pod, bundles, at) values (%s, %s, %s, now())
                 on conflict (instance_id) do update set pod = excluded.pod, bundles = excluded.bundles, at = now()""",
              (labels["id"], labels.get("pod"), Jsonb(bundles)))


def activate_due(c, data_bundle: str, pods: set[str] | None, window: str = "5 minutes") -> list[str]:
    """Marks active every published revision all OPAs have loaded; returns them."""
    if pods is not None:
        if not pods:
            return []
        rows = c.execute("""select distinct on (pod) pod, bundles from opa_status where pod = any(%s)
                            order by pod, at desc""", (list(pods),)).fetchall()
        if {r["pod"] for r in rows} != pods:
            return []                  # a ready OPA hasn't reported yet
    else:
        rows = c.execute("select bundles from opa_status where at > now() - %s::interval", (window,)).fetchall()
        if not rows:
            return []
    everywhere = min(r["bundles"].get(data_bundle) or "" for r in rows)   # projects-NNNNNNNN sorts like its number
    done = []
    for pub in c.execute("""select revision, change_ids from publication
                            where active_at is null and state = 'active' and revision <= %s""",
                         (everywhere,)).fetchall():
        c.execute("update publication set active_at = now() where revision = %s", (pub["revision"],))
        c.execute("update change_request set state = 'active', updated_at = now() "
                  "where id = any(%s) and state = 'publishing'", (pub["change_ids"],))
        dbm.audit(c, "opa", "active", f"{data_bundle}@{pub['revision']}", None, {"changes": pub["change_ids"]})
        done.append(pub["revision"])
    return done
