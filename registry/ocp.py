"""OPA Control Plane (OCP): the registry pins what it builds for the platform's other OPA
fleets (the gateway's own OPA gets the registry's signed bundles, not OCP's).

OCP has no signing and no approval of its own, so it only ever builds what the registry
has approved:

- its git sources, one per fleet directory of the policy (`policies/admission`, and
  `policies/platform`, which a stack mounts into every fleet's bundle), are pinned to
  the active policy commit; OCP never follows a branch;
- the facts the fleets check against are the active records, pushed as data.registry
  (`facts`): the gateway's key ids, the catalog models' deployments, the serving
  namespaces.

The publisher calls `pin` when the active policy commit or data bundle changes, and every
five minutes, which also mends an OCP that lost its state. The bundles, their labels,
stacks and destinations are OCP's own config (the deployment repo); the sources named
here are only ever written by the registry.
"""
from __future__ import annotations

import requests

from . import keys as keysmod

# OCP source -> the policy directory it builds from (under POLICY_SUBDIR).
SOURCES = {"admission": "policies/admission", "platform": "policies/platform"}
DATA_SOURCE = "registry"        # pushed facts, as data.registry


def facts(records: dict) -> dict:
    """What the fleets check against, from the active records."""
    models = records.get("model") or {}
    settings = (records.get("catalog") or {}).get("settings") or {}
    return {
        "keys": keysmod.owners(records),
        "deployments": {m["deployment"]: name for name, m in sorted(models.items()) if m.get("deployment")},
        "serving_namespaces": sorted(settings.get("servingNamespaces") or []),
    }


class OCP:
    def __init__(self, url: str, token: str, repo: str, subdir: str | None, ref: str = "main", session=None):
        self.url, self.repo, self.subdir, self.ref = url.rstrip("/"), repo, subdir, ref
        self.http = session or requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"

    def _put(self, path: str, body) -> None:
        r = self.http.put(f"{self.url}{path}", json=body, timeout=10)
        if r.status_code >= 300:
            raise RuntimeError(f"OCP PUT {path}: {r.status_code} {r.text[:200]}")

    def source(self, directory: str, commit: str) -> dict:
        path = f"{self.subdir}/{directory}" if self.subdir else directory
        return {"git": {"repo": self.repo, "reference": f"refs/heads/{self.ref}", "commit": commit, "path": path,
                        "excluded_files": ["*_test.rego"]}}

    def pin(self, commit: str, data: dict) -> None:
        """Every fleet source at `commit`, and the facts; OCP rebuilds the bundles that
        require them on its next round (about 30 s)."""
        for name, directory in SOURCES.items():
            self._put(f"/v1/sources/{name}", self.source(directory, commit))
        self._put(f"/v1/sources/{DATA_SOURCE}/data/{DATA_SOURCE}", data)
