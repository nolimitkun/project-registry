"""The gateway's model routes, published as a Helm chart for Argo CD.

The policy repository has the chart (charts/gateway-models: an AgentgatewayModel per
model, the auto models, the Google API routes) and the catalog it is templated over
(generated/agentgateway-catalog.yaml). Once a policy commit is active, the publisher
packages the chart at that commit with the catalog as its values and publishes it to
a Helm repository in a bucket of its own (index.yaml next to the charts); the
deployment repo's Argo CD application installs the newest version, with the
gateway's own values. Argo CD can't read values from MinIO, so the catalog travels in
the chart.

The routes and the policy take effect apart, but both fail closed: a route OPA
doesn't allow yet answers 403, a model OPA allows without a route yet 404.
"""
from __future__ import annotations

import hashlib
import io
import logging
import tarfile
import time
from pathlib import Path

import yaml

log = logging.getLogger("gatewaychart")

CHART = "charts/gateway-models"
CATALOG = "generated/agentgateway-catalog.yaml"
POLICY_ANNOTATION = "project-registry/policy-revision"


class HelmRepo:
    """A Helm chart repository in an S3 bucket: index.yaml and <name>-<version>.tgz."""

    def __init__(self, s3, bucket: str, name: str = "gateway-models"):
        self.s3, self.bucket, self.name = s3, bucket, name

    def index(self) -> dict:
        try:
            body = self.s3.get_object(Bucket=self.bucket, Key="index.yaml")["Body"].read()
        except Exception as e:
            if "NoSuchKey" in type(e).__name__ or "NoSuchKey" in str(e) or "404" in str(e):
                return {"apiVersion": "v1", "entries": {}}
            raise
        return yaml.safe_load(body) or {"apiVersion": "v1", "entries": {}}

    def newest(self) -> dict | None:
        entries = self.index().get("entries", {}).get(self.name) or []
        return entries[0] if entries else None

    def publish(self, chart_dir: Path, values: dict, app_version: str, annotations: dict) -> str:
        """Packages chart_dir with values merged over its values.yaml; returns the version."""
        index = self.index()
        entries = index.setdefault("entries", {}).setdefault(self.name, [])
        version = f"1.0.{len(entries) + 1}"
        chart = yaml.safe_load((chart_dir / "Chart.yaml").read_text())
        chart.update(version=version, appVersion=app_version)
        chart["annotations"] = {**(chart.get("annotations") or {}), **annotations}
        defaults = yaml.safe_load((chart_dir / "values.yaml").read_text()) or {}
        files = {"Chart.yaml": yaml.safe_dump(chart, sort_keys=False).encode(),
                 "values.yaml": yaml.safe_dump({**defaults, **values}, sort_keys=False).encode()}
        for p in sorted(chart_dir.rglob("*")):
            rel = str(p.relative_to(chart_dir))
            if p.is_file() and rel not in files:
                files[rel] = p.read_bytes()
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            for rel, data in files.items():
                info = tarfile.TarInfo(f"{self.name}/{rel}")
                info.size, info.mode, info.mtime = len(data), 0o644, int(time.time())
                tar.addfile(info, io.BytesIO(data))
        tgz = buf.getvalue()
        key = f"{self.name}-{version}.tgz"
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=tgz, ContentType="application/gzip")
        entries.insert(0, {**{k: chart[k] for k in ("apiVersion", "name", "description", "type") if k in chart},
                           "version": version, "appVersion": app_version, "annotations": chart["annotations"],
                           "urls": [key], "digest": hashlib.sha256(tgz).hexdigest(),
                           "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})
        index["generated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        # last: Argo CD sees the version once the index names it
        self.s3.put_object(Bucket=self.bucket, Key="index.yaml", Body=yaml.safe_dump(index, sort_keys=False).encode(),
                           ContentType="application/x-yaml")
        return version


def ensure(repo: HelmRepo, renderer, policy_rev: str) -> str | None:
    """Publishes the chart of the active policy commit, unless the newest version is it.
    Returns the new version, or None (already published, or a commit without the chart)."""
    newest = repo.newest()
    if newest and (newest.get("annotations") or {}).get(POLICY_ANNOTATION) == policy_rev:
        return None
    work = renderer.checkout(policy_rev)
    if not (work / CHART / "Chart.yaml").exists() or not (work / CATALOG).exists():
        log.info("policy %s has no %s: no gateway-models chart", policy_rev[:12], CHART)
        return None
    catalog = (yaml.safe_load((work / CATALOG).read_text()) or {}).get("catalog") or {}
    version = repo.publish(work / CHART, {"catalog": catalog}, policy_rev[:12], {POLICY_ANNOTATION: policy_rev})
    log.info("published gateway-models %s for policy %s", version, policy_rev[:12])
    return version
