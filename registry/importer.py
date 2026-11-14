"""First load of an empty registry, then its first signed gateway-projects bundle.

    python -m registry.importer --owner-group project-owners --seed /seed/seed.yaml

The records come from the registry's latest snapshot in the bundle store
(snapshot.py: a registry that lost its database), or else from the seed (a new
cluster: the platform's own projects, a file of the project-registry chart). Both
have the format of GET /export: {"project": {id: spec}, "agent": {...},
"exception": {...}}. Does nothing once the registry has records, so it can run on
every sync. Waits for an active policy bundle, which the publisher publishes first.
"""
from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path

import yaml
from psycopg.types.json import Jsonb

from . import db as dbm
from .bundles import build

KINDS = ("project", "agent", "exception")


def records_from(seed: Path | None, snapshot: bytes | None) -> tuple[dict, str]:
    doc = json.loads(snapshot) if snapshot else None
    if doc and doc.get("project"):        # a snapshot without projects is no recovery point
        source = "snapshot"
    elif seed:
        doc, source = yaml.safe_load(seed.read_text()) or {}, f"seed {seed.name}"
    else:
        raise SystemExit("no snapshot in the store and no --seed: nothing to import")
    return {k: doc.get(k) or {} for k in KINDS}, source


def skip_used_revisions(c, store, data_bundle: str) -> None:
    """A new database starts bundle_seq over, but the store keeps every revision it had: move
    the sequence past them, so no published revision is written over."""
    used = [int(r.split("-", 1)[1]) for r in store.revisions(data_bundle)
            if r.startswith("projects-") and r.split("-", 1)[1].isdigit()]
    row = c.execute("select last_value, is_called from bundle_seq").fetchone()
    current = row["last_value"] if row["is_called"] else row["last_value"] - 1
    if used and max(used) > current:
        c.execute("select setval('bundle_seq', %s)", (max(used),))


def run(db: dbm.DB, store, signer, renderer, owner_group: str, records: dict, source: str,
        data_bundle="gateway-projects", policy_bundle="gateway-policy", opa="opa") -> str:
    policy_rev = store.active(policy_bundle)
    if not policy_rev:
        raise SystemExit(f"no active {policy_bundle} yet (the publisher publishes it first): retrying")
    with db.tx() as c, tempfile.TemporaryDirectory() as tmp:
        if c.execute("select 1 from resource limit 1").fetchone():
            print("the registry already has records: nothing to import")
            return store.active(data_bundle)
        for kind in KINDS:
            for oid, spec in records[kind].items():
                c.execute("insert into resource (kind, id, spec) values (%s, %s, %s)", (kind, oid, Jsonb(spec)))
        for pid in records["project"]:
            c.execute("insert into project_owner values (%s, %s) on conflict do nothing", (pid, owner_group))
        rendered = renderer.render(dbm.resources(c), policy_rev, Path(tmp) / "gateway-projects")
        skip_used_revisions(c, store, data_bundle)
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        revision = f"projects-{seq:08d}"
        out = Path(tmp) / "bundle.tar.gz"
        build(rendered, revision, signer, out, opa=opa)
        store.put_revision(data_bundle, revision, out)
        c.execute("update publication set state = 'superseded' where state = 'active'")
        c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                     values (%s, %s, '{}', 'active', %s, %s)""", (revision, seq, policy_rev, Jsonb(records)))
        dbm.audit(c, "importer", "import", source, None, {k: sorted(v) for k, v in records.items()})
        store.activate(data_bundle, revision)
    print(f"imported {', '.join(f'{len(v)} {k}s' for k, v in records.items())} from {source}; activated {revision}")
    return revision


def main() -> None:
    import boto3

    from .bundles import Store
    from .render import renderer_from_env
    from .vault import TransitSigner, Vault

    p = argparse.ArgumentParser()
    p.add_argument("--owner-group", required=True, help="Keycloak group approving as owner of every imported project")
    p.add_argument("--seed", type=Path, help="the seed file, for a new cluster")
    a = p.parse_args()
    env = os.environ
    db = dbm.DB(env["DATABASE_URL"])
    db.migrate()
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    store = Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", ""))
    with db.tx() as c:
        if c.execute("select 1 from resource limit 1").fetchone():
            print("the registry already has records: nothing to import")
            return
    records, source = records_from(a.seed, store.latest_snapshot())
    run(db, store,
        TransitSigner(Vault(env["VAULT_ADDR"], env["VAULT_ROLE"]), env["TRANSIT_KEY"], env["SIGNING_KEYID"],
                      version=int(env["SIGNING_KEY_VERSION"]) if env.get("SIGNING_KEY_VERSION") else None),
        renderer_from_env(env), a.owner_group,
        records, source)


if __name__ == "__main__":
    main()
