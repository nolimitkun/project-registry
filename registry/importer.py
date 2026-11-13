"""First load: records from projects/*.yaml and agents/*.yaml, then the first
signed gateway-projects bundle (migration steps 2 to 4 of the design).

    python -m registry.importer --owner-group platform-admins

Reads the deployment repo at the active policy revision, imports its records
(once: refuses if the registry has any), renders them with gen-projects.py and
compares the result with the commit's policies/gateway-projects byte for byte
(the shadow check). Only if they match does it publish and activate.
"""
from __future__ import annotations

import argparse
import filecmp
import os
import tempfile
from pathlib import Path

from psycopg.types.json import Jsonb

from . import db as dbm
from .bundles import build
from .render import import_git


def differences(a: Path, b: Path) -> list[str]:
    out = []
    cmp = filecmp.dircmp(a, b)
    out += [f"only in registry render: {x}" for x in cmp.left_only]
    out += [f"only in Git: {x}" for x in cmp.right_only]
    out += [f"differs: {x}" for x in filecmp.cmpfiles(a, b, cmp.common_files, shallow=False)[1]]
    for sub in cmp.common_dirs:
        out += [f"{sub}/{d}" for d in differences(a / sub, b / sub)]
    return out


def run(db: dbm.DB, store, signer, renderer, owner_group: str, data_bundle="gateway-projects",
        policy_bundle="gateway-policy", opa="opa") -> str:
    policy_rev = store.active(policy_bundle)
    if not policy_rev:
        raise SystemExit(f"no active {policy_bundle}: run the policy build first")
    checkout = renderer.checkout(policy_rev)
    records = import_git(checkout)
    with db.tx() as c, tempfile.TemporaryDirectory() as tmp:
        if c.execute("select 1 from resource limit 1").fetchone():
            raise SystemExit("the registry already has records; import runs once")
        for kind, items in records.items():
            for oid, spec in items.items():
                c.execute("insert into resource (kind, id, spec) values (%s, %s, %s)", (kind, oid, Jsonb(spec)))
        for pid in records["project"]:
            c.execute("insert into project_owner values (%s, %s)", (pid, owner_group))
        rendered = renderer.render(dbm.resources(c), policy_rev, Path(tmp) / "gateway-projects")
        diff = differences(rendered, checkout / "policies" / "gateway-projects")
        if diff:
            raise SystemExit("shadow check failed, nothing imported:\n  " + "\n  ".join(diff))
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        revision = f"projects-{seq:08d}"
        out = Path(tmp) / "bundle.tar.gz"
        build(rendered, revision, signer, out, opa=opa)
        store.put_revision(data_bundle, revision, out)
        c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                     values (%s, %s, '{}', 'active', %s, %s)""", (revision, seq, policy_rev, Jsonb(records)))
        dbm.audit(c, "importer", "import", f"git@{policy_rev}", None,
                  {k: sorted(v) for k, v in records.items()})
        store.activate(data_bundle, revision)
    print(f"imported {', '.join(f'{len(v)} {k}s' for k, v in records.items())} from {policy_rev}; "
          f"render matches Git; activated {revision}")
    return revision


def main() -> None:
    import boto3

    from .bundles import Store
    from .render import Renderer
    from .vault import TransitSigner, Vault

    p = argparse.ArgumentParser()
    p.add_argument("--owner-group", required=True, help="Keycloak group approving as owner of every imported project")
    a = p.parse_args()
    env = os.environ
    db = dbm.DB(env["DATABASE_URL"])
    db.migrate()
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    run(db, Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", "")),
        TransitSigner(Vault(env["VAULT_ADDR"], env["VAULT_ROLE"]), env["TRANSIT_KEY"], env["SIGNING_KEYID"]),
        Renderer(env["DEPLOY_REPO"], Path(env.get("WORKDIR", "/tmp/registry")) / "checkouts"), a.owner_group)


if __name__ == "__main__":
    main()
