"""Daily snapshot of the registry's records into the bundle store.

    python -m registry.snapshot

Writes GET /export's document (every record, and the active data revision) to
registry-snapshots/<UTC time>.json and registry-snapshots/latest.json, next to the
bundles. A registry that lost its database imports latest.json (importer.py).
The records live only in the registry: this, and the signed bundle revisions,
are their copies. Not a backup of the database (approvals, audit log).
"""
from __future__ import annotations

import json
import os
import time

from . import db as dbm


def run(db: dbm.DB, store) -> str:
    with db.tx() as c:
        records = dbm.resources(c)
        active = c.execute("select revision from publication where state = 'active' "
                           "order by seq desc limit 1").fetchone()
    body = json.dumps({"revision": active["revision"] if active else None, **records},
                      indent=1, sort_keys=True).encode()
    name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + ".json"
    store.put_snapshot(name, body)
    store.put_snapshot("latest.json", body)
    print(f"snapshot {name}: {', '.join(f'{len(v)} {k}s' for k, v in records.items())}", flush=True)
    return name


def main() -> None:
    import boto3

    from .bundles import Store
    env = os.environ
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    run(dbm.DB(env["DATABASE_URL"]), Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", "")))


if __name__ == "__main__":
    main()
