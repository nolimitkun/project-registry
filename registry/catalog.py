"""The catalog in the registry: every model (placement, provider, price), Google API and
MCP tool (risk), and the catalog's settings (task classes, serving namespaces, MCP
targets), as records with change requests and approvals, like a project's.

They render with the policy repo's gen-catalog.py (render.write_catalog writes them as its
input files) into data.catalog in the gateway-projects bundle, and into the values of the
gateway-models chart (gatewaychart.py).

adopt(): the first time, the records come from the active policy commit's catalog files,
from before the catalog moved here.
"""
from __future__ import annotations

import logging

from psycopg.types.json import Jsonb

from . import db as dbm
from .render import read_catalog

log = logging.getLogger("catalog")


def adopt(db: dbm.DB, renderer, policy_rev: str) -> int:
    """Imports the active policy commit's catalog files as records, if the registry has no
    catalog records yet. Returns the number of records imported.

    Only once the initial import is done (the registry has a project): the importer
    takes any record as a finished import, so catalog records first would make it skip
    the seed or the snapshot. A seed or snapshot with the catalog makes this a no-op."""
    with db.tx() as c:
        if not c.execute("select 1 from resource where kind = any(%s) limit 1", (list(dbm.PROJECT_KINDS),)).fetchone():
            return 0
        if c.execute("select 1 from resource where kind = any(%s) limit 1", (list(dbm.CATALOG_KINDS),)).fetchone():
            return 0
        records = read_catalog(renderer.checkout(policy_rev))
        n = 0
        for kind, items in records.items():
            for oid, spec in items.items():
                c.execute("insert into resource (kind, id, spec) values (%s, %s, %s)", (kind, oid, Jsonb(spec)))
                n += 1
        if n:
            dbm.audit(c, "catalog", "adopt", f"policy@{policy_rev}", None, {k: sorted(v) for k, v in records.items()})
    if n:
        log.info("adopted the catalog of policy %s: %s records", policy_rev[:12], n)
    return n
