"""The registry API. Every edit is a change request: validated by rendering the
whole bundle with it, its approvals decided by policy (OPA:
data.portal.required_approvals, Rego in the deployment repo), approved by other
people than its author, then published by the publisher.

    uvicorn registry.api:app
"""
from __future__ import annotations

import copy
import os
import tempfile
from pathlib import Path

import requests
from fastapi import Depends, FastAPI, HTTPException
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from . import db as dbm
from .auth import ROLE_GROUPS, User, current_user
from .bundles import Store
from .render import Renderer, RenderError

KINDS = {"projects": "project", "agents": "agent", "exceptions": "exception"}


class ChangeIn(BaseModel):
    spec: dict | None = None             # create: the whole record; update: a merge patch
    owner_group: str | None = None       # create project: who approves as its owner
    comment: str | None = None


class Decision(BaseModel):
    comment: str | None = None


def merge(base: dict, patch: dict) -> dict:
    """RFC 7386 JSON merge patch."""
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = merge(out[k], v)
        else:
            out[k] = v
    return out


class Registry:
    def __init__(self, db: dbm.DB, renderer: Renderer, store: Store, opa_url: str,
                 policy_bundle="gateway-policy", data_bundle="gateway-projects"):
        self.db, self.renderer, self.store, self.opa_url = db, renderer, store, opa_url.rstrip("/")
        self.policy_bundle, self.data_bundle = policy_bundle, data_bundle

    # --- approvals ---
    def required_approvals(self, change: dict, requester: str) -> list[str]:
        r = requests.post(f"{self.opa_url}/v1/data/portal/required_approvals",
                          json={"input": {"change": change, "requester": requester}}, timeout=5)
        r.raise_for_status()
        roles = r.json().get("result")
        if not isinstance(roles, list) or not roles or not set(roles) <= {*ROLE_GROUPS, "project_owner"}:
            raise HTTPException(503, f"approval policy gave no valid answer: {roles!r}")   # fail closed
        return sorted(set(roles))

    def owner_group(self, c, kind: str, oid: str, spec: dict | None) -> str | None:
        pid = oid if kind in ("project", "exception") else (spec or {}).get("project")
        row = c.execute("select owner_group from project_owner where project_id = %s", (pid,)).fetchone()
        return row["owner_group"] if row else None

    def roles_of(self, c, user: User, change: dict) -> set[str]:
        roles = {role for role, group in ROLE_GROUPS.items() if group in user.groups}
        owner = self.owner_group(c, change["kind"], change["object_id"], change["after"] or change["before"])
        if owner and owner in user.groups:
            roles.add("project_owner")
        return roles

    # --- changes ---
    def submit(self, user: User, kind: str, oid: str, op: str, body: ChangeIn) -> dict:
        with self.db.tx() as c:
            row = c.execute("select spec from resource where kind = %s and id = %s", (kind, oid)).fetchone()
            before = row["spec"] if row else None
            if op == "create":
                if before is not None:
                    raise HTTPException(409, f"{kind} {oid} exists")
                if kind == "project" and not body.owner_group:
                    raise HTTPException(422, "a new project needs owner_group")
                after = body.spec
            elif before is None:
                raise HTTPException(404, f"no {kind} {oid}")
            else:
                after = None if op == "delete" else merge(before, body.spec or {})
            if after == before:
                raise HTTPException(422, "the change changes nothing")
            pending = c.execute("select id from change_request where kind = %s and object_id = %s and "
                                "state in ('pending_approval', 'approved', 'publishing')", (kind, oid)).fetchone()
            if pending:
                raise HTTPException(409, f"change {pending['id']} for {kind} {oid} is not finished yet")
            records = dbm.resources(c)
            if after is None:
                records[kind].pop(oid, None)
            else:
                records[kind][oid] = after
            policy_rev = self.store.active(self.policy_bundle)
            if not policy_rev:
                raise HTTPException(503, "no active policy bundle to validate against")
            with tempfile.TemporaryDirectory() as tmp:
                try:
                    self.renderer.render(records, policy_rev, Path(tmp) / "out")
                except RenderError as e:
                    raise HTTPException(422, {"errors": e.errors}) from e
            change = {"kind": kind, "object_id": oid, "op": op, "before": before, "after": after}
            required = self.required_approvals(change, user.name)
            row = c.execute("""insert into change_request (kind, object_id, op, before, after, state,
                                   required_approvals, created_by)
                               values (%s, %s, %s, %s, %s, 'pending_approval', %s, %s) returning *""",
                            (kind, oid, op, Jsonb(before) if before is not None else None,
                             Jsonb(after) if after is not None else None, Jsonb(required), user.name)).fetchone()
            if kind == "project" and op == "create":
                c.execute("insert into project_owner values (%s, %s) on conflict (project_id) do update "
                          "set owner_group = excluded.owner_group", (oid, body.owner_group))
            dbm.audit(c, user.name, f"change_{op}", f"{kind}/{oid}", before, after)
            return dict(row)

    def decide(self, user: User, change_id: int, decision: str, comment: str | None) -> dict:
        with self.db.tx() as c:
            ch = c.execute("select * from change_request where id = %s for update", (change_id,)).fetchone()
            if not ch:
                raise HTTPException(404, "no such change")
            if ch["state"] != "pending_approval":
                raise HTTPException(409, f"change is {ch['state']}")
            if ch["created_by"] == user.name:
                raise HTTPException(403, "four eyes: nobody approves their own change")
            done = {a["role"] for a in c.execute(
                "select role from approval where change_id = %s and decision = 'approve'", (change_id,))}
            if c.execute("select 1 from approval where change_id = %s and approver = %s",
                         (change_id, user.name)).fetchone():
                raise HTTPException(409, "you have already decided on this change")
            open_roles = [r for r in ch["required_approvals"] if r not in done]
            mine = [r for r in open_roles if r in self.roles_of(c, user, ch)]
            if not mine:
                raise HTTPException(403, f"none of the open approvals {open_roles} is yours")
            role = mine[0]
            c.execute("insert into approval (change_id, approver, role, decision, comment) values (%s, %s, %s, %s, %s)",
                      (change_id, user.name, role, decision, comment))
            if decision == "reject":
                state = "rejected"
            elif set(open_roles) - {role}:
                state = "pending_approval"
            else:
                state = "approved"
                c.execute("insert into outbox (change_id) values (%s)", (change_id,))
            c.execute("update change_request set state = %s, updated_at = now() where id = %s", (state, change_id))
            dbm.audit(c, user.name, decision, f"change/{change_id}", None, {"role": role, "comment": comment})
            return {"id": change_id, "state": state, "approved_as": role}

    # --- activation, from OPA status reports ---
    def status(self, report: dict) -> None:
        instance = (report.get("labels") or {}).get("id")
        bundles = {name: b.get("active_revision") for name, b in (report.get("bundles") or {}).items()}
        if not instance:
            return
        with self.db.tx() as c:
            c.execute("""insert into opa_status values (%s, %s, now())
                         on conflict (instance_id) do update set bundles = excluded.bundles, at = now()""",
                      (instance, Jsonb(bundles)))
            live = [r["bundles"].get(self.data_bundle) or "" for r in c.execute(
                "select bundles from opa_status where at > now() - interval '5 minutes'")]
            if not live:
                return
            everywhere = min(live)         # projects-NNNNNNNN sorts like its number
            for pub in c.execute("""select revision, change_ids from publication
                                    where active_at is null and state = 'active' and revision <= %s""",
                                 (everywhere,)).fetchall():
                c.execute("update publication set active_at = now() where revision = %s", (pub["revision"],))
                c.execute("update change_request set state = 'active', updated_at = now() "
                          "where id = any(%s) and state = 'publishing'", (pub["change_ids"],))
                dbm.audit(c, "opa", "active", f"{self.data_bundle}@{pub['revision']}", None,
                          {"changes": pub["change_ids"]})

    def rollback(self, user: User, revision: str) -> dict:
        if ROLE_GROUPS["platform"] not in user.groups:
            raise HTTPException(403, "rollback is for the platform team")
        with self.db.tx() as c:
            pub = c.execute("select * from publication where revision = %s", (revision,)).fetchone()
            if not pub:
                raise HTTPException(404, "no such revision")
            later = c.execute("select revision, change_ids from publication where seq > %s and state <> 'rolled_back'",
                              (pub["seq"],)).fetchall()
            c.execute("delete from resource")
            for kind, items in pub["records"].items():
                for oid, spec in items.items():
                    c.execute("insert into resource (kind, id, spec) values (%s, %s, %s)", (kind, oid, Jsonb(spec)))
            for p in later:
                c.execute("update publication set state = 'rolled_back' where revision = %s", (p["revision"],))
                c.execute("update change_request set state = 'rolled_back', updated_at = now() where id = any(%s)",
                          (p["change_ids"],))
            c.execute("update publication set state = 'active' where revision = %s", (revision,))
            dbm.audit(c, user.name, "rollback", f"{self.data_bundle}@{revision}", None,
                      {"rolled_back": [p["revision"] for p in later]})
            self.store.activate(self.data_bundle, revision)      # last, as in the publisher
            return {"active": revision, "rolled_back": [p["revision"] for p in later]}


def create_app(reg: Registry) -> FastAPI:
    app = FastAPI(title="project registry")

    def kind_of(collection: str) -> str:
        if collection not in KINDS:
            raise HTTPException(404, f"no collection {collection}")
        return KINDS[collection]

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    # specific routes first: FastAPI matches in declaration order
    @app.get("/changes/{change_id}")
    def get_change(change_id: int, user: User = Depends(current_user)):
        with reg.db.tx() as c:
            ch = c.execute("select * from change_request where id = %s", (change_id,)).fetchone()
            if not ch:
                raise HTTPException(404)
            ch["approvals"] = c.execute("select approver, role, decision, comment, at from approval "
                                        "where change_id = %s order by at", (change_id,)).fetchall()
        return ch

    @app.post("/changes/{change_id}/approve")
    def approve(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.decide(user, change_id, "approve", body.comment)

    @app.post("/changes/{change_id}/reject")
    def reject(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.decide(user, change_id, "reject", body.comment)

    @app.get("/publications")
    def publications(user: User = Depends(current_user)):
        with reg.db.tx() as c:
            return c.execute("select revision, change_ids, state, policy_revision, created_at, active_at "
                             "from publication order by seq desc limit 50").fetchall()

    @app.post("/rollback/{revision}")
    def rollback(revision: str, user: User = Depends(current_user)):
        return reg.rollback(user, revision)

    # OPA's status plugin posts here; cluster-internal, no user token
    @app.post("/opa/status")
    @app.post("/opa/status/{partition}")
    def opa_status(report: dict, partition: str | None = None):
        reg.status(report)
        return {}

    @app.get("/{collection}")
    def list_records(collection: str, user: User = Depends(current_user)):
        kind = kind_of(collection)
        with reg.db.tx() as c:
            return {r["id"]: r["spec"] for r in c.execute(
                "select id, spec from resource where kind = %s order by id", (kind,))}

    @app.get("/{collection}/{oid}")
    def get_record(collection: str, oid: str, user: User = Depends(current_user)):
        kind = kind_of(collection)
        with reg.db.tx() as c:
            row = c.execute("select spec, revision from resource where kind = %s and id = %s", (kind, oid)).fetchone()
        if not row:
            raise HTTPException(404)
        return row

    @app.post("/{collection}/{oid}", status_code=201)
    def create(collection: str, oid: str, body: ChangeIn, user: User = Depends(current_user)):
        return reg.submit(user, kind_of(collection), oid, "create", body)

    @app.patch("/{collection}/{oid}")
    def update(collection: str, oid: str, body: ChangeIn, user: User = Depends(current_user)):
        return reg.submit(user, kind_of(collection), oid, "update", body)

    @app.delete("/{collection}/{oid}")
    def delete(collection: str, oid: str, user: User = Depends(current_user)):
        return reg.submit(user, kind_of(collection), oid, "delete", ChangeIn())

    return app


def _from_env() -> FastAPI:
    import boto3
    env = os.environ
    db = dbm.DB(env["DATABASE_URL"])
    db.migrate()
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    return create_app(Registry(db, Renderer(env["DEPLOY_REPO"], Path(env.get("WORKDIR", "/tmp/registry")) / "checkouts"),
                               Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", "")), env["OPA_URL"]))


app = _from_env() if os.environ.get("DATABASE_URL") else None
