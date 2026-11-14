"""The registry API and its portal page. Every edit is a change request, proposed
only by whom policy allows (OPA: data.portal.may_submit), validated by rendering
the whole bundle with it, its approvals decided by policy
(data.portal.required_approvals; both Rego in the deployment repo), approved by
other people than its author (or withdrawn), then published by the publisher.
Policy changes (kind `policy`, a commit of the Rego in Git) are filed by the
publisher itself (policy.py) and approved here the same way.

    uvicorn registry.api:app
"""
from __future__ import annotations

import copy
import os
import tempfile
from pathlib import Path

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse
from psycopg.types.json import Jsonb
from pydantic import BaseModel

from . import activation, approvals
from . import db as dbm
from .auth import ROLE_GROUPS, User, current_user
from . import bundles
from .bundles import Store
from .policy import same_data
from .render import Renderer, RenderError

KINDS = {"projects": "project", "agents": "agent", "exceptions": "exception"}
PORTAL = Path(__file__).resolve().parent / "static" / "portal.html"


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
                 policy_bundle="gateway-policy", data_bundle="gateway-projects", signing_keyid: str | None = None):
        self.db, self.renderer, self.store, self.opa_url = db, renderer, store, opa_url.rstrip("/")
        self.policy_bundle, self.data_bundle = policy_bundle, data_bundle
        self.signing_keyid = signing_keyid or os.environ.get("SIGNING_KEYID")
        self.opa_pods = activation.ready_opa_pods        # replaced in tests

    # --- approvals ---
    def required_approvals(self, change: dict, requester: str) -> list[str]:
        try:
            return approvals.required(self.opa_url, change, requester)
        except approvals.NoAnswer as e:
            raise HTTPException(503, str(e)) from e                                     # fail closed

    def may_submit(self, change: dict, user: User, owner_group: str | None) -> bool:
        """data.portal.may_submit: who may propose this change at all (approval is separate)."""
        r = requests.post(f"{self.opa_url}/v1/data/portal/may_submit", timeout=5, json={"input": {
            "change": change, "requester": user.name, "groups": sorted(user.groups),
            "owner_group": owner_group}})
        r.raise_for_status()
        return r.json().get("result") is True          # undefined or anything else: no

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
            owner = body.owner_group if (kind == "project" and op == "create") else \
                self.owner_group(c, kind, oid, after or before)
            if not self.may_submit(change, user, owner):
                raise HTTPException(403, f"you may not propose changes to {kind} {oid}")
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

    def withdraw(self, user: User, change_id: int, comment: str | None) -> dict:
        """Its author, or the platform team, takes back a change not yet published: the way out
        of a change nobody can approve (say, its author is the only member of a role it needs)."""
        with self.db.tx() as c:
            ch = c.execute("select * from change_request where id = %s for update", (change_id,)).fetchone()
            if not ch:
                raise HTTPException(404, "no such change")
            if user.name != ch["created_by"] and ROLE_GROUPS["platform"] not in user.groups:
                raise HTTPException(403, "only its author or the platform team may withdraw a change")
            if ch["state"] not in ("pending_approval", "approved"):
                raise HTTPException(409, f"change is {ch['state']}")
            published = c.execute("select 1 from outbox where change_id = %s and published_at is not null",
                                  (change_id,)).fetchone()
            if published:
                raise HTTPException(409, "change is being published")
            c.execute("delete from outbox where change_id = %s", (change_id,))
            c.execute("update change_request set state = 'withdrawn', updated_at = now() where id = %s", (change_id,))
            dbm.audit(c, user.name, "withdraw", f"change/{change_id}", None, {"comment": comment})
            return {"id": change_id, "state": "withdrawn"}

    # --- activation, from OPA status reports ---
    def status(self, report: dict) -> None:
        with self.db.tx() as c:
            activation.record(c, report)
            activation.activate_due(c, self.data_bundle, self.opa_pods(), policy_bundle=self.policy_bundle)

    def rollback(self, user: User, revision: str) -> dict:
        if ROLE_GROUPS["platform"] not in user.groups:
            raise HTTPException(403, "rollback is for the platform team")
        with self.db.tx() as c:
            if c.execute("select 1 from policy_publication where revision = %s", (revision,)).fetchone():
                return self._rollback_policy(c, user, revision)
            pub = c.execute("select * from publication where revision = %s", (revision,)).fetchone()
            if not pub:
                raise HTTPException(404, "no such revision")
            later = c.execute("select revision, change_ids from publication where seq > %s and state <> 'rolled_back'",
                              (pub["seq"],)).fetchall()
            policy_rev = self.store.active(self.policy_bundle)
            if pub["policy_revision"] != policy_rev:
                self._data_fits(c, policy_rev, records=pub["records"], bundle=revision)
            c.execute("delete from resource")
            for kind, items in pub["records"].items():
                for oid, spec in items.items():
                    c.execute("insert into resource (kind, id, spec) values (%s, %s, %s)", (kind, oid, Jsonb(spec)))
            for p in later:
                c.execute("update publication set state = 'rolled_back' where revision = %s", (p["revision"],))
                c.execute("update change_request set state = 'rolled_back', updated_at = now() where id = any(%s)",
                          (p["change_ids"],))
            # rolling forward to a later revision leaves an earlier one active: supersede it
            c.execute("update publication set state = 'superseded' where state = 'active' and revision <> %s",
                      (revision,))
            c.execute("update publication set state = 'active' where revision = %s", (revision,))
            dbm.audit(c, user.name, "rollback", f"{self.data_bundle}@{revision}", None,
                      {"rolled_back": [p["revision"] for p in later]})
            self.store.activate(self.data_bundle, revision)      # last, as in the publisher
            return {"active": revision, "rolled_back": [p["revision"] for p in later]}

    def _data_fits(self, c, policy_rev: str, records: dict | None = None, bundle: str | None = None) -> None:
        """A rollback activates one bundle only. Refuse it (409) when the project data it would
        run with is not what the policy commit renders: the format may have changed between
        commits. records/bundle: those of a data rollback; by default, the active ones."""
        with tempfile.TemporaryDirectory() as tmp:
            rendered = self.renderer.render(records if records is not None else dbm.resources(c), policy_rev,
                                            Path(tmp) / "render")
            bundle = bundle or self.store.active(self.data_bundle)
            if not same_data(rendered, self.store.fetch(self.data_bundle, bundle, Path(tmp) / "data.tar.gz")):
                raise HTTPException(409, f"the project data renders differently at policy {policy_rev[:12]}: "
                                         "roll back with a new commit (a revert), which republishes both")

    def _rollback_policy(self, c, user: User, revision: str) -> dict:
        """An earlier policy commit, as it was signed. The branch's head isn't proposed again
        (it has its change); the next commit is, a revert for instance."""
        pub = c.execute("select * from policy_publication where revision = %s for update", (revision,)).fetchone()
        if pub["state"] == "active":
            raise HTTPException(409, f"{revision} is the active policy")
        with tempfile.TemporaryDirectory() as tmp:
            keyid = bundles.signed_keyid(self.store.fetch(self.policy_bundle, revision, Path(tmp) / "b.tar.gz"))
        if keyid != self.signing_keyid:
            raise HTTPException(409, f"{revision} is signed with {keyid}, which OPA no longer accepts")
        self._data_fits(c, revision)
        later = c.execute("select revision, change_id from policy_publication where seq > %s and state <> 'rolled_back'",
                          (pub["seq"],)).fetchall()
        for p in later:
            c.execute("update policy_publication set state = 'rolled_back' where revision = %s", (p["revision"],))
            c.execute("update change_request set state = 'rolled_back', updated_at = now() where id = %s",
                      (p["change_id"],))
        c.execute("update policy_publication set state = 'superseded' where state = 'active' and revision <> %s",
                  (revision,))
        c.execute("update policy_publication set state = 'active', active_at = null where revision = %s", (revision,))
        dbm.audit(c, user.name, "rollback", f"{self.policy_bundle}@{revision}", None,
                  {"rolled_back": [p["revision"] for p in later]})
        self.store.activate(self.policy_bundle, revision)
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

    def internal_only(request: Request) -> None:
        """/opa/status and /metrics answer only callers inside the cluster. A request through
        the ingress carries X-Forwarded-For (ingress-nginx always sets it); a forged status
        report could otherwise mark a change active."""
        if "x-forwarded-for" in request.headers:
            raise HTTPException(403, "cluster-internal endpoint")

    # --- the portal: one page, same origin as the API ---
    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/portal/")

    @app.get("/portal/", include_in_schema=False)
    def portal():
        return FileResponse(PORTAL, media_type="text/html")

    @app.get("/portal/config.json", include_in_schema=False)
    def portal_config():
        """Where the browser logs in: the realm's public URL (not the in-cluster one the API
        checks tokens against) and the public client, with PKCE."""
        return {"issuer": os.environ.get("KEYCLOAK_ISSUER", ""),
                "clientId": os.environ.get("KEYCLOAK_CLIENT_ID", "project-registry")}

    @app.get("/changes")
    def list_changes(state: str | None = None, object_id: str | None = None, limit: int = 50,
                     user: User = Depends(current_user)):
        """Change requests, newest first, with their approvals; state=open for the ones still
        waiting (pending_approval, approved, publishing)."""
        states = {"open": ["pending_approval", "approved", "publishing"]}.get(state, [state] if state else None)
        with reg.db.tx() as c:
            rows = c.execute("""select id, kind, object_id, op, state, required_approvals, bundle_revision,
                                     error, created_by, created_at, updated_at, before, after
                              from change_request
                              where (%(states)s::text[] is null or state = any(%(states)s))
                                and (%(oid)s::text is null or object_id = %(oid)s)
                              order by id desc limit %(limit)s""",
                           {"states": states, "oid": object_id, "limit": max(1, min(limit, 500))}).fetchall()
            ids = [r["id"] for r in rows]
            approvals = {}
            for a in c.execute("select change_id, approver, role, decision, comment, at from approval "
                               "where change_id = any(%s) order by at", (ids,)):
                approvals.setdefault(a["change_id"], []).append(a)
        for r in rows:
            r["approvals"] = approvals.get(r["id"], [])
        return rows

    @app.get("/me")
    def me(user: User = Depends(current_user)):
        return {"name": user.name, "groups": sorted(user.groups)}

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

    @app.post("/changes/{change_id}/withdraw")
    def withdraw(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.withdraw(user, change_id, body.comment)

    @app.get("/export")
    def export(user: User = Depends(current_user)):
        """Every record, in the deployment repo's file format: projects/<id>.yaml, agents/<id>.yaml
        and projects/_exceptions.yaml (scripts/registry-export.py writes them to Git)."""
        with reg.db.tx() as c:
            records = dbm.resources(c)
            active = c.execute("select revision from publication where state = 'active' "
                               "order by seq desc limit 1").fetchone()
        return {"revision": active["revision"] if active else None, **records}

    @app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(internal_only)])
    def metrics():
        """Prometheus: each project's budget (USD per 30 days), for one alert rule over all
        projects; cluster-internal, no user token."""
        with reg.db.tx() as c:
            rows = c.execute("select id, spec from resource where kind = 'project' order by id").fetchall()
        lines = ["# HELP project_budget_usd A project's spend cap in USD per 30-day window.",
                 "# TYPE project_budget_usd gauge"]
        for r in rows:
            usd = (r["spec"].get("budget") or {}).get("usd_per_30_days")
            if usd is not None:
                lines.append(f'project_budget_usd{{project="{r["id"]}"}} {float(usd)}')
        return "\n".join(lines) + "\n"

    @app.get("/publications")
    def publications(user: User = Depends(current_user)):
        with reg.db.tx() as c:
            return c.execute(f"""select '{reg.data_bundle}' as bundle, revision, change_ids, state, policy_revision,
                                        created_at, active_at, seq from publication
                                 union all
                                 select '{reg.policy_bundle}', revision,
                                        case when change_id is null then '{{}}'::bigint[] else array[change_id] end,
                                        state, revision, created_at, active_at, seq from policy_publication
                                 order by seq desc limit 50""").fetchall()

    @app.post("/rollback/{revision}")
    def rollback(revision: str, user: User = Depends(current_user)):
        return reg.rollback(user, revision)

    # OPA's status plugin posts here; cluster-internal, no user token
    @app.post("/opa/status", dependencies=[Depends(internal_only)])
    @app.post("/opa/status/{partition}", dependencies=[Depends(internal_only)])
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
