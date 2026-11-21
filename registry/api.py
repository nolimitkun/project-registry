"""The registry API and its portal page. Every edit of a record is a change request, proposed
only by whom policy allows (OPA: data.portal.may_submit), validated by rendering
the whole bundle with it, its approvals decided by policy
(data.portal.required_approvals; both Rego in the policy repo), approved by
other people than its author (or withdrawn), then published by the publisher.
Policy changes (kind `policy`, a commit of the Rego in Git) are filed by the
publisher itself (policy.py) and approved here the same way. Rotating a gateway key
is not a change request: the key id, and so every record, stays (keys.py).

    uvicorn registry.api:app
"""
from __future__ import annotations

import copy
import logging
import os
import subprocess
import tempfile
from pathlib import Path

import requests
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, PlainTextResponse, RedirectResponse, Response
from psycopg.types.json import Jsonb
from pydantic import BaseModel

import datetime as dt

from . import activation, approvals, health, picks, usage, wakeup
from . import db as dbm
from .auth import ROLE_GROUPS, User, current_user
from . import bundles, insight
from . import keys as keysmod
from .bundles import Store
from .policy import same_data
from .render import Renderer, RenderError, kagent_wiring_from_env, renderer_from_env

log = logging.getLogger("api")

KINDS = {"projects": "project", "agents": "agent", "exceptions": "exception",
         # the catalog: proposed by the platform team (portal.may_submit)
         "models": "model", "google-apis": "google_api", "tools": "tool", "catalog": "catalog",
         # the policy's parameters (data_classes, autonomy, approvals): platform team only
         "settings": "setting"}
PORTAL = Path(__file__).resolve().parent / "static" / "portal.html"


class ChangeIn(BaseModel):
    spec: dict | None = None             # create: the whole record; update: a merge patch
    owner_group: str | None = None       # create project: who approves as its owner
    comment: str | None = None


class PreviewIn(ChangeIn):
    collection: str                      # projects, agents, settings, ...
    object_id: str
    op: str = "update"                   # create, update, delete


class RotateIn(BaseModel):
    grace_hours: float = 24              # how long the previous key still works; 0: revoked at once
    comment: str | None = None


MAX_GRACE_HOURS = 7 * 24


class ExplainIn(BaseModel):
    project: str
    kind: str                            # model, tool, google, models (the listing)
    name: str | None = None              # the model, tool or Google API
    key_id: str | None = None            # default: the project's own key


def like(q: str | None) -> str | None:
    """A search term as an ILIKE pattern, its own % and _ taken literally."""
    if not q:
        return None
    return "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Decision(BaseModel):
    comment: str | None = None


def merge(base: dict, patch: dict) -> dict:
    """RFC 7386 JSON merge patch."""
    out = copy.deepcopy(base)
    for k, v in patch.items():
        if v is None:
            out.pop(k, None)
        elif isinstance(v, dict):    # into what is there, or {}: nulls in a new object are dropped
            out[k] = merge(out[k] if isinstance(out.get(k), dict) else {}, v)
        else:
            out[k] = v
    return out


def drop_gone_keys(before: dict, after: dict) -> dict:
    """A key dropped from a project's keys takes its own limits (key_limits) along, so
    removing a key is one step. Only keys the change drops: an entry naming a key the
    project never had is still the render's error, which catches a misspelt key."""
    gone = set(before.get("keys") or []) - set(after.get("keys") or [])
    limits = after.get("key_limits") or {}
    if not gone & set(limits):
        return after
    kept = {k: v for k, v in limits.items() if k not in gone}
    out = {k: v for k, v in after.items() if k != "key_limits"}
    return {**out, "key_limits": kept} if kept else out


class Registry:
    def __init__(self, db: dbm.DB, renderer: Renderer, store: Store, opa_url: str,
                 policy_bundle="gateway-policy", data_bundle="gateway-projects", signing_keyid: str | None = None,
                 kagent_wiring=None, usage_reader: usage.Reader | None = None):
        self.db, self.renderer, self.store, self.opa_url = db, renderer, store, opa_url.rstrip("/")
        self.usage = usage_reader            # the gateway's spend and usage (usage.py), if configured
        self.kagent_wiring = kagent_wiring    # checks a proposed agent's kagent wiring (render.py)
        self.policy_bundle, self.data_bundle = policy_bundle, data_bundle
        self.signing_keyid = signing_keyid or os.environ.get("SIGNING_KEYID")
        self.opa_pods = activation.ready_opa_pods        # replaced in tests
        self.serving = picks.serving                     # replaced in tests
        self.opa = "opa"

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

    def yours(self, c, user: User, change: dict, approvals: list[dict]) -> list[str]:
        """The open approvals of a pending change this user may give now: none for its author
        (four eyes) or once they have decided."""
        if change["state"] != "pending_approval" or change["created_by"] == user.name:
            return []
        if any(a["approver"] == user.name for a in approvals):
            return []
        done = {a["role"] for a in approvals if a["decision"] == "approve"}
        mine = self.roles_of(c, user, change)
        return [r for r in change["required_approvals"] if r not in done and r in mine]

    # --- changes ---
    def check(self, c, user: User, kind: str, oid: str, op: str,
              body: ChangeIn) -> tuple[dict, str | None, list[str], dict]:
        """Everything a submit checks, without filing it: the change, its owner group, who
        must approve it, and what model auto picks for each project before and after
        (picks.py). Raises what a submit would."""
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
            if kind == "project" and after is not None:
                after = drop_gone_keys(before, after)
        if after == before:
            raise HTTPException(422, "the change changes nothing")
        pending = c.execute("select id from change_request where kind = %s and object_id = %s and "
                            "state in ('pending_approval', 'approved', 'publishing')", (kind, oid)).fetchone()
        if pending:
            raise HTTPException(409, f"change {pending['id']} for {kind} {oid} is not finished yet")
        # who may propose it, before any work on it: a refusal says nothing of other records
        change = {"kind": kind, "object_id": oid, "op": op, "before": before, "after": after}
        owner = body.owner_group if (kind == "project" and op == "create") else \
            self.owner_group(c, kind, oid, after or before)
        if not self.may_submit(change, user, owner):
            raise HTTPException(403, f"you may not propose changes to {kind} {oid}")
        records = dbm.resources(c)
        if after is None:
            records[kind].pop(oid, None)
        else:
            records[kind][oid] = after
        policy_rev = self.store.active(self.policy_bundle)
        if not policy_rev:
            raise HTTPException(503, "no active policy bundle to validate against")
        # A proposed agent is also checked against the deployment repo's kagent wiring.
        # Only here: a publish never fails over wiring changed since.
        wiring = None
        if self.kagent_wiring and kind == "agent" and after:
            try:
                wiring = self.kagent_wiring.env()
            except (OSError, subprocess.CalledProcessError) as e:
                raise HTTPException(503, f"can't read the deployment repo's kagent wiring: {e}") from e
        with tempfile.TemporaryDirectory() as tmp:
            try:
                rendered = self.renderer.render(records, policy_rev, Path(tmp) / "out", env=wiring)
            except RenderError as e:
                raise HTTPException(422, {"errors": e.errors}) from e
            auto = self.auto_impact(policy_rev, rendered, records.get("model") or {}, Path(tmp))
        if auto.get("refusal"):
            raise HTTPException(422, auto["refusal"])
        return change, owner, self.required_approvals(change, user.name), auto

    def auto_impact(self, policy_rev: str, rendered: Path, models: dict, tmp: Path) -> dict:
        """picks.impact of the candidate records against the active bundles. Evidence, so an
        evaluation that fails is reported, not raised; a move onto an unserved model is
        the change's refusal."""
        data_rev = self.store.active(self.data_bundle)
        if not data_rev:
            return {"error": f"no active {self.data_bundle} bundle to compare with"}
        try:
            policy = self.store.fetch(self.policy_bundle, policy_rev, tmp / "policy.tar.gz")
            data = self.store.fetch(self.data_bundle, data_rev, tmp / "data.tar.gz")
            report = picks.impact([policy, data], [policy, rendered], models, self.opa, self.serving)
        except (RuntimeError, OSError) as e:
            log.warning("auto picks: %s", e)
            return {"error": str(e)[-500:]}
        report["refusal"] = picks.refusal(report)
        return report

    def preview(self, user: User, kind: str, oid: str, op: str, body: ChangeIn) -> dict:
        """What a submit would file, without filing it: who must approve, and what changes."""
        with self.db.tx() as c:
            change, owner, required, auto = self.check(c, user, kind, oid, op, body)
        return {**change, "owner_group": owner, "required_approvals": required, "auto": auto}

    def submit(self, user: User, kind: str, oid: str, op: str, body: ChangeIn) -> dict:
        with self.db.tx() as c:
            change, _, required, auto = self.check(c, user, kind, oid, op, body)
            before, after = change["before"], change["after"]
            # the auto picks are the approvers' evidence until the publish replaces it with its own
            row = c.execute("""insert into change_request (kind, object_id, op, before, after, state,
                                   required_approvals, created_by, replay_report)
                               values (%s, %s, %s, %s, %s, 'pending_approval', %s, %s, %s) returning *""",
                            (kind, oid, op, Jsonb(before) if before is not None else None,
                             Jsonb(after) if after is not None else None, Jsonb(required), user.name,
                             Jsonb({"auto": auto}))).fetchone()
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
                wakeup.notify(c)                            # the publisher starts once this commits
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
                     awaiting: str | None = None, kind: str | None = None, q: str | None = None,
                     offset: int = 0, user: User = Depends(current_user)):
        """Change requests, newest first, with their approvals and `yours`: the open approvals
        the caller may give. state=open for the ones still waiting (pending_approval,
        approved, publishing); awaiting=me for the ones waiting for the caller. kind: one
        record kind; q: part of the object id or of the author's name; offset: paging."""
        states = {"open": ["pending_approval", "approved", "publishing"]}.get(state, [state] if state else None)
        if awaiting not in (None, "me"):
            raise HTTPException(422, "awaiting takes only me")
        if awaiting:
            states, limit = ["pending_approval"], 500
        with reg.db.tx() as c:
            rows = c.execute("""select id, kind, object_id, op, state, required_approvals, bundle_revision,
                                     error, created_by, created_at, updated_at, before, after
                              from change_request
                              where (%(states)s::text[] is null or state = any(%(states)s))
                                and (%(oid)s::text is null or object_id = %(oid)s)
                                and (%(kind)s::text is null or kind = %(kind)s)
                                and (%(q)s::text is null or object_id ilike %(q)s or created_by ilike %(q)s)
                              order by id desc limit %(limit)s offset %(offset)s""",
                           {"states": states, "oid": object_id, "kind": kind, "q": like(q),
                            "limit": max(1, min(limit, 500)), "offset": max(0, offset)}).fetchall()
            ids = [r["id"] for r in rows]
            approvals = {}
            for a in c.execute("select change_id, approver, role, decision, comment, at from approval "
                               "where change_id = any(%s) order by at", (ids,)):
                approvals.setdefault(a["change_id"], []).append(a)
            for r in rows:
                r["approvals"] = approvals.get(r["id"], [])
                r["yours"] = reg.yours(c, user, r, r["approvals"])
        return [r for r in rows if r["yours"]] if awaiting else rows

    @app.post("/changes/preview")
    def preview_change(body: PreviewIn, user: User = Depends(current_user)):
        """What submitting this change would file, without filing it: it is validated as a
        submit is, and the answer says who must approve it."""
        if body.op not in ("create", "update", "delete"):
            raise HTTPException(422, f"no op {body.op}")
        return reg.preview(user, kind_of(body.collection), body.object_id, body.op, body)

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
            ch["yours"] = reg.yours(c, user, ch, ch["approvals"])
        return ch

    @app.get("/changes/{change_id}/diff")
    def change_diff(change_id: int, user: User = Depends(current_user)):
        """A policy change's code, file by file, so approvers read it in the portal: the
        active commit it was checked against, and the proposed one."""
        from .policy import PolicySource
        with reg.db.tx() as c:
            ch = c.execute("select kind, before, after from change_request where id = %s", (change_id,)).fetchone()
        if not ch:
            raise HTTPException(404)
        if ch["kind"] != "policy" or not (ch["before"] or {}).get("commit") or not (ch["after"] or {}).get("commit"):
            raise HTTPException(400, "only a policy change has a code diff; a record change shows its fields")
        try:
            return PolicySource("main", reg.renderer).diff(ch["before"]["commit"], ch["after"]["commit"])
        except subprocess.CalledProcessError as e:
            raise HTTPException(502, f"can't check out the commits: {(e.stderr or '')[-300:]}") from e

    @app.post("/changes/{change_id}/approve")
    def approve(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.decide(user, change_id, "approve", body.comment)

    @app.post("/changes/{change_id}/reject")
    def reject(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.decide(user, change_id, "reject", body.comment)

    @app.post("/changes/{change_id}/withdraw")
    def withdraw(change_id: int, body: Decision, user: User = Depends(current_user)):
        return reg.withdraw(user, change_id, body.comment)

    # --- spend and usage (usage.py: the gateway's access log, as Parquet) ---
    def usage_scope(user: User) -> set[str] | None:
        """The projects whose usage a caller sees: all of them (None) for the platform team
        and the cost owners, else those of the caller's owner groups."""
        if reg.usage is None:
            raise HTTPException(404, "usage is not configured (USAGE_BUCKET)")
        if user.groups & {ROLE_GROUPS["platform"], ROLE_GROUPS["cost_owner"]}:
            return None
        with reg.db.tx() as c:
            return {r["project_id"] for r in c.execute("select project_id, owner_group from project_owner").fetchall()
                    if r["owner_group"] in user.groups}

    def a_date(value: str | None, default: dt.date) -> dt.date:
        try:
            return dt.date.fromisoformat(value) if value else default
        except ValueError as e:
            raise HTTPException(422, f"not a date: {value}") from e

    @app.get("/usage")
    def usage_report(start: str | None = None, end: str | None = None, project: str | None = None,
                     user: User = Depends(current_user)):
        """Spend and usage of [start, end] (default: the last 30 days), for every project the
        caller may see or for one, with each project's spend in the 30 days up to `end`
        against its budget."""
        visible = usage_scope(user)
        today = dt.datetime.now(dt.timezone.utc).date()
        end_d = a_date(end, today)
        start_d = a_date(start, end_d - dt.timedelta(days=29))
        if not start_d <= end_d or (end_d - start_d).days > 366:
            raise HTTPException(422, "start must be before end, at most a year apart")
        if project is not None and visible is not None and project not in visible:
            raise HTTPException(403, f"not an owner of project {project}")
        with reg.db.tx() as c:
            records = dbm.resources(c)
        budgets = {pid: (p.get("budget") or {}).get("usd_per_30_days") for pid, p in records["project"].items()}
        prices = {m: spec.get("price") for m, spec in records.get("model", {}).items()}
        out = usage.report(reg.usage, visible, start_d, end_d, end_d, project, budgets, prices,
                           os.environ.get("USAGE_REFERENCE_MODEL", "gemini-3.5-flash"),
                           key_budgets(records["project"].values()))
        out["projects"] = sorted(records["project"]) if visible is None else sorted(visible)
        return out

    @app.get("/usage/requests")
    def usage_requests(project: str, date: str, limit: int = 50, user: User = Depends(current_user)):
        """A project's requests of one day, the dearest first: what each key and model cost."""
        visible = usage_scope(user)
        if visible is not None and project not in visible:
            raise HTTPException(403, f"not an owner of project {project}")
        return usage.requests_of(reg.usage, project, a_date(date, dt.date.today()), max(1, min(limit, 500)))

    @app.get("/export")
    def export(user: User = Depends(current_user)):
        """Every record: {"project": {id: spec}, "agent": {...}, "exception": {...}}, each spec in
        the format of the policy repo's schemas (the format of the seed and the snapshots)."""
        with reg.db.tx() as c:
            records = dbm.resources(c)
            active = c.execute("select revision from publication where state = 'active' "
                               "order by seq desc limit 1").fetchone()
        return {"revision": active["revision"] if active else None, **records}

    def key_budgets(projects) -> dict[str, float]:
        """key id -> its own budget (key_limits), for the keys that have one."""
        return {k: kl["budget"]["usd_per_30_days"] for p in projects
                for k, kl in (p.get("key_limits") or {}).items() if (kl.get("budget") or {}).get("usd_per_30_days")}

    @app.get("/metrics", response_class=PlainTextResponse, dependencies=[Depends(internal_only)])
    def metrics():
        """Prometheus: each project's budget (USD per 30 days), for one alert rule over all
        projects; each budgeted key's budget and 30 days' spend (key_budget_usd,
        key_spend_30d_usd), for the alert on a key's budget; when each gateway key was
        issued, for the alert on old keys; each model's catalog price, for the alert that the gateway's own price
        table (what budgets are charged at) still agrees; and how each publisher output is
        doing (health.py). Cluster-internal, no user token."""
        with reg.db.tx() as c:
            rows = c.execute("select id, spec from resource where kind = 'project' order by id").fetchall()
            models = c.execute("select id, spec from resource where kind = 'model' order by id").fetchall()
            outputs = health.metrics(c)
            records = dbm.resources(c)
            issued = c.execute("select key_id, issued_at from gateway_key order by key_id").fetchall()
        lines = ["# HELP project_budget_usd A project's spend cap in USD per 30-day window.",
                 "# TYPE project_budget_usd gauge"]
        for r in rows:
            usd = (r["spec"].get("budget") or {}).get("usd_per_30_days")
            if usd is not None:
                lines.append(f'project_budget_usd{{project="{r["id"]}"}} {float(usd)}')
        # Keys with a budget of their own (key_limits), and what each spent in the last 30
        # days by the ledger: the gateway's metrics have no key label (high cardinality),
        # so the alert on a key's budget compares these two. As current as the ledger,
        # which the usage job extracts every hour.
        owner = {k: r["id"] for r in rows for k in (r["spec"].get("key_limits") or {})}
        kb = key_budgets(r["spec"] for r in rows)
        lines += ["# HELP key_budget_usd A key's own spend cap in USD per 30-day window.",
                  "# TYPE key_budget_usd gauge"]
        lines += [f'key_budget_usd{{project="{owner[k]}",key_id="{k}"}} {float(v)}' for k, v in sorted(kb.items())]
        if kb and reg.usage is not None:
            try:
                spent = usage.key_spend_30d(reg.usage, sorted(kb), dt.datetime.now(dt.timezone.utc).date())
            except Exception as e:          # the rest of the page still answers
                log.warning("key spend: %s", e)
            else:
                lines += ["# HELP key_spend_30d_usd What a key with its own budget spent in the last 30 days (usage ledger).",
                          "# TYPE key_spend_30d_usd gauge"]
                lines += [f'key_spend_30d_usd{{project="{owner[k]}",key_id="{k}"}} {v}' for k, v in sorted(spent.items())]
        # When each key's current key was issued (or first seen, for one from before the
        # registry kept this), for the alert on keys not rotated for a long time: one
        # series per key id, as many as the gateway's key map has.
        key_owner = keysmod.owners(records)
        lines += ["# HELP gateway_key_issued_timestamp_seconds When a gateway key id's current key was issued.",
                  "# TYPE gateway_key_issued_timestamp_seconds gauge"]
        lines += [f'gateway_key_issued_timestamp_seconds{{project="{key_owner[r["key_id"]]["project"]}",'
                  f'key_id="{r["key_id"]}"}} {r["issued_at"].timestamp()}' for r in issued if r["key_id"] in key_owner]
        # Labelled like the gateway's token and cost metrics: the model name the provider
        # got (a KServe model's servedModel: its route replaces the catalog name), and the
        # token type.
        lines += ["# HELP model_price_usd_per_million_tokens A model's catalog price.",
                  "# TYPE model_price_usd_per_million_tokens gauge"]
        for r in models:
            price, label = r["spec"].get("price") or {}, r["spec"].get("servedModel") or r["id"]
            for kind in ("input", "output"):
                if kind in price:
                    lines.append(f'model_price_usd_per_million_tokens{{model="{r["id"]}",'
                                 f'gen_ai_request_model="{label}",gen_ai_token_type="{kind}"}} {float(price[kind])}')
        return "\n".join(lines + outputs) + "\n"

    # --- the gateway's keys: rotating one keeps its key id (keys.py) ---
    def key_scope(c, user: User, oid: str, manage: bool) -> dict:
        """The project's records, if the caller may see its keys (the platform team, security,
        the cost owners, its owners) or, with manage, rotate them (the platform team, its
        owners)."""
        records = dbm.resources(c)
        if oid not in records["project"]:
            raise HTTPException(404, f"no project {oid}")
        teams = {ROLE_GROUPS["platform"]} | (set() if manage else {ROLE_GROUPS["security"], ROLE_GROUPS["cost_owner"]})
        if not user.groups & teams and reg.owner_group(c, "project", oid, None) not in user.groups:
            raise HTTPException(403, f"not an owner of project {oid}")
        return records

    def key_rows(c, records: dict, oid: str) -> list[dict]:
        owned = {k: o for k, o in keysmod.owners(records).items() if o["project"] == oid}
        rows = {r["key_id"]: r for r in c.execute(
            "select * from gateway_key where key_id = any(%s)", (sorted(owned),)).fetchall()}
        out = []
        for k, o in sorted(owned.items()):
            r = rows.get(k) or {}
            out.append({"key_id": k, "agent": o["agent"], "issued_at": r.get("issued_at"),
                        "rotation_pending": bool(r.get("rotate_requested_at")),
                        "rotate_requested_by": r.get("rotate_requested_by"),
                        "grace_hours": (r["grace_seconds"] / 3600 if r.get("rotate_requested_at")
                                        and r.get("grace_seconds") is not None else None),
                        "previous_until": r.get("previous_until")})
        return out

    def own_key(records: dict, oid: str, key_id: str) -> None:
        owner = keysmod.owners(records).get(key_id)
        if not owner or owner["project"] != oid:
            raise HTTPException(404, f"key {key_id} is not one of project {oid}'s")

    @app.get("/projects/{oid}/keys")
    def project_keys(oid: str, user: User = Depends(current_user)):
        """The project's gateway keys (its own and its agents'): when each was issued, a
        rotation asked for, and until when a rotated key's previous key still works."""
        with reg.db.tx() as c:
            return key_rows(c, key_scope(c, user, oid, manage=False), oid)

    @app.post("/projects/{oid}/keys/{key_id}/rotate")
    def rotate_key(oid: str, key_id: str, body: RotateIn, user: User = Depends(current_user)):
        """A fresh key for this key id, from the publisher within seconds: the clients' copies
        take it on their next refresh, and the previous key works for grace_hours more (0:
        revoked at once, for a key that leaked). Not a change request: the key id, and so
        everything the policy decides about it, stays."""
        if not 0 <= body.grace_hours <= MAX_GRACE_HOURS:
            raise HTTPException(422, f"grace_hours is between 0 and {MAX_GRACE_HOURS}")
        with reg.db.tx() as c:
            records = key_scope(c, user, oid, manage=True)
            own_key(records, oid, key_id)
            c.execute("""insert into gateway_key (key_id, rotate_requested_at, rotate_requested_by, grace_seconds)
                         values (%s, now(), %s, %s) on conflict (key_id) do update set
                         rotate_requested_at = excluded.rotate_requested_at,
                         rotate_requested_by = excluded.rotate_requested_by, grace_seconds = excluded.grace_seconds""",
                      (key_id, user.name, round(body.grace_hours * 3600)))
            dbm.audit(c, user.name, "rotate_key", key_id, None,
                      {"project": oid, "grace_hours": body.grace_hours, "comment": body.comment})
            wakeup.notify(c)
            return next(r for r in key_rows(c, records, oid) if r["key_id"] == key_id)

    @app.post("/projects/{oid}/keys/{key_id}/revoke-previous")
    def revoke_previous_key(oid: str, key_id: str, body: Decision, user: User = Depends(current_user)):
        """Ends a rotated key's grace period now: the publisher drops its previous key."""
        with reg.db.tx() as c:
            records = key_scope(c, user, oid, manage=True)
            own_key(records, oid, key_id)
            row = c.execute("select previous_until from gateway_key where key_id = %s and previous_until > now()",
                            (key_id,)).fetchone()
            if not row:
                raise HTTPException(409, f"key {key_id} has no previous key in a grace period")
            c.execute("update gateway_key set previous_until = now() where key_id = %s", (key_id,))
            dbm.audit(c, user.name, "revoke_previous_key", key_id, {"previous_until": row["previous_until"].isoformat()},
                      {"project": oid, "comment": body.comment})
            wakeup.notify(c)
            return next(r for r in key_rows(c, records, oid) if r["key_id"] == key_id)

    @app.get("/projects/{oid}/effective")
    def project_effective(oid: str, user: User = Depends(current_user)):
        """What the project can use now, as the gateway's OPA decides it (insight.py)."""
        try:
            return insight.effective(insight.ask_opa(reg.opa_url, oid))
        except (requests.RequestException, RuntimeError) as e:
            raise HTTPException(503, f"OPA did not answer: {e}") from e

    @app.post("/explain")
    def explain(body: ExplainIn, user: User = Depends(current_user)):
        """Would the gateway let this project (with this key, by default its own) make this
        call now, and if not, authz.rego's reason and what would change it."""
        if body.kind not in insight.KINDS:
            raise HTTPException(422, f"kind is one of {', '.join(insight.KINDS)}")
        if body.kind != "models" and not body.name:
            raise HTTPException(422, f"name the {body.kind}")
        try:
            return insight.explain(reg.opa_url, body.project, body.kind, body.name, body.key_id)
        except (requests.RequestException, RuntimeError) as e:
            raise HTTPException(503, f"OPA did not answer: {e}") from e

    @app.get("/audit")
    def audit_log(actor: str | None = None, action: str | None = None, q: str | None = None,
                  limit: int = 100, offset: int = 0, user: User = Depends(current_user)):
        """The audit log, newest first: who did what to which object. For the platform
        team, security and the cost owners. q: part of the object."""
        if not set(ROLE_GROUPS.values()) & user.groups:
            raise HTTPException(403, "the audit log is for the platform team, security and the cost owners")
        with reg.db.tx() as c:
            return c.execute("""select seq, at, actor, action, object, before, after from audit_log
                                where (%(actor)s::text is null or actor = %(actor)s)
                                  and (%(action)s::text is null or action = %(action)s)
                                  and (%(q)s::text is null or object ilike %(q)s)
                                order by seq desc limit %(limit)s offset %(offset)s""",
                             {"actor": actor, "action": action, "q": like(q),
                              "limit": max(1, min(limit, 500)), "offset": max(0, offset)}).fetchall()

    @app.get("/status")
    def platform_status(user: User = Depends(current_user)):
        """What OPA has loaded, the publisher's outputs, the usage ledger and the alerts."""
        with reg.db.tx() as c:
            return insight.status(c, reg.store, (reg.policy_bundle, reg.data_bundle), reg.opa_pods(), reg.usage)

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

    # --- cluster-internal reads, no user token (the records live only here) ---
    @app.get("/internal/bundles/{bundle}", dependencies=[Depends(internal_only)])
    def internal_bundle(bundle: str):
        """The active bundle, as OPA loads it (scripts/policy-replay.py)."""
        if bundle not in (reg.policy_bundle, reg.data_bundle):
            raise HTTPException(404)
        rev = reg.store.active(bundle)
        if not rev:
            raise HTTPException(404, f"no active {bundle}")
        with tempfile.TemporaryDirectory() as tmp:
            body = reg.store.fetch(bundle, rev, Path(tmp) / "b.tar.gz").read_bytes()
        return Response(body, media_type="application/gzip", headers={"X-Revision": rev})

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
    reader = usage.Reader(usage.Bucket(s3, env["USAGE_BUCKET"])) if env.get("USAGE_BUCKET") else None
    return create_app(Registry(db, renderer_from_env(env),
                               Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", "")), env["OPA_URL"],
                               kagent_wiring=kagent_wiring_from_env(env), usage_reader=reader))


app = _from_env() if os.environ.get("DATABASE_URL") else None
