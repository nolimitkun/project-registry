"""Publishes approved changes: both of OPA's bundles, signed.

    python -m registry.publisher

Project data (gateway-projects): take the approved changes from the outbox (at
most one publish every MIN_INTERVAL seconds, so changes batch), apply them to the
records, render the bundle directory with gen-projects.py at the active policy
revision, replay recent decisions, build and sign, upload, activate. All of it in
one database transaction: if any step fails, no record changes, the changes are
marked `failed` with the reason, and OPA keeps the active bundle.

Policy (gateway-policy): every POLICY_POLL seconds the loop files the policy
branch's new commit as a change request (policy.py); an approved one is published
here, with the records rendered at its commit when they differ.

A change becomes `active` once every ready OPA pod reports its revision
(activation.py, on every OPA report and every round of this loop).
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from pathlib import Path

import requests
import yaml
from psycopg.types.json import Jsonb

from . import activation, gatewaychart
from . import db as dbm
from .bundles import Store, build, signed_keyid
from .policy import PolicyWatch, same_data
from .render import Renderer, renderer_from_env
from .replay import fetch, replay

log = logging.getLogger("publisher")


class ReplayStopped(Exception):
    def __init__(self, report: dict):
        super().__init__(f"replay: decisions changed for {report['changed_for_other_projects']} "
                         "requests of projects the change does not touch")
        self.report = report


def projects_touched(change: dict) -> set[str]:
    if change["kind"] in ("project", "exception"):
        return {change["object_id"]}
    return {s["project"] for s in (change["before"], change["after"]) if s and s.get("project")}


class Publisher:
    def __init__(self, db: dbm.DB, store: Store, signer, renderer: Renderer, events,
                 policy_bundle="gateway-policy", data_bundle="gateway-projects", opa="opa",
                 policy: PolicyWatch | None = None):
        self.db, self.store, self.signer, self.renderer = db, store, signer, renderer
        self.events = events                      # () -> recent decision log events
        self.policy_bundle, self.data_bundle, self.opa = policy_bundle, data_bundle, opa
        self.policy = policy

    def publish_once(self) -> str | None:
        """Publishes what is approved: a policy change first, else every approved data change
        waiting in the outbox. Returns the new revision, or None when there was nothing."""
        return self.publish_policy_once() or self.publish_data_once()

    def _failed(self, ids: list[int], failure: Exception, bundle: str) -> None:
        """The failed attempt changed nothing; record why, outside it."""
        report = getattr(failure, "report", None)
        with self.db.tx() as c:
            c.execute("update outbox set published_at = now() where change_id = any(%s)", (ids,))
            c.execute("update change_request set state = 'failed', error = %s, "
                      "replay_report = coalesce(%s, replay_report), updated_at = now() where id = any(%s)",
                      (str(failure), Jsonb(report) if report else None, ids))
            dbm.audit(c, "publisher", "publish_failed", bundle, None, {"changes": ids, "error": str(failure)})
        log.warning("publishing changes %s failed: %s", ids, failure)

    def publish_policy_once(self) -> str | None:
        """Publishes the approved policy change, if there is one: the records rendered at its
        commit (when they differ from the active ones), then the policy."""
        ids: list[int] = []
        try:
            with self.db.tx() as c:
                ch = c.execute("""select cr.* from outbox o join change_request cr on cr.id = o.change_id
                                  where o.published_at is null and cr.state = 'approved' and cr.kind = 'policy'
                                  order by o.seq desc limit 1 for update of o skip locked""").fetchone()
                if not ch:
                    return None
                if self.policy is None:
                    raise RuntimeError("this publisher has no policy source")
                ids = [ch["id"]]
                sha = ch["object_id"]
                if not self._still_checked(c, ch):
                    return None
                with tempfile.TemporaryDirectory() as tmp:
                    tmp = Path(tmp)
                    self.policy.ensure_built(sha, tmp)
                    data = self._render_at(c, sha, tmp)
                    c.execute("update outbox set published_at = now() where change_id = %s", (ch["id"],))
                    c.execute("update change_request set state = 'publishing', bundle_revision = %s, error = null, "
                              "updated_at = now() where id = %s", (sha, ch["id"]))
                    self.policy.record(c, sha, ch["id"])
                    dbm.audit(c, "publisher", "publish", f"{self.policy_bundle}@{sha}", None,
                              {"changes": ids, "records": data})
                    # last, data first: once activated OPA may load them, so nothing may fail after.
                    # If the policy's activation fails, the data goes back to what was active.
                    previous = self.store.active(self.data_bundle)
                    if data:
                        self.store.activate(self.data_bundle, data)
                    try:
                        self.store.activate(self.policy_bundle, sha)
                    except Exception:
                        if data and previous:
                            self.store.activate(self.data_bundle, previous)
                        raise
            log.info("published policy %s (change %s)%s", sha, ch["id"], f" with records {data}" if data else "")
            return sha
        except Exception as e:
            if not ids:
                raise
            self._failed(ids, e, self.policy_bundle)
            return None

    def _still_checked(self, c, ch: dict) -> bool:
        """Whether the approved check still holds. If either bundle was published since, the
        check runs again on what is active now (raising Rejected fails the change). If what the
        approvers were shown changed (the records republished or not, verdicts flipping where
        none did), the change goes back to them: False."""
        old = ch["replay_report"] or {}
        active = self.store.active(self.policy_bundle)
        if (old.get("policy_revision"), old.get("data_revision")) == (active, self.store.active(self.data_bundle)):
            return True
        new = self.policy.check(ch["object_id"], active)
        if (old.get("records_change") == new["records_change"]
                and bool(old.get("allowed_to_denied")) == bool(new["allowed_to_denied"])
                and bool(old.get("denied_to_allowed")) == bool(new["denied_to_allowed"])):
            c.execute("update change_request set replay_report = %s where id = %s", (Jsonb(new), ch["id"]))
            return True
        approvals = c.execute("select approver, role, comment, at::text from approval where change_id = %s",
                              (ch["id"],)).fetchall()
        c.execute("delete from approval where change_id = %s", (ch["id"],))
        c.execute("delete from outbox where change_id = %s", (ch["id"],))
        c.execute("update change_request set state = 'pending_approval', replay_report = %s, error = %s, "
                  "updated_at = now() where id = %s",
                  (Jsonb(new), "the bundles changed since this was approved, and so did its replay: approve again",
                   ch["id"]))
        dbm.audit(c, "publisher", "reapproval", f"change/{ch['id']}", {"approvals": approvals, "report": old},
                  {"report": new})
        log.info("policy change %s: its check changed since the approval; back to approval", ch["id"])
        return False

    def _render_at(self, c, sha: str, tmp: Path) -> str | None:
        """The active records rendered at the policy commit, published as a new data revision
        (not yet activated) if they differ from the active bundle; its revision, or None."""
        records = dbm.resources(c)
        data_dir = self.renderer.render(records, sha, tmp / "gateway-projects")
        active = self.store.active(self.data_bundle)
        if active and same_data(data_dir, self.store.fetch(self.data_bundle, active, tmp / "active.tar.gz")):
            return None
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        revision = f"projects-{seq:08d}"
        build(data_dir, revision, self.signer, tmp / "bundle.tar.gz", opa=self.opa)
        self.store.put_revision(self.data_bundle, revision, tmp / "bundle.tar.gz")
        c.execute("update publication set state = 'superseded' where state = 'active'")
        c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                     values (%s, %s, '{}', 'active', %s, %s)""", (revision, seq, sha, Jsonb(records)))
        return revision

    def publish_data_once(self) -> str | None:
        ids: list[int] = []
        try:
            with self.db.tx() as c:
                changes = c.execute("""select cr.* from outbox o join change_request cr on cr.id = o.change_id
                                       where o.published_at is null and cr.state = 'approved' and cr.kind <> 'policy'
                                       order by o.seq for update of o skip locked""").fetchall()
                if not changes:
                    return None
                ids = [ch["id"] for ch in changes]
                revision = self._publish(c, changes)          # an exception here rolls everything back
                c.execute("update outbox set published_at = now() where change_id = any(%s)", (ids,))
                c.execute("update change_request set state = 'publishing', bundle_revision = %s, updated_at = now() "
                          "where id = any(%s)", (revision, ids))
                dbm.audit(c, "publisher", "publish", f"{self.data_bundle}@{revision}", None, {"changes": ids})
            log.info("published %s with changes %s", revision, ids)
            return revision
        except Exception as e:
            if not ids:
                raise
            self._failed(ids, e, self.data_bundle)
            return None

    # gen-projects.py writes agentregistry's Agent entries here, in the checkout it runs in: in
    # gateway-policy, or in a policy commit from before it (the deployment repo's path)
    AGENTREGISTRY_FILES = ("generated/agentregistry-agents.yaml",
                           "minikube/gitops/agentregistry-catalog/files/agents.yaml")

    def sync_agentregistry(self, url: str | None) -> int | None:
        """Applies the registered agents to agentregistry's catalog (/v0/apply: idempotent,
        deletes nothing), as gen-projects.py renders them from the active records. The
        records live only here, so the registry keeps agentregistry current: after a
        publish, and every hour. Returns the number of entries applied."""
        if not url:
            return None
        policy_rev = self.store.active(self.policy_bundle)
        if not policy_rev:
            return None
        with self.db.tx() as c:
            records = dbm.resources(c)
        with tempfile.TemporaryDirectory() as tmp:
            outs = [Path(tmp) / f"agents-{i}.yaml" for i in range(len(self.AGENTREGISTRY_FILES))]
            self.renderer.render(records, policy_rev, Path(tmp) / "bundle",
                                 also=dict(zip(self.AGENTREGISTRY_FILES, outs)))
            out = next((o for o in outs if o.exists()), None)
            if out is None:
                return 0
            # one YAML document per entry; gen-projects.py opens with a comment-only one, which
            # agentregistry refuses as an entry without apiVersion
            docs = [d for d in yaml.safe_load_all(out.read_text()) if d]
            if not docs:
                return 0
            body = yaml.safe_dump_all(docs, sort_keys=False).encode()
        r = requests.post(f"{url.rstrip('/')}/v0/apply", data=body, headers={"content-type": "application/yaml"},
                          timeout=30)
        r.raise_for_status()
        if '"status":"failed"' in r.text.replace(" ", ""):
            raise RuntimeError(f"agentregistry refused an entry: {r.text[-500:]}")
        n = r.text.count('"status"')
        log.info("agentregistry: applied %s agent entries", n)
        return n

    def resign_if_needed(self) -> str | None:
        """After a signing key rotation: publishes the active records again, signed with the
        current key, so OPA pods configured for the new key have a bundle to load. Returns the
        new revision, or None when the active bundle is already signed with the current key."""
        active = self.store.active(self.data_bundle)
        if not active:
            return None
        with tempfile.TemporaryDirectory() as tmp:
            keyid = signed_keyid(self.store.fetch(self.data_bundle, active, Path(tmp) / "active.tar.gz"))
        if keyid == self.signer.keyid:
            return None
        with self.db.tx() as c:
            policy_rev = self.store.active(self.policy_bundle)
            records = dbm.resources(c)
            seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
            revision = f"projects-{seq:08d}"
            with tempfile.TemporaryDirectory() as tmp:
                tmp = Path(tmp)
                data_dir = self.renderer.render(records, policy_rev, tmp / "gateway-projects")
                build(data_dir, revision, self.signer, tmp / "bundle.tar.gz", opa=self.opa)
                self.store.put_revision(self.data_bundle, revision, tmp / "bundle.tar.gz")
                c.execute("update publication set state = 'superseded' where state = 'active'")
                c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                             values (%s, %s, '{}', 'active', %s, %s)""", (revision, seq, policy_rev, Jsonb(records)))
                dbm.audit(c, "publisher", "resign", f"{self.data_bundle}@{revision}", {"keyid": keyid},
                          {"keyid": self.signer.keyid, "records_of": active})
                self.store.activate(self.data_bundle, revision)
        log.info("re-signed %s as %s with %s (was %s)", active, revision, self.signer.keyid, keyid)
        return revision

    def _publish(self, c, changes: list[dict]) -> str:
        policy_rev = self.store.active(self.policy_bundle)
        if not policy_rev:
            raise RuntimeError(f"no active {self.policy_bundle} bundle to publish against")
        for ch in changes:
            dbm.apply_change(c, ch)
        records = dbm.resources(c)
        touched = set().union(*(projects_touched(ch) for ch in changes))
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        revision = f"projects-{seq:08d}"
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            data_dir = self.renderer.render(records, policy_rev, tmp / "gateway-projects")
            policy = self.store.fetch(self.policy_bundle, policy_rev, tmp / "policy.tar.gz")
            active_rev = self.store.active(self.data_bundle)
            if not active_rev:
                raise RuntimeError(f"no active {self.data_bundle} bundle to compare with (run the import)")
            active = self.store.fetch(self.data_bundle, active_rev, tmp / "active.tar.gz")
            report = replay(self.events(), policy, active, data_dir, touched, self.opa)
            if not report["ok"]:
                raise ReplayStopped(report)
            out = tmp / "bundle.tar.gz"
            build(data_dir, revision, self.signer, out, opa=self.opa)
            self.store.put_revision(self.data_bundle, revision, out)
            c.execute("update publication set state = 'superseded' where state = 'active'")
            c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                         values (%s, %s, %s, 'active', %s, %s)""",
                      (revision, seq, [ch["id"] for ch in changes], policy_rev, Jsonb(records)))
            c.execute("update change_request set replay_report = %s where id = any(%s)",
                      (Jsonb(report), [ch["id"] for ch in changes]))
            # last: once activated, OPA may load it, so nothing may fail after this
            self.store.activate(self.data_bundle, revision)
        return revision


def main() -> None:
    import boto3

    from .policy import from_env as policy_from_env
    from .vault import TransitSigner, Vault

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    env = os.environ
    db = dbm.DB(env["DATABASE_URL"])
    db.migrate()
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    store = Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", ""))
    signer = TransitSigner(Vault(env["VAULT_ADDR"], env["VAULT_ROLE"]), env["TRANSIT_KEY"], env["SIGNING_KEYID"],
                           version=int(env["SIGNING_KEY_VERSION"]) if env.get("SIGNING_KEY_VERSION") else None)
    renderer = renderer_from_env(env)
    loki, ns = env["LOKI_URL"], env.get("DECISION_LOG_NAMESPACE", "mini-platform")
    since, limit = env.get("REPLAY_SINCE", "24h"), int(env.get("REPLAY_LIMIT", "2000"))
    events = lambda: fetch(loki, ns, since, limit)                          # noqa: E731
    watch = policy_from_env(db, store, signer, renderer, events)
    pub = Publisher(db, store, signer, renderer, events, policy=watch)
    interval, poll = int(env.get("MIN_INTERVAL", "30")), int(env.get("POLICY_POLL", "60"))
    agentregistry, synced = env.get("AGENTREGISTRY_URL"), 0.0
    charts = gatewaychart.HelmRepo(s3, env["GATEWAY_MODELS_BUCKET"]) if env.get("GATEWAY_MODELS_BUCKET") else None
    charted = None

    def chart() -> None:
        """The gateway-models chart of the active policy commit (gatewaychart.py)."""
        nonlocal charted
        if not charts:
            return
        try:
            active = store.active(pub.policy_bundle)       # MinIO may be down: log, try next round
            if not active or active == charted:
                return
            version = gatewaychart.ensure(charts, renderer, active)
            if version:
                with db.tx() as c:
                    dbm.audit(c, "publisher", "publish", f"gateway-models@{version}", None, {"policy": active})
            charted = active
        except Exception:
            log.exception("publishing the gateway-models chart")

    def sync() -> None:
        nonlocal synced
        synced = time.time()
        try:
            pub.sync_agentregistry(agentregistry)
        except Exception:
            log.exception("syncing agentregistry's catalog")
    while True:
        try:
            watch.bootstrap()                       # a new cluster: the branch's head, unapproved
            watch.resign_if_needed()
            pub.resign_if_needed()
            break
        except Exception:
            log.exception("bootstrapping or re-signing the active bundles")
            time.sleep(10)
    polled = 0.0
    while True:
        if time.time() - polled >= poll:
            polled = time.time()
            try:
                watch.propose()
            except Exception:
                log.exception("proposing the policy branch's head")
        if time.time() - synced >= 3600:
            sync()
        chart()
        try:
            with db.tx() as c:                      # OPA reports only on changes: check here too
                activation.activate_due(c, pub.data_bundle, activation.ready_opa_pods(),
                                        policy_bundle=pub.policy_bundle)
        except Exception:
            log.exception("activation check")
        try:
            if pub.publish_once():
                sync()                              # the agents may have changed
                time.sleep(interval)
                continue
        except Exception:
            log.exception("publish loop")
        time.sleep(5)


if __name__ == "__main__":
    main()
