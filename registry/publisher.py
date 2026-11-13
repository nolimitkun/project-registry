"""Publishes approved changes as a signed gateway-projects bundle.

    python -m registry.publisher

Loop: take the approved changes from the outbox (at most one publish every
MIN_INTERVAL seconds, so changes batch), apply them to the records, render the
bundle directory with gen-projects.py at the active policy revision, replay
recent decisions, build and sign, upload, activate. All of it in one database
transaction: if any step fails, no record changes, the changes are marked
`failed` with the reason, and OPA keeps the active bundle.

A change becomes `active` once every OPA reports its revision (api.py /status).
"""
from __future__ import annotations

import logging
import os
import tempfile
import time
from pathlib import Path

from psycopg.types.json import Jsonb

from . import activation
from . import db as dbm
from .bundles import Store, build, signed_keyid
from .render import Renderer
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
                 policy_bundle="gateway-policy", data_bundle="gateway-projects", opa="opa"):
        self.db, self.store, self.signer, self.renderer = db, store, signer, renderer
        self.events = events                      # () -> recent decision log events
        self.policy_bundle, self.data_bundle, self.opa = policy_bundle, data_bundle, opa

    def publish_once(self) -> str | None:
        """Publishes every approved change waiting in the outbox. Returns the new
        revision, or None when there was nothing to publish."""
        ids: list[int] = []
        try:
            with self.db.tx() as c:
                changes = c.execute("""select cr.* from outbox o join change_request cr on cr.id = o.change_id
                                       where o.published_at is null and cr.state = 'approved'
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
            failure = e
        # the failed attempt changed nothing; record why, outside it
        report = getattr(failure, "report", None)
        with self.db.tx() as c:
            c.execute("update outbox set published_at = now() where change_id = any(%s)", (ids,))
            c.execute("update change_request set state = 'failed', error = %s, replay_report = %s, updated_at = now() "
                      "where id = any(%s)", (str(failure), Jsonb(report) if report else None, ids))
            dbm.audit(c, "publisher", "publish_failed", self.data_bundle, None,
                      {"changes": ids, "error": str(failure)})
        log.warning("publishing changes %s failed: %s", ids, failure)
        return None

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

    from .vault import TransitSigner, Vault

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    env = os.environ
    db = dbm.DB(env["DATABASE_URL"])
    db.migrate()
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    store = Store(s3, env["S3_BUCKET"], env.get("BUNDLE_PREFIX", ""))
    signer = TransitSigner(Vault(env["VAULT_ADDR"], env["VAULT_ROLE"]), env["TRANSIT_KEY"], env["SIGNING_KEYID"],
                           version=int(env["SIGNING_KEY_VERSION"]) if env.get("SIGNING_KEY_VERSION") else None)
    renderer = Renderer(env["DEPLOY_REPO"], Path(env.get("WORKDIR", "/tmp/registry")) / "checkouts")
    loki, ns = env["LOKI_URL"], env.get("DECISION_LOG_NAMESPACE", "mini-platform")
    since, limit = env.get("REPLAY_SINCE", "24h"), int(env.get("REPLAY_LIMIT", "2000"))
    pub = Publisher(db, store, signer, renderer, lambda: fetch(loki, ns, since, limit))
    interval = int(env.get("MIN_INTERVAL", "30"))
    while True:
        try:
            pub.resign_if_needed()
            break
        except Exception:
            log.exception("re-signing the active bundle")
            time.sleep(10)
    while True:
        try:
            with db.tx() as c:                      # OPA reports only on changes: check here too
                activation.activate_due(c, pub.data_bundle, activation.ready_opa_pods())
        except Exception:
            log.exception("activation check")
        try:
            if pub.publish_once():
                time.sleep(interval)
                continue
        except Exception:
            log.exception("publish loop")
        time.sleep(5)


if __name__ == "__main__":
    main()
