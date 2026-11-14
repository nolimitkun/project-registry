"""The gateway-policy bundle, published by the registry like any other change.

The Rego is written and reviewed in Git (pull request, CI). Whether a commit reaches
OPA is the registry's decision. The publisher watches the branch, and for each new
commit it:
  1. runs `opa test` over the commit's policy and project data;
  2. builds and signs the bundle, kept as a revision in the store, not activated;
  3. renders the registry's records with that commit's gen-projects.py;
  4. replays recent decisions under the active bundles and under the new ones;
  5. files a change request (kind `policy`, object the commit) with the report.
Its approvals come from data.portal.required_approvals of the active policy, the
platform team at least (approvals.py). Once approved, the publisher activates the
records rendered at that commit (if they differ from the active ones), then the
policy; the change is active once every ready OPA pod reports the commit.

A newer commit supersedes an open policy change. A commit whose test fails, or
under which the records don't render, becomes a failed change, shown in the
portal, and nothing is published. On a store with no policy at all (a new
cluster), the branch's head is published without a change: there is nothing to
protect yet, and nothing else can be published without it.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import tarfile
import tempfile
from pathlib import Path

from psycopg.types.json import Jsonb

from . import approvals
from . import db as dbm
from .bundles import Store, build, signed_keyid
from .render import Renderer, RenderError
from .replay import replay_all

log = logging.getLogger("policy")
ACTOR = "policy-watch"


class Rejected(Exception):
    """The commit can't be proposed: its test fails, or the records don't render with it."""


class PolicySource:
    """The branch the policy follows, and builds of its commits."""

    def __init__(self, repo: str, ref: str, renderer: Renderer, policy_dir: str = "policies/gateway",
                 test_dirs: tuple[str, ...] = ("policies/gateway", "policies/gateway-projects"), opa: str = "opa"):
        self.repo, self.ref, self.renderer = repo, ref, renderer
        self.policy_dir, self.test_dirs, self.opa = policy_dir, test_dirs, opa

    def head(self) -> str:
        out = subprocess.run(["git", "ls-remote", self.repo, f"refs/heads/{self.ref}"],
                             check=True, capture_output=True, text=True).stdout.split()
        if not out:
            raise RuntimeError(f"no branch {self.ref} in {self.repo}")
        return out[0]

    def info(self, sha: str) -> dict:
        out = subprocess.run(["git", "-C", str(self.renderer.checkout(sha)), "log", "-1", "--format=%s%x00%an"],
                             check=True, capture_output=True, text=True).stdout.strip()
        subject, _, author = out.partition("\0")
        info = {"commit": sha, "subject": subject, "author": author, "ref": self.ref}
        if self.repo.startswith("https://github.com/"):
            info["url"] = f"{self.repo.removesuffix('.git')}/commit/{sha}"
        return info

    def build(self, sha: str, signer, out: Path) -> None:
        """Tests the commit and builds its signed policy bundle into out; Rejected if a test fails."""
        work = self.renderer.checkout(sha)
        test = subprocess.run([self.opa, "test", *self.test_dirs], cwd=work, capture_output=True, text=True)
        if test.returncode != 0:
            raise Rejected(f"opa test failed at {sha[:12]}:\n{(test.stdout + test.stderr)[-3000:]}")
        build(work / self.policy_dir, sha, signer, out, opa=self.opa)


def stored_with_key(store: Store, bundle: str, revision: str, keyid: str) -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        try:
            path = store.fetch(bundle, revision, Path(tmp) / "b.tar.gz")
        except Exception:
            return False
        return signed_keyid(path) == keyid


def same_data(directory: Path, bundle: Path) -> bool:
    """Whether a rendered bundle directory holds the same data as a built bundle. Compared as
    data, not files: `opa build` merges every data file into one /data.json."""
    mine: dict = {}
    for p in directory.rglob("data.json"):
        _put(mine, p.relative_to(directory).parent.parts, json.loads(p.read_text()))
    theirs: dict = {}
    with tarfile.open(bundle) as tar:
        for m in tar.getmembers():
            if m.isfile() and Path(m.name).name == "data.json":
                _put(theirs, Path(m.name.lstrip("/")).parent.parts, json.loads(tar.extractfile(m).read()))
    return mine == theirs


def _put(tree: dict, path: tuple[str, ...], value) -> None:
    """Merges value into tree at path, as OPA does with a bundle's data files."""
    for key in path:
        tree = tree.setdefault(key, {})
    for k, v in value.items():
        if isinstance(v, dict) and isinstance(tree.get(k), dict):
            _put(tree[k], (), v)
        else:
            tree[k] = v


class PolicyWatch:
    def __init__(self, db: dbm.DB, store: Store, signer, renderer: Renderer, source: PolicySource, events,
                 opa_url: str, policy_bundle="gateway-policy", data_bundle="gateway-projects", opa="opa"):
        self.db, self.store, self.signer, self.renderer, self.source = db, store, signer, renderer, source
        self.events, self.opa_url, self.opa = events, opa_url, opa
        self.policy_bundle, self.data_bundle = policy_bundle, data_bundle

    def ensure_built(self, sha: str, tmp: Path) -> Path:
        """The commit's bundle in the store, signed with the current key; a local copy of it."""
        path = tmp / f"policy-{sha[:12]}.tar.gz"
        if stored_with_key(self.store, self.policy_bundle, sha, self.signer.keyid):
            return self.store.fetch(self.policy_bundle, sha, path)
        self.source.build(sha, self.signer, path)
        self.store.put_revision(self.policy_bundle, sha, path)
        return path

    def record(self, c, sha: str, change_id: int | None) -> None:
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        c.execute("update policy_publication set state = 'superseded' where state = 'active'")
        c.execute("""insert into policy_publication (revision, seq, change_id, state) values (%s, %s, %s, 'active')
                     on conflict (revision) do update set seq = excluded.seq, change_id = excluded.change_id,
                     state = 'active', created_at = now(), active_at = null""", (sha, seq, change_id))

    # --- a new cluster ---
    def bootstrap(self) -> str | None:
        active = self.store.active(self.policy_bundle)
        if active:
            with self.db.tx() as c:          # from before the registry published the policy: adopt it
                if not c.execute("select 1 from policy_publication limit 1").fetchone():
                    self.record(c, active, None)
                    c.execute("update policy_publication set active_at = now() where revision = %s", (active,))
                    dbm.audit(c, ACTOR, "adopt", f"{self.policy_bundle}@{active}", None, None)
            return None
        sha = self.source.head()
        with self.db.tx() as c, tempfile.TemporaryDirectory() as tmp:
            self.ensure_built(sha, Path(tmp))
            self.record(c, sha, None)
            dbm.audit(c, ACTOR, "bootstrap", f"{self.policy_bundle}@{sha}", None, self.source.info(sha))
            self.store.activate(self.policy_bundle, sha)
        log.info("no active policy: published %s@%s", self.source.ref, sha)
        return sha

    # --- after a signing key rotation ---
    def resign_if_needed(self) -> str | None:
        """The active commit, signed again with the current key: same content, no approval."""
        active = self.store.active(self.policy_bundle)
        if not active or stored_with_key(self.store, self.policy_bundle, active, self.signer.keyid):
            return None
        with self.db.tx() as c, tempfile.TemporaryDirectory() as tmp:
            self.source.build(active, self.signer, Path(tmp) / "b.tar.gz")
            self.store.put_revision(self.policy_bundle, active, Path(tmp) / "b.tar.gz")
            dbm.audit(c, ACTOR, "resign", f"{self.policy_bundle}@{active}", None, {"keyid": self.signer.keyid})
            self.store.activate(self.policy_bundle, active)
        log.info("re-signed %s@%s with %s", self.policy_bundle, active, self.signer.keyid)
        return active

    # --- a new commit ---
    def propose(self) -> int | None:
        """Files the branch's new head as a policy change. Returns its id, or None when there is
        nothing new. Transient failures raise, and the next round tries again."""
        sha = self.source.head()
        active = self.store.active(self.policy_bundle)
        if not active or sha == active:
            return None
        with self.db.tx() as c:
            if c.execute("select 1 from change_request where kind = 'policy' and object_id = %s", (sha,)).fetchone():
                return None
        info = self.source.info(sha)
        before = {"commit": active}
        change = {"kind": "policy", "object_id": sha, "op": "update", "before": before, "after": info}
        try:
            report = self._check(sha, active)
            error = None
        except Rejected as e:
            report, error = None, str(e)
        required = [] if error else approvals.required(self.opa_url, change, ACTOR)
        with self.db.tx() as c:
            # a failed commit supersedes nothing: the open change is still a good candidate
            for old in [] if error else c.execute("""select id from change_request where kind = 'policy'
                                    and state in ('pending_approval', 'approved') for update""").fetchall():
                if c.execute("select 1 from outbox where change_id = %s and published_at is not null",
                             (old["id"],)).fetchone():
                    continue                                    # being published: let it finish
                c.execute("delete from outbox where change_id = %s", (old["id"],))
                c.execute("update change_request set state = 'withdrawn', error = %s, updated_at = now() "
                          "where id = %s", (f"superseded by {sha[:12]}", old["id"]))
                dbm.audit(c, ACTOR, "withdraw", f"change/{old['id']}", None, {"superseded_by": sha})
            row = c.execute("""insert into change_request (kind, object_id, op, before, after, state,
                                   required_approvals, replay_report, error, created_by)
                               values ('policy', %s, 'update', %s, %s, %s, %s, %s, %s, %s) returning id""",
                            (sha, Jsonb(before), Jsonb(info), "failed" if error else "pending_approval",
                             Jsonb(required), Jsonb(report) if report else None, error, ACTOR)).fetchone()
            dbm.audit(c, ACTOR, "change_failed" if error else "change_update", f"policy/{sha}", before, info)
        log.info("policy change %s for %s: %s", row["id"], sha, error or "pending approval")
        return row["id"]

    def _check(self, sha: str, active: str) -> dict:
        """Test, build, render the records, replay. Rejected for what the commit itself gets wrong."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            new_policy = self.ensure_built(sha, tmp)
            old_policy = self.store.fetch(self.policy_bundle, active, tmp / "old-policy.tar.gz")
            data_rev = self.store.active(self.data_bundle)
            if not data_rev:
                raise RuntimeError(f"no active {self.data_bundle} bundle (run the import)")
            old_data = self.store.fetch(self.data_bundle, data_rev, tmp / "old-data.tar.gz")
            with self.db.tx() as c:
                records = dbm.resources(c)
            try:
                new_data = self.renderer.render(records, sha, tmp / "gateway-projects")
            except RenderError as e:
                raise Rejected(f"the registry's records don't render at {sha[:12]}: {e}") from e
            report = replay_all(self.events(), [old_policy, old_data], [new_policy, new_data], self.opa)
            report["records_change"] = not same_data(new_data, old_data)
            return report


def from_env(db: dbm.DB, store: Store, signer, renderer: Renderer, events) -> PolicyWatch:
    env = os.environ
    source = PolicySource(env.get("POLICY_REPO", env["DEPLOY_REPO"]), env.get("POLICY_REF", "main"), renderer,
                          env.get("POLICY_DIR", "policies/gateway"),
                          tuple(env.get("POLICY_TEST_DIRS", "policies/gateway,policies/gateway-projects").split(",")))
    return PolicyWatch(db, store, signer, renderer, source, events, env["OPA_URL"])
