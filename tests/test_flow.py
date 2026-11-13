"""End to end on a real Postgres and the real gen-projects.py of the deployment repo.

Needs TEST_DATABASE_URL (a disposable database) and, optionally, DEPLOY_REPO
(default: the public deployment repo) and DEPLOY_REVISION (default: its main).
"""
import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from registry import api, bundles, db as dbm, importer, publisher, render
from registry.auth import User
from tests.test_bundles import OPA, FakeS3

DSN = os.environ.get("TEST_DATABASE_URL")
REPO = os.environ.get("DEPLOY_REPO", "https://github.com/nolimitkun/mini-platform-deployment.git")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

ALICE = User("alice", {"platform-admins"})              # platform team, owner of every project
BOB = User("bob", {"platform-admins"})
SEC = User("sec", {"security-reviewers"})
COST = User("cost", {"cost-owners"})


def head(repo):
    rev = os.environ.get("DEPLOY_REVISION")
    if rev:
        return rev
    out = subprocess.run(["git", "ls-remote", repo, "refs/heads/main"], capture_output=True, text=True, check=True)
    return out.stdout.split()[0]


@pytest.fixture
def world(tmp_path, monkeypatch):
    db = dbm.DB(DSN)
    with db.tx() as c:
        c.execute("drop schema public cascade; create schema public")
    db.migrate()
    s3 = FakeS3()
    store = bundles.Store(s3, "b")
    policy_rev = head(REPO)
    # an active policy bundle at that commit, as the policy build leaves it
    (tmp_path / "p").write_bytes(b"placeholder")
    store.put_revision("gateway-policy", policy_rev, tmp_path / "p")
    store.activate("gateway-policy", policy_rev)
    signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "opa-bundles")
    renderer = render.Renderer(REPO, tmp_path / "checkouts")
    roles = {"value": ["project_owner"]}

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"result": roles["value"]}

    monkeypatch.setattr(api.requests, "post", lambda *a, **k: Resp())
    reg = api.Registry(db, renderer, store, "http://opa")
    pub = publisher.Publisher(db, store, signer, renderer, lambda: [], opa=OPA)
    monkeypatch.setattr(publisher, "replay", lambda events, bundles_, touched, opa: {"ok": True, "replayed": 0})
    return {"db": db, "store": store, "signer": signer, "renderer": renderer, "reg": reg, "pub": pub,
            "roles": roles, "s3": s3}


def test_import_matches_git_then_a_change_goes_through_approval_publish_and_activation(world):
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", opa=OPA)
    assert store.active("gateway-projects") == first

    # a limit raise needs the owner and the cost owner (as the Rego would answer)
    roles["value"] = ["cost_owner", "project_owner"]
    ch = reg.submit(ALICE, "project", "admin", "update",
                    api.ChangeIn(spec={"limits": {"requests_per_minute": 120}}))
    assert ch["state"] == "pending_approval" and ch["after"]["limits"]["requests_per_minute"] == 120
    with pytest.raises(HTTPException) as e:                      # four eyes
        reg.decide(ALICE, ch["id"], "approve", None)
    assert e.value.status_code == 403
    with pytest.raises(HTTPException) as e:                      # security holds no open role here
        reg.decide(SEC, ch["id"], "approve", None)
    assert e.value.status_code == 403
    assert reg.decide(BOB, ch["id"], "approve", None) == {"id": ch["id"], "state": "pending_approval",
                                                          "approved_as": "project_owner"}
    assert pub.publish_once() is None                            # not approved yet: nothing to publish
    assert reg.decide(COST, ch["id"], "approve", None)["state"] == "approved"

    rev = pub.publish_once()
    assert rev and store.active("gateway-projects") == rev
    with db.tx() as c:
        assert c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"] == "publishing"
        assert c.execute("select spec from resource where kind='project' and id='admin'").fetchone()["spec"]["limits"] \
            == {"requests_per_minute": 120}

    # active once every OPA reports the revision
    reg.status({"labels": {"id": "opa-1"}, "bundles": {"gateway-projects": {"active_revision": first}}})
    reg.status({"labels": {"id": "opa-2"}, "bundles": {"gateway-projects": {"active_revision": rev}}})
    with db.tx() as c:
        assert c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"] == "publishing"
    reg.status({"labels": {"id": "opa-1"}, "bundles": {"gateway-projects": {"active_revision": rev}}})
    with db.tx() as c:
        assert c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"] == "active"

    # rollback: the previous revision and its records come back
    assert reg.rollback(ALICE, first) == {"active": first, "rolled_back": [rev]}
    assert store.active("gateway-projects") == first
    with db.tx() as c:
        assert c.execute("select spec from resource where kind='project' and id='admin'").fetchone()["spec"]["limits"] \
            == {"requests_per_minute": 60}
        assert c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"] == "rolled_back"
        actions = [r["action"] for r in c.execute("select action from audit_log order by seq")]
    assert actions[0] == "import" and actions[-1] == "rollback"


def test_invalid_changes_are_refused_before_approval(world):
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", opa=OPA)
    with pytest.raises(HTTPException) as e:          # a model the catalog doesn't have
        reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"models": {"allow": ["no-such-model"]}}))
    assert e.value.status_code == 422 and "matches no catalog model" in str(e.value.detail)
    with pytest.raises(HTTPException) as e:
        reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={}))
    assert e.value.status_code == 422


def test_a_failed_replay_publishes_nothing(world, monkeypatch):
    db, store, reg, pub = world["db"], world["store"], world["reg"], world["pub"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", opa=OPA)
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    reg.decide(BOB, ch["id"], "approve", None)
    stopped = {"ok": False, "replayed": 3, "changed_for_other_projects": 2, "changed_for_changed_projects": 0,
               "examples": []}
    monkeypatch.setattr(publisher, "replay", lambda *a: stopped)
    assert pub.publish_once() is None
    assert store.active("gateway-projects") == first
    with db.tx() as c:
        row = c.execute("select state, error, replay_report from change_request where id = %s", (ch["id"],)).fetchone()
        spec = c.execute("select spec from resource where kind='project' and id='admin'").fetchone()["spec"]
    assert row["state"] == "failed" and "replay" in row["error"] and row["replay_report"]["changed_for_other_projects"] == 2
    assert spec["limits"] == {"requests_per_minute": 60}         # the record did not change
