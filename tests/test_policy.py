"""Policy changes through the registry: a commit on the branch is filed as a change,
approved, published with the records rendered at it, activated, rolled back.

A small repo stands in for the deployment repo: a decision rule, its test, and a
gen-projects.py that renders projects/*.yaml. Needs TEST_DATABASE_URL.
"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from psycopg.types.json import Jsonb

from registry import api, bundles, db as dbm, policy, publisher, render
from registry.auth import User
from tests.test_bundles import OPA, FakeS3

DSN = os.environ.get("TEST_DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

BOB = User("bob", {"platform-admins"})
SEC = User("sec", {"security-reviewers"})

RULE = """package gateway.authz

import rego.v1

default decision := {"allowed": false}

decision := {"allowed": true} if { %s }
"""
TEST = """package gateway.authz

import rego.v1

test_on if decision.allowed with input as {"p": "a"} with data.projects as {"a": {"on": true}}
"""
GEN = """import json, pathlib, shutil, yaml
FORMAT = %d
out = pathlib.Path("policies/gateway-projects/projects")
shutil.rmtree(out, ignore_errors=True)
for f in sorted(pathlib.Path("projects").glob("*.yaml")):
    (out / f.stem).mkdir(parents=True)
    (out / f.stem / "data.json").write_text(json.dumps({**yaml.safe_load(f.read_text()), "format": FORMAT}))
"""
ALLOW = 'data.projects[input.p].on'


def git(*args, cwd):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=tester", *args], cwd=cwd, check=True,
                   capture_output=True)


def commit(repo: Path, msg: str, rule: str = ALLOW, fmt: int = 1, test: str = TEST) -> str:
    (repo / "policies" / "gateway" / "authz.rego").write_text(RULE % rule)
    (repo / "policies" / "gateway" / "authz_test.rego").write_text(test)
    (repo / "scripts" / "gen-projects.py").write_text(GEN % fmt)
    subprocess.run([sys.executable, "scripts/gen-projects.py"], cwd=repo, check=True)
    git("add", "-A", cwd=repo)
    git("commit", "-q", "--allow-empty", "-m", msg, cwd=repo)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()


@pytest.fixture
def world(tmp_path, monkeypatch):
    repo = tmp_path / "origin"
    for d in ("policies/gateway", "policies/gateway-projects", "projects", "agents", "scripts"):
        (repo / d).mkdir(parents=True)
    (repo / "policies" / "gateway" / ".manifest").write_text(json.dumps({"roots": ["gateway"]}))
    (repo / "policies" / "gateway-projects" / ".manifest").write_text(json.dumps({"roots": ["projects"]}))
    (repo / "projects" / "a.yaml").write_text("on: true\n")
    git("init", "-q", "-b", "main", cwd=repo)
    first = commit(repo, "first policy")

    db = dbm.DB(DSN)
    with db.tx() as c:
        c.execute("drop schema public cascade; create schema public")
    db.migrate()
    store = bundles.Store(FakeS3(), "b")
    signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k1")
    renderer = render.Renderer(str(repo), tmp_path / "checkouts")
    source = policy.PolicySource("main", renderer, opa=OPA)
    events = [{"input": {"p": "a"}, "result": {"allowed": True}, "time": "t"},
              {"input": {"p": "b"}, "result": {"allowed": False}, "time": "t"}]
    asked = []

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"result": ["project_owner"]}       # what a portal.rego without policy rules answers

    def opa(url, json=None, timeout=None):
        asked.append(json["input"])
        return Resp()

    monkeypatch.setattr(api.requests, "post", opa)
    watch = policy.PolicyWatch(db, store, signer, renderer, source, lambda: events, "http://opa", opa=OPA)
    pub = publisher.Publisher(db, store, signer, renderer, lambda: events, opa=OPA, policy=watch)
    reg = api.Registry(db, renderer, store, "http://opa", signing_keyid="k1")

    # a new cluster: the head is published without a change, then the records
    assert watch.bootstrap() == first and store.active("gateway-policy") == first
    with db.tx() as c, tempfile.TemporaryDirectory() as tmp:
        c.execute("insert into resource (kind, id, spec) values ('project', 'a', %s)", (Jsonb({"on": True}),))
        data = renderer.render(dbm.resources(c), first, Path(tmp) / "d")
        bundles.build(data, "projects-00000001", signer, Path(tmp) / "d.tar.gz", opa=OPA)
        store.put_revision("gateway-projects", "projects-00000001", Path(tmp) / "d.tar.gz")
        c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                     values ('projects-00000001', 0, '{}', 'active', %s, '{}')""", (first,))
        store.activate("gateway-projects", "projects-00000001")
    return {"repo": repo, "db": db, "store": store, "signer": signer, "watch": watch, "pub": pub, "reg": reg,
            "first": first, "asked": asked}


def state(db, cid):
    with db.tx() as c:
        return c.execute("select state, error from change_request where id = %s", (cid,)).fetchone()


def report(reg, pod, policy_rev, data_rev):
    reg.status({"labels": {"id": pod}, "bundles": {"gateway-policy": {"active_revision": policy_rev},
                                                    "gateway-projects": {"active_revision": data_rev}}})


def test_a_commit_is_proposed_approved_published_and_activated(world):
    db, store, watch, pub, reg, first = (world[k] for k in ("db", "store", "watch", "pub", "reg", "first"))
    assert watch.propose() is None                               # nothing new
    sha = commit(world["repo"], "deny project b explicitly, new data format", fmt=2,
                 rule='data.projects[input.p].on; input.p != "a"',  # flips the logged allow for a
                 test=TEST.replace('"a"', '"c"'))
    cid = watch.propose()
    with db.tx() as c:
        ch = c.execute("select * from change_request where id = %s", (cid,)).fetchone()
    assert ch["kind"] == "policy" and ch["state"] == "pending_approval" and ch["object_id"] == sha
    assert ch["required_approvals"] == ["platform"]              # no project owns the policy
    assert ch["after"]["subject"].startswith("deny project b") and ch["before"] == {"commit": first}
    r = ch["replay_report"]
    assert (r["kind"], r["replayed"], r["changed"], r["allowed_to_denied"], r["records_change"]) == \
        ("policy", 2, 1, 1, True)
    assert store.active("gateway-policy") == first               # built, not active
    assert watch.propose() is None                               # filed once

    assert pub.publish_once() is None                            # not approved yet
    assert reg.decide(BOB, cid, "approve", "ok")["state"] == "approved"
    assert pub.publish_once() == sha
    assert store.active("gateway-policy") == sha
    data = store.active("gateway-projects")
    assert data != "projects-00000001"                           # records rendered at the new commit
    with tempfile.TemporaryDirectory() as tmp:
        b = store.fetch("gateway-projects", data, Path(tmp) / "d.tar.gz")
        assert bundles.signed_keyid(b) == "k1"
    assert state(db, cid)["state"] == "publishing"

    report(reg, "opa-1", first, "projects-00000001")
    assert state(db, cid)["state"] == "publishing"
    report(reg, "opa-1", sha, data)
    assert state(db, cid)["state"] == "active"

    # the data format changed with it: rolling back the policy alone would mismatch, so it's refused
    with pytest.raises(HTTPException) as e:
        reg.rollback(BOB, first)
    assert e.value.status_code == 409 and "renders differently" in e.value.detail
    assert store.active("gateway-policy") == sha


def approve_and_publish(world, sha):
    cid = world["watch"].propose()
    world["reg"].decide(BOB, cid, "approve", None)
    assert world["pub"].publish_once() == sha
    return cid


def test_rollback_and_forward_of_a_policy_with_the_same_data_format(world):
    db, store, watch, reg, first = (world[k] for k in ("db", "store", "watch", "reg", "first"))
    data = store.active("gateway-projects")
    sha = commit(world["repo"], "rules only", rule='data.projects[input.p].on; input.p != "z"')
    cid = approve_and_publish(world, sha)
    assert store.active("gateway-projects") == data               # same records: not republished
    with pytest.raises(HTTPException):
        reg.rollback(User("x", {"security-reviewers"}), first)
    assert reg.rollback(BOB, first) == {"active": first, "rolled_back": [sha]}
    assert store.active("gateway-policy") == first and state(db, cid)["state"] == "rolled_back"
    assert watch.propose() is None                                # the head isn't proposed again
    assert reg.rollback(BOB, sha) == {"active": sha, "rolled_back": []}
    with db.tx() as c:
        assert [r["revision"] for r in c.execute(
            "select revision from policy_publication where state = 'active'")] == [sha]


def test_a_failed_policy_activation_puts_the_data_back(world, monkeypatch):
    db, store, first = world["db"], world["store"], world["first"]
    data = store.active("gateway-projects")
    sha = commit(world["repo"], "new format", fmt=3)
    cid = world["watch"].propose()
    world["reg"].decide(BOB, cid, "approve", None)
    activate = store.activate

    def flaky(bundle, revision):
        if bundle == "gateway-policy":
            raise RuntimeError("store unavailable")
        activate(bundle, revision)

    monkeypatch.setattr(store, "activate", flaky)
    assert world["pub"].publish_once() is None
    assert store.active("gateway-policy") == first and store.active("gateway-projects") == data
    assert state(db, cid)["state"] == "failed" and sha
    with db.tx() as c:
        assert c.execute("select revision from publication where state = 'active'").fetchone()["revision"] == data


def test_a_newer_commit_supersedes_and_a_failing_test_publishes_nothing(world):
    db, store, watch, reg, first = (world[k] for k in ("db", "store", "watch", "reg", "first"))
    commit(world["repo"], "one", rule='data.projects[input.p].on; input.p != "y"')
    old = watch.propose()
    assert reg.decide(BOB, old, "approve", None)["state"] == "approved"
    bad = commit(world["repo"], "breaks its test", rule="false")
    failed = watch.propose()
    assert state(db, failed)["state"] == "failed" and "opa test failed" in state(db, failed)["error"]
    assert state(db, old)["state"] == "approved"                 # a failed commit supersedes nothing
    assert watch.propose() is None and store.active("gateway-policy") == first
    good = commit(world["repo"], "fixed", rule='data.projects[input.p].on; input.p != "x"')
    new = watch.propose()
    assert state(db, old) == {"state": "withdrawn", "error": f"superseded by {good[:12]}"}
    assert state(db, new)["state"] == "pending_approval" and bad != good


def test_a_key_change_re_signs_the_active_commit(world):
    store, watch, first = world["store"], world["watch"], world["first"]
    assert watch.resign_if_needed() is None
    watch.signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k2")
    assert watch.resign_if_needed() == first and store.active("gateway-policy") == first
    with tempfile.TemporaryDirectory() as tmp:
        assert bundles.signed_keyid(store.fetch("gateway-policy", first, Path(tmp) / "p")) == "k2"
    assert watch.resign_if_needed() is None


def test_policy_approvals_need_the_platform_team(monkeypatch):
    from registry import approvals

    class Resp:
        def __init__(self, result):
            self.result = result

        def raise_for_status(self):
            pass

        def json(self):
            return {"result": self.result}

    for answer, want in ((["project_owner"], ["platform"]), (["security"], ["platform", "security"])):
        monkeypatch.setattr(approvals.requests, "post", lambda *a, answer=answer, **k: Resp(answer))
        assert approvals.required("http://opa", {"kind": "policy"}, "x") == want
    monkeypatch.setattr(approvals.requests, "post", lambda *a, **k: Resp([]))
    with pytest.raises(approvals.NoAnswer):                      # a data change still fails closed
        approvals.required("http://opa", {"kind": "project"}, "x")


def test_a_policy_published_before_the_registry_did_is_adopted(world):
    db, watch, first = world["db"], world["watch"], world["first"]
    with db.tx() as c:
        c.execute("delete from policy_publication")
    assert watch.bootstrap() is None
    with db.tx() as c:
        rows = c.execute("select revision, state, active_at is not null as on from policy_publication").fetchall()
    assert rows == [{"revision": first, "state": "active", "on": True}]
    assert watch.bootstrap() is None


def test_same_data_compares_data_not_files(tmp_path):
    src = tmp_path / "src"
    (src / "projects" / "a").mkdir(parents=True)
    (src / ".manifest").write_text('{"roots": ["projects"]}')
    (src / "projects" / "a" / "data.json").write_text('{\n  "on": true, "n": {"x": 1}\n}\n')
    signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k")
    bundles.build(src, "r1", signer, tmp_path / "b.tar.gz", opa=OPA)      # merged into one /data.json
    assert policy.same_data(src, tmp_path / "b.tar.gz")
    (src / "projects" / "a" / "data.json").write_text('{"on": true, "n": {"x": 2}}')
    assert not policy.same_data(src, tmp_path / "b.tar.gz")


def test_a_format_change_the_old_policy_or_data_cant_take_is_refused(world):
    db, store, first = world["db"], world["store"], world["first"]
    # the new rule needs the new format: the new policy with the old data denies project a
    sha = commit(world["repo"], "rule reads the new format", fmt=2, rule="data.projects[input.p].format == 2",
                 test=TEST.replace('{"a": {"on": true}}', '{"a": {"format": 2}}'))
    cid = world["watch"].propose()
    ch = state(db, cid)
    assert ch["state"] == "failed" and "Stage it" in ch["error"] and sha
    assert store.active("gateway-policy") == first


def test_policy_repo_must_be_the_deploy_repo(world, monkeypatch):
    monkeypatch.setenv("POLICY_REPO", "https://example.invalid/other.git")
    monkeypatch.setenv("OPA_URL", "http://opa")
    with pytest.raises(SystemExit, match="POLICY_REPO must be the renderer's repository"):
        policy.from_env(world["db"], world["store"], world["signer"], world["watch"].renderer, lambda: [])


def publish_records(world, on: bool) -> str:
    """Project a's records changed and published at the active policy, as a data change would."""
    db, store, signer = world["db"], world["store"], world["signer"]
    policy_rev = store.active("gateway-policy")
    with db.tx() as c, tempfile.TemporaryDirectory() as tmp:
        c.execute("update resource set spec = %s where kind = 'project' and id = 'a'", (Jsonb({"on": on}),))
        seq = c.execute("select nextval('bundle_seq') as n").fetchone()["n"]
        rev = f"projects-{seq:08d}"
        data = world["watch"].renderer.render(dbm.resources(c), policy_rev, Path(tmp) / "d")
        bundles.build(data, rev, signer, Path(tmp) / "d.tar.gz", opa=OPA)
        store.put_revision("gateway-projects", rev, Path(tmp) / "d.tar.gz")
        c.execute("update publication set state = 'superseded' where state = 'active'")
        c.execute("""insert into publication (revision, seq, change_ids, state, policy_revision, records)
                     values (%s, %s, '{}', 'active', %s, '{}')""", (rev, seq, policy_rev))
        store.activate("gateway-projects", rev)
    return rev


def test_records_published_while_waiting_are_checked_again_before_the_policy(world):
    db, store, first = world["db"], world["store"], world["first"]
    publish_records(world, False)
    # needs the new format; safe while project a is off (every pair denies it)
    commit(world["repo"], "rule reads the new format", fmt=2, rule="data.projects[input.p].on; data.projects[input.p].format == 2",
           test=TEST.replace('{"a": {"on": true}}', '{"a": {"on": true, "format": 2}}'))
    cid = world["watch"].propose()
    assert state(db, cid)["state"] == "pending_approval"
    world["reg"].decide(BOB, cid, "approve", None)
    publish_records(world, True)            # now the new policy with the old data denies a: unsafe
    assert world["pub"].publish_once() is None
    assert state(db, cid)["state"] == "failed" and "Stage it" in state(db, cid)["error"]
    assert store.active("gateway-policy") == first


def test_a_replay_that_changes_after_the_approval_goes_back_to_the_approvers(world):
    db, store, first = world["db"], world["store"], world["first"]
    publish_records(world, False)
    sha = commit(world["repo"], "deny a", rule='data.projects[input.p].on; input.p != "a"',
                 test=TEST.replace('"a"', '"c"'))
    cid = world["watch"].propose()                     # a is off: nothing flips
    world["reg"].decide(BOB, cid, "approve", None)
    publish_records(world, True)                       # now a would flip from allowed to denied
    assert world["pub"].publish_once() is None
    ch = state(db, cid)
    assert ch["state"] == "pending_approval" and "approve again" in ch["error"]
    with db.tx() as c:
        assert not c.execute("select 1 from approval where change_id = %s", (cid,)).fetchone()
        assert c.execute("select replay_report from change_request where id = %s",
                         (cid,)).fetchone()["replay_report"]["allowed_to_denied"] == 1
    world["reg"].decide(BOB, cid, "approve", "seen the flip")
    assert world["pub"].publish_once() == sha and state(db, cid) == {"state": "publishing", "error": None}


def test_a_commit_that_changes_neither_bundle_is_skipped(world):
    db, store, watch, first = world["db"], world["store"], world["watch"], world["first"]
    (world["repo"] / "README.md").write_text("docs only\n")
    docs = commit(world["repo"], "docs only")
    cid = watch.propose()
    with db.tx() as c:
        ch = c.execute("select * from change_request where id = %s", (cid,)).fetchone()
    assert (ch["state"], ch["required_approvals"], ch["object_id"]) == ("skipped", [], docs)
    assert ch["replay_report"]["unchanged"] is True
    assert ch["replay_report"]["records_change"] is False         # the fields a recheck reads
    assert store.active("gateway-policy") == first and watch.propose() is None
    # a real change after it is compared with the active commit, and filed
    sha = commit(world["repo"], "rules", rule='data.projects[input.p].on; input.p != "z"')
    cid2 = watch.propose()
    with db.tx() as c:
        ch2 = c.execute("select * from change_request where id = %s", (cid2,)).fetchone()
    assert ch2["state"] == "pending_approval" and ch2["before"] == {"commit": first} and ch2["object_id"] == sha
    assert state(db, cid)["state"] == "skipped"                  # not superseded: it was never open


def test_a_renderer_change_is_not_skipped_even_if_todays_records_render_the_same(world):
    db, watch = world["db"], world["watch"]
    gen = world["repo"] / "scripts" / "gen-projects.py"
    gen.write_text(gen.read_text() + "# accepts an optional field from now on\n")
    git("add", "-A", cwd=world["repo"])
    git("commit", "-qm", "renderer change", cwd=world["repo"])
    cid = watch.propose()
    with db.tx() as c:
        ch = c.execute("select state, replay_report from change_request where id = %s", (cid,)).fetchone()
    assert ch["state"] == "pending_approval" and ch["replay_report"]["records_change"] is False
