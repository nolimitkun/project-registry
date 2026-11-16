"""End to end on a real Postgres and the real renderers of the policy (policy/).

Needs TEST_DATABASE_URL (a disposable database). The policy is this repository's policy/
at HEAD (commit first), or POLICY_REPO / POLICY_SUBDIR / POLICY_REVISION.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest
import yaml
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException

from registry import api, bundles, db as dbm, importer, publisher, render
from registry.auth import User
from tests.test_bundles import OPA, FakeS3
from tests import test_usage

DSN = os.environ.get("TEST_DATABASE_URL")
# The platform's own projects, as the project-registry chart seeds a new cluster with
SEED = json.loads((Path(__file__).parent / "fixtures" / "seed.json").read_text())
# The policy: this repository's policy/ at HEAD by default, so the code and the policy
# are tested together (POLICY_REPO / POLICY_SUBDIR / POLICY_REVISION for another).
ROOT = Path(__file__).resolve().parent.parent
REPO = os.environ.get("POLICY_REPO", str(ROOT))
SUBDIR = os.environ.get("POLICY_SUBDIR", "policy" if REPO == str(ROOT) else "") or None
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

ALICE = User("alice", {"platform-admins"})              # platform team, owner of every project
BOB = User("bob", {"platform-admins"})
SEC = User("sec", {"security-reviewers"})
COST = User("cost", {"cost-owners"})


def head(repo):
    rev = os.environ.get("POLICY_REVISION")
    if rev:
        return rev
    if repo == str(ROOT):
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
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
    # an active policy bundle at that commit, as the publisher leaves it
    (tmp_path / "p").write_bytes(b"placeholder")
    store.put_revision("gateway-policy", policy_rev, tmp_path / "p")
    store.activate("gateway-policy", policy_rev)
    signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "opa-bundles")
    renderer = render.Renderer(REPO, tmp_path / "checkouts", subdir=SUBDIR)
    # the catalog and the settings: a seed carries them, like the deployment's (the policy's
    # test fixture)
    fixture = yaml.safe_load((renderer.checkout(policy_rev) / "fixtures" / "records.yaml").read_text())
    for kind in dbm.CATALOG_KINDS + dbm.SETTING_KINDS:
        monkeypatch.setitem(SEED, kind, fixture.get(kind) or {})
    roles = {"value": ["project_owner"], "may_submit": True, "asked": []}

    class Resp:
        def __init__(self, result):
            self.result = result

        def raise_for_status(self):
            pass

        def json(self):
            return {"result": self.result}

    def opa(url, json=None, timeout=None):
        roles["asked"].append((url.rsplit("/", 1)[1], json["input"]))
        return Resp(roles["may_submit"] if url.endswith("/may_submit") else roles["value"])

    monkeypatch.setattr(api.requests, "post", opa)
    reg = api.Registry(db, renderer, store, "http://opa")
    pub = publisher.Publisher(db, store, signer, renderer, lambda: [], opa=OPA)
    monkeypatch.setattr(publisher, "replay", lambda *a: {"ok": True, "replayed": 0})
    return {"db": db, "store": store, "signer": signer, "renderer": renderer, "reg": reg, "pub": pub,
            "roles": roles, "s3": s3}


def test_import_from_the_seed_then_a_change_goes_through_approval_publish_and_activation(world):
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
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

    # and forward again: one active publication
    assert reg.rollback(ALICE, rev) == {"active": rev, "rolled_back": []}
    with db.tx() as c:
        assert [r["revision"] for r in c.execute("select revision from publication where state = 'active'")] == [rev]


def test_invalid_changes_are_refused_before_approval(world):
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    with pytest.raises(HTTPException) as e:          # a model the catalog doesn't have
        reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"models": {"allow": ["no-such-model"]}}))
    assert e.value.status_code == 422 and "matches no catalog model" in str(e.value.detail)
    with pytest.raises(HTTPException) as e:
        reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={}))
    assert e.value.status_code == 422


def test_key_limits_only_narrow_the_projects_keys(world):
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    for key_limits, error in [({"nobody": {"limits": {"requests_per_minute": 5}}}, "not one of the project's keys"),
                              ({"admin": {"limits": {"requests_per_minute": 61}}}, "above the project's 60"),
                              ({"admin": {"budget": {"usd_per_30_days": 26}}}, "above the project's 25")]:
        with pytest.raises(HTTPException) as e:
            reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"key_limits": key_limits}))
        assert e.value.status_code == 422 and error in str(e.value.detail), e.value.detail
    # tokens: the project has no limit, so any
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"key_limits": {
        "admin": {"limits": {"requests_per_minute": 5, "tokens_per_minute": 10**9}, "budget": {"usd_per_30_days": 1}}}}))
    assert ch["state"] in ("pending_approval", "approved")


def test_a_failed_replay_publishes_nothing(world, monkeypatch):
    db, store, reg, pub = world["db"], world["store"], world["reg"], world["pub"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
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


def test_submit_rights_come_from_policy(world):
    db, reg, roles = world["db"], world["reg"], world["roles"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    roles["may_submit"] = False
    with pytest.raises(HTTPException) as e:
        reg.submit(SEC, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    assert e.value.status_code == 403
    name, asked = roles["asked"][-1]
    assert name == "may_submit" and asked["requester"] == "sec" and asked["groups"] == ["security-reviewers"]
    assert asked["owner_group"] == "platform-admins" and asked["change"]["object_id"] == "admin"
    roles["may_submit"] = None                       # undefined in the policy: no
    with pytest.raises(HTTPException):
        reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    roles["may_submit"] = True
    assert reg.submit(ALICE, "project", "admin", "update",
                      api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))["state"] == "pending_approval"


def test_metrics_and_export(world, monkeypatch):
    from fastapi.testclient import TestClient
    db = world["db"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    app = api.create_app(world["reg"])
    app.dependency_overrides[api.current_user] = lambda: ALICE
    client = TestClient(app)
    m = client.get("/metrics").text
    assert '# TYPE project_budget_usd gauge' in m and 'project_budget_usd{project="admin"} 25.0' in m
    assert '# TYPE key_budget_usd gauge' in m and "key_budget_usd{" not in m      # no key has a budget of its own
    with db.tx() as c:                               # a key with one
        c.execute("""update resource set spec = spec || '{"key_limits": {"admin": {"budget": {"usd_per_30_days": 2}}}}'::jsonb
                     where kind = 'project' and id = 'admin'""")
    assert 'key_budget_usd{project="admin",key_id="admin"} 2.0' in client.get("/metrics").text
    assert ('model_price_usd_per_million_tokens{model="gemini-3.5-flash",'
            'gen_ai_request_model="gemini-3.5-flash",gen_ai_token_type="output"}') in m
    # a KServe model under the name its route sends, as the gateway's metrics carry it
    assert 'model="qwen3.6-27b",gen_ai_request_model="unsloth/Qwen3.6-27B-NVFP4@' in m
    out = client.get("/export").json()
    assert out["revision"] == "projects-00000001"
    assert out["project"]["admin"]["limits"] == {"requests_per_minute": 60}
    assert set(out["exception"]) == {"kagent", "holmes"} and len(out["agent"]) == 5


def test_a_key_change_re_signs_the_active_records(world):
    db, store, pub = world["db"], world["store"], world["pub"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    assert pub.resign_if_needed() is None                     # same key: nothing to do
    pub.signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048),
                                        "opa-bundles-v2")
    rev = pub.resign_if_needed()
    assert rev and rev != first and store.active("gateway-projects") == rev
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        path = store.fetch("gateway-projects", rev, Path(tmp) / "b.tar.gz")
        assert bundles.signed_keyid(path) == "opa-bundles-v2"
        bundles.verify(path, pub.signer.public_pem(), "opa-bundles-v2", opa=OPA)
    assert pub.resign_if_needed() is None
    with db.tx() as c:
        assert c.execute("select action from audit_log order by seq desc limit 1").fetchone()["action"] == "resign"


def test_a_change_nobody_can_approve_can_be_withdrawn(world):
    db, reg, pub = world["db"], world["reg"], world["pub"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    with pytest.raises(HTTPException) as e:
        reg.withdraw(SEC, ch["id"], None)                       # neither author nor platform team
    assert e.value.status_code == 403
    assert reg.withdraw(ALICE, ch["id"], "nobody else owns it") == {"id": ch["id"], "state": "withdrawn"}
    with pytest.raises(HTTPException) as e:
        reg.decide(BOB, ch["id"], "approve", None)               # nothing left to approve
    assert e.value.status_code == 409
    # an approved one leaves the outbox too, so it is never published
    ch2 = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 31}}))
    reg.decide(BOB, ch2["id"], "approve", None)
    assert reg.withdraw(BOB, ch2["id"], None)["state"] == "withdrawn"   # platform team
    assert pub.publish_once() is None
    with db.tx() as c:
        assert c.execute("select spec from resource where kind='project' and id='admin'").fetchone()["spec"]["limits"] \
            == {"requests_per_minute": 60}


def test_portal_change_list_and_internal_only_endpoints(world, monkeypatch):
    from fastapi.testclient import TestClient
    monkeypatch.setenv("KEYCLOAK_ISSUER", "http://keycloak.test/realms/mini-platform")
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    reg.decide(BOB, ch["id"], "approve", "fine")
    app = api.create_app(reg)
    app.dependency_overrides[api.current_user] = lambda: ALICE
    client = TestClient(app)
    page = client.get("/portal/")
    assert page.status_code == 200 and "Project registry" in page.text and "code_challenge_method" in page.text
    assert client.get("/", follow_redirects=False).headers["location"] == "/portal/"
    assert client.get("/portal/config.json").json() == {"issuer": "http://keycloak.test/realms/mini-platform",
                                                       "clientId": "project-registry"}
    assert client.get("/me").json() == {"name": "alice", "groups": ["platform-admins"]}
    listed = client.get("/changes?state=open").json()
    assert [c["id"] for c in listed] == [ch["id"]] and listed[0]["approvals"][0]["approver"] == "bob"
    assert client.get("/changes?state=active").json() == []
    assert client.get("/changes?object_id=holmes").json() == []
    # through the ingress (X-Forwarded-For), the cluster-internal endpoints refuse
    via_ingress = {"X-Forwarded-For": "203.0.113.7"}
    assert client.get("/metrics", headers=via_ingress).status_code == 403
    assert client.post("/opa/status", json={"labels": {"id": "x"}}, headers=via_ingress).status_code == 403
    assert client.get("/metrics").status_code == 200
    assert client.post("/opa/status", json={"labels": {"id": "x"}, "bundles": {}}).status_code == 200


def test_active_counts_only_ready_opa_pods_and_is_checked_without_a_report(world):
    from registry import activation
    db, reg, pub, store = world["db"], world["reg"], world["pub"], world["store"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    report = lambda iid, pod, rev: {"labels": {"id": iid, "pod": pod}, "bundles": {"gateway-projects": {"active_revision": rev}}}
    reg.opa_pods = lambda: {"opa-old"}
    reg.status(report("i-old", "opa-old", first))                # the pod about to be replaced
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    reg.decide(BOB, ch["id"], "approve", None)
    rev = pub.publish_once()
    reg.opa_pods = lambda: {"opa-old", "opa-new"}
    reg.status(report("i-new", "opa-new", rev))                  # the new pod has it, the old one not
    def state():
        with db.tx() as c:
            return c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"]
    assert state() == "publishing"
    # the old pod is gone: no report arrives, the periodic check activates it
    with db.tx() as c:
        assert activation.activate_due(c, "gateway-projects", {"opa-new"}) == [rev]
    assert state() == "active"
    # a ready pod that hasn't reported holds activation back
    ch2 = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 31}}))
    reg.decide(BOB, ch2["id"], "approve", None)
    rev2 = pub.publish_once()
    reg.status(report("i-new", "opa-new", rev2))
    with db.tx() as c:
        assert activation.activate_due(c, "gateway-projects", {"opa-new", "opa-third"}) == []
        assert activation.activate_due(c, "gateway-projects", {"opa-new"}) == [rev2]


def test_internal_reads_for_the_replay_and_the_gateway_keys_from_the_records(world):
    from fastapi.testclient import TestClient
    from registry import keys
    from tests.test_keys import FakeKV
    db, store = world["db"], world["store"]
    rev = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    client = TestClient(api.create_app(world["reg"]))
    b = client.get("/internal/bundles/gateway-projects")
    assert b.status_code == 200 and b.headers["x-revision"] == rev and b.content[:2] == b"\x1f\x8b"
    assert client.get("/internal/bundles/other").status_code == 404
    via_ingress = {"X-Forwarded-For": "203.0.113.7"}
    assert client.get("/internal/bundles/gateway-projects", headers=via_ingress).status_code == 403
    with db.tx() as c:
        records = dbm.resources(c)
    want = keys.wanted(world["renderer"].lines(records, store.active("gateway-policy"), "--keys"))
    assert want["admin"] == "admin" and want["open-webui"] == "open-webui"
    assert want["kagent-k8s-agent"] == "kagent"                                 # agent keys too
    kv = FakeKV()
    assert set(keys.reconcile(kv, "m", want)["added"]) == set(want)
    assert set(kv.data[keys.CLIENTS]) == set(want)


def test_a_snapshot_is_what_an_empty_registry_imports(world):
    from registry import snapshot
    db, store = world["db"], world["store"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    with db.tx() as c:
        c.execute("update resource set spec = jsonb_set(spec, '{owner}', '\"changed\"') "
                  "where kind = 'project' and id = 'admin'")
    snapshot.run(db, store)
    records, source = importer.records_from(None, store.latest_snapshot())
    assert source == "snapshot" and records["project"]["admin"]["owner"] == "changed"
    before = set(store.revisions("gateway-projects"))
    with db.tx() as c:                                     # the database is lost: a new one
        c.execute("drop schema public cascade; create schema public")
    db.migrate()
    assert snapshot.run(db, store) is None                 # empty: latest.json stays the recovery point
    records, source = importer.records_from(None, store.latest_snapshot())
    assert source == "snapshot"
    rev = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", records, source, opa=OPA)
    assert rev not in before                               # bundle_seq moved past the kept revisions
    with db.tx() as c:
        assert c.execute("select spec from resource where kind='project' and id='admin'").fetchone()["spec"]["owner"] \
            == "changed"
    seed, source = importer.records_from(Path(__file__).parent / "fixtures" / "seed.json", None)
    assert source == "seed seed.json" and set(seed["project"]) == set(SEED["project"])


def test_the_registry_keeps_agentregistry_current(world, monkeypatch):
    db, store, pub = world["db"], world["store"], world["pub"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    sent = []

    class Resp:
        text = '{"results":[{"status":"created"},{"status":"updated"}]}'

        def raise_for_status(self):
            pass

    def post(url, data=None, headers=None, timeout=None):
        sent.append((url, data))
        return Resp()

    monkeypatch.setattr(publisher.requests, "post", post)
    assert pub.sync_agentregistry(None) is None
    assert pub.sync_agentregistry("http://agentregistry:12121") == 2
    url, body = sent[0]
    assert url == "http://agentregistry:12121/v0/apply" and b"kagent-k8s-agent" in body
    import yaml
    docs = list(yaml.safe_load_all(body))
    assert len(docs) == 5 and all(d and d.get("apiVersion") for d in docs)   # no comment-only document


def test_agentregistry_from_a_policy_commit_of_the_deployment_repo(world, monkeypatch):
    # a policy commit from before gateway-policy writes the agents to the old path
    db, store, pub = world["db"], world["store"], world["pub"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    real = pub.renderer.render

    def old_layout(records, rev, out, also=None):
        moved = {("minikube/gitops/agentregistry-catalog/files/agents.yaml" if k.startswith("generated/") else k): v
                 for k, v in (also or {}).items()}
        legacy = {k: v for k, v in moved.items() if k.startswith("minikube/")}
        result = real(records, rev, out, also={"generated/agentregistry-agents.yaml": legacy[next(iter(legacy))]})
        return result

    monkeypatch.setattr(pub.renderer, "render", old_layout)
    sent = []

    class Resp:
        text = '{"results":[{"status":"updated"}]}'

        def raise_for_status(self):
            pass

    monkeypatch.setattr(publisher.requests, "post", lambda url, data=None, headers=None, timeout=None:
                        sent.append(data) or Resp())
    assert pub.sync_agentregistry("http://agentregistry:12121") == 1 and b"kagent-k8s-agent" in sent[0]


def test_a_proposed_kagent_agent_is_checked_against_the_deployment_repos_wiring(world, tmp_path):
    from registry import render as rmod
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    world["roles"]["value"] = ["project_owner"]
    # a key its ModelConfig doesn't read (the deployment copies kagent-k8s-agent's key for it)
    unwired = api.ChangeIn(spec={"keys": ["kagent-k8s-agent-2"]})
    assert reg.submit(ALICE, "agent", "kagent-k8s-agent", "update", unwired)["state"] == "pending_approval"
    with db.tx() as c:                                    # no wiring check configured: accepted
        c.execute("update change_request set state = 'withdrawn'")
    reg.kagent_wiring = rmod.KagentWiring(os.environ.get("KAGENT_WIRING_REPO",
                                                         "https://github.com/nolimitkun/mini-platform-deployment.git"),
                                          "main", Path(os.path.relpath(tmp_path)))   # a relative WORKDIR
    with pytest.raises(HTTPException) as e:
        reg.submit(ALICE, "agent", "kagent-k8s-agent", "update", unwired)
    assert e.value.status_code == 422 and "vaultSecrets" in str(e.value.detail)
    # a change that keeps the agent wired passes the check
    assert reg.submit(ALICE, "agent", "kagent-k8s-agent", "update",
                      api.ChangeIn(spec={"owner": "platform on-call"}))["state"] == "pending_approval"
    # a project change doesn't depend on the wiring
    assert reg.submit(ALICE, "project", "admin", "update",
                      api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))["state"] == "pending_approval"


def test_concurrent_agent_proposals_share_one_wiring_refresh(world, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from registry import render as rmod
    wiring = rmod.KagentWiring(os.environ.get("KAGENT_WIRING_REPO",
                                              "https://github.com/nolimitkun/mini-platform-deployment.git"),
                               "main", tmp_path, ttl=0)          # every call refreshes
    with ThreadPoolExecutor(8) as pool:
        results = list(pool.map(lambda _: wiring.env(), range(16)))
    assert all(Path(r["KAGENT_VALUES"]).exists() for r in results)


def test_the_catalog_is_changed_by_request_into_the_data_bundle_and_the_chart(world):
    import json
    import tarfile
    import tempfile
    from registry import gatewaychart
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    rev = store.active("gateway-policy")
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    with db.tx() as c:
        model = c.execute("select spec from resource where kind = 'model' and id = 'gemini-3.5-flash'").fetchone()["spec"]
    roles["value"] = ["cost_owner", "platform"]
    with pytest.raises(HTTPException) as e:                                   # gen-catalog.py validates it
        reg.submit(ALICE, "model", "gemini-3.5-flash", "update", api.ChangeIn(spec={"placement": "moon"}))
    assert e.value.status_code == 422 and "placement" in str(e.value.detail)
    ch = reg.submit(ALICE, "model", "gemini-3.5-flash", "update", api.ChangeIn(spec={"price": {"input": 9, "output": 9}}))
    assert ch["after"]["price"] == {"input": 9, "output": 9} and ch["before"] == model
    reg.decide(BOB, ch["id"], "approve", None)
    reg.decide(COST, ch["id"], "approve", None)
    data = pub.publish_once()
    assert data and store.active("gateway-projects") == data
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(store.fetch("gateway-projects", data, Path(tmp) / "b.tar.gz")) as tar:
            merged = json.loads(tar.extractfile(next(m for m in tar.getmembers() if m.name.endswith("data.json"))).read())
    assert merged["registry"]["catalog"]["models"]["gemini-3.5-flash"]["price"] == {"input": 9, "output": 9}
    # the gateway's chart values come from the records too
    with db.tx() as c:
        records = dbm.resources(c)
    records["google_api"]["speech"] = {**records["google_api"]["speech"], "host": "elsewhere.googleapis.com"}
    values = gatewaychart.catalog_values(world["renderer"], rev, records)
    assert values["googleApis"]["speech"]["host"] == "elsewhere.googleapis.com"


def test_publisher_outputs_report_their_health_on_metrics(world):
    import time as t
    from fastapi.testclient import TestClient
    from registry.health import Health
    db = world["db"]
    h = Health(db, write_every=0)
    assert h.run("chart", lambda: "published") == "published"
    calls = []

    def vault_refuses():
        calls.append(1)
        raise RuntimeError("403 Forbidden")
    assert h.run("keys", vault_refuses, retry_after=60) is None             # never raises
    assert h.run("keys", vault_refuses, retry_after=60) is None and len(calls) == 1   # waits to retry
    with db.tx() as c:
        row = c.execute("select * from publisher_health where output = 'keys'").fetchone()
    assert row["last_success"] is None and "403 Forbidden" in row["last_error"]
    body = TestClient(api.create_app(world["reg"])).get("/metrics").text
    ok = [l for l in body.splitlines() if l.startswith('registry_output_last_success_timestamp_seconds{output="chart"}')]
    assert ok and abs(float(ok[0].split()[-1]) - t.time()) < 60
    assert 'registry_output_last_failure_timestamp_seconds{output="keys"}' in body
    assert 'registry_output_last_success_timestamp_seconds{output="keys"}' not in body


def test_a_signing_failure_fails_the_change_and_reaches_health(world, monkeypatch):
    from registry.health import Health
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 61}}))
    reg.decide(BOB, ch["id"], "approve", None)

    def vault_refuses(*a, **k):
        raise RuntimeError("Vault: permission denied")
    monkeypatch.setattr(world["signer"], "sign", vault_refuses)
    h = Health(db, write_every=0)
    assert h.run("data", pub.publish_once) is None
    with db.tx() as c:
        assert c.execute("select state from change_request where id = %s", (ch["id"],)).fetchone()["state"] == "failed"
        row = c.execute("select last_success, last_error from publisher_health where output = 'data'").fetchone()
    assert row["last_success"] is None and "permission denied" in row["last_error"]


def test_a_setting_is_changed_by_request_into_the_data_bundle(world):
    import json
    import tarfile
    import tempfile
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    rev = store.active("gateway-policy")
    if not (world["renderer"].checkout(rev) / "scripts" / "gen-settings.py").exists():
        pytest.skip("the policy repo has no settings yet")
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    roles["value"] = ["platform", "security"]
    with pytest.raises(HTTPException) as e:                                   # gen-settings.py validates it
        reg.submit(ALICE, "setting", "autonomy", "update", api.ChangeIn(spec={"supervised": ["read", "fly"]}))
    assert e.value.status_code == 422
    ch = reg.submit(ALICE, "setting", "autonomy", "update", api.ChangeIn(spec={"supervised": ["read", "write"]}))
    reg.decide(BOB, ch["id"], "approve", None)
    reg.decide(SEC, ch["id"], "approve", None)
    data = pub.publish_once()
    assert data and store.active("gateway-projects") == data
    with tempfile.TemporaryDirectory() as tmp:
        with tarfile.open(store.fetch("gateway-projects", data, Path(tmp) / "b.tar.gz")) as tar:
            merged = json.loads(tar.extractfile(next(m for m in tar.getmembers() if m.name.endswith("data.json"))).read())
    assert merged["registry"]["settings"]["autonomy"]["supervised"] == ["read", "write"]


def test_a_setting_change_may_change_any_project():
    from registry.publisher import Everyone, projects_touched
    assert isinstance(projects_touched({"kind": "setting", "object_id": "approvals", "before": {}, "after": {}}), Everyone)


def test_an_approval_wakes_the_publisher(world):
    import threading
    import time as t
    from registry.wakeup import Wakeup
    db, store, reg, roles = world["db"], world["store"], world["reg"], world["roles"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    wake = Wakeup(DSN)
    assert wake.wait(0.2) is False                                            # nothing yet
    ch = reg.submit(ALICE, "project", "admin", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 30}}))
    started = t.time()
    threading.Timer(0.5, lambda: reg.decide(BOB, ch["id"], "approve", None)).start()
    assert wake.wait(10) is True and t.time() - started < 5                   # not the whole timeout
    assert wake.wait(0.2) is False                                            # one notice, one wake


def test_a_chart_asks_argo_cd_to_refresh_its_application(tmp_path, monkeypatch):
    from registry import argo
    (tmp_path / "token").write_text("t0ken")
    (tmp_path / "ca.crt").write_text("ca")
    calls = []

    class Resp:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(argo.requests, "patch", lambda url, **k: calls.append((url, k)) or Resp())
    assert argo.refresh("argocd/mini-platform-gateway-models", sa=tmp_path) is True
    url, k = calls[0]
    assert url.endswith("/namespaces/argocd/applications/mini-platform-gateway-models")
    assert k["json"] == {"metadata": {"annotations": {"argocd.argoproj.io/refresh": "normal"}}}
    assert k["headers"]["Content-Type"] == "application/merge-patch+json"

    def refused(url, **k):
        raise argo.requests.ConnectionError("no route")
    monkeypatch.setattr(argo.requests, "patch", refused)
    assert argo.refresh("argocd/x", sa=tmp_path) is False                     # never raises


def test_the_usage_page_shows_each_caller_the_projects_it_may_see(world):
    from fastapi.testclient import TestClient

    from registry import usage
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    app = api.create_app(reg)
    client = TestClient(app)
    app.dependency_overrides[api.current_user] = lambda: COST
    assert client.get("/usage").status_code == 404                  # not configured

    with db.tx() as c:
        c.execute("update project_owner set owner_group = 'webui-owners' where project_id = 'open-webui'")
        records = dbm.resources(c)
        owners = {r["project_id"]: r["owner_group"] for r in c.execute("select * from project_owner").fetchall()}
    reg.usage = usage.Reader(usage.Bucket(test_usage.FakeS3(), "usage"))
    usage.run(reg.usage.bucket, test_usage.loki([test_usage.CLOUD, test_usage.KSERVE, test_usage.AUTO, test_usage.DENIED]),
              records, owners, now=test_usage.NOW, backfill=3)
    day = {"start": "2026-11-01", "end": "2026-11-15"}

    r = client.get("/usage", params=day).json()                     # the cost owners see every project
    assert {p["project"] for p in r["by_project"]} == {"admin", "kagent", "open-webui"}
    assert r["totals"]["requests"] == 3 and r["totals"]["denied"] == 1
    admin = next(p for p in r["by_project"] if p["project"] == "admin")
    assert admin["budget_usd_30d"] == 25 and admin["cost_30d"] == pytest.approx(0.00025485)
    assert r["onprem"]["output_tokens"] == 18 and r["onprem"]["reference_usd"] > 0     # Qwen at Gemini 3.5 Flash's price
    assert {(m["model"], m["via_auto"]) for m in r["by_model"]} >= {("gemini-3.5-flash-lite", 1), ("qwen3.6-27b", 0)}
    assert r["through"] == "2026-11-15T11:30:00+00:00"

    app.dependency_overrides[api.current_user] = lambda: User("wendy", {"webui-owners"})
    r = client.get("/usage", params=day).json()                     # an owner: only its projects
    assert r["projects"] == ["open-webui"] and [p["project"] for p in r["by_project"]] == ["open-webui"]
    assert r["totals"]["denied"] == 1 and r["totals"]["cost_usd"] == 0
    assert client.get("/usage", params={**day, "project": "admin"}).status_code == 403
    assert client.get("/usage/requests", params={"project": "admin", "date": "2026-11-15"}).status_code == 403
    [req] = client.get("/usage/requests", params={"project": "open-webui", "date": "2026-11-15"}).json()
    assert (req["outcome"], req["status"], req["trace_id"]) == ("denied", 403, "t4")

    app.dependency_overrides[api.current_user] = lambda: User("nobody", {"someone-else"})
    assert client.get("/usage", params=day).json()["by_project"] == []
    assert client.get("/usage", params={"start": "2026-11-15", "end": "2026-11-01"}).status_code == 422


def test_the_inbox_lists_what_waits_for_the_caller_and_preview_files_nothing(world):
    from fastapi.testclient import TestClient
    db, reg, roles = world["db"], world["reg"], world["roles"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    app = api.create_app(reg)
    client = TestClient(app)
    as_ = lambda u: app.dependency_overrides.__setitem__(api.current_user, lambda: u)  # noqa: E731

    # preview: who would approve, validated like a submit, nothing filed
    roles["value"] = ["cost_owner", "project_owner"]
    as_(ALICE)
    p = client.post("/changes/preview", json={"collection": "projects", "object_id": "admin",
                                              "spec": {"limits": {"requests_per_minute": 120}}}).json()
    assert p["required_approvals"] == ["cost_owner", "project_owner"] and p["after"]["limits"]["requests_per_minute"] == 120
    assert p["owner_group"] == "platform-admins" and client.get("/changes").json() == []
    bad = client.post("/changes/preview", json={"collection": "projects", "object_id": "admin",
                                                "spec": {"limits": {"requests_per_minute": 0}}})
    assert bad.status_code == 422 and bad.json()["detail"]["errors"]                    # what gen-projects.py says
    assert client.post("/changes/preview", json={"collection": "nope", "object_id": "x"}).status_code == 404

    # filed: it waits for the cost owners and the project's owners, not for its author
    ch = client.patch("/projects/admin", json={"spec": {"limits": {"requests_per_minute": 120}}}).json()
    assert client.get("/changes", params={"awaiting": "me"}).json() == []               # ALICE wrote it
    assert client.get(f"/changes/{ch['id']}").json()["yours"] == []
    as_(COST)
    [mine] = client.get("/changes", params={"awaiting": "me"}).json()
    assert mine["id"] == ch["id"] and mine["yours"] == ["cost_owner"]
    as_(BOB)                                                                            # platform-admins own admin
    assert client.get("/changes", params={"awaiting": "me"}).json()[0]["yours"] == ["project_owner"]
    assert client.post(f"/changes/{ch['id']}/approve", json={}).status_code == 200
    assert client.get("/changes", params={"awaiting": "me"}).json() == []               # decided
    as_(SEC)
    assert client.get("/changes", params={"awaiting": "me"}).json() == []               # no role in it
    as_(COST)
    assert [c["id"] for c in client.get("/changes", params={"awaiting": "me"}).json()] == [ch["id"]]
    assert client.get("/changes", params={"awaiting": "you"}).status_code == 422


def test_the_project_page_shows_what_opa_lets_a_project_use(world, monkeypatch, tmp_path):
    """insight.EFFECTIVE run by the opa binary over this repository's policy and the data
    bundle the importer published, as the API's /v1/query call would on the gateway's OPA."""
    from fastapi.testclient import TestClient
    from registry import insight
    db, store = world["db"], world["store"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    data = store.fetch("gateway-projects", store.active("gateway-projects"), tmp_path / "data.tar.gz")
    policy = Path(world["renderer"].checkout(head(REPO))) / "policies"

    class Resp:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    def opa_query(url, json=None, timeout=None):
        assert url == "http://opa/v1/query"
        out = subprocess.run([OPA, "eval", "-f", "json", "-d", str(policy), "-b", str(data), "-I", json["query"]],
                             input=__import__("json").dumps(json["input"]), capture_output=True, text=True, check=True)
        return Resp({"result": [r["bindings"] for r in __import__("json").loads(out.stdout).get("result", [])]})

    monkeypatch.setattr(insight.requests, "post", opa_query)
    app = api.create_app(world["reg"])
    app.dependency_overrides[api.current_user] = lambda: ALICE
    client = TestClient(app)

    holmes = client.get("/projects/holmes/effective").json()
    assert holmes["published"] and holmes["placements"] == ["gcp", "onprem"]
    by_name = {m["name"]: m for m in holmes["models"]}
    assert by_name["deepseek-v4-pro"]["via"] == "exception"              # external, through its exception
    assert by_name["qwen3.6-27b"]["via"] == "rule"
    assert all(t.startswith("grafana_") for risk in holmes["tools"].values() for t in risk)
    agent = holmes["agents"][0]
    assert agent["id"] == "holmes" and agent["models"] == ["deepseek-v4-pro"]
    # supervised: reads without a human, writes and irreversible calls need one
    assert set(agent["tools"]) == set(holmes["tools"]["read"])
    assert set(agent["tools_needing_approval"]) == set(holmes["tools"]["write"] + holmes["tools"]["irreversible"])

    admin = {m["name"]: m for m in client.get("/projects/admin/effective").json()["models"]}
    assert admin["deepseek-v4-pro"]["via"] == "rule"                   # public data: external allowed

    nobody = client.get("/projects/nobody/effective").json()
    assert not nobody["published"] and not any(m["via"] for m in nobody["models"])
    assert "not one of the project's" in nobody["models"][0]["why_not"]


def test_the_status_page_compares_what_opa_loaded_with_what_is_published(world, monkeypatch):
    from fastapi.testclient import TestClient
    from registry import health, insight
    db, store, reg = world["db"], world["store"], world["reg"]
    first = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    policy = store.active("gateway-policy")
    reg.opa_pods = lambda: {"opa-a", "opa-b", "opa-c"}
    reg.status({"labels": {"id": "1", "pod": "opa-a"}, "bundles": {"gateway-projects": {"active_revision": first},
                                                                  "gateway-policy": {"active_revision": policy}}})
    reg.status({"labels": {"id": "2", "pod": "opa-b"}, "bundles": {"gateway-projects": {"active_revision": "old"},
                                                                  "gateway-policy": {"active_revision": policy}}})
    h = health.Health(db, write_every=0)
    h.run("data-bundle", lambda: None)
    h.run("agentregistry", lambda: 1 / 0)

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"data": {"alerts": [
                {"labels": {"alertname": "GatewayModelPriceDrift", "model": "m", "severity": "warning"}, "state": "firing",
                 "activeAt": "2026-11-15T10:00:00Z", "annotations": {"summary": "s"}},
                {"labels": {"alertname": "KubePodCrashLooping"}, "state": "firing"}]}}

    monkeypatch.setattr(insight.requests, "get", lambda url, timeout=None: Resp())
    monkeypatch.setenv("PROMETHEUS_URL", "http://prom")
    app = api.create_app(reg)
    app.dependency_overrides[api.current_user] = lambda: COST
    s = TestClient(app).get("/status").json()
    assert s["published"] == {"gateway-policy": policy, "gateway-projects": first}
    opa = {o["pod"]: o for o in s["opa"]}
    assert opa["opa-a"]["current"] and not opa["opa-b"]["current"]
    assert opa["opa-c"]["reported_at"] is None and not opa["opa-c"]["current"]     # ready, never reported
    outputs = {o["output"]: o for o in s["outputs"]}
    assert not outputs["data-bundle"]["failing"] and outputs["agentregistry"]["failing"]
    assert "ZeroDivisionError" in outputs["agentregistry"]["last_error"]
    assert [a["name"] for a in s["alerts"]["alerts"]] == ["GatewayModelPriceDrift"]  # only the gateway's and the registry's
    assert s["alerts"]["alerts"][0]["labels"] == {"model": "m"}


def test_why_denied_evaluates_the_gateway_policy_and_the_audit_log_is_for_approvers(world, monkeypatch, tmp_path):
    """/explain runs authz.rego (the opa binary over this repository's policy and the
    imported data) on the input the gateway would send; /audit and the changes filters."""
    from fastapi.testclient import TestClient
    from registry import insight
    db, store, reg, roles = world["db"], world["store"], world["reg"], world["roles"]
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    data = store.fetch("gateway-projects", store.active("gateway-projects"), tmp_path / "data.tar.gz")
    policy = Path(world["renderer"].checkout(head(REPO))) / "policies"

    class Resp:
        def __init__(self, body):
            self.body = body

        def raise_for_status(self):
            pass

        def json(self):
            return self.body

    world_opa = insight.requests.post        # the world's fake: approvals and may_submit

    def opa_query(url, json=None, timeout=None):
        if url != "http://opa/v1/query":
            return world_opa(url, json=json, timeout=timeout)
        out = subprocess.run([OPA, "eval", "-f", "json", "-d", str(policy), "-b", str(data), "-I", json["query"]],
                             input=__import__("json").dumps(json["input"]), capture_output=True, text=True, check=True)
        return Resp({"result": [r["bindings"] for r in __import__("json").loads(out.stdout).get("result", [])]})

    monkeypatch.setattr(insight.requests, "post", opa_query)
    app = api.create_app(reg)
    client = TestClient(app)
    as_ = lambda u: app.dependency_overrides.__setitem__(api.current_user, lambda: u)  # noqa: E731
    as_(ALICE)

    ok = client.post("/explain", json={"project": "admin", "kind": "model", "name": "qwen3.6-27b"}).json()
    assert ok["allowed"] and ok["key_id"] == "admin" and ok["reason"] is None
    agent = client.post("/explain", json={"project": "holmes", "kind": "model", "name": "gemini-4-argon"}).json()
    assert not agent["allowed"] and agent["key_id"] == "holmes" and agent["agent"] == "holmes"
    assert agent["reason"] == "model gemini-4-argon is not allowed for agent holmes (project holmes)"
    assert agent["hint"].startswith("Widen the agent's models patterns")
    write = client.post("/explain", json={"project": "holmes", "kind": "tool", "name": "grafana_create_incident"}).json()
    assert not write["allowed"] and "needs a human approval" in write["reason"] and "autonomy" in write["hint"]
    tool = client.post("/explain", json={"project": "open-webui", "kind": "tool", "name": "grafana_list_datasources"}).json()
    assert tool["hint"] == "Add a pattern for it to the project's MCP tools."
    assert client.post("/explain", json={"project": "nobody", "kind": "model", "name": "x"}).json()["reason"] == "unknown project"
    assert client.post("/explain", json={"project": "admin", "kind": "listing"}).status_code == 422
    assert client.post("/explain", json={"project": "admin", "kind": "tool"}).status_code == 422

    # the changes list: by kind, by a part of the object id, a page at a time
    roles["value"] = ["project_owner"]
    for rpm in (31, 32, 33):
        ch = reg.submit(ALICE, "project", "holmes", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": rpm}}))
        reg.withdraw(ALICE, ch["id"], None)
    reg.submit(ALICE, "project", "kagent", "update", api.ChangeIn(spec={"limits": {"requests_per_minute": 7}}))
    page = client.get("/changes", params={"q": "olm", "limit": 2}).json()
    assert [c["object_id"] for c in page] == ["holmes", "holmes"]
    rest = client.get("/changes", params={"q": "olm", "limit": 2, "offset": 2}).json()
    assert len(rest) == 1 and rest[0]["id"] < page[-1]["id"]
    assert client.get("/changes", params={"kind": "agent"}).json() == []
    assert client.get("/changes", params={"q": "%"}).json() == []          # a literal %, not a wildcard

    # the audit log: the approver groups only
    entries = client.get("/audit", params={"action": "withdraw"}).json()
    assert len(entries) == 3 and all(e["actor"] == "alice" for e in entries)
    assert client.get("/audit", params={"q": "project/kag"}).json()[0]["action"] == "change_update"
    as_(COST)
    assert client.get("/audit", params={"limit": 1}).status_code == 200
    as_(User("dev", {"some-team"}))
    assert client.get("/audit").status_code == 403


def test_merge_is_rfc_7386():
    # a null in an object the target doesn't have yet is dropped, not kept (the portal's
    # per-key form sends one for a limit a new key leaves empty)
    assert api.merge({"a": 1}, {"k": {"x": {"y": 2}, "z": None}}) == {"a": 1, "k": {"x": {"y": 2}}}
    assert api.merge({"k": 3}, {"k": {"z": None}}) == {"k": {}}
    assert api.merge({"k": {"x": 1, "z": 2}}, {"k": {"z": None}, "a": None}) == {"k": {"x": 1}}
