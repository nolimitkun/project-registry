"""End to end on a real Postgres and the real gen-projects.py of the policy repo.

Needs TEST_DATABASE_URL (a disposable database) and, optionally, POLICY_REPO
(default: nolimitkun/gateway-policy) and POLICY_REVISION (default: its main).
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

DSN = os.environ.get("TEST_DATABASE_URL")
# The platform's own projects, as the project-registry chart seeds a new cluster with
SEED = json.loads((Path(__file__).parent / "fixtures" / "seed.json").read_text())
REPO = os.environ.get("POLICY_REPO", "https://github.com/nolimitkun/gateway-policy.git")
pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")

ALICE = User("alice", {"platform-admins"})              # platform team, owner of every project
BOB = User("bob", {"platform-admins"})
SEC = User("sec", {"security-reviewers"})
COST = User("cost", {"cost-owners"})


def head(repo):
    rev = os.environ.get("POLICY_REVISION")
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
    # an active policy bundle at that commit, as the publisher leaves it
    (tmp_path / "p").write_bytes(b"placeholder")
    store.put_revision("gateway-policy", policy_rev, tmp_path / "p")
    store.activate("gateway-policy", policy_rev)
    signer = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "opa-bundles")
    renderer = render.Renderer(REPO, tmp_path / "checkouts")
    work = renderer.checkout(policy_rev)
    catalog_seeded = not (work / "catalog" / "models.yaml").exists()
    if catalog_seeded:          # the catalog lives in the registry: a seed carries it, like the deployment's
        fixture = yaml.safe_load((work / "fixtures" / "records.yaml").read_text())
        for kind in dbm.CATALOG_KINDS:
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
            "roles": roles, "s3": s3, "catalog_seeded": catalog_seeded}


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


def test_internal_reads_for_the_bootstrap_and_the_replay(world):
    from fastapi.testclient import TestClient
    db, store = world["db"], world["store"]
    rev = importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    client = TestClient(api.create_app(world["reg"]))
    keys = client.get("/internal/keys").text.splitlines()
    assert "admin admin" in keys and "open-webui open-webui" in keys
    assert any(line.startswith("kagent-k8s-agent ") for line in keys)           # agent keys too
    mirrors = client.get("/internal/mirrors").text.splitlines()
    assert mirrors and all(len(line.split()) == 3 for line in mirrors)
    b = client.get("/internal/bundles/gateway-projects")
    assert b.status_code == 200 and b.headers["x-revision"] == rev and b.content[:2] == b"\x1f\x8b"
    assert client.get("/internal/bundles/other").status_code == 404
    via_ingress = {"X-Forwarded-For": "203.0.113.7"}
    for path in ("/internal/keys", "/internal/mirrors", "/internal/bundles/gateway-projects"):
        assert client.get(path, headers=via_ingress).status_code == 403


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
    unwired = api.ChangeIn(spec={"secret": {"name": "not-in-kagent-resources", "field": "OPENAI_API_KEY"}})
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


def test_the_catalog_is_adopted_then_changed_by_request_into_the_data_bundle(world):
    import json
    import tarfile
    import tempfile
    from registry import catalog, gatewaychart
    db, store, reg, pub, roles = world["db"], world["store"], world["reg"], world["pub"], world["roles"]
    rev = store.active("gateway-policy")
    assert catalog.adopt(db, world["renderer"], rev) == 0                    # not before the import:
    importer.run(db, store, world["signer"], world["renderer"], "platform-admins", SEED, "seed", opa=OPA)
    with db.tx() as c:                                                        # it would have skipped the seed
        assert c.execute("select 1 from resource where kind = 'project' limit 1").fetchone()
    n = catalog.adopt(db, world["renderer"], rev)
    if world["catalog_seeded"]:                                               # the seed had it: nothing to adopt
        assert n == 0
    else:
        assert n > 0 and catalog.adopt(db, world["renderer"], rev) == 0      # once
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
    if "registry" not in merged:          # the policy repo before its step 1 (no data.registry.catalog)
        pytest.skip("the policy repo's gen-catalog.py doesn't write the registry's catalog yet")
    assert merged["registry"]["catalog"]["models"]["gemini-3.5-flash"]["price"] == {"input": 9, "output": 9}
    # the gateway's chart values come from the records too
    with db.tx() as c:
        records = dbm.resources(c)
    records["google_api"]["speech"] = {**records["google_api"]["speech"], "host": "elsewhere.googleapis.com"}
    values = gatewaychart.catalog_values(world["renderer"], rev, records)
    assert values["googleApis"]["speech"]["host"] == "elsewhere.googleapis.com"
