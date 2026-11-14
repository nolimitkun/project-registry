import json

from registry import replay
from tests.test_bundles import OPA


def event(project, allowed):
    return {"path": replay.RULE, "result": {"allowed": allowed},
            "input": {"attributes": {"metadataContext": {"filterMetadata": {"agentgateway": {"project": project}}},
                                     "request": {"http": {"path": "/v1/chat/completions"}}},
                      "parsed_body": {"model": "m"}}}


def test_only_the_touched_projects_may_change(tmp_path):
    policy, active, candidate = tmp_path / "policy", tmp_path / "active", tmp_path / "candidate"
    (policy / "gateway").mkdir(parents=True)
    (policy / ".manifest").write_text(json.dumps({"roots": ["gateway"]}))
    (policy / "gateway" / "authz.rego").write_text(
        "package gateway.authz\n\n"
        "p := input.attributes.metadataContext.filterMetadata.agentgateway.project\n\n"
        'decision := {"allowed": data.projects[p].on == true}\n')
    for d, b_on in ((active, "true"), (candidate, "false")):     # the change switches b off
        for pid, on in (("a", "true"), ("b", b_on)):
            (d / "projects" / pid).mkdir(parents=True)
            (d / "projects" / pid / "data.json").write_text('{"on": %s}' % on)
        (d / ".manifest").write_text(json.dumps({"roots": ["projects"]}))
    events = [event("a", True), event("b", True), event("a", True)]
    ok = replay.replay(events, policy, active, candidate, {"b"}, OPA)
    assert ok["ok"] and ok["replayed"] == 3 and ok["changed_for_changed_projects"] == 1
    stopped = replay.replay(events, policy, active, candidate, {"a"}, OPA)
    assert not stopped["ok"] and stopped["changed_for_other_projects"] == 1
    assert stopped["examples"][0]["project"] == "b" and stopped["examples"][0]["after"] is False


def test_a_verdict_logged_under_another_policy_is_not_blamed_on_the_change(tmp_path):
    # logged as denied (an older policy), allowed under the active one with either data
    policy, data = tmp_path / "policy", tmp_path / "data"
    (policy / "gateway").mkdir(parents=True)
    (policy / ".manifest").write_text(json.dumps({"roots": ["gateway"]}))
    (policy / "gateway" / "authz.rego").write_text('package gateway.authz\n\ndecision := {"allowed": true}\n')
    (data / "projects").mkdir(parents=True)
    (data / ".manifest").write_text(json.dumps({"roots": ["projects"]}))
    report = replay.replay([event("a", False), event("b", False)], policy, data, data, set(), OPA)
    assert report["ok"] and report["changed_for_other_projects"] == 0


def test_an_undefined_decision_is_a_denial_and_keeps_the_order(tmp_path):
    def policy(name, rego):
        d = tmp_path / name
        (d / "gateway").mkdir(parents=True)
        (d / ".manifest").write_text(json.dumps({"roots": ["gateway"]}))
        (d / "gateway" / "authz.rego").write_text("package gateway.authz\n\nimport rego.v1\n\n" + rego)
        return d
    p = "input.attributes.metadataContext.filterMetadata.agentgateway.project"
    old = policy("old", 'decision := {"allowed": true}\n')
    new = policy("new", f'decision := {{"allowed": true}} if {p} == "b"\n')   # no default: undefined for a
    events = [event("a", True), event("b", True)]
    report = replay.replay_all(events, [old], [new], OPA)
    assert (report["replayed"], report["changed"], report["allowed_to_denied"]) == (2, 1, 1)
    assert report["examples"][0]["project"] == "a"


def test_a_request_without_a_body_replays_one_whose_body_was_dropped_does_not():
    def logged(method, erased):
        return {"path": replay.RULE, "result": {"allowed": True}, "erased": erased,
                "input": {"attributes": {"request": {"http": {"method": method, "path": "/v1/models"}}}}}
    assert replay.replayable(logged("GET", ["/input/parsed_body", "/input/truncated_body"]))
    assert not replay.replayable(logged("POST", ["/input/parsed_body", "/input/truncated_body"]))
    assert replay.replayable(logged("POST", ["/input/truncated_body"]))
    # a GET that carried a body (a JSON-RPC call to /mcp) lost what the policy decided on
    with_body = logged("GET", ["/input/parsed_body"])
    with_body["input"]["attributes"]["request"]["http"]["headers"] = {"content-length": "57"}
    assert not replay.replayable(with_body)
    chunked = logged("DELETE", ["/input/parsed_body"])
    chunked["input"]["attributes"]["request"]["http"]["headers"] = {"Transfer-Encoding": "chunked"}
    assert not replay.replayable(chunked)
