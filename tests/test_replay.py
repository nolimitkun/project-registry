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
