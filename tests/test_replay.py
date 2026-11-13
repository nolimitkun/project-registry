import json

from registry import replay
from tests.test_bundles import OPA


def event(project, allowed):
    return {"path": replay.RULE, "result": {"allowed": allowed},
            "input": {"attributes": {"metadataContext": {"filterMetadata": {"agentgateway": {"project": project}}},
                                     "request": {"http": {"path": "/v1/chat/completions"}}},
                      "parsed_body": {"model": "m"}}}


def test_only_the_touched_projects_may_change(tmp_path):
    policy, data = tmp_path / "policy", tmp_path / "data"
    (policy / "gateway").mkdir(parents=True)
    (data / "projects" / "a").mkdir(parents=True)
    (data / "projects" / "b").mkdir(parents=True)
    (policy / ".manifest").write_text(json.dumps({"roots": ["gateway"]}))
    (data / ".manifest").write_text(json.dumps({"roots": ["projects"]}))
    (policy / "gateway" / "authz.rego").write_text(
        "package gateway.authz\n\n"
        "p := input.attributes.metadataContext.filterMetadata.agentgateway.project\n\n"
        'decision := {"allowed": data.projects[p].on == true}\n')
    (data / "projects" / "a" / "data.json").write_text('{"on": true}')
    (data / "projects" / "b" / "data.json").write_text('{"on": false}')   # b switched off by the change
    events = [event("a", True), event("b", True), event("a", True)]
    ok = replay.replay(events, [policy, data], {"b"}, OPA)
    assert ok["ok"] and ok["replayed"] == 3 and ok["changed_for_changed_projects"] == 1
    stopped = replay.replay(events, [policy, data], {"a"}, OPA)
    assert not stopped["ok"] and stopped["changed_for_other_projects"] == 1
    assert stopped["examples"][0]["project"] == "b" and stopped["examples"][0]["after"] is False
