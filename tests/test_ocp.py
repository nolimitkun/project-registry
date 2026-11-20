from pathlib import Path

import yaml

from registry import ocp

RECORDS = yaml.safe_load((Path(__file__).resolve().parent.parent / "policy" / "fixtures" / "records.yaml").read_text())


def test_facts_are_the_records_the_fleets_check_against():
    f = ocp.facts(RECORDS)
    assert f["keys"]["admin"] == {"project": "admin", "agent": None}
    assert f["keys"]["holmes"] == {"project": "holmes", "agent": "holmes"}      # an agent's key
    assert f["deployments"]["model-prod/unsloth-qwen3-6-27b-nvfp4-ccdaab7e-e8eb38"] == "qwen3.6-27b"
    assert f["serving_namespaces"] == ["model-hprd", "model-prod"]


class Session:
    def __init__(self, status=200):
        self.headers, self.calls, self.status = {}, [], status

    def put(self, url, json=None, timeout=None):
        self.calls.append((url, json))
        return type("R", (), {"status_code": self.status, "text": "boom"})()


def test_pin_sets_every_fleet_source_to_the_commit_then_pushes_the_facts():
    s = Session()
    o = ocp.OCP("http://ocp:8282/", "t", "https://github.com/o/r.git", "policy", "main", session=s)
    o.pin("abc", {"keys": {}})
    assert s.headers["Authorization"] == "Bearer t"
    assert [u for u, _ in s.calls] == ["http://ocp:8282/v1/sources/admission", "http://ocp:8282/v1/sources/platform",
                                       "http://ocp:8282/v1/sources/registry/data/registry"]
    assert s.calls[0][1] == {"git": {"repo": "https://github.com/o/r.git", "reference": "refs/heads/main", "commit": "abc",
                                     "path": "policy/policies/admission", "excluded_files": ["*_test.rego"]}}
    assert s.calls[2][1] == {"keys": {}}


def test_a_refused_put_fails_the_round():
    import pytest
    o = ocp.OCP("http://ocp:8282", "t", "r", None, session=Session(status=403))
    with pytest.raises(RuntimeError, match="403"):
        o.pin("abc", {})
