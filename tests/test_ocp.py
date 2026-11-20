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


def test_pinned_compares_each_source_with_the_commit():
    o = ocp.OCP("http://ocp", "t", "r", "policy")

    class S(Session):
        def __init__(self, sources):
            super().__init__()
            self.sources = sources

        def get(self, url, timeout=None):
            name = url.rsplit("/", 1)[1]
            body = {"result": {"name": name, **self.sources.get(name, {})}}
            return type("R", (), {"status_code": 200, "json": lambda self: body, "text": ""})()
    both = {n: o.source(d, "abc") for n, d in ocp.SOURCES.items()}
    o.http = S(both)
    assert o.pinned("abc") and not o.pinned("def")
    o.http = S({"admission": both["admission"]})                    # platform reset to its placeholder
    assert not o.pinned("abc")
