import json
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from registry import bundles, policybuild
from tests.test_bundles import OPA, FakeS3


def git(*args, cwd):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "origin"
    (r / "policies" / "gateway" / "gw").mkdir(parents=True)
    (r / "policies" / "gateway-projects" / "projects" / "a").mkdir(parents=True)
    (r / "policies" / "gateway" / ".manifest").write_text(json.dumps({"roots": ["gw"]}))
    (r / "policies" / "gateway-projects" / ".manifest").write_text(json.dumps({"roots": ["projects"]}))
    (r / "policies" / "gateway-projects" / "projects" / "a" / "data.json").write_text('{"rpm": 5}')
    (r / "policies" / "gateway" / "gw" / "p.rego").write_text(
        "package gw\n\nallow if data.projects[input.p]\n")
    (r / "policies" / "gateway" / "gw" / "p_test.rego").write_text(
        'package gw\n\ntest_known if allow with input as {"p": "a"}\n')
    git("init", "-q", "-b", "main", cwd=r)
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x", cwd=r)
    git("add", "-A", cwd=r)
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "policy", cwd=r)
    return r


def head(r):
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=r, capture_output=True, text=True).stdout.strip()


def test_builds_once_per_commit_and_refuses_a_failing_test(repo):
    s3, signer = FakeS3(), bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k")
    store = bundles.Store(s3, "b")
    args = (store, signer, str(repo), "main", "policies/gateway",
            ["policies/gateway", "policies/gateway-projects"], "gateway-policy", OPA)
    first = policybuild.run(*args)
    assert first == head(repo) and store.active("gateway-policy") == first
    assert policybuild.run(*args) == "unchanged"
    # a commit whose test fails is not published
    (repo / "policies" / "gateway" / "gw" / "p.rego").write_text("package gw\n\nallow := false\n")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "break", cwd=repo)
    with pytest.raises(SystemExit, match="opa test failed"):
        policybuild.run(*args)
    assert store.active("gateway-policy") == first


def test_a_key_change_rebuilds_the_same_commit(repo):
    s3 = FakeS3()
    store = bundles.Store(s3, "b")
    old = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k")
    new = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "k-v2")
    args = (str(repo), "main", "policies/gateway", ["policies/gateway", "policies/gateway-projects"],
            "gateway-policy", OPA)
    sha = policybuild.run(store, old, *args)
    assert policybuild.run(store, old, *args) == "unchanged"
    assert policybuild.run(store, new, *args) == sha            # re-signed, same revision
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        assert bundles.signed_keyid(store.fetch("gateway-policy", sha, Path(tmp) / "b")) == "k-v2"
    assert policybuild.run(store, new, *args) == "unchanged"
