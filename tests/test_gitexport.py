"""The daily export, against a local bare copy of the deployment repo and a fake GitHub API."""
import os
import subprocess
from pathlib import Path

import pytest

from registry import gitexport
from tests.test_flow import DSN, REPO, head, world  # noqa: F401  (fixture)
from registry import importer
from tests.test_bundles import OPA

pytestmark = pytest.mark.skipif(not DSN, reason="TEST_DATABASE_URL not set")


class FakeGitHub:
    def __init__(self):
        self.prs, self.calls = [], []

    def get(self, url, params=None, timeout=None):
        self.calls.append(("GET", url))
        return Resp(self.prs)

    def post(self, url, json=None, timeout=None):
        self.calls.append(("POST", url))
        self.prs.append({"number": 1, "html_url": "https://github.example/pr/1", "body": json["body"], "head": json["head"]})
        return Resp(self.prs[-1])

    def patch(self, url, json=None, timeout=None):
        self.calls.append(("PATCH", url))
        self.prs[0]["body"] = json["body"]
        return Resp(self.prs[0])


class Resp:
    def __init__(self, data):
        self.data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self.data


@pytest.fixture
def remote(tmp_path):
    bare = tmp_path / "deploy.git"
    rev = head(REPO)
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    subprocess.run(["git", "-C", str(bare), "fetch", "-q", REPO, f"{rev}:refs/heads/main"], check=True)
    script = subprocess.run(["git", "-C", str(bare), "show", "main:scripts/registry-export.py"],
                            capture_output=True, text=True).stdout
    if "--from-file" not in script:
        pytest.skip("the deployment repo's registry-export.py has no --from-file yet")
    return bare


def test_export_opens_one_pr_and_updates_it(world, remote, monkeypatch):
    db, reg = world["db"], world["reg"]
    importer.run(db, world["store"], world["signer"], world["renderer"], "platform-admins", opa=OPA)
    gh = FakeGitHub()
    # the registry matches Git: nothing to do
    assert gitexport.run(db, "o/deploy", "t", remote=str(remote), session=gh) is None and not gh.calls
    # a record changes in the registry
    with db.tx() as c:
        c.execute("""update resource set spec = jsonb_set(spec, '{limits,requests_per_minute}', '61')
                     where kind = 'project' and id = 'admin'""")
    assert gitexport.run(db, "o/deploy", "t", remote=str(remote), session=gh) == "https://github.example/pr/1"
    shown = subprocess.run(["git", "-C", str(remote), "show", "registry-export:projects/admin.yaml"],
                           capture_output=True, text=True, check=True).stdout
    assert "requests_per_minute: 61" in shown and "Exported from the project registry" in shown
    files = subprocess.run(["git", "-C", str(remote), "diff", "--name-only", "main", "registry-export"],
                           capture_output=True, text=True, check=True).stdout.split()
    # the record and the data file gen-projects.py generates from it (CI checks they match)
    assert files == ["policies/gateway-projects/projects/admin/data.json", "projects/admin.yaml"]
    author = subprocess.run(["git", "-C", str(remote), "log", "-1", "--format=%an", "registry-export"],
                            capture_output=True, text=True, check=True).stdout.strip()
    assert author == "project-registry"
    # a second change: the same branch and PR, updated
    with db.tx() as c:
        c.execute("""update resource set spec = jsonb_set(spec, '{limits,requests_per_minute}', '62')
                     where kind = 'project' and id = 'admin'""")
    gitexport.run(db, "o/deploy", "t", remote=str(remote), session=gh)
    assert len(gh.prs) == 1 and [m for m, _ in gh.calls].count("POST") == 1 and ("PATCH", gh.calls[-1][1]) == gh.calls[-1]


def test_a_failing_git_command_does_not_print_the_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_secret_value")
    with pytest.raises(RuntimeError) as e:
        gitexport.git("clone", "--quiet", "https://127.0.0.1:9/nothing.git", str(tmp_path / "x"), cwd=tmp_path)
    assert "ghp_secret_value" not in str(e.value)


def test_no_token_does_nothing(monkeypatch, capsys):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    gitexport.main()
    assert "nothing exported" in capsys.readouterr().out
