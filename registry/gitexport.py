"""Daily export of the registry's records to the deployment repo, as a pull request.

    python -m registry.gitexport

Reads every record from the registry's database, clones the deployment repo and
runs that repo's own scripts/registry-export.py on them (--from-file), so the files
are written exactly as by hand: only changed records are rewritten, removed ones
deleted, generated files regenerated. If anything changed, it force-pushes the
branch `registry-export` and opens a pull request, or updates the one already
open: at most one export PR at a time, and nothing merges by itself.

Settings (environment):
    DATABASE_URL                      the registry's database
    DEPLOY_REPO_SLUG                  owner/name on GitHub (nolimitkun/mini-platform-deployment)
    DEPLOY_BRANCH                     base branch (main)
    EXPORT_BRANCH                     the PR's branch (registry-export)
    GITHUB_TOKEN                      fine-grained token for that repo only: Contents and
                                      Pull requests, read and write. Without it the job
                                      says so and does nothing.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

from . import db as dbm

API = "https://api.github.com"
AUTHOR = ["-c", "user.name=project-registry", "-c", "user.email=project-registry@mini-platform.test"]
# The token reaches git through this helper and the environment, never a command line or
# a URL, so a failing command can't print it.
CREDENTIALS = ["-c", "credential.helper=",
               "-c", "credential.helper=!f() { echo username=x-access-token; echo \"password=$GITHUB_TOKEN\"; }; f"]


def git(*args: str, cwd: Path) -> str:
    r = subprocess.run(["git", *CREDENTIALS, *args], cwd=cwd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"git {args[0]} failed: {r.stderr.strip()[-500:]}")
    return r.stdout.strip()


def records(db: dbm.DB) -> dict:
    with db.tx() as c:
        out = dbm.resources(c)
        active = c.execute("select revision from publication where state = 'active' "
                           "order by seq desc limit 1").fetchone()
    return {"revision": active["revision"] if active else None, **out}


def open_or_update_pr(session: requests.Session, slug: str, base: str, branch: str, revision: str,
                      changed: list[str]) -> str:
    owner = slug.split("/")[0]
    prs = session.get(f"{API}/repos/{slug}/pulls", params={"head": f"{owner}:{branch}", "state": "open"}, timeout=30)
    prs.raise_for_status()
    body = (f"The project registry's records at revision `{revision}`, written by its daily export "
            "(`scripts/registry-export.py --from-file`).\n\nChanged files:\n"
            + "\n".join(f"- `{c}`" for c in changed)
            + "\n\nThese files mirror the registry, which OPA reads its project data from; merging "
              "keeps the API key ids, the agentregistry catalog and the recovery copy current. "
              "Review, merge, then run the Vault bootstrap (`SEED_MISSING_ONLY=true`) if a key id is new.")
    if prs.json():
        pr = prs.json()[0]
        session.patch(f"{API}/repos/{slug}/pulls/{pr['number']}", json={"body": body}, timeout=30).raise_for_status()
        return pr["html_url"]
    r = session.post(f"{API}/repos/{slug}/pulls", timeout=30, json={
        "title": "registry export: projects and agents from the project registry",
        "head": branch, "base": base, "body": body})
    r.raise_for_status()
    return r.json()["html_url"]


def run(db: dbm.DB, slug: str, token: str, base: str = "main", branch: str = "registry-export",
        remote: str | None = None, session: requests.Session | None = None) -> str | None:
    """Returns the PR's URL, or None when Git already matches the registry."""
    export = records(db)
    remote = remote or f"https://github.com/{slug}.git"
    os.environ["GITHUB_TOKEN"] = token
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        git("clone", "--quiet", "--depth", "1", "--branch", base, remote, str(work), cwd=Path(tmp))
        (Path(tmp) / "export.json").write_text(json.dumps(export))
        r = subprocess.run([sys.executable, "scripts/registry-export.py", "--from-file", str(Path(tmp) / "export.json")],
                           cwd=work, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"scripts/registry-export.py on {base} failed: {(r.stderr or r.stdout).strip()[-800:]}")
        git("add", "-A", cwd=work)
        changed = [l for l in git("status", "--porcelain", cwd=work).splitlines() if l.strip()]
        if not changed:
            print(f"Git matches the registry at {export['revision']}: nothing to export", flush=True)
            return None
        git("checkout", "-q", "-b", branch, cwd=work)
        git(*AUTHOR, "commit", "-q", "-m", f"registry export: records at {export['revision']}\n\n"
            "Written by the project registry's daily export (scripts/registry-export.py --from-file).", cwd=work)
        git("push", "-q", "--force", remote, f"HEAD:refs/heads/{branch}", cwd=work)
    files = [l[3:] for l in changed]
    if session is None:
        session = requests.Session()
        session.headers.update({"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json"})
    url = open_or_update_pr(session, slug, base, branch, export["revision"], files)
    print(f"export of {export['revision']}: {len(files)} file(s), {url}", flush=True)
    return url


def main() -> None:
    token = os.environ.get("GITHUB_TOKEN", "").strip()
    if not token:
        print("no GITHUB_TOKEN (Vault mini-platform/registry-git): nothing exported", flush=True)
        return
    db = dbm.DB(os.environ["DATABASE_URL"])
    run(db, os.environ.get("DEPLOY_REPO_SLUG", "nolimitkun/mini-platform-deployment"), token,
        os.environ.get("DEPLOY_BRANCH", "main"), os.environ.get("EXPORT_BRANCH", "registry-export"))


if __name__ == "__main__":
    main()
