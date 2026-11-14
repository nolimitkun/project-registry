"""Renders the gateway-projects bundle directory from the registry's records with the
policy repository's scripts/gen-projects.py, at the commit of the active policy bundle.

One validation library: the schema, the rules across files and the output format
stay in the policy repository (nolimitkun/gateway-policy), reviewed with the Rego
and the catalog. The
registry writes its records as the project, agent and exception files that script
reads, runs it, and takes policies/gateway-projects. The records themselves live
only in the registry; Git keeps the schema and the script, not a copy of them.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path

import yaml


def renderer_from_env(env) -> "Renderer":
    """The policy repository (POLICY_REPO; DEPLOY_REPO is its older name), the repositories
    older policy commits may be in (POLICY_REPO_FALLBACKS, space-separated: where the policy
    lived before), and a cache."""
    repo = env.get("POLICY_REPO") or env["DEPLOY_REPO"]
    return Renderer(repo, Path(env.get("WORKDIR", "/tmp/registry")) / "checkouts",
                    fallbacks=(env.get("POLICY_REPO_FALLBACKS") or "").split())


class RenderError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class Renderer:
    def __init__(self, repo: str, cache: Path, fallbacks: list[str] | None = None):
        self.repo, self.cache, self.fallbacks = repo, cache, list(fallbacks or [])
        cache.mkdir(parents=True, exist_ok=True)

    def checkout(self, revision: str) -> Path:
        path = self.cache / revision
        if not (path / ".git").exists():
            tmp = Path(tempfile.mkdtemp(dir=self.cache))
            subprocess.run(["git", "init", "-q", str(tmp)], check=True)
            # the policy's repository, or one it lived in before (an active or older commit)
            for i, repo in enumerate([self.repo, *self.fallbacks]):
                fetch = subprocess.run(["git", "-C", str(tmp), "fetch", "-q", "--depth", "1", repo, revision],
                                       capture_output=True, text=True)
                if fetch.returncode == 0:
                    break
                if i == len(self.fallbacks):
                    shutil.rmtree(tmp, ignore_errors=True)
                    raise subprocess.CalledProcessError(fetch.returncode, fetch.args, fetch.stdout, fetch.stderr)
            subprocess.run(["git", "-C", str(tmp), "checkout", "-q", "FETCH_HEAD"], check=True)
            tmp.rename(path)
        return path

    @contextmanager
    def prepared(self, records: dict[str, dict[str, dict]], revision: str):
        """A copy of the repo at revision with the records written as the files gen-projects.py
        reads (projects/<id>.yaml, agents/<id>.yaml, projects/_exceptions.yaml)."""
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(self.checkout(revision), work, ignore=shutil.ignore_patterns(".git"))
            for folder in ("projects", "agents"):
                (work / folder).mkdir(exist_ok=True)
                for f in (work / folder).glob("*.yaml"):
                    f.unlink()
            for pid, spec in records["project"].items():
                (work / "projects" / f"{pid}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
            for aid, spec in records["agent"].items():
                (work / "agents" / f"{aid}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
            if records["exception"]:
                (work / "projects" / "_exceptions.yaml").write_text(
                    yaml.safe_dump({"exceptions": records["exception"]}, sort_keys=False))
            yield work

    @staticmethod
    def _gen(work: Path, *args: str) -> str:
        run = subprocess.run([sys.executable, "scripts/gen-projects.py", *args], cwd=work,
                             capture_output=True, text=True)
        if run.returncode != 0:
            errors = [l.strip() for l in (run.stderr or run.stdout).splitlines() if l.strip()]
            raise RenderError(errors or ["gen-projects.py failed"])
        return run.stdout

    def render(self, records: dict[str, dict[str, dict]], revision: str, out: Path,
               also: dict[str, Path] | None = None) -> Path:
        """records: {"project": {id: spec}, "agent": {...}, "exception": {project: entry}}.
        Writes the bundle directory to out; raises RenderError with the script's findings.
        also: {path in the repo: destination}, other generated files to keep."""
        with self.prepared(records, revision) as work:
            self._gen(work)
            if out.exists():
                shutil.rmtree(out)
            shutil.copytree(work / "policies" / "gateway-projects", out)
            for src, dst in (also or {}).items():
                if (work / src).exists():
                    shutil.copyfile(work / src, dst)
        return out

    def lines(self, records: dict[str, dict[str, dict]], revision: str, flag: str) -> str:
        """gen-projects.py --keys or --mirrors over the records."""
        with self.prepared(records, revision) as work:
            return self._gen(work, flag)
