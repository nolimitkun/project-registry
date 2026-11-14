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

import os
import shutil
import subprocess
import time
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


class KagentWiring:
    """The deployment repo's kagent values, for gen-projects.py's check that a kagent agent
    is wired to its own key (KAGENT_VALUES, KAGENT_RESOURCES). The wiring is deployed from
    there, so it lands first and an agent is accepted after. Fetched from its branch,
    at most every `ttl` seconds."""

    FILES = {"KAGENT_VALUES": "minikube/values/kagent-values.yaml",
             "KAGENT_RESOURCES": "minikube/values/kagent-resources.yaml"}

    def __init__(self, repo: str, ref: str, cache: Path, ttl: int = 300):
        # absolute: gen-projects.py runs in another directory (a copy of the policy repo)
        self.repo, self.ref, self.cache, self.ttl = repo, ref, cache.resolve(), ttl
        self.fetched = 0.0

    def env(self) -> dict[str, str]:
        work = self.cache / "kagent-wiring"
        if time.time() - self.fetched > self.ttl or not (work / ".git").exists():
            if not (work / ".git").exists():
                work.mkdir(parents=True, exist_ok=True)
                subprocess.run(["git", "init", "-q", str(work)], check=True)
                subprocess.run(["git", "-C", str(work), "config", "core.sparseCheckout", "true"], check=True)
                (work / ".git" / "info" / "sparse-checkout").write_text("\n".join(self.FILES.values()) + "\n")
            subprocess.run(["git", "-C", str(work), "fetch", "-q", "--depth", "1", self.repo, self.ref],
                           check=True, capture_output=True)
            subprocess.run(["git", "-C", str(work), "checkout", "-q", "-f", "FETCH_HEAD"], check=True,
                           capture_output=True)
            self.fetched = time.time()
        return {k: str(work / v) for k, v in self.FILES.items()}


def kagent_wiring_from_env(env) -> "KagentWiring | None":
    """KAGENT_WIRING_REPO (the deployment repo) and KAGENT_WIRING_REF (main); unset: no check."""
    if not env.get("KAGENT_WIRING_REPO"):
        return None
    return KagentWiring(env["KAGENT_WIRING_REPO"], env.get("KAGENT_WIRING_REF", "main"),
                        Path(env.get("WORKDIR", "/tmp/registry")))


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
    def _gen(work: Path, *args: str, env: dict[str, str] | None = None) -> str:
        run = subprocess.run([sys.executable, "scripts/gen-projects.py", *args], cwd=work,
                             capture_output=True, text=True, env={**os.environ, **(env or {})})
        if run.returncode != 0:
            errors = [l.strip() for l in (run.stderr or run.stdout).splitlines() if l.strip()]
            raise RenderError(errors or ["gen-projects.py failed"])
        return run.stdout

    def render(self, records: dict[str, dict[str, dict]], revision: str, out: Path,
               also: dict[str, Path] | None = None, env: dict[str, str] | None = None) -> Path:
        """records: {"project": {id: spec}, "agent": {...}, "exception": {project: entry}}.
        Writes the bundle directory to out; raises RenderError with the script's findings.
        also: {path in the repo: destination}, other generated files to keep.
        env: for gen-projects.py (KAGENT_VALUES, KAGENT_RESOURCES: KagentWiring)."""
        with self.prepared(records, revision) as work:
            self._gen(work, env=env)
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
