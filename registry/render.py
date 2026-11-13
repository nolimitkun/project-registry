"""Renders the gateway-projects bundle directory from the registry's records with the
platform's own scripts/gen-projects.py, at the commit of the active policy bundle.

One validation library: the schema, the rules across files and the output format
stay in the deployment repository, reviewed with the Rego and the catalog. The
registry writes its records as the project, agent and exception files that script
reads, runs it, and takes policies/gateway-projects. The output therefore matches
what the same records would produce from Git, byte for byte.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml


class RenderError(Exception):
    def __init__(self, errors: list[str]):
        super().__init__("; ".join(errors))
        self.errors = errors


class Renderer:
    def __init__(self, repo: str, cache: Path):
        self.repo, self.cache = repo, cache
        cache.mkdir(parents=True, exist_ok=True)

    def checkout(self, revision: str) -> Path:
        path = self.cache / revision
        if not (path / ".git").exists():
            tmp = Path(tempfile.mkdtemp(dir=self.cache))
            subprocess.run(["git", "init", "-q", str(tmp)], check=True)
            subprocess.run(["git", "-C", str(tmp), "fetch", "-q", "--depth", "1", self.repo, revision], check=True)
            subprocess.run(["git", "-C", str(tmp), "checkout", "-q", "FETCH_HEAD"], check=True)
            tmp.rename(path)
        return path

    def render(self, records: dict[str, dict[str, dict]], revision: str, out: Path) -> Path:
        """records: {"project": {id: spec}, "agent": {...}, "exception": {project: entry}}.
        Writes the bundle directory to out; raises RenderError with the script's findings."""
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "repo"
            shutil.copytree(self.checkout(revision), work, ignore=shutil.ignore_patterns(".git"))
            for folder in ("projects", "agents"):
                for f in (work / folder).glob("*.yaml"):
                    f.unlink()
            for pid, spec in records["project"].items():
                (work / "projects" / f"{pid}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
            for aid, spec in records["agent"].items():
                (work / "agents" / f"{aid}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
            if records["exception"]:
                (work / "projects" / "_exceptions.yaml").write_text(
                    yaml.safe_dump({"exceptions": records["exception"]}, sort_keys=False))
            run = subprocess.run([sys.executable, "scripts/gen-projects.py"], cwd=work, capture_output=True, text=True)
            if run.returncode != 0:
                errors = [l.strip() for l in (run.stderr or run.stdout).splitlines() if l.strip()]
                raise RenderError(errors or ["gen-projects.py failed"])
            if out.exists():
                shutil.rmtree(out)
            shutil.copytree(work / "policies" / "gateway-projects", out)
        return out


def import_git(checkout: Path) -> dict[str, dict[str, dict]]:
    """Records from a deployment repo checkout (projects/, agents/), for the first import."""
    records: dict[str, dict[str, dict]] = {"project": {}, "agent": {}, "exception": {}}
    for f in sorted((checkout / "projects").glob("*.yaml")):
        if f.name == "_exceptions.yaml":
            records["exception"] = (yaml.safe_load(f.read_text()) or {}).get("exceptions") or {}
        else:
            records["project"][f.stem] = yaml.safe_load(f.read_text())
    for f in sorted((checkout / "agents").glob("*.yaml")):
        records["agent"][f.stem] = yaml.safe_load(f.read_text())
    return records
