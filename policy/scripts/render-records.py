#!/usr/bin/env python3
"""Render a set of project registry records with scripts/gen-projects.py.

    python3 scripts/render-records.py RECORDS --out DIR   the gateway-projects bundle directory
          [--catalog-values FILE]                          and the gateway-models chart's catalog values
    python3 scripts/render-records.py RECORDS --keys      "<key_id> <project>" per API key

RECORDS is a file in the format of the registry's GET /export (YAML or JSON):
{"project": {id: spec}, "agent": {id: spec}, "exception": {project: entry}, "model",
"google_api", "tool": {id: spec}, "catalog": {"settings": {...}}, "setting": {id: spec}}, e.g.
the deployment repo's seed, or fixtures/records.yaml here. The project registry
holds the records; this repo keeps only their schema and the renderer. The
registry does the same thing (registry/render.py): it writes the records as the
files gen-projects.py reads, in a copy of this repo, and runs it there.

Used by CI (scripts/validate.sh: the Rego is tested with the fixture rendered), and
by the deployment repo: its CI (with KAGENT_VALUES and KAGENT_RESOURCES set, for
the kagent wiring check).
"""
import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
COPY = ("scripts", "projects", "agents", "catalog", "policies", "settings")


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("records", type=Path)
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("--out", type=Path, help="write the bundle directory here (replaced)")
    mode.add_argument("--keys", action="store_true")
    p.add_argument("--catalog-values", type=Path, help="with --out: also write the gateway-models chart's values")
    a = p.parse_args()
    records = yaml.safe_load(a.records.read_text()) or {}
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for d in COPY:
            if (ROOT / d).exists():
                shutil.copytree(ROOT / d, work / d, ignore=shutil.ignore_patterns("__pycache__", "*.yaml")
                                if d in ("projects", "agents") else shutil.ignore_patterns("__pycache__"))
        for name, spec in (records.get("project") or {}).items():
            (work / "projects" / f"{name}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
        for name, spec in (records.get("agent") or {}).items():
            (work / "agents" / f"{name}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
        if records.get("exception"):
            (work / "projects" / "_exceptions.yaml").write_text(
                yaml.safe_dump({"exceptions": records["exception"]}, sort_keys=False))
        write_catalog(work, records)
        for name, spec in (records.get("setting") or {}).items():
            (work / "settings" / f"{name}.yaml").write_text(yaml.safe_dump(spec, sort_keys=False))
        st = subprocess.run([sys.executable, str(work / "scripts" / "gen-settings.py")], cwd=work,
                            capture_output=True, text=True)
        if st.returncode != 0:
            sys.stderr.write(st.stderr or st.stdout)
            return 1
        cat = subprocess.run([sys.executable, str(work / "scripts" / "gen-catalog.py")], cwd=work,
                             capture_output=True, text=True)
        if cat.returncode != 0:
            sys.stderr.write(cat.stderr or cat.stdout)
            return 1
        flag = ["--keys"] if a.keys else []
        run = subprocess.run([sys.executable, str(work / "scripts" / "gen-projects.py"), *flag], cwd=work,
                             capture_output=True, text=True)
        if run.returncode != 0:
            sys.stderr.write(run.stderr or run.stdout)
            return 1
        if flag:
            sys.stdout.write(run.stdout)
            return 0
        if a.out.exists():
            shutil.rmtree(a.out)
        shutil.copytree(work / "policies" / "gateway-projects", a.out)
        if a.catalog_values:
            shutil.copyfile(work / "generated" / "agentgateway-catalog.yaml", a.catalog_values)
    return 0


def write_catalog(work: Path, records: dict) -> None:
    """The catalog records as the files gen-catalog.py reads (the project registry does the
    same, registry/render.py write_catalog)."""
    settings = (records.get("catalog") or {}).get("settings") or {}
    (work / "catalog").mkdir(exist_ok=True)
    (work / "catalog" / "models.yaml").write_text(yaml.safe_dump({
        "servingNamespaces": settings.get("servingNamespaces") or [],
        "models": records.get("model") or {},
        "tasks": settings.get("tasks") or {},
        "googleApis": records.get("google_api") or {}}, sort_keys=False))
    (work / "catalog" / "tools.yaml").write_text(yaml.safe_dump({
        "targets": settings.get("targets") or [],
        "tools": records.get("tool") or {}}, sort_keys=False))


if __name__ == "__main__":
    sys.exit(main())
