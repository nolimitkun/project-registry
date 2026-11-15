#!/usr/bin/env python3
"""Validate project registry records and render the gateway policy's project data.

The records live in the project registry, not in this repo. The registry (and
scripts/render-records.py, for CI) writes them as the files
this script reads, projects/<id>.yaml, projects/_exceptions.yaml and agents/<id>.yaml,
in a copy of this repo, and runs it there:

    python3 scripts/gen-projects.py           write the generated files
    python3 scripts/gen-projects.py --keys    print "<key_id> <project>" per key (the
                                              registry writes the gateway's key maps from it)

Each project file is checked against projects/schema.json, then against rules
that span files:
  - the file name is the project id
  - placement only narrows what the data class allows
  - every models.allow pattern matches a catalog model (catalog/models.yaml)
  - a fixed:<model> routing names a model the project may use
  - key ids are the project id or start with it plus "-", and are unique
  - exceptions (projects/_exceptions.yaml) name existing projects and models

Agents (agents/*.yaml, checked against agents/schema.json) belong to a project
and narrow it: their keys are added to the project, which maps each to its
agent (agent_keys), and OPA gives a call with such a key the agent's models and
tools. A kagent agent must also be wired to its own key: kagent-values.yaml
modelConfigRef names a ModelConfig in kagent-resources.yaml extraObjects, whose
apiKeySecret and apiKeySecretKey are a vaultSecrets copy of one of the agent's keys
(an entry {name, gatewayKey, field}). The deployment repo says where the key goes;
the record says only which keys the agent has.

Outputs, read by OPA from the gateway-projects bundle (policies/gateway-projects,
separate from the policy bundle so a project change never rebuilds the Rego):
  policies/gateway-projects/projects/<id>/data.json    data.projects.<id>
  policies/gateway-projects/exceptions/<id>/data.json  data.exceptions.<id>
  policies/gateway-projects/agents/<id>/data.json      data.agents.<id>
and, applied to agentregistry (agentregistry-catalog chart):
  generated/agentregistry-agents.yaml  one Agent per agent
One file per project, so changes to different projects never touch the same
file. Files of removed projects are deleted.
(the registry applies these to agentregistry itself).

A kagent agent must be wired to its own key in the deployment repo's kagent values
(modelConfigRef, a ModelConfig, the secret in vaultSecrets). That is checked only
when KAGENT_VALUES and KAGENT_RESOURCES name those files (the deployment repo's CI
does, with the seed): this repo doesn't have them.
"""

import argparse
import fnmatch
import json
import os
import sys
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parent.parent
PROJECTS = ROOT / "projects"
SCHEMA = PROJECTS / "schema.json"
EXCEPTIONS = PROJECTS / "_exceptions.yaml"
CATALOG = ROOT / "catalog" / "models.yaml"
SETTINGS_OUT = ROOT / "policies" / "gateway-projects" / "registry" / "settings" / "data.json"   # gen-settings.py
PROJECTS_BUNDLE = ROOT / "policies" / "gateway-projects"
PROJECTS_OUT = PROJECTS_BUNDLE / "projects"
EXCEPTIONS_OUT = PROJECTS_BUNDLE / "exceptions"
AGENTS = ROOT / "agents"
AGENT_SCHEMA = AGENTS / "schema.json"
AGENTS_OUT = PROJECTS_BUNDLE / "agents"
REGISTRY_OUT = ROOT / "generated" / "agentregistry-agents.yaml"
# The deployment repo's kagent values, for the wiring check (optional, see above)
KAGENT_VALUES = Path(os.environ["KAGENT_VALUES"]) if os.environ.get("KAGENT_VALUES") else None
KAGENT_RESOURCES = Path(os.environ["KAGENT_RESOURCES"]) if os.environ.get("KAGENT_RESOURCES") else None

def rel(path):
    return path.relative_to(ROOT)


def load():
    """Return (projects, exceptions, errors). projects: id -> effective entry."""
    errors = []
    schema = json.loads(SCHEMA.read_text())
    validator = jsonschema.Draft202012Validator(schema)
    catalog_models = (yaml.safe_load(CATALOG.read_text()) or {}).get("models") or {}
    models = set(catalog_models)
    classes = json.loads(SETTINGS_OUT.read_text())["data_classes"]

    projects, key_owner = {}, {}
    for path in sorted(PROJECTS.glob("*.yaml")):
        if path.name.startswith("_"):
            continue
        doc = yaml.safe_load(path.read_text())
        schema_errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        for e in schema_errors:
            where = ".".join(str(p) for p in e.path) or "(file)"
            errors.append(f"{rel(path)}: {where}: {e.message}")
        if schema_errors:
            continue

        pid = doc["project"]
        if path.stem != pid:
            errors.append(f"{rel(path)}: project is {pid!r}, but the file must then be named {pid}.yaml")

        class_placements = classes[doc["data_class"]]
        placement = doc.get("placement", class_placements)
        beyond = sorted(set(placement) - set(class_placements))
        if beyond:
            errors.append(
                f"{rel(path)}: placement {beyond} is beyond what {doc['data_class']} data allows "
                f"({class_placements}); ask for an exception instead"
            )

        allow = doc.get("models", {}).get("allow", ["*"])
        for pattern in allow:
            if not fnmatch.filter(models, pattern):
                errors.append(f"{rel(path)}: models.allow pattern {pattern!r} matches no catalog model")

        # Optional: a project whose keys all belong to its agents may omit it.
        own_keys = doc.get("keys", [])
        for key_id in own_keys:
            if key_id != pid and not key_id.startswith(pid + "-"):
                errors.append(f"{rel(path)}: key id {key_id!r} must be {pid!r} or start with {pid + '-'!r}")
            if key_id in key_owner:
                errors.append(f"{rel(path)}: key id {key_id!r} is already used by {key_owner[key_id]}")
            key_owner[key_id] = pid

        routing = doc.get("routing", "cheapest")

        deployments = doc.get("deployments", False)
        if deployments and "onprem" not in placement:
            errors.append(f"{rel(path)}: deployments: true needs onprem among its placements")

        projects[pid] = {
            "owner": doc["owner"],
            "data_class": doc["data_class"],
            # Order kept as the class lists it, so the output is stable.
            "placement": [p for p in class_placements if p in placement],
            "models_allow": allow,
            "keys": own_keys,
            "mcp_tools": doc.get("mcp_tools", []),
            "routing": routing,
            "limits": doc.get("limits", {}),
            "budget": doc.get("budget", {}),
            "deployments": deployments,
        }

    if not projects:
        errors.append("projects/: no project files")

    exceptions = ((yaml.safe_load(EXCEPTIONS.read_text()) or {}).get("exceptions") or {}) if EXCEPTIONS.exists() else {}

    # The same rule as allowed() in policies/gateway/lib.rego.
    for pid, p in projects.items():
        if not p["routing"].startswith("fixed:"):
            continue
        model = p["routing"].removeprefix("fixed:")
        by_rule = (
            model in catalog_models
            and catalog_models[model]["placement"] in p["placement"]
            and any(fnmatch.fnmatchcase(model, pat) for pat in p["models_allow"])
        )
        by_exception = model in ((exceptions.get(pid) or {}).get("models") or [])
        if not (by_rule or by_exception):
            errors.append(f"projects/{pid}.yaml: routing {p['routing']!r} names a model the project may not use")

    for pid, exc in exceptions.items():
        where = f"{rel(EXCEPTIONS)}: {pid}"
        if pid not in projects:
            errors.append(f"{where}: no project {pid!r}")
        if not isinstance(exc, dict):
            errors.append(f"{where}: must be a mapping")
            continue
        missing = {"owner", "why", "models"} - set(exc)
        unknown = set(exc) - {"owner", "why", "models"}
        if missing:
            errors.append(f"{where}: needs {sorted(missing)}")
        if unknown:
            errors.append(f"{where}: unknown fields {sorted(unknown)}")
        for m in exc.get("models") or []:
            if m not in models:
                errors.append(f"{where}: model {m!r} is not in the catalog")

    agents = load_agents(projects, exceptions, catalog_models, key_owner, errors)
    for pid, p in projects.items():
        if not p["keys"]:
            errors.append(f"projects/{pid}.yaml: no key, neither its own nor one of its agents'")
    return projects, exceptions, agents, errors


def project_models(p, pid, exceptions, catalog_models):
    """The models a project may use: the same rule as allowed() in lib.rego."""
    by_rule = {
        m for m, model in catalog_models.items()
        if model["placement"] in p["placement"] and any(fnmatch.fnmatchcase(m, pat) for pat in p["models_allow"])
    }
    return by_rule | set((exceptions.get(pid) or {}).get("models") or [])


def load_agents(projects, exceptions, catalog_models, key_owner, errors):
    """Validate agents/*.yaml; add each agent's keys to its project.

    Returns agent id -> entry for data.agents. Each project gains agent_keys
    (key id -> agent id), which is how OPA tells an agent's call from the
    project's own: a key listed there gets the agent's scope."""
    validator = jsonschema.Draft202012Validator(json.loads(AGENT_SCHEMA.read_text()))
    wiring = bool(KAGENT_VALUES and KAGENT_RESOURCES)
    kagent_values = (yaml.safe_load(KAGENT_VALUES.read_text()) or {}) if wiring else {}
    kagent_resources = (yaml.safe_load(KAGENT_RESOURCES.read_text()) or {}) if wiring else {}
    # Each entry: a Vault path's name, or a copy of one gateway key ({name, gatewayKey, field}:
    # VSO picks the key id out of agentgateway-client-keys).
    kagent_secrets = {(e if isinstance(e, str) else e["name"]): e for e in kagent_resources.get("vaultSecrets") or []}
    model_configs = {
        o["metadata"]["name"]: o.get("spec", {})
        for o in kagent_resources.get("extraObjects") or []
        if o.get("kind") == "ModelConfig"
    }
    for p in projects.values():
        p["agent_keys"] = {}
    agents = {}
    for path in sorted(AGENTS.glob("*.yaml")):
        doc = yaml.safe_load(path.read_text())
        schema_errors = sorted(validator.iter_errors(doc), key=lambda e: list(e.path))
        for e in schema_errors:
            where = ".".join(str(x) for x in e.path) or "(file)"
            errors.append(f"{rel(path)}: {where}: {e.message}")
        if schema_errors:
            continue
        aid, pid = doc["agent"], doc["project"]
        if path.stem != aid:
            errors.append(f"{rel(path)}: agent is {aid!r}, but the file must then be named {aid}.yaml")
        if pid not in projects:
            errors.append(f"{rel(path)}: no project {pid!r}")
            continue
        p = projects[pid]

        usable = project_models(p, pid, exceptions, catalog_models)
        allow = doc.get("models", {}).get("allow", ["*"])
        for pattern in allow:
            if not fnmatch.filter(usable, pattern):
                errors.append(f"{rel(path)}: models.allow pattern {pattern!r} matches no model project {pid} may use")
        tools = doc.get("mcp_tools", [])
        if tools and not p["mcp_tools"]:
            errors.append(f"{rel(path)}: mcp_tools set, but project {pid} may use no MCP tool")

        for key_id in doc["keys"]:
            if key_id != pid and not key_id.startswith(pid + "-"):
                errors.append(f"{rel(path)}: key id {key_id!r} must be {pid!r} or start with {pid + '-'!r}")
            if key_id in key_owner:
                errors.append(f"{rel(path)}: key id {key_id!r} is already used by {key_owner[key_id]}")
            key_owner[key_id] = f"agent {aid}"
            p["keys"] = p["keys"] + [key_id]
            p["agent_keys"][key_id] = aid

        runtime = doc["runtime"]
        if runtime["kind"] == "kagent" and wiring:
            # The kagent agent must read one of its own keys: its ModelConfig names a
            # Secret and field that a vaultSecrets entry copies from one of them.
            ref = ((kagent_values.get(runtime["name"]) or {}).get("modelConfigRef")) or ""
            if ref not in model_configs:
                errors.append(f"{rel(path)}: {KAGENT_VALUES.name} {runtime['name']}.modelConfigRef must name a ModelConfig in {KAGENT_RESOURCES.name} extraObjects")
            else:
                name, field = model_configs[ref].get("apiKeySecret"), model_configs[ref].get("apiKeySecretKey")
                entry = kagent_secrets.get(name)
                if not isinstance(entry, dict) or entry.get("gatewayKey") not in doc["keys"]:
                    errors.append(f"{rel(path)}: ModelConfig {ref} reads secret {name!r}, which {KAGENT_RESOURCES.name} "
                                  f"vaultSecrets must list as a copy of one of the agent's keys {doc['keys']} "
                                  f"(name, gatewayKey, field)")
                elif entry.get("field") != field:
                    errors.append(f"{rel(path)}: ModelConfig {ref} reads field {field!r} of {name}, "
                                  f"the copy writes {entry.get('field')!r}")

        agents[aid] = {
            "project": pid,
            "owner": doc["owner"],
            "description": doc["description"],
            "runtime": runtime,
            "autonomy": doc["autonomy"],
            "models_allow": allow,
            "mcp_tools": tools,
            "keys": doc["keys"],
        }
    return agents


def registry_catalog(agents):
    """agentregistry entries for the agents (files/agents.yaml of the catalog chart)."""
    docs = []
    for aid, a in sorted(agents.items()):
        spec = {
            "title": aid,
            "description": (
                f"{a['description']} Owner: {a['owner']}. Project: {a['project']}. "
                f"Autonomy: {a['autonomy']}. Runs on {a['runtime']['kind']} as {a['runtime']['name']}. "
                f"Models: {', '.join(a['models_allow'])}. "
                f"MCP tools: {', '.join(a['mcp_tools']) or 'none through the gateway'}."
            ),
            "modelProvider": "openai",
        }
        if len(a["models_allow"]) == 1 and "*" not in a["models_allow"][0]:
            spec["modelName"] = a["models_allow"][0]
        if a["mcp_tools"]:
            spec["mcpServers"] = [{"kind": "MCPServer", "name": "platform-tools"}]
        docs.append({
            "apiVersion": "ar.dev/v1alpha1",
            "kind": "Agent",
            "metadata": {
                "name": aid,
                "labels": {"project": a["project"], "autonomy": a["autonomy"], "runtime": a["runtime"]["kind"]},
            },
            "spec": spec,
        })
    header = (
        "# Generated by scripts/gen-projects.py from agents/*.yaml; do not edit.\n"
        "# Applied to agentregistry together with catalog.yaml.\n"
    )
    return header + "".join("---\n" + yaml.safe_dump(d, sort_keys=False, width=200) for d in docs)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--keys", action="store_true", help="print one '<key_id> <project>' line per key")
    args = parser.parse_args()

    projects, exceptions, agents, errors = load()
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        return 1

    if args.keys:
        for pid, p in sorted(projects.items()):
            for key_id in p["keys"]:
                print(key_id, pid)
        return 0

    outputs = {REGISTRY_OUT: registry_catalog(agents)}
    for out, entries in ((PROJECTS_OUT, projects), (EXCEPTIONS_OUT, exceptions), (AGENTS_OUT, agents)):
        for pid, entry in entries.items():
            outputs[out / pid / "data.json"] = json.dumps(entry, indent=2, sort_keys=True) + "\n"
    # Per-project files no project produces any more (a removed project).
    leftover = sorted(
        path
        for out in (PROJECTS_OUT, EXCEPTIONS_OUT, AGENTS_OUT)
        for path in out.glob("**/*")
        if path.is_file() and path not in outputs
    )
    for path, content in outputs.items():
        if not path.exists() or path.read_text() != content:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            print(f"wrote {rel(path)}")
    for path in leftover:
        path.unlink()
        if not any(path.parent.iterdir()):
            path.parent.rmdir()
        print(f"removed {rel(path)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
