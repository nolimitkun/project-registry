"""Read-only views the portal shows next to the records: what a project can use now, as
the gateway's OPA decides it, and how the platform behind the registry is doing.

What a project can use is asked of the OPA that serves the gateway, with the policy's
own rules (data.gateway.lib), so the answer is what the gateway enforces with the
bundles it has loaded, not a second reading of the records: a change not yet published
shows up once OPA has loaded it.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import re

import requests

log = logging.getLogger("insight")

# One ad-hoc query (OPA's /v1/query), every binding from the same rules authz.rego and
# select.rego use. A project OPA doesn't have yet leaves `published` null and the rest
# empty. Tools are the catalog's (a tool it doesn't list counts as irreversible and is
# out of agents' reach, authz.rego tool_risk), matched as authz.rego matches them.
EFFECTIVE = """
p := input.project
published := object.get(data.projects, p, null)
placements := data.gateway.lib.placements(p)
by_rule := data.gateway.lib.by_rule(p)
by_exception := data.gateway.lib.by_exception(p)
models := {m: x.placement | some m, x in data.gateway.lib.catalog.models}
google_apis := {g: x.placement | some g, x in data.gateway.lib.catalog.google_apis}
tools := {t: r | some t, r in data.gateway.lib.catalog.tools; some pat in object.get(data.projects, [p, "mcp_tools"], []); glob.match(pat, [], t)}
agents := {aid: {"autonomy": a.autonomy, "models": data.gateway.lib.agent_allowed(p, aid), "tools": {t: r | some t, r in tools; some pat in object.get(a, "mcp_tools", []); glob.match(pat, [], t)}} | some aid, a in data.agents; a.project == p}
autonomy := data.gateway.lib.settings.autonomy
"""

RISKS = ("read", "write", "irreversible")


def ask_opa(opa_url: str, project: str) -> dict:
    r = requests.post(f"{opa_url}/v1/query", timeout=5, json={"query": EFFECTIVE, "input": {"project": project}})
    r.raise_for_status()
    rows = r.json().get("result") or []
    if not rows:
        raise RuntimeError("OPA answered nothing: is the policy bundle loaded?")
    return rows[0]


def effective(answer: dict) -> dict:
    """The portal's shape of EFFECTIVE's answer: each catalog model with how the project
    gets it or why not, the Google APIs in its placements, its tools by risk, and each of
    its agents' share of them."""
    placements = sorted(answer.get("placements") or [])
    by_rule, by_exception = set(answer.get("by_rule") or []), set(answer.get("by_exception") or [])
    models = []
    for name, placement in sorted((answer.get("models") or {}).items()):
        if name in by_rule:
            via, why_not = "rule", None
        elif name in by_exception:
            via, why_not = "exception", None
        elif placement not in placements:
            via, why_not = None, f"its placement, {placement}, is not one of the project's"
        else:
            via, why_not = None, "no pattern in the project's models matches it"
        models.append({"name": name, "placement": placement, "via": via, "why_not": why_not})
    # an exception may name a model the catalog no longer has
    models += [{"name": m, "placement": None, "via": "exception", "why_not": None}
               for m in sorted(by_exception - set(answer.get("models") or {}))]
    tools = answer.get("tools") or {}
    autonomy = answer.get("autonomy") or {}
    agents = []
    for aid, a in sorted((answer.get("agents") or {}).items()):
        free = set(autonomy.get(a.get("autonomy"), []))
        agent_tools = a.get("tools") or {}
        agents.append({"id": aid, "autonomy": a.get("autonomy"), "models": sorted(a.get("models") or []),
                       "tools": sorted(t for t, r in agent_tools.items() if r in free),
                       "tools_needing_approval": sorted(t for t, r in agent_tools.items() if r not in free)})
    return {"published": answer.get("published") is not None, "placements": placements, "models": models,
            "google_apis": sorted(g for g, pl in (answer.get("google_apis") or {}).items() if pl in placements),
            "tools": {risk: sorted(t for t, r in tools.items() if r == risk) for risk in RISKS},
            "agents": agents}


# The alerts about what the registry runs or watches (mini-platform-deployment
# app-resources/alerts/agentgateway-projects.yml).
ALERT_PREFIXES = ("Gateway", "ProjectRegistry")


def alerts(prometheus_url: str | None) -> dict:
    """Pending and firing alerts about the gateway and the registry, from Prometheus."""
    if not prometheus_url:
        return {"error": "not configured (PROMETHEUS_URL)", "alerts": []}
    try:
        r = requests.get(f"{prometheus_url.rstrip('/')}/api/v1/alerts", timeout=3)
        r.raise_for_status()
        found = r.json()["data"]["alerts"]
    except (requests.RequestException, KeyError, ValueError) as e:
        log.warning("prometheus alerts: %s", e)
        return {"error": f"Prometheus did not answer: {type(e).__name__}", "alerts": []}
    keep = [a for a in found if a.get("labels", {}).get("alertname", "").startswith(ALERT_PREFIXES)]
    return {"error": None, "alerts": [{"name": a["labels"]["alertname"], "state": a.get("state"),
                                       "since": a.get("activeAt"),
                                       "labels": {k: v for k, v in a["labels"].items()
                                                  if k not in ("alertname", "severity")},
                                       "severity": a["labels"].get("severity"),
                                       "summary": (a.get("annotations") or {}).get("summary")} for a in keep]}


def status(c, store, bundle_names: tuple[str, ...], pods: set[str] | None, usage_reader,
           prometheus_url: str | None = None, now: dt.datetime | None = None) -> dict:
    """What OPA has loaded against what is published, each publisher output's last round,
    how far the usage ledger reaches, and the alerts."""
    now = now or dt.datetime.now(dt.timezone.utc)
    published = {b: store.active(b) for b in bundle_names}
    rows = c.execute("select instance_id, pod, bundles, at from opa_status order by pod, at desc").fetchall()
    if pods is not None:
        rows = [r for r in rows if r["pod"] in pods]
    else:            # no Kubernetes API: the OPAs that reported lately (activation.py's fallback)
        rows = [r for r in rows if now - r["at"] < dt.timedelta(minutes=5)]
    opa = [{"pod": r["pod"] or r["instance_id"], "reported_at": r["at"],
            "bundles": {b: r["bundles"].get(b) for b in bundle_names},
            "current": all(r["bundles"].get(b) == published[b] for b in bundle_names)} for r in rows]
    if pods is not None:
        opa += [{"pod": p, "reported_at": None, "bundles": {}, "current": False}
                for p in sorted(pods - {r["pod"] for r in rows})]
    outputs = [{"output": r["output"], "last_success": r["last_success"], "last_failure": r["last_failure"],
                "last_error": r["last_error"],
                "failing": r["last_failure"] is not None and (r["last_success"] is None or r["last_failure"] > r["last_success"])}
               for r in c.execute("select * from publisher_health order by output").fetchall()]
    ledger = None
    if usage_reader is not None:
        try:
            ledger = {"through": usage_reader.state().get("through")}
        except Exception as e:        # the page still shows the rest
            ledger = {"error": f"{type(e).__name__}: {e}"}
    return {"published": published, "opa": opa, "outputs": outputs, "usage": ledger,
            "alerts": alerts(prometheus_url if prometheus_url is not None else os.environ.get("PROMETHEUS_URL"))}


# Why the gateway would refuse a call: authz.rego evaluated on the input agentgateway
# would send for it (the project and key it attaches after checking the key, the path and
# the parsed body), with the policy and data OPA has loaded now.
EXPLAIN = """
allow := data.gateway.authz.allow
reason := data.gateway.authz.reason
"""
KEYS = """
keys := object.get(data.projects, [input.project, "keys"], [])
agent_keys := object.get(data.projects, [input.project, "agent_keys"], {})
"""
KINDS = ("model", "tool", "google", "models")

# What would change each kind of refusal, by authz.rego's reason.
HINTS = [
    (r"^unknown project$", "The project is not published: OPA has no record of it."),
    (r"^key .* is not active", "Add the key id to the project's keys (or the agent's, for an agent's key)."),
    (r"may not call model deployments directly$", "Only a project with deployments set (the onboarding pipeline) may, and never with an agent's key."),
    (r"^model .* is not allowed for agent ", "Widen the agent's models patterns; it can never go past its project's."),
    (r"^model .* is not allowed for project ", "The model's placement must be one the project's data class and placements allow, and match its models patterns; otherwise an exception, which security approves."),
    (r"^tool .* needs a human approval", "The agent's autonomy does not let it call a tool of this risk without a human, and the gateway has no approval path yet: raise its autonomy, or leave the call to a person."),
    (r"^tool .* is not allowed for agent ", "Add a pattern for it to the agent's MCP tools; it must match the project's too."),
    (r"^tool .* is not allowed for project ", "Add a pattern for it to the project's MCP tools."),
    (r"^agent .* may use no MCP tools", "Give the agent MCP tools patterns."),
    (r"^project .* may use no MCP tools", "Give the project MCP tools patterns."),
]


def explain_input(project: str, key_id: str, kind: str, name: str | None) -> dict:
    meta = {"metadataContext": {"filterMetadata": {"agentgateway": {"project": project, "key_id": key_id}}}}
    if kind == "model":
        path, body = "/v1/chat/completions", {"model": name}
    elif kind == "tool":
        path, body = "/mcp", {"method": "tools/call", "params": {"name": name}}
    elif kind == "google":
        path, body = f"/google/{name}/v1/x", {}
    else:
        path, body = "/v1/models", {}
    return {"attributes": {**meta, "request": {"http": {"path": path}}}, "parsed_body": body}


def query(opa_url: str, q: str, input_: dict) -> dict:
    r = requests.post(f"{opa_url}/v1/query", timeout=5, json={"query": q, "input": input_})
    r.raise_for_status()
    rows = r.json().get("result") or []
    if not rows:
        raise RuntimeError("OPA answered nothing: is the policy bundle loaded?")
    return rows[0]


def hint(reason: str | None) -> str | None:
    return next((text for pattern, text in HINTS if reason and re.search(pattern, reason)), None)


def explain(opa_url: str, project: str, kind: str, name: str | None, key_id: str | None = None) -> dict:
    """Whether the gateway would let this project (with this key, by default its own) make
    this call now, and authz.rego's reason when it would not."""
    k = query(opa_url, KEYS, {"project": project})
    keys, agent_keys = list(k.get("keys") or []), dict(k.get("agent_keys") or {})
    if key_id is None:      # the project's own key first: an agent's key is narrower
        key_id = next((x for x in keys if x not in agent_keys), keys[0] if keys else project)
    a = query(opa_url, EXPLAIN, explain_input(project, key_id, kind, name))
    reason = None if a.get("allow") else a.get("reason")
    return {"project": project, "key_id": key_id, "agent": agent_keys.get(key_id), "kind": kind, "name": name,
            "allowed": bool(a.get("allow")), "reason": reason, "hint": hint(reason),
            "keys": [{"id": x, "agent": agent_keys.get(x)} for x in keys]}
