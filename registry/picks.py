"""What model "auto" picks for each project, before and after a change: evidence for its
approvers, since replaying past decisions compares only the allowed verdict and can't
show it.

For every project, and for no task and each of the catalog's tasks, select.rego's answer
is evaluated under the bundles OPA has and under the candidate ones. Rankings (fastest)
are left out on both sides: they come from Prometheus at decision time and move from
hour to hour, so `fastest` is compared as its fallback, by price.

A change may move a pick, which is what a catalog or project change is for. It may not
move one onto a model nobody serves: a KServe model whose LLMInferenceService has no
replicas or is gone (`unserved`). Its calls would fail. Such a model gets replicas, or
`auto: false` in its record (select.rego leaves it out of price and speed orders).
"""
from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import requests

from .activation import SA

log = logging.getLogger("picks")

QUERY = """{p: {t: m |
	some t in array.concat([""], sort([t | some t, _ in object.get(data.registry.catalog, "tasks", {})]))
	m := data.gateway.select.result.model with input as {"project": p, "task": t}
		with data.gateway.rankings.latency_ms as {}
} | some p, _ in data.projects}"""


def picks(bundles: list[Path], opa: str = "opa") -> dict[str, dict[str, str]]:
    """project -> task ("" for none) -> the model auto picks. A project with no allowed model
    has no entry for that task."""
    args = [opa, "eval", "--format", "json"]
    for b in bundles:
        args += ["-b", str(b)]
    out = subprocess.run(args + [QUERY], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa eval failed: {out.stdout[-1000:]}{out.stderr[-1000:]}")
    result = json.loads(out.stdout).get("result") or []
    return result[0]["expressions"][0]["value"] if result else {}


def moves(before: dict, after: dict) -> list[dict]:
    """Every (project, task) whose pick differs; None where there is none. A task's move
    that is the same as the project's move without a task (a project whose routing
    doesn't read the task) is left out: the row without a task says it."""
    out = []
    for p in sorted(set(before) | set(after)):
        b, a = before.get(p) or {}, after.get(p) or {}
        for t in sorted(set(b) | set(a)):
            if b.get(t) != a.get(t) and (t == "" or (b.get(t), a.get(t)) != (b.get(""), a.get(""))):
                out.append({"project": p, "task": t or None, "before": b.get(t), "after": a.get(t)})
    return out


def serving(deployment: str) -> str | None:
    """Why a KServe deployment (<namespace>/<name>) serves nothing: "no replicas" or "not
    found"; None if it has replicas. Raises OSError / RequestException if the API can't say."""
    ns, _, name = deployment.partition("/")
    token = (SA / "token").read_text()
    r = requests.get(f"https://kubernetes.default.svc/apis/serving.kserve.io/v1alpha2/namespaces/{ns}"
                     f"/llminferenceservices/{name}", headers={"Authorization": f"Bearer {token}"},
                     verify=str(SA / "ca.crt"), timeout=5)
    if r.status_code == 404:
        return "not found"
    r.raise_for_status()
    replicas = (r.json().get("spec") or {}).get("replicas", 1)
    return "no replicas" if replicas == 0 else None


def impact(before: list[Path], after: list[Path], models: dict, opa: str = "opa", serving=serving,
           models_before: dict | None = None) -> dict:
    """The evidence: the moves, and the models auto picks after the change that nobody serves
    (`unserved`: model -> why). Checked: every model a pick moves onto, and every model
    picked whose deployment the change repoints (models_before: the model records before;
    a release promoted onto the same name moves no pick, but its calls go to the new
    deployment). `stranded`: the picks on an unserved model. `unknown` names the models the
    cluster couldn't be asked about."""
    now = picks(after, opa)
    moved = moves(picks(before, opa), now)
    picked = {m for tasks in now.values() for m in tasks.values() if m}
    repointed = {m for m in picked if models_before is not None
                 and (models_before.get(m) or {}).get("deployment") != (models.get(m) or {}).get("deployment")}
    unserved, unknown = {}, []
    for m in sorted({x["after"] for x in moved if x["after"]} | repointed):
        deployment = (models.get(m) or {}).get("deployment")
        if not deployment:
            continue                    # a provider's model: served as long as the provider is
        try:
            why = serving(deployment)
        except (OSError, requests.RequestException) as e:
            log.warning("can't tell whether %s serves: %s", deployment, e)
            unknown.append(m)
            continue
        if why:
            unserved[m] = f"{deployment}: {why}"
    # a task's pick that is the project's own pick without a task is said by that row
    stranded = [{"project": p, "task": t or None, "model": m}
                for p, tasks in sorted(now.items()) for t, m in sorted(tasks.items())
                if m in unserved and (t == "" or m != tasks.get(""))]
    return {"moves": moved, "unserved": unserved, "stranded": stranded, "unknown": unknown}


def refusal(report: dict) -> str | None:
    """Why the change may not go ahead, or None: after it, auto would pick a model nobody
    serves (moved onto it, or a model picked already whose deployment it repoints)."""
    bad = report.get("stranded")
    if bad is None:                     # a report from before stranded: the moves alone
        bad = [{"project": x["project"], "task": x["task"], "model": x["after"]}
               for x in report["moves"] if x["after"] in report["unserved"]]
    if not bad:
        return None
    m = bad[0]["model"]
    bad = [x for x in bad if x["model"] == m]
    who = ", ".join(sorted({x["project"] + (f" ({x['task']})" if x["task"] else "") for x in bad}))
    return (f"auto would pick {m} for {who}, but {report['unserved'][m]}: give it replicas, or set "
            f"auto: false in its record")

