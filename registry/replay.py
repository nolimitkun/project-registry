"""Replays recent gateway decisions against a candidate bundle set.

The publisher's safety valve: a change may change decisions for the projects it
touches, and for no other. The inputs come from OPA's decision log in Loki (the
format scripts/policy-replay.py in the policy repo reads). Each is evaluated
twice under the active policy bundle, with the active data bundle and with the
candidate, so only the data change shows: a policy or catalog change since the
request was logged (which would flip verdicts for every project) is not blamed
on it. Only the `allowed` verdict is compared, since the model behind `auto` can
change from hour to hour.

A policy change (replay_all) may change any decision, so nothing is held back: the
report, under the active bundles and under the new policy with the records
rendered at its commit, is for its approvers.
"""
from __future__ import annotations

import json
import subprocess
import tempfile
import urllib.parse
from pathlib import Path

import requests

RULE = "gateway/authz/decision"
QUERY = '{namespace="%s", container="opa"} |= "decision_id"'


def fetch(loki: str, namespace: str, since: str = "24h", limit: int = 2000) -> list[dict]:
    params = {"query": QUERY % namespace, "since": since, "limit": limit, "direction": "backward"}
    r = requests.get(f"{loki.rstrip('/')}/loki/api/v1/query_range?{urllib.parse.urlencode(params)}", timeout=60)
    r.raise_for_status()
    events = []
    for stream in r.json()["data"]["result"]:
        for _, line in stream["values"]:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("path") == RULE and "input" in e and "result" in e and replayable(e):
                events.append(e)
    return events


BODILESS = {"GET", "HEAD", "DELETE", "OPTIONS"}


def replayable(event: dict) -> bool:
    """Whether the logged input still holds what the policy decided on. The log mask keeps a
    body's model and MCP method and tool, and drops a body that isn't an object: an empty
    one (a GET), a JSON-RPC batch. A request without a body replays as it was; one whose
    body was dropped (or logged before the mask kept the model) doesn't."""
    if "/input/parsed_body" not in (event.get("erased") or []):
        return True
    return bodiless(event["input"].get("attributes", {}).get("request", {}).get("http", {}))


def bodiless(http: dict) -> bool:
    """A request that carried no body: a method without one, and no Content-Length above 0
    or Transfer-Encoding (a GET may carry a body, such as a JSON-RPC call to /mcp)."""
    headers = {k.lower(): v for k, v in (http.get("headers") or {}).items()}
    length = str(headers.get("content-length", "0")).strip() or "0"
    return (http.get("method", "").upper() in BODILESS and "transfer-encoding" not in headers
            and length.isdigit() and int(length) == 0)


def project_of(event: dict) -> str | None:
    meta = (event["input"].get("attributes", {}).get("metadataContext", {})
            .get("filterMetadata", {}).get("agentgateway", {}))
    return meta.get("project")


def evaluate(inputs: list[dict], bundles: list[Path], opa: str = "opa") -> list[dict]:
    """One decision per input, in order. An undefined decision (a candidate policy without a
    default, say) counts as a denial, so the results stay aligned with the inputs."""
    query = (f"[ds | some x in data.replay; "
             f"ds := [d | d := data.{RULE.replace('/', '.')} with input as x]]")
    with tempfile.TemporaryDirectory() as tmp:
        replay = Path(tmp) / "replay.json"
        replay.write_text(json.dumps({"replay": inputs}))
        args = [opa, "eval", "--format", "json", "-d", str(replay)]
        for b in bundles:
            args += ["-b", str(b)]
        out = subprocess.run(args + [query], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa eval failed: {out.stdout[-2000:]}{out.stderr[-2000:]}")
    results = json.loads(out.stdout)["result"][0]["expressions"][0]["value"]
    if len(results) != len(inputs):
        raise RuntimeError(f"opa eval returned {len(results)} results for {len(inputs)} inputs")
    return [ds[0] if ds else {"allowed": False, "undefined": True} for ds in results]


def flips(events: list[dict], before: list[dict], after: list[dict]) -> list[dict]:
    out = []
    for e, old, new in zip(events, before, after):
        was, now = bool(old.get("allowed")), bool(new.get("allowed"))
        if was != now:
            out.append({"project": project_of(e), "before": was, "after": now, "time": e.get("time"),
                        "path": e["input"].get("attributes", {}).get("request", {}).get("http", {}).get("path"),
                        "model": (e["input"].get("parsed_body") or {}).get("model")})
    return out


def compare(events: list[dict], before: list[dict], after: list[dict], allowed_projects: set[str]) -> dict:
    flipped = flips(events, before, after)
    expected = [f for f in flipped if f["project"] in allowed_projects]
    unexpected = [f for f in flipped if f["project"] not in allowed_projects]
    return {"replayed": len(events), "changed_for_changed_projects": len(expected),
            "changed_for_other_projects": len(unexpected), "examples": (unexpected + expected)[:20],
            "ok": not unexpected}


def replay_all(events: list[dict], active: list[Path], candidate: list[Path], opa: str = "opa") -> dict:
    """A policy change: any request may change, so nothing is held back; the report is for
    the approvers. active / candidate: the bundles OPA would load, before and after."""
    out = {"kind": "policy", "replayed": len(events), "changed": 0, "allowed_to_denied": 0,
           "denied_to_allowed": 0, "examples": [], "ok": True}
    if not events:
        return out
    inputs = [e["input"] for e in events]
    flipped = flips(events, evaluate(inputs, active, opa), evaluate(inputs, candidate, opa))
    out.update(changed=len(flipped), allowed_to_denied=sum(1 for f in flipped if f["before"]),
               denied_to_allowed=sum(1 for f in flipped if not f["before"]), examples=flipped[:20])
    return out


def replay_mixed(events: list[dict], active: list[Path], candidate: list[Path], mixes: list[list[Path]],
                 opa: str = "opa") -> int:
    """How many requests some mix of the bundles decides differently from both the active and
    the candidate set (the allowed verdict). Raises RuntimeError if a mix doesn't evaluate,
    which includes loading: it runs even without events."""
    inputs = [e["input"] for e in events]
    before, after = evaluate(inputs, active, opa), evaluate(inputs, candidate, opa)
    odd = set()
    for mix in mixes:
        for i, d in enumerate(evaluate(inputs, mix, opa)):
            if bool(d.get("allowed")) not in (bool(before[i].get("allowed")), bool(after[i].get("allowed"))):
                odd.add(i)
    return len(odd)


def replay(events: list[dict], policy: Path, active_data: Path, candidate_data: Path,
           allowed_projects: set[str], opa: str = "opa") -> dict:
    if not events:
        return {"replayed": 0, "changed_for_changed_projects": 0, "changed_for_other_projects": 0,
                "examples": [], "ok": True}
    inputs = [e["input"] for e in events]
    return compare(events, evaluate(inputs, [policy, active_data], opa),
                   evaluate(inputs, [policy, candidate_data], opa), allowed_projects)
