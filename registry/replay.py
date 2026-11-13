"""Replays recent gateway decisions against a candidate bundle set.

The publisher's safety valve: a change may change decisions for the projects it
touches, and for no other. The inputs come from OPA's decision log in Loki (the
format scripts/policy-replay.py in the deployment repo reads). Each is evaluated
twice under the active policy bundle, with the active data bundle and with the
candidate, so only the data change shows: a policy or catalog change since the
request was logged (which would flip verdicts for every project) is not blamed
on it. Only the `allowed` verdict is compared, since the model behind `auto` can
change from hour to hour.
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
            if (e.get("path") == RULE and "input" in e and "result" in e
                    and "/input/parsed_body" not in (e.get("erased") or [])):
                events.append(e)
    return events


def project_of(event: dict) -> str | None:
    meta = (event["input"].get("attributes", {}).get("metadataContext", {})
            .get("filterMetadata", {}).get("agentgateway", {}))
    return meta.get("project")


def evaluate(inputs: list[dict], bundles: list[Path], opa: str = "opa") -> list[dict]:
    query = f"[d | some x in data.replay; d := data.{RULE.replace('/', '.')} with input as x]"
    with tempfile.TemporaryDirectory() as tmp:
        replay = Path(tmp) / "replay.json"
        replay.write_text(json.dumps({"replay": inputs}))
        args = [opa, "eval", "--format", "json", "-d", str(replay)]
        for b in bundles:
            args += ["-b", str(b)]
        out = subprocess.run(args + [query], capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"opa eval failed: {out.stdout[-2000:]}{out.stderr[-2000:]}")
    return json.loads(out.stdout)["result"][0]["expressions"][0]["value"]


def compare(events: list[dict], before: list[dict], after: list[dict], allowed_projects: set[str]) -> dict:
    flips, unexpected = [], []
    for e, old, new in zip(events, before, after):
        was, now = bool(old.get("allowed")), bool(new.get("allowed"))
        if was == now:
            continue
        flip = {"project": project_of(e), "before": was, "after": now, "time": e.get("time"),
                "path": e["input"].get("attributes", {}).get("request", {}).get("http", {}).get("path"),
                "model": (e["input"].get("parsed_body") or {}).get("model")}
        (flips if flip["project"] in allowed_projects else unexpected).append(flip)
    return {"replayed": len(events), "changed_for_changed_projects": len(flips),
            "changed_for_other_projects": len(unexpected), "examples": (unexpected + flips)[:20],
            "ok": not unexpected}


def replay(events: list[dict], policy: Path, active_data: Path, candidate_data: Path,
           allowed_projects: set[str], opa: str = "opa") -> dict:
    if not events:
        return {"replayed": 0, "changed_for_changed_projects": 0, "changed_for_other_projects": 0,
                "examples": [], "ok": True}
    inputs = [e["input"] for e in events]
    return compare(events, evaluate(inputs, [policy, active_data], opa),
                   evaluate(inputs, [policy, candidate_data], opa), allowed_projects)
