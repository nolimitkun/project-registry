#!/usr/bin/env python3
"""Compare the MCP tools behind the gateway with the catalog's tools in the project registry.

    python3 scripts/tools-drift.py                 through kubectl port-forward
    python3 scripts/tools-drift.py --gateway http://agentgateway.test

Lists the tools the gateway's merged /mcp endpoint announces, with the admin
project's key, and reports:

  new        announced, not in the catalog: agents can't call it (it counts as
             irreversible) until someone classifies it (a tool record)
  removed    in the catalog, no longer announced
  changed    its description or input schema changed since it was classified
             (fingerprint): check the risk still holds, then update it

Exit code 1 on any drift. For a new or changed tool the record to propose in the
registry (POST or PATCH /tools/<name>) is printed with its current fingerprint and
the risk left for you to fill in.

Needs kubectl access to the cluster: the catalog's tools come from the registry's
pod (or --tools, a file in the format of its /export), the key from the
agentgateway-api-keys Secret, and without --gateway the endpoint is reached
through a port-forward to svc/agentgateway-proxy.
"""

import argparse
import base64
import contextlib
import hashlib
import json
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
READ_TOOLS = """
import json, os
from registry import db
with db.DB(os.environ["DATABASE_URL"]).tx() as c:
    print(json.dumps({r["id"]: r["spec"] for r in c.execute("select id, spec from resource where kind = 'tool'")}))
"""


def registry_tools():
    """The catalog's tool records, read in the project registry's pod (its database)."""
    out = subprocess.run(["kubectl", "-n", NAMESPACE, "exec", "deploy/project-registry", "--", "python", "-c", READ_TOOLS],
                         capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"could not read the tools from the project registry: {out.stderr[-500:]}")
    return json.loads(out.stdout)
NAMESPACE = "mini-platform"


def fingerprint(tool):
    """sha256 over the description and input schema, first 16 hex digits."""
    body = {"description": tool.get("description", ""), "inputSchema": tool.get("inputSchema", {})}
    return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


def gateway_key(key_id):
    out = subprocess.check_output(
        ["kubectl", "-n", NAMESPACE, "get", "secret", "agentgateway-api-keys", "-o", "json"]
    )
    data = json.loads(out)["data"]
    if key_id not in data:
        sys.exit(f"no key {key_id!r} in agentgateway-api-keys")
    return json.loads(base64.b64decode(data[key_id]))["key"]


@contextlib.contextmanager
def gateway_url(given):
    if given:
        yield given.rstrip("/")
        return
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    pf = subprocess.Popen(
        ["kubectl", "-n", NAMESPACE, "port-forward", "svc/agentgateway-proxy", f"{port}:80"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                break
            except OSError:
                time.sleep(0.2)
        else:
            sys.exit("the gateway did not answer through kubectl port-forward")
        yield f"http://127.0.0.1:{port}"
    finally:
        pf.terminate()


def list_tools(url, key):
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
    }

    def post(body, session=None):
        h = dict(headers)
        if session:
            h["Mcp-Session-Id"] = session
        req = urllib.request.Request(f"{url}/mcp", json.dumps(body).encode(), h)
        with urllib.request.urlopen(req, timeout=60) as r:
            text = r.read().decode()
            session = r.headers.get("Mcp-Session-Id") or session
        msgs = [json.loads(line[5:]) for line in text.splitlines() if line.startswith("data:")]
        if not msgs and text.strip():
            msgs = [json.loads(text)]
        return session, msgs

    session, _ = post({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                   "clientInfo": {"name": "tools-drift", "version": "1"}},
    })
    post({"jsonrpc": "2.0", "method": "notifications/initialized"}, session)
    tools, cursor = [], None
    while True:
        params = {"cursor": cursor} if cursor else {}
        _, msgs = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": params}, session)
        result = msgs[-1]["result"]
        tools += result["tools"]
        cursor = result.get("nextCursor")
        if not cursor:
            return {t["name"]: t for t in tools}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--gateway", help="gateway base URL; default: kubectl port-forward svc/agentgateway-proxy")
    parser.add_argument("--key-id", default="admin", help="key id to list tools with (needs mcp_tools: ['*'])")
    parser.add_argument("--tools", type=Path, help="records file (the registry's /export format); default: the registry")
    args = parser.parse_args()

    catalog = ((yaml.safe_load(args.tools.read_text()) or {}).get("tool") or {}) if args.tools else registry_tools()
    with gateway_url(args.gateway) as url:
        live = list_tools(url, gateway_key(args.key_id))

    new = sorted(set(live) - set(catalog))
    removed = sorted(set(catalog) - set(live))
    changed = sorted(
        n for n in set(live) & set(catalog)
        if catalog[n].get("fingerprint") and catalog[n]["fingerprint"] != fingerprint(live[n])
    )
    print(f"{len(live)} tools announced, {len(catalog)} in the catalog")
    for label, names in (("new", new), ("removed", removed), ("changed", changed)):
        print(f"{label}: {len(names)}")
        for n in names:
            if n in live:
                risk = catalog.get(n, {}).get("risk", "<read|write|irreversible>")
                print(f'  {n}: {{risk: {risk}, fingerprint: "{fingerprint(live[n])}"}}')
            else:
                print(f"  {n}")
    return 1 if new or removed or changed else 0


if __name__ == "__main__":
    sys.exit(main())
