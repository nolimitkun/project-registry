"""The gateway's API keys, written to Vault by the registry from its records.

Two maps in Vault's KV, one entry per key id (gen-projects.py --keys lists them with
their projects):

- agentgateway-api-keys: what agentgateway reads (its apiKeysSecret, through VSO), a
  JSON value per key id with the key and the {project, key_id} metadata OPA keys on;
- agentgateway-client-keys: the raw keys. Every client's copy (kagent's, an agent's,
  Open WebUI's, the onboarding pipeline's) is a VSO transformation of this map in the
  deployment repo, which picks its key id and names the field; nothing else in Vault
  holds a gateway key.

A key id keeps its key: an existing one is reused (the gateway's map first, then the
clients'), a new key id gets a fresh random key, and a key id no record lists any more
is dropped from both maps, which revokes it. The gateway's map is written first, so
the gateway knows a new key before any client holds it.
"""
from __future__ import annotations

import json
import logging
import secrets

log = logging.getLogger("keys")

GATEWAY = "agentgateway-api-keys"
CLIENTS = "agentgateway-client-keys"


def wanted(lines: str) -> dict[str, str]:
    """key id -> project, from gen-projects.py --keys ("<key_id> <project>" lines)."""
    out = {}
    for line in lines.splitlines():
        if line.strip():
            key_id, project = line.split()
            out[key_id] = project
    return out


def _key(value) -> str | None:
    try:
        return json.loads(value)["key"] if isinstance(value, str) else value["key"]
    except (ValueError, KeyError, TypeError):
        return None


def reconcile(kv, mount: str, want: dict[str, str], new_key=lambda: secrets.token_urlsafe(32)) -> dict | None:
    """Brings both maps to `want`. Returns {"added", "removed", "changed"} (key ids, never
    keys) when it wrote, None when both were current already."""
    if not want:
        raise ValueError("no key ids: refusing to empty the gateway's key maps")
    gateway, clients = kv.kv_get(mount, GATEWAY) or {}, kv.kv_get(mount, CLIENTS) or {}
    keys = {k: _key(gateway[k]) if k in gateway else None for k in want}
    keys = {k: v or clients.get(k) or new_key() for k, v in keys.items()}
    new_gateway = {k: json.dumps({"key": keys[k], "metadata": {"project": p, "key_id": k}}, separators=(",", ":"))
                   for k, p in sorted(want.items())}
    new_clients = {k: keys[k] for k in sorted(want)}
    parsed = {k: _parse(v) for k, v in gateway.items()}
    if parsed == {k: json.loads(v) for k, v in new_gateway.items()} and clients == new_clients:
        return None
    kv.kv_put(mount, GATEWAY, new_gateway)
    kv.kv_put(mount, CLIENTS, new_clients)
    changed = sorted(k for k in want if k in gateway and parsed.get(k) != json.loads(new_gateway[k])
                     or k in clients and clients[k] != keys[k])
    out = {"added": sorted(set(want) - set(gateway)), "removed": sorted(set(gateway) - set(want)), "changed": changed}
    log.info("gateway key maps written: %s", out)
    return out


def _parse(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except ValueError:
        return value
