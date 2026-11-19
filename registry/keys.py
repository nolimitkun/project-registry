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

Rotating a key keeps its key id: the key id gets a fresh key in both maps, and its
previous key stays in the gateway's map only, as `<key id>.previous` with the same
metadata, until its grace period ends (none: revoked at once). The gateway and OPA see
the same key id either way, so its limits, usage and alerts carry on; the clients'
copies take the new key on their next refresh. The registry's gateway_key table holds
the requests and the grace periods (api.py, publisher.py).
"""
from __future__ import annotations

import base64
import json
import logging
import secrets

log = logging.getLogger("keys")

GATEWAY = "agentgateway-api-keys"
CLIENTS = "agentgateway-client-keys"
PREVIOUS = ".previous"      # a key id never has a dot (the schemas' pattern)

# VSO copies the gateway's map into one Kubernetes Secret, which can't pass 1 MiB (with
# its metadata). An entry is about 165 bytes there, so some 6,000 keys fit; past
# WARN_AT the log warns, past LIMIT the map isn't written: the gateway keeps the keys it
# has and the publisher's failure (status page, alerts) says why.
LIMIT = 1024 * 1024 - 32 * 1024
WARN_AT = 768 * 1024


def secret_bytes(m: dict[str, str]) -> int:
    """The size of a map's data in a Secret: its names and base64 values."""
    return sum(len(k) + len(base64.b64encode(v.encode())) for k, v in m.items())


def wanted(lines: str) -> dict[str, str]:
    """key id -> project, from gen-projects.py --keys ("<key_id> <project>" lines)."""
    out = {}
    for line in lines.splitlines():
        if line.strip():
            key_id, project = line.split()
            out[key_id] = project
    return out


def owners(records: dict) -> dict[str, dict]:
    """key id -> {"project", "agent"}: a project's own keys (agent None) and its agents'."""
    out = {k: {"project": pid, "agent": None} for pid, p in records.get("project", {}).items()
           for k in p.get("keys") or []}
    out.update({k: {"project": a.get("project"), "agent": aid} for aid, a in records.get("agent", {}).items()
                for k in a.get("keys") or []})
    return out


def _key(value) -> str | None:
    try:
        return json.loads(value)["key"] if isinstance(value, str) else value["key"]
    except (ValueError, KeyError, TypeError):
        return None


def reconcile(kv, mount: str, want: dict[str, str], new_key=lambda: secrets.token_urlsafe(32),
              wrote=lambda name, diff: None, rotate: dict[str, bool] | None = None,
              keep_previous: set[str] = frozenset()) -> dict | None:
    """Brings both maps to `want`. rotate: key ids to give a fresh key, each True if its
    old key is kept as the previous one (a grace period) or False if it is revoked now;
    keep_previous: key ids whose previous key is still in its grace period (any other
    previous key is dropped). Calls wrote(map name, diff) after each map it writes, so a
    write is recorded even if the next one fails; returns the gateway map's diff
    {"added", "removed", "changed", "issued"} (key ids, never keys; "issued": those that
    got a fresh key) when it wrote anything, None when both were current already."""
    if not want:
        raise ValueError("no key ids: refusing to empty the gateway's key maps")
    gateway, clients = kv.kv_get(mount, GATEWAY) or {}, kv.kv_get(mount, CLIENTS) or {}
    keys = {k: _key(gateway[k]) if k in gateway else None for k in want}
    keys = {k: v or clients.get(k) for k, v in keys.items()}
    previous = {k: _key(gateway[k + PREVIOUS]) for k in want if k in keep_previous and k + PREVIOUS in gateway}
    for k, keep in (rotate or {}).items():
        if k in want:
            if keep and keys[k]:
                previous[k] = keys[k]
            elif not keep:
                previous.pop(k, None)
            keys[k] = None
    issued = sorted(k for k, v in keys.items() if v is None)
    keys = {k: v or new_key() for k, v in keys.items()}
    previous = {k: v for k, v in previous.items() if v and v != keys[k]}
    entry = lambda key, p, k: json.dumps({"key": key, "metadata": {"project": p, "key_id": k}},   # noqa: E731
                                         separators=(",", ":"))
    new_gateway = {k: entry(keys[k], p, k) for k, p in want.items()}
    new_gateway.update({k + PREVIOUS: entry(v, want[k], k) for k, v in previous.items()})
    new_gateway = dict(sorted(new_gateway.items()))
    new_clients = {k: keys[k] for k in sorted(want)}
    parsed, target = {k: _parse(v) for k, v in gateway.items()}, {k: json.loads(v) for k, v in new_gateway.items()}
    gateway_diff, clients_diff = _diff(parsed, target), _diff(clients, new_clients)
    if not any(gateway_diff.values()) and not any(clients_diff.values()):
        return None
    size = secret_bytes(new_gateway)
    if size > LIMIT:
        raise ValueError(f"the gateway's key map would be {size} bytes in its Secret, over {LIMIT}: "
                         f"{len(new_gateway)} keys; not written")
    if size > WARN_AT:
        log.warning("the gateway's key map is %d bytes in its Secret (%d keys), near the %d limit",
                    size, len(new_gateway), LIMIT)
    gateway_diff["issued"] = issued
    if any(gateway_diff.values()):
        kv.kv_put(mount, GATEWAY, new_gateway)
        wrote(GATEWAY, gateway_diff)
    if any(clients_diff.values()):
        kv.kv_put(mount, CLIENTS, new_clients)
        wrote(CLIENTS, clients_diff)
    log.info("gateway key maps written: %s", {GATEWAY: gateway_diff, CLIENTS: clients_diff})
    return gateway_diff if any(gateway_diff.values()) else clients_diff


def _diff(old: dict, new: dict) -> dict:
    return {"added": sorted(set(new) - set(old)), "removed": sorted(set(old) - set(new)),
            "changed": sorted(k for k in set(old) & set(new) if old[k] != new[k])}


def _parse(value):
    try:
        return json.loads(value) if isinstance(value, str) else value
    except ValueError:
        return value
