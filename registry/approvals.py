"""Who must approve a change: data.portal.required_approvals on the gateway's OPA, so
the approval rules are Rego in the policy repo (policies/gateway/portal.rego),
answered by the policy that is active now."""
from __future__ import annotations

import requests

from .auth import ROLE_GROUPS

ROLES = {*ROLE_GROUPS, "project_owner"}


class NoAnswer(Exception):
    """The policy gave no usable answer: the change can't be filed (fail closed)."""


def required(opa_url: str, change: dict, requester: str) -> list[str]:
    r = requests.post(f"{opa_url.rstrip('/')}/v1/data/portal/required_approvals",
                      json={"input": {"change": change, "requester": requester}}, timeout=5)
    r.raise_for_status()
    roles = r.json().get("result")
    if change.get("kind") == "policy" and isinstance(roles, list):
        # No project owns the policy. The platform team approves every policy change, also
        # under a portal.rego written before policy changes existed (which asks for an owner).
        roles = [x for x in roles if x != "project_owner"] + ["platform"]
    if not isinstance(roles, list) or not roles or not set(roles) <= ROLES:
        raise NoAnswer(f"approval policy gave no valid answer: {roles!r}")
    return sorted(set(roles))
