"""Callers are people with a Keycloak access token (Authorization: Bearer).

The token must be signed by the realm (JWKS), come from the registry's client
(azp) and be unexpired. Identity is preferred_username; roles come from the
flat `groups` claim the realm's groups scope adds.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import jwt
from fastapi import Header, HTTPException

ROLE_GROUPS = {          # approval role -> Keycloak group; project_owner is per project
    "platform": "platform-admins",
    "security": "security-reviewers",
    "cost_owner": "cost-owners",
}


@dataclass
class User:
    name: str
    groups: set[str] = field(default_factory=set)


class Verifier:
    def __init__(self, jwks_url: str, issuer: str, client_id: str):
        self.jwks, self.issuer, self.client_id = jwt.PyJWKClient(jwks_url, cache_keys=True), issuer, client_id

    def user(self, token: str) -> User:
        key = self.jwks.get_signing_key_from_jwt(token).key
        claims = jwt.decode(token, key, algorithms=["RS256"], issuer=self.issuer,
                            options={"verify_aud": False, "require": ["exp", "iss", "azp"]})
        if claims["azp"] != self.client_id:
            raise jwt.InvalidTokenError("token is for another client")
        return User(claims["preferred_username"], set(claims.get("groups") or []))


_verifier: Verifier | None = None


def current_user(authorization: str = Header(default="")) -> User:
    global _verifier
    if _verifier is None:
        _verifier = Verifier(os.environ["KEYCLOAK_JWKS_URL"], os.environ["KEYCLOAK_ISSUER"],
                             os.environ.get("KEYCLOAK_CLIENT_ID", "project-registry"))
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(401, "bearer token required")
    try:
        return _verifier.user(token)
    except jwt.PyJWTError as e:
        raise HTTPException(401, f"invalid token: {e}") from e
