"""Vault: Kubernetes login and Transit signing. The signing key never leaves Vault."""
from __future__ import annotations

import base64
import time
from pathlib import Path

import requests

SA_TOKEN = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")


class Vault:
    def __init__(self, addr: str, role: str, jwt_path: Path = SA_TOKEN, mount: str = "kubernetes"):
        self.addr, self.role, self.jwt_path, self.mount = addr.rstrip("/"), role, jwt_path, mount
        self._token, self._expires = None, 0.0

    def token(self) -> str:
        if self._token is None or time.time() > self._expires - 60:
            r = requests.post(f"{self.addr}/v1/auth/{self.mount}/login",
                              json={"role": self.role, "jwt": self.jwt_path.read_text().strip()}, timeout=10)
            r.raise_for_status()
            auth = r.json()["auth"]
            self._token, self._expires = auth["client_token"], time.time() + auth["lease_duration"]
        return self._token

    def post(self, path: str, body: dict) -> dict:
        r = requests.post(f"{self.addr}/v1/{path}", json=body, headers={"X-Vault-Token": self.token()}, timeout=10)
        r.raise_for_status()
        return r.json()


class TransitSigner:
    """RS256 signatures from a Vault Transit RSA key (pkcs1v15 over SHA-256).

    Pinned to one key version: OPA verifies a bundle with the one key its config
    names for it, so a rotation moves the version, the key id and OPA's config in
    one change (docs/project-registry.md "Rotating the signing key")."""

    def __init__(self, vault: Vault, key: str, keyid: str, mount: str = "transit", version: int | None = None):
        self.vault, self.key, self.keyid, self.mount, self.version = vault, key, keyid, mount, version

    def sign(self, signing_input: bytes) -> bytes:
        body = {"input": base64.b64encode(signing_input).decode(),
                "hash_algorithm": "sha2-256", "signature_algorithm": "pkcs1v15"}
        if self.version:
            body["key_version"] = self.version
        data = self.vault.post(f"{self.mount}/sign/{self.key}", body)["data"]
        # "vault:v<version>:<standard base64>"
        return base64.b64decode(data["signature"].split(":", 2)[2])
