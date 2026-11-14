"""Build, sign and publish OPA bundles.

Signing keeps the private key in Vault Transit. `opa build` cannot sign with a key
it doesn't hold, so a bundle is built with a throwaway key: OPA computes the file
hashes and writes `.signatures.json`. The token's payload (the file list) is then
signed again with the real key, through a `Signer`, and the token in the bundle is
replaced. OPA verifies it like any bundle signed by `opa build --signing-key`.

Store layout (one bucket, OPA reads `<bundle>/bundle.tar.gz`):
    <prefix><bundle>/revisions/<revision>/bundle.tar.gz   every build, kept
    <prefix><bundle>/bundle.tar.gz                        the active one, what OPA pulls
    <prefix><bundle>/active.json                          {"revision", "at"}
Activating a revision copies it over the active object; a rollback activates an
older revision.
"""
from __future__ import annotations

import base64
import io
import json
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

SIGNATURES = ".signatures.json"


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Signer(Protocol):
    keyid: str

    def sign(self, signing_input: bytes) -> bytes:
        """RS256: RSASSA-PKCS1-v1_5 over SHA-256 of signing_input."""


class LocalKeySigner:
    """A private key in memory. Tests only: the platform signs with Vault Transit."""

    def __init__(self, private_key: rsa.RSAPrivateKey, keyid: str):
        self.key, self.keyid = private_key, keyid

    def sign(self, signing_input: bytes) -> bytes:
        return self.key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())

    def public_pem(self) -> str:
        return self.key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def _member(tar: tarfile.TarFile, name: str) -> tarfile.TarInfo | None:
    for m in tar.getmembers():
        if m.name.lstrip("/") == name:
            return m
    return None


def build(src: Path, revision: str, signer: Signer, out: Path, opa: str = "opa",
          ignore: tuple[str, ...] = ("*_test.rego",)) -> dict:
    """Builds the bundle in directory src (its .manifest sets the roots), signed by
    signer, into out. Returns the signed payload (file list and keyid)."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        throwaway = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        (tmp / "key.pem").write_bytes(throwaway.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        (tmp / "claims.json").write_text(json.dumps({"keyid": signer.keyid}))
        cmd = [opa, "build", "-b", ".", "-r", revision, "-o", str(tmp / "unsigned.tar.gz"),
               "--signing-key", str(tmp / "key.pem"), "--signing-alg", "RS256",
               "--claims-file", str(tmp / "claims.json")]
        for pattern in ignore:
            cmd += ["--ignore", pattern]
        subprocess.run(cmd, cwd=src, check=True, capture_output=True, text=True)

        with tarfile.open(tmp / "unsigned.tar.gz") as tar:
            sig = _member(tar, SIGNATURES)
            if sig is None:
                raise RuntimeError("opa build wrote no .signatures.json")
            token = json.loads(tar.extractfile(sig).read())["signatures"][0]
            payload = json.loads(b64u_decode(token.split(".")[1]))
            if payload.get("keyid") != signer.keyid:
                raise RuntimeError("signature payload has the wrong keyid")
            header = {"alg": "RS256", "typ": "JWT", "kid": signer.keyid}
            signing_input = (b64u(json.dumps(header, separators=(",", ":")).encode()) + "." +
                             b64u(json.dumps(payload, separators=(",", ":")).encode()))
            signed = signing_input + "." + b64u(signer.sign(signing_input.encode()))
            body = json.dumps({"signatures": [signed]}).encode()

            out.parent.mkdir(parents=True, exist_ok=True)
            with tarfile.open(out, "w:gz") as dst:
                for m in tar.getmembers():
                    if m is sig:
                        info = tarfile.TarInfo(m.name)
                        info.size, info.mode, info.mtime = len(body), m.mode, m.mtime
                        dst.addfile(info, io.BytesIO(body))
                    else:
                        dst.addfile(m, tar.extractfile(m) if m.isfile() else None)
    return payload


def signed_keyid(path: Path) -> str | None:
    """The key id a bundle's signature names (None: unsigned)."""
    with tarfile.open(path) as tar:
        sig = _member(tar, SIGNATURES)
        if sig is None:
            return None
        token = json.loads(tar.extractfile(sig).read())["signatures"][0]
    return json.loads(b64u_decode(token.split(".")[1])).get("keyid")


def verify(path: Path, public_pem: str, keyid: str, opa: str = "opa") -> None:
    """Raises CalledProcessError unless OPA accepts the bundle's signature."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem") as f:
        f.write(public_pem)
        f.flush()
        subprocess.run([opa, "build", "-b", str(path), "--verification-key", f.name,
                        "--verification-key-id", keyid, "-o", "/dev/null"],
                       check=True, capture_output=True, text=True)


class Store:
    """Versioned bundles in an S3 bucket (MinIO)."""

    def __init__(self, s3, bucket: str, prefix: str = ""):
        self.s3, self.bucket, self.prefix = s3, bucket, prefix

    def _key(self, bundle: str, *parts: str) -> str:
        return "/".join([self.prefix + bundle, *parts])

    def put_revision(self, bundle: str, revision: str, path: Path) -> str:
        key = self._key(bundle, "revisions", revision, "bundle.tar.gz")
        self.s3.upload_file(str(path), self.bucket, key)
        return key

    def activate(self, bundle: str, revision: str) -> None:
        src = self._key(bundle, "revisions", revision, "bundle.tar.gz")
        self.s3.head_object(Bucket=self.bucket, Key=src)        # exists, or raise
        self.s3.copy_object(Bucket=self.bucket, Key=self._key(bundle, "bundle.tar.gz"),
                            CopySource={"Bucket": self.bucket, "Key": src})
        self.s3.put_object(Bucket=self.bucket, Key=self._key(bundle, "active.json"),
                           Body=json.dumps({"revision": revision, "at": int(time.time())}).encode(),
                           ContentType="application/json")

    def active(self, bundle: str) -> str | None:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=self._key(bundle, "active.json"))
        except self.s3.exceptions.NoSuchKey:
            return None
        except Exception as e:   # botocore ClientError for a missing key on some servers
            if "NoSuchKey" in str(e) or "404" in str(e):
                return None
            raise
        return json.loads(obj["Body"].read())["revision"]

    def revisions(self, bundle: str) -> list[str]:
        """Every revision kept for the bundle."""
        prefix = self._key(bundle, "revisions") + "/"
        out, token = [], None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": prefix, "Delimiter": "/"}
            if token:
                kw["ContinuationToken"] = token
            page = self.s3.list_objects_v2(**kw)
            out += [p["Prefix"][len(prefix):].rstrip("/") for p in page.get("CommonPrefixes") or []]
            if not page.get("IsTruncated"):
                return out
            token = page["NextContinuationToken"]

    # --- the registry's own snapshots (snapshot.py), next to the bundles ---
    SNAPSHOTS = "registry-snapshots"

    def put_snapshot(self, name: str, body: bytes) -> str:
        key = f"{self.prefix}{self.SNAPSHOTS}/{name}"
        self.s3.put_object(Bucket=self.bucket, Key=key, Body=body, ContentType="application/json")
        return key

    def latest_snapshot(self) -> bytes | None:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=f"{self.prefix}{self.SNAPSHOTS}/latest.json")
        except self.s3.exceptions.NoSuchKey:
            return None
        except Exception as e:
            if "NoSuchKey" in str(e) or "404" in str(e):
                return None
            raise
        return obj["Body"].read()

    def fetch(self, bundle: str, revision: str, path: Path) -> Path:
        self.s3.download_file(self.bucket, self._key(bundle, "revisions", revision, "bundle.tar.gz"), str(path))
        return path
