"""Builds, tests and signs the gateway-policy bundle from Git: the platform's stand-in
for CI, run as a CronJob. It replaces OPA Control Plane for the Rego bundle.

    python -m registry.policybuild

Each run resolves the branch, and does nothing if the active revision is already
that commit. Otherwise it runs `opa test` over the policy and the project data in
the same commit, builds the policy bundle with the commit as its revision, signs
it through Vault Transit and activates it. A failing test publishes nothing: OPA
keeps the active bundle.

Settings (environment):
    POLICY_REPO, POLICY_REF        Git repository and branch
    POLICY_DIR                     the bundle's directory (policies/gateway)
    POLICY_TEST_DIRS               comma-separated, loaded together by opa test
    BUNDLE_NAME                    gateway-policy
    BUNDLE_PREFIX                  "" for main; a branch build writes under its own
                                   prefix (e.g. branches/my-change/) so it never
                                   replaces what OPA loads
    S3_ENDPOINT, S3_BUCKET, AWS_*  the bundle store
    VAULT_ADDR, VAULT_ROLE, TRANSIT_KEY, SIGNING_KEYID
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import boto3

from .bundles import Store, build, signed_keyid
from .vault import TransitSigner, Vault


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        sys.exit(f"{name} is not set")
    return value


def git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def run(store: Store, signer, repo: str, ref: str, policy_dir: str, test_dirs: list[str],
        bundle: str, opa: str = "opa") -> str:
    head = git("ls-remote", repo, f"refs/heads/{ref}").split()[0]
    active = store.active(bundle)
    if active == head:
        with tempfile.TemporaryDirectory() as tmp:
            keyid = signed_keyid(store.fetch(bundle, active, Path(tmp) / "active.tar.gz"))
        if keyid == signer.keyid:
            print(f"{bundle}: {head} is active, nothing to do", flush=True)
            return "unchanged"
        print(f"{bundle}: {head} is signed with {keyid}, not {signer.keyid}: re-signing", flush=True)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "repo"
        git("clone", "--quiet", "--depth", "1", "--branch", ref, repo, str(work))
        sha = git("rev-parse", "HEAD", cwd=work)
        test = subprocess.run([opa, "test", *test_dirs], cwd=work, capture_output=True, text=True)
        if test.returncode != 0:
            print(test.stdout[-4000:], test.stderr[-2000:], sep="\n", flush=True)
            raise SystemExit(f"{bundle}: opa test failed at {sha}; {active} stays active")
        out = Path(tmp) / "bundle.tar.gz"
        build(work / policy_dir, sha, signer, out, opa=opa)
        store.put_revision(bundle, sha, out)
        store.activate(bundle, sha)
    print(f"{bundle}: activated {sha} (was {active})", flush=True)
    return sha


def main() -> None:
    s3 = boto3.client("s3", endpoint_url=env("S3_ENDPOINT"), region_name=os.environ.get("AWS_REGION", "us-east-1"))
    store = Store(s3, env("S3_BUCKET"), os.environ.get("BUNDLE_PREFIX", ""))
    signer = TransitSigner(Vault(env("VAULT_ADDR"), env("VAULT_ROLE")), env("TRANSIT_KEY"), env("SIGNING_KEYID"),
                           version=int(os.environ["SIGNING_KEY_VERSION"]) if os.environ.get("SIGNING_KEY_VERSION") else None)
    run(store, signer, env("POLICY_REPO"), env("POLICY_REF"), env("POLICY_DIR", "policies/gateway"),
        env("POLICY_TEST_DIRS", "policies/gateway,policies/gateway-projects").split(","),
        env("BUNDLE_NAME", "gateway-policy"))


if __name__ == "__main__":
    main()
