# project-registry

The project registry of [Mini Platform](https://github.com/nolimitkun/mini-platform-deployment)'s AI gateway: phase 2 of its multi-project policy, designed in [docs/project-registry.md](https://github.com/nolimitkun/mini-platform-deployment/blob/main/docs/project-registry.md).

Projects, their agents and exceptions live in Postgres instead of `projects/*.yaml`. Every edit is a change request:

1. **Validation.** The registry renders the whole data bundle with the change applied, using the platform's own `scripts/gen-projects.py` at the commit of the active policy bundle. Schema errors and cross-file errors come back before anyone is asked to approve.
2. **Approvals.** Who has to approve is decided by policy: the registry asks OPA for `data.portal.required_approvals` (Rego in the deployment repo). The roles are:

   | Role | Who holds it |
   |---|---|
   | `project_owner` | the project's owner group |
   | `cost_owner` | the `cost-owners` group |
   | `security` | the `security-reviewers` group |
   | `platform` | the `platform-admins` group |

   Two rules hold for every change: nobody approves their own change, and nobody bypasses approval. Who may propose a change at all is policy too (`data.portal.may_submit`): anyone may request a new project; otherwise only the project's owner group and the platform team.
3. **Publishing.** The publisher takes approved changes in batches and:
   1. applies them;
   2. renders the bundle;
   3. replays recent gateway decisions from Loki. A change may only change decisions for the projects it touches. Otherwise it is marked `failed` and nothing is published;
   4. builds the bundle, signs it with Vault Transit, uploads it and activates it.

   All of this runs in one database transaction.
4. **Activation.** A change is `active` once every OPA reports its bundle revision (OPA's status plugin posts to `/opa/status`).

Rollback activates an earlier revision and restores the records it was rendered from. A change not yet published can be withdrawn by its author or the platform team, for example one that nobody but its author could approve.

`/metrics` exports `project_budget_usd{project}` for the platform's one budget alert rule. `/export` returns every record in the deployment repo's file format; its `scripts/registry-export.py` writes them back to Git.

The same image also builds the **policy bundle** (`python -m registry.policybuild`): when the Git branch moves, it runs `opa test`, then builds and signs. This replaces OPA Control Plane.

## Signing

`opa build --signing-key` needs the private key as a file. Here the key stays in Vault Transit and is never exported, so the bundle is signed in three steps:

1. Build it with a throwaway key, so OPA computes the file hashes.
2. Sign the token's payload again through Transit (`pkcs1v15`, SHA-256: RS256).
3. Put the new token into the bundle.

OPA verifies the result like any bundle signed with `--signing-key`, using the public key and the key id (`registry/bundles.py`).

The signing key version is pinned (`SIGNING_KEY_VERSION`). OPA verifies a bundle only with the key its config names for it, so a rotation moves the version, the key id (`SIGNING_KEYID`) and OPA's config in one change. When the active bundle is signed with another key, the policy build and the publisher sign it again: the same commit and the same records. The runbook is in the deployment repo's `docs/project-registry.md`.

## Layout

| Path | What |
|---|---|
| `registry/api.py` | REST API (FastAPI): records, change requests, approvals, rollback, OPA status |
| `registry/publisher.py` | the publish loop |
| `registry/policybuild.py` | the policy bundle build (a CronJob) |
| `registry/importer.py` | the first load from `projects/*.yaml`, with a byte-for-byte check against Git |
| `registry/bundles.py` | build, sign, verify; the versioned bundle store (S3/MinIO) |
| `registry/render.py` | rendering through the deployment repo's `gen-projects.py` |
| `registry/replay.py` | decision replay |
| `registry/auth.py` | Keycloak access tokens (realm JWKS, `azp`, `groups` claim) |

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
TEST_DATABASE_URL=postgresql://postgres:test@localhost:5432/registry .venv/bin/pytest -q
```

The tests need `opa` on `PATH`. The flow tests need a disposable Postgres. They fetch the deployment repo from GitHub; to use a local checkout, set `DEPLOY_REPO` and `DEPLOY_REVISION`.

## Deployment

The `project-registry` application in the deployment repo deploys the API, the publisher and its Postgres, and the `opa-policy` application deploys the policy build CronJob. The image is `ghcr.io/nolimitkun/project-registry`.
