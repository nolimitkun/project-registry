# project-registry

The project registry of [Mini Platform](https://github.com/nolimitkun/mini-platform-deployment)'s AI gateway: phase 2 of its multi-project policy, designed in [docs/project-registry.md](https://github.com/nolimitkun/mini-platform-deployment/blob/main/docs/project-registry.md).

The registry publishes both of the gateway's OPA bundles, and every change to either is a change request with approvals, a replay report, activation tracking and rollback:

- **project data** (`gateway-projects`): projects, their agents and exceptions, kept in Postgres instead of `projects/*.yaml`, changed in the portal or through the API;
- **policy** (`gateway-policy`): the Rego, written and reviewed in Git. A new commit on the branch becomes a change request here, and OPA loads it only once it is approved.

A project data change goes like this:

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
4. **Activation.** A change is `active` once every ready OPA pod has reported its bundle revision. OPA's status plugin posts to `/opa/status`, with the pod name as a label. The ready pods come from the OPA Service's EndpointSlices, and the check also runs on every round of the publisher (`registry/activation.py`).

A policy change (`registry/policy.py`) goes like this. Every minute the publisher checks the branch. For a new commit it:

1. runs `opa test`;
2. builds and signs the bundle, but doesn't activate it;
3. renders the records with that commit's `gen-projects.py`;
4. replays recent decisions under the active bundles and under the new ones;
5. files the change, kind `policy`, object the commit.

The approvers see the commit, a link to its diff and how many decisions would change. The platform team approves every policy change, plus whatever `portal.rego` asks for. Once it is approved, the publisher activates the records rendered at that commit, if they differ, and then the policy.

A newer commit supersedes a policy change still waiting. A commit whose test fails, or under which the records don't render, is filed as `failed` and nothing is published. On a store with no policy at all (a new cluster), the branch's head is published without a change.

Rollback activates an earlier revision. For project data it also restores the records that revision was rendered from; for the policy it activates an earlier commit, which must be signed with the current key. A change not yet published can be withdrawn by its author or the platform team, for example one that nobody but its author could approve.

A daily job (`python -m registry.gitexport`) writes the records back to the deployment repo through that repo's `scripts/registry-export.py` and opens one pull request (branch `registry-export`), or updates the open one; it needs a fine-grained GitHub token for that repo, read from the environment through a git credential helper so it never appears in a command line.

`/metrics` exports `project_budget_usd{project}` for the platform's one budget alert rule. `/export` returns every record in the deployment repo's file format; its `scripts/registry-export.py` writes them back to Git.

**Portal.** The registry serves a page at `/portal/` (one HTML file, `registry/static/portal.html`, same origin as the API) with these views:

- projects, and their changes;
- proposing a change (a JSON merge patch) or a new project;
- change requests with their diff, approvals and replay report, and approve, reject and withdraw;
- the published bundles of both kinds, with rollback for the platform team.

People log in to Keycloak with the authorization code flow and PKCE, through the public client `project-registry`; there is no client secret. `/opa/status` and `/metrics` refuse requests that came through the ingress.

## Signing

`opa build --signing-key` needs the private key as a file. Here the key stays in Vault Transit and is never exported, so the bundle is signed in three steps:

1. Build it with a throwaway key, so OPA computes the file hashes.
2. Sign the token's payload again through Transit (`pkcs1v15`, SHA-256: RS256).
3. Put the new token into the bundle.

OPA verifies the result like any bundle signed with `--signing-key`, using the public key and the key id (`registry/bundles.py`).

The signing key version is pinned (`SIGNING_KEY_VERSION`). OPA verifies a bundle only with the key its config names for it, so a rotation moves the version, the key id (`SIGNING_KEYID`) and OPA's config in one change. When an active bundle is signed with another key, the publisher signs it again: the same commit, or the same records, with no approval. The runbook is in the deployment repo's `docs/project-registry.md`.

## Layout

| Path | What |
|---|---|
| `registry/api.py` | REST API (FastAPI): records, change requests, approvals, rollback, OPA status |
| `registry/publisher.py` | the publish loop |
| `registry/policy.py` | policy commits from Git as change requests: test, build, replay, file |
| `registry/approvals.py` | who approves: `data.portal.required_approvals` on OPA |
| `registry/activation.py` | when a published revision is active on every ready OPA pod |
| `registry/gitexport.py` | the daily export of the records to Git |
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

The `project-registry` application in the deployment repo deploys the API, the publisher, the daily export and its Postgres; the `opa-policy` application deploys OPA. The image is `ghcr.io/nolimitkun/project-registry`.
