# project-registry

The project registry of [Mini Platform](https://github.com/nolimitkun/mini-platform-deployment)'s AI gateway: phase 2 of its multi-project policy, designed in [docs/design.md](docs/design.md).

The registry publishes both of the gateway's OPA bundles, and every change to either is a change request with approvals, a replay report, activation tracking and rollback:

- **project data** (`gateway-projects`): projects, their agents and exceptions. They live only here, in Postgres; Git has their schema and the script that renders them, not a copy. They change in the portal or through the API;
- **the catalog**: every model (placement, provider, price), Google API and MCP tool (risk), and the catalog's settings (task classes, serving namespaces, MCP targets), as records like a project's (`/models`, `/google-apis`, `/tools`, `/catalog/settings`). They render with the policy repo's `gen-catalog.py` into the data bundle (`data.registry.catalog`) and into the gateway's routes (`registry/gatewaychart.py`). The platform team proposes them; `portal.rego` adds security and the cost owner where a change widens placement or tool risk, or changes a price. The first time, the registry adopts the active policy commit's catalog files (`registry/catalog.py`). A catalog change may change any project's decisions, so its replay is a report, as for a policy change;
- **policy** (`gateway-policy`): the Rego, written and reviewed in Git ([nolimitkun/gateway-policy](https://github.com/nolimitkun/gateway-policy)). A new commit on the branch becomes a change request here, and OPA loads it only once it is approved.

A project data change goes like this:

1. **Validation.** The registry renders the whole data bundle with the change applied, using the platform's own `scripts/gen-projects.py` at the commit of the active policy bundle. Schema errors and cross-file errors come back before anyone is asked to approve. A proposed kagent agent is also checked against the deployment repo's kagent wiring (`KAGENT_WIRING_REPO`): its own ModelConfig and secret must be there first.
2. **Approvals.** Who has to approve is decided by policy: the registry asks OPA for `data.portal.required_approvals` (Rego in [gateway-policy](https://github.com/nolimitkun/gateway-policy)). The roles are:

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

A commit that changes the data format must work in both mixed states, because each OPA loads the two bundles on its own: the old policy with the new data, and the new policy with the old. If either decides a replayed request differently from both the old and the new pair, the commit is filed as `failed`. Stage such a change: first a policy that reads both formats, then the format change. If either bundle was published while the change waited, the publisher checks it again before activating: an unsafe result fails it, and a different outcome from what the approvers saw (the records republished or not, verdicts flipping where none did) sends it back to them. A newer commit supersedes a policy change still waiting. A commit whose test fails, or under which the records don't render, is filed as `failed` and nothing is published. A commit under which neither bundle changes (docs, another chart) is recorded as `skipped`: no approval, and OPA keeps the active commit. On a store with no policy at all (a new cluster), the branch's head is published without a change.

Rollback activates an earlier revision. For project data it also restores the records that revision was rendered from; for the policy it activates an earlier commit, which must be signed with the current key. A rollback moves one bundle, so it is refused when the project data it would run with is not what that policy commit renders (a format change between commits); roll back with a revert commit instead, which publishes both. A change not yet published can be withdrawn by its author or the platform team, for example one that nobody but its author could approve.

**Copies of the records.** Since the records live only here:

- a daily job (`python -m registry.snapshot`) writes them, as `/export` returns them, to `registry-snapshots/` in the bundle store;
- an empty registry imports the latest snapshot (`python -m registry.importer`), or the chart's seed on a new cluster;
- the signed data bundles keep every published revision.

None of these is a backup of the database (approvals, audit log).

**What other parts of the platform read from here** (cluster-internal, refused through the ingress):

- the gateway's API keys: the publisher writes Vault's two key maps from the records, after each data bundle and every five minutes (`GATEWAY_KEYS_MOUNT`, `registry/keys.py`): `agentgateway-api-keys`, which the gateway reads, and `agentgateway-client-keys`, the raw keys every client's copy is a VSO transformation of. A new key id gets a key, a removed one is revoked, an existing one keeps its key.
- `/internal/bundles/<bundle>`: the active bundle, for `scripts/policy-replay.py`.
- agentregistry's catalog of registered agents: the publisher applies it after each publish and every hour (`AGENTREGISTRY_URL`).
- the gateway's model routes: once a policy commit is active, the publisher packages its `charts/gateway-models` with the catalog as values and publishes it to a Helm repository in MinIO (`GATEWAY_MODELS_BUCKET`, `registry/gatewaychart.py`), which Argo CD installs.
- `/metrics`: `project_budget_usd{project}`, for the platform's one budget alert rule.

`/export` returns every record (a signed-in user).

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

The signing key version is pinned (`SIGNING_KEY_VERSION`). OPA verifies a bundle only with the key its config names for it, so a rotation moves the version, the key id (`SIGNING_KEYID`) and OPA's config in one change. When an active bundle is signed with another key, the publisher signs it again: the same commit, or the same records, with no approval. The runbook is in this repo's `docs/design.md`.

## Layout

| Path | What |
|---|---|
| `registry/api.py` | REST API (FastAPI): records, change requests, approvals, rollback, OPA status |
| `registry/publisher.py` | the publish loop |
| `registry/policy.py` | policy commits from Git as change requests: test, build, replay, file |
| `registry/approvals.py` | who approves: `data.portal.required_approvals` on OPA |
| `registry/activation.py` | when a published revision is active on every ready OPA pod |
| `registry/catalog.py` | the catalog's records: adopted the first time from the policy commit's files |
| `registry/gatewaychart.py` | the gateway-models chart, published as a Helm repository in MinIO |
| `registry/snapshot.py` | the daily snapshot of the records into the bundle store |
| `registry/importer.py` | the first load of an empty registry: the latest snapshot, or the seed |
| `registry/bundles.py` | build, sign, verify; the versioned bundle store (S3/MinIO) |
| `registry/render.py` | rendering through the policy repo's `gen-projects.py` (`POLICY_REPO`) |
| `registry/replay.py` | decision replay |
| `registry/auth.py` | Keycloak access tokens (realm JWKS, `azp`, `groups` claim) |

## Tests

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
TEST_DATABASE_URL=postgresql://postgres:test@localhost:5432/registry .venv/bin/pytest -q
```

The tests need `opa` on `PATH`. The flow tests need a disposable Postgres. They fetch the policy repo (nolimitkun/gateway-policy) from GitHub; to use a local checkout, set `POLICY_REPO` and `POLICY_REVISION`.

## Deployment

The `project-registry` application in the deployment repo deploys the API, the publisher, the daily snapshot and its Postgres; the `opa-policy` application deploys OPA. The image is `ghcr.io/nolimitkun/project-registry`.
