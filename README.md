# project-registry

The project registry of [Mini Platform](https://github.com/nolimitkun/mini-platform-deployment)'s AI gateway: phase 2 of its multi-project policy, designed in [docs/design.md](docs/design.md). The gateway's policy is in this repository too, in [`policy/`](policy/README.md): the Rego, the record schemas, the renderers and the gateway-models chart.

The registry publishes both of the gateway's OPA bundles, and every change to either is a change request with approvals, a replay report, activation tracking and rollback:

- **project data** (`gateway-projects`): projects, their agents and exceptions. They live only here, in Postgres; Git has their schema and the script that renders them, not a copy. They change in the portal or through the API;
- **the catalog**: every model (placement, provider, price), Google API and MCP tool (risk), and the catalog's settings (task classes, serving namespaces, MCP targets), as records like a project's (`/models`, `/google-apis`, `/tools`, `/catalog/settings`). They render with the policy's `gen-catalog.py` into the data bundle (`data.registry.catalog`) and into the gateway's routes (`registry/gatewaychart.py`). The platform team proposes them and approves every one; the `approvals` setting adds, today, security for a new model or Google API, a change to one's placement or provider settings, a tool made less risky, or a change to the MCP targets or serving namespaces, and the cost owner for a price. A catalog change may change any project's decisions, so its replay is a report, as for a policy change;
- **settings**: the policy's parameters that reviewers decide: `data_classes` (the placements each data class allows), `autonomy` (what each agent autonomy may do without a human) and `approvals` (who approves each kind of change, on top of floors the policy keeps in code). Records like the catalog's (`/settings/<id>`, a Settings page in the portal), rendered by the policy's `gen-settings.py` into `data.registry.settings`; the platform team proposes, the platform team and security approve, and the replay is a report;
- **policy** (`gateway-policy`): the Rego, written and reviewed in Git, in this repository's [`policy/`](policy/README.md). A new commit on the branch that changes it becomes a change request here, and OPA loads it only once it is approved; a commit that changes only the registry's code is followed with no request (the same bundle).

A project data change goes like this:

1. **Validation.** The registry renders the whole data bundle with the change applied, using the platform's own `scripts/gen-projects.py` at the commit of the active policy bundle. Schema errors and cross-file errors come back before anyone is asked to approve. A proposed kagent agent is also checked against the deployment repo's kagent wiring (`KAGENT_WIRING_REPO`): its own ModelConfig and secret must be there first.
2. **Approvals.** Who has to approve is decided by policy: the registry asks OPA for `data.portal.required_approvals` (Rego in [`policy/policies/gateway/portal.rego`](policy/policies/gateway/portal.rego)). The roles are:

   | Role | Who holds it |
   |---|---|
   | `project_owner` | the project's owner group |
   | `cost_owner` | the `cost-owners` group |
   | `security` | the `security-reviewers` group |
   | `platform` | the `platform-admins` group |

   Two rules hold for every change: nobody approves their own change, and nobody bypasses approval. Who may propose a change at all is policy too (`data.portal.may_submit`): anyone may request a new project; otherwise only the project's owner group and the platform team.
3. **Publishing.** The publisher takes approved changes in batches (an approval wakes it at once: the API sends a Postgres `NOTIFY` in the approving transaction, `registry/wakeup.py`; the outbox stays the record, so a missed notice costs at most a round of 5 s; after a publish it waits `MIN_INTERVAL`, so OPA reloads at most that often) and:
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

The approvers see the commit, its diff file by file in the portal (`GET /changes/<id>/diff`; files no publish reads start folded), the `opa test` result and how many decisions would change. The platform team approves every policy change, plus whatever `portal.rego` asks for. Once it is approved, the publisher activates the records rendered at that commit, if they differ, and then the policy.

A commit that changes the data format must work in both mixed states, because each OPA loads the two bundles on its own: the old policy with the new data, and the new policy with the old. If either decides a replayed request differently from both the old and the new pair, the commit is filed as `failed`. Stage such a change: first a policy that reads both formats, then the format change. If either bundle was published while the change waited, the publisher checks it again before activating: an unsafe result fails it, and a different outcome from what the approvers saw (the records republished or not, verdicts flipping where none did) sends it back to them. A newer commit supersedes a policy change still waiting. A commit whose test fails, or under which the records don't render, is filed as `failed` and nothing is published. A commit that changes only inert files (docs, CI, tools no publish runs: `INERT` in `registry/policy.py`), and neither bundle, is recorded as `skipped`: no approval, and OPA keeps the active commit. Any other file is presumed to matter (the renderers, the schemas and the chart act through the active commit), so an unlisted file costs an approval rather than a change that silently never applies. On a store with no policy at all (a new cluster), the branch's head is published without a change.

Rollback activates an earlier revision. For project data it also restores the records that revision was rendered from; for the policy it activates an earlier commit, which must be signed with the current key. A rollback moves one bundle, so it is refused when the project data it would run with is not what that policy commit renders (a format change between commits); roll back with a revert commit instead, which publishes both. A change not yet published can be withdrawn by its author or the platform team, for example one that nobody but its author could approve.

**Copies of the records.** Since the records live only here:

- a daily job (`python -m registry.snapshot`) writes them, as `/export` returns them, to `registry-snapshots/` in the bundle store;
- an empty registry imports the latest snapshot (`python -m registry.importer`), or the chart's seed on a new cluster;
- the signed data bundles keep every published revision.

None of these is a backup of the database (approvals, audit log).

**What other parts of the platform read from here** (cluster-internal, refused through the ingress):

- the gateway's API keys: the publisher writes Vault's two key maps from the records, after each data bundle and every five minutes (`GATEWAY_KEYS_MOUNT`, `registry/keys.py`): `agentgateway-api-keys`, which the gateway reads, and `agentgateway-client-keys`, the raw keys every client's copy is a VSO transformation of. A new key id gets a key, a removed one is revoked, an existing one keeps its key. The gateway's map becomes one Kubernetes Secret (1 MiB at most, about 6,000 keys): the publisher warns past 768 KiB and, past the limit, writes neither map and fails its `keys` output, so the gateway keeps the keys it has.
- `/internal/bundles/<bundle>`: the active bundle, for `scripts/policy-replay.py`.
- agentregistry's catalog of registered agents: the publisher applies it after each publish and every hour (`AGENTREGISTRY_URL`).
- the gateway's model routes: once a policy commit is active, the publisher packages its `charts/gateway-models` with the catalog as values and publishes it to a Helm repository in MinIO (`GATEWAY_MODELS_BUCKET`, `registry/gatewaychart.py`), which Argo CD installs; after a new version the publisher asks Argo CD to refresh that one Application (`GATEWAY_MODELS_ARGO_APP`, `registry/argo.py`) rather than wait for its poll.
- `/metrics`: `project_budget_usd{project}`, for the platform's one budget alert rule; `model_price_usd_per_million_tokens{model, gen_ai_request_model, gen_ai_token_type}`, each catalog price labelled like the gateway's token metrics (a KServe model under its served name), for the price drift alert (budgets charge agentgateway's own price table); and `registry_output_last_success_timestamp_seconds{output}` / `..._last_failure_...` for each of the publisher's outputs (`data`, `policy`, `chart`, `keys`, `activation`, `agentregistry`) and the hourly usage job (`usage`; `registry/health.py`), so one that keeps failing alerts rather than only logging.

`/export` returns every record (a signed-in user).

**Spend and usage.** An hourly job (`python -m registry.usage`, `registry/usage.py`) reads the gateway's access log from Loki: one line per request, with the project and key the gateway adds, the model, tokens, the cost the gateway charged (what budgets count), status and duration. It writes Parquet to its own bucket (`USAGE_BUCKET`) and shapes it with DuckDB:

- `raw/date=D/hour=HH.parquet`: one file per hour, rewritten whole; each run takes the current hour and the `USAGE_LOOKBACK_HOURS` (3) before it again, for lines that came late, and any hour of the last `USAGE_BACKFILL_HOURS` (168, about what Loki keeps) that has no file yet;
- `dims/date=D/`: that day's projects (owner group, budget, limits), keys with the agent each belongs to, and models (placement, price, served name), so a request is joined with the agent and placement of its day. The Usage page compares spend with each project's current budget, the one the rate limit enforces;
- `fact/date=D/part.parquet`, one row per request, deduplicated on (trace id, span id), with the model as the catalog names it (a KServe model's served name and `auto`'s virtual model mapped back) and its outcome: `ok`, `denied` (OPA's 403), `limited` (the rate limit's 429), `error` (including a provider's 429), `unauthenticated`;
- `daily/date=D/part.parquet`: per project, agent, key, kind of request (`model`, `list` for `/v1/models`, `mcp`, `other`), model and outcome. A call OPA refused is a `model` or `mcp` call by its path, without its model or tool: the gateway logs neither before it parses the call;
- `state.json`: up to when it is complete (the time of the last run).

An MCP tool is named as the catalog and the policy do: the gateway logs `tools/call` with the tool's name and its target apart (`gen_ai.tool.name=list_datasources`, `mcp.target=grafana`), joined as `grafana_list_datasources`.

Its runs record health as the output `usage`. `GET /usage` reports a date range from the daily files and `GET /usage/requests` a project's requests of one day from the facts, both for the projects the caller may see: every one for the platform team and the cost owners, otherwise those of the caller's owner groups. The API caches the files locally and queries them in process with DuckDB. Parquet travels through boto3, not DuckDB's S3 extension, which it would download at run time.

**Portal.** The registry serves a page at `/portal/` (one HTML file, `registry/static/portal.html`, same origin as the API) with these views, each at its own address (`#/changes/82`, `#/projects/admin`, `#/usage?project=admin&days=7`) so a change can be sent to its approvers; a login returns to the address it started from:

- waiting for me, the start page: the changes with an open approval the caller may give (`GET /changes?awaiting=me`; every change carries `yours`, the approvals the caller may give now), with a count in the menu;
- projects: each one's facts, what it can use now, a form for its fields (owner, data class, placement, model for `auto`, models, MCP tools, limits, budget, keys), or a JSON merge patch, and its changes. What it can use is asked of the gateway's OPA (`GET /projects/<id>/effective`, one `/v1/query` over `data.gateway.lib`, the rules `authz.rego` enforces): every catalog model with how the project gets it (its patterns or an exception) or why not, the Google APIs and MCP tools by risk, and each of its agents' share, the tools its autonomy lets it call without a human apart from those it is refused. It is what OPA has loaded, so a change shows once it is published;
- agents, exceptions and the catalog (models with their prices and tasks, Google APIs, MCP tools by risk), read only;
- status (`GET /status`): the published revision of each bundle against what every ready OPA pod reports it loaded, each publisher output's last success and failure, how far the usage ledger reaches, and the pending and firing `Gateway*` and `ProjectRegistry*` alerts from Prometheus (`PROMETHEUS_URL`);
- proposing a change in two steps: Review asks `POST /changes/preview`, which checks it as a submit would and answers who must approve it and what changes field by field, without filing anything; Submit files what was reviewed;
- change requests with their field-by-field diff, approvals and replay report; approve and reject only for the approvals that are the caller's, withdraw for its author and the platform team. The list filters by state, kind and a part of the object id or author (`GET /changes?state=&kind=&q=&offset=`), 50 to a page;
- why denied: whether the gateway would let a project, with its own key or a chosen one, call a model, an MCP tool or a Google API, or list the models (`POST /explain`). The registry evaluates `authz.rego`'s `allow` and `reason` on OPA with the input agentgateway would send, so the answer is the 403's reason under the policy loaded now, with what would change it. A refused request on the usage page links here;
- the audit log (`GET /audit?actor=&action=&q=`), for the platform team, security and the cost owners: every change, decision, publication, rollback and key map write (key ids only);
- CSV export of the usage tables, a day's requests, the changes and the audit log, built in the browser from what the page shows; search boxes over the projects and the usage page's agents and keys;
- the published bundles of both kinds, with rollback for the platform team;
- usage: spend per day, each project's last 30 days against its budget and its pace, models (and what `auto` chose), agents and keys, what on-prem models served (`USAGE_REFERENCE_MODEL` prices it), and a project's dearest requests of a day with their trace ids.

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
| `policy/` | the gateway's policy: the Rego, the record schemas, the renderers (`gen-settings.py`, `gen-catalog.py`, `gen-projects.py`), the gateway-models chart ([its README](policy/README.md)) |
| `registry/api.py` | REST API (FastAPI): records, change requests, approvals, rollback, OPA status |
| `registry/publisher.py` | the publish loop |
| `registry/policy.py` | policy commits from Git as change requests: test, build, replay, file |
| `registry/approvals.py` | who approves: `data.portal.required_approvals` on OPA |
| `registry/activation.py` | when a published revision is active on every ready OPA pod |
| `registry/gatewaychart.py` | the gateway-models chart, published as a Helm repository in MinIO |
| `registry/insight.py` | what a project can use and why a call is refused, asked of OPA, and the status page's reads |
| `registry/health.py` | each publisher output's last success and failure, for `/metrics` |
| `registry/keys.py` | the gateway's API key maps in Vault, written from the records |
| `registry/vault.py` | Vault: Kubernetes login, Transit signing, KV reads and writes |
| `registry/snapshot.py` | the daily snapshot of the records into the bundle store |
| `registry/usage.py` | the gateway's spend and usage: access log → Parquet → DuckDB, and the reports `/usage` serves |
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

The tests need `opa` on `PATH`. The flow tests need a disposable Postgres. They use the policy in `policy/` at `HEAD` (commit first), so the registry and the policy are tested together; `POLICY_REPO`, `POLICY_SUBDIR` and `POLICY_REVISION` pick another. CI also runs `policy/scripts/validate.sh`.

## Deployment

The `project-registry` application in the deployment repo deploys the API, the publisher, the daily snapshot, the hourly usage job and its Postgres; the `opa-policy` application deploys OPA. The image is `ghcr.io/nolimitkun/project-registry`.
