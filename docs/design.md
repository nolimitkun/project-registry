# Design: project registry (phase 2)

> Moved here from nolimitkun/mini-platform-deployment (`docs/project-registry.md`) on
> 2026-11-14. Paths such as `minikube/...` and `scripts/...` are in that repo;
> `policies/`, `catalog/` and the record schemas are in nolimitkun/gateway-policy.

Status: **proof of concept built and deployed on minikube** (2026-11-13): the
core below, in [nolimitkun/project-registry](https://github.com/nolimitkun/project-registry)
and the `project-registry` and `opa-policy` apps, with a portal page at
`registry.test/portal/`. OAuth clients for callers are not built yet.
[Proof of concept](#proof-of-concept) has what was built, what differs from this
design and what was measured.

Today a project is a file, `projects/<id>.yaml`, changed by pull request.
[multi-project-policy.md](https://github.com/nolimitkun/gateway-policy/blob/main/docs/design.md) records that design and
how it was built. It works for about 200 projects. This document is the next
step, for 1,000 projects or more on several sites, edited through a portal.

## Goals

- **One source of truth.** A registry service holds every project: its
  models, exceptions, limits and budget. The portal reads and writes the
  registry.
- **Small, fast changes.** A change touches one project and is live within
  minutes.
- **Controls a bank needs:** approval by the right people, an audit trail,
  replay of past decisions before publishing, and signed bundles.
- **Decisions don't depend on the registry.** If the registry is down, no
  request decision changes.
- **One path for every change.** The registry's publisher builds and signs
  both bundles: the policy from Git once its policy change is approved, the
  project data once a project change is. A merge to `main` alone doesn't change
  what OPA loads. OPA Control Plane is retired (see
  [Why OCP goes](#why-ocp-goes)).

**Out of scope:** the Rego policy, the model catalog (`catalog/models.yaml`)
and the project schema stay in Git, reviewed by the platform team in pull
requests. The registry decides only when a merged commit reaches OPA.

## Architecture

```mermaid
flowchart LR
  kc[Keycloak<br/>people, one OAuth client per project]
  ui[Portal UI] --> api[Registry API]
  api --> pg[(Postgres<br/>projects, changes,<br/>approvals, audit log)]
  api -->|diff| opap[OPA: required approvals]
  api --> kc
  pg -->|outbox| pub[Publisher<br/>check, replay,<br/>build and sign]
  git[Git main: Rego, catalog, schema<br/>reviewed in pull requests] -->|new commit:<br/>a policy change| pub
  pub -->|policy changes| pg
  vt[Vault Transit<br/>signing key] -.-> pub
  pub -->|gateway-policy,<br/>gateway-projects| s3[(Object store<br/>versioned bundles,<br/>copied to each site)]
  s3 --> opa[OPA, N per site<br/>verifies signatures]
  opa -->|status: bundle revisions| api
  gw[agentgateway] -->|ext_authz| opa
  opa -->|allow + limits in<br/>dynamic metadata| gw
  gw -->|descriptors with<br/>limitOverride| rl[rate-limit service]
```

## Decisions

### Limits travel with the decision

This is the decision the rest depends on.

- **OPA returns the limits.** Each project's limits and budget are fields in
  the `gateway-projects` data bundle. The allow decision returns them as gRPC
  `dynamic_metadata`.
- **The gateway applies them.** agentgateway reads that metadata in CEL as
  `extauthz.*`, and each rate-limit descriptor sets `limitOverride` from it,
  for example `{"unit": "minute", "requestsPerUnit": extauthz.rpm}`.
- **The rate-limit service counts.** It honours an override for any
  descriptor in a known domain, with no entry for the project in its config.
  Its config shrinks to the domain and a default entry with a limit of 0, and
  stops changing with projects.

What this fixes:

- **A limit change is atomic.** It is one field in one project's data, so it
  goes live in the same bundle as the project's access.
- **No more paths out of step.** Today a project change reaches OPA, the
  rate-limit config and the alert rules separately. That gap, and a new
  project being let through without limits until the rate-limit sync, both
  go away.
- **No tiers.** An earlier draft had a fixed set of tiers. The spike showed
  the value itself can travel, so each project gets its own number.

**Every override expression needs a default of 0**, for example
`has(extauthz.rpm) ? extauthz.rpm : 0`. agentgateway skips a descriptor whose
expression fails to evaluate, which means no limit. With the default, a
project OPA allows but has no limits for is refused.

Metadata, not a request header. A client cannot forge `extauthz.*`, and a
header would also have to be stripped before the upstream call.

### Two signed bundles, no OCP

| Bundle | Roots | Built by | When |
|--------|-------|----------|------|
| `gateway-policy` | `gateway`, `catalog`, `system`, `portal` | the publisher, from a commit on `main` | when that commit's policy change is approved (a few times a week) |
| `gateway-projects` | `projects`, `exceptions`, `agents` | the publisher | on every approved change |

- **Signing:** the publisher signs both. The key lives in Vault Transit and
  is never exported, and the publisher's Vault role can only sign with it.
  `opa build` hashes the files with a throwaway key, and the token is signed
  again through Transit (`registry/bundles.py`).
- **Verification:** OPA verifies each bundle with the public key in its
  `keys` config and refuses a bundle without a valid signature. A bundle that
  fails verification leaves the last good one active (`persist: true`).
- **Roots:** each bundle declares its roots in `.manifest`, and the roots are
  disjoint, as today (`policies/gateway-projects`).
- **Versions:** each bundle is written under its revision. A `latest` object
  points at the active revision, so a rollback is moving `latest` back.

### Callers authenticate with JWTs

- **One OAuth client per project or agent.** Each project gets a client in Keycloak
  (client credentials), and its tokens carry a `project` claim.
- **The gateway validates tokens** against Keycloak's JWKS. OPA reads the
  project from the claim instead of the API key's metadata.
- **The key path goes away.** Keys are created in Vault, synced by VSO and
  pushed to the gateway over xDS. That chain grows with every project and is
  removed.
- **The registry manages the clients.** It creates, rotates and revokes them
  through Keycloak's admin API. A client secret is shown once, in the portal.
- **Migration:** OPA accepts both the claim and the API key metadata while
  projects move over. API keys get an end date.

### One validation library

`gen-projects.py`'s loading, model resolution, agent checks and schema
validation become a library:

- the registry calls it when a change is submitted;
- the publisher calls it when it renders;
- CI keeps calling it on the YAML during migration.

The model choices a project sees are the intersection of the catalog in Git
and the model registry's versions in lifecycle `prod`, so a model the
onboarding pipeline promotes shows up without a catalog edit.

### Approval rules are policy

The registry sends a change's diff to OPA and asks
`data.portal.required_approvals`. The rules are Rego in Git, reviewed like
the gateway policy.

| The change | Approved by |
|------------|-------------|
| Add or remove models within the data class, lower a limit, edit a description | the project owner |
| Raise a limit or the budget | plus the cost owner |
| Raise `data_class`, add an exception (with an expiry date), wildcard `mcp_tools`, raise an agent's `autonomy` | plus security |
| Create a project | the platform team and security |

Two rules hold for every change:

- **Four eyes:** nobody approves their own change.
- **No bypass:** platform admins can't skip approval either.

Who may propose a change at all is policy too, `data.portal.may_submit`
(with the requester's groups and the project's owner group as input):

- **A new project:** anyone signed in may request one. The platform team and
  security approve it.
- **Anything else:** the project's owner group, for the project and for its
  agents and exceptions, and the platform team. Everyone else gets 403.

### "Active" comes from OPA

- **OPA reports.** Every OPA runs the status plugin and reports the bundle
  revisions it has loaded to the registry's `/opa/status`, with its pod name
  as a label.
- **Active means every ready OPA.** A change is `active` once every ready pod
  behind the OPA Service (its EndpointSlices, which the registry may list) has
  reported a revision at or after the change's. A replaced pod stops counting
  at once. Without access to the Kubernetes API, the registry falls back to
  every OPA that reported in the last 5 minutes. With several sites, it would
  be every site's OPA.
- **Checked without a report.** OPA reports only when something changes, so
  the publisher's loop checks on every round too.
- **Late changes alert.** A change that isn't active within a set time raises
  an alert (not built yet).

### The registry is off the request path

- **Requests keep working.** OPA keeps deciding with its cached bundles. While
  the registry is down, nobody can change a project; nothing else stops.
- **Modest availability.** One Postgres primary with a standby and
  point-in-time recovery is enough.
- **Multiple sites.** The registry runs on one primary site. Bundles are
  copied to an object store on each site, and each site's OPA pulls only from
  its own.

## Data model (Postgres)

```
project(id, owner_group, data_class, placement, routing, limits jsonb,
        budget_usd_per_30_days, mcp_tools[],
        status[active|suspended|deleted], revision)
project_model(project_id, model)              -- explicitly granted models
exception(project_id, models[], why, owner, expires_at)
agent(project_id, name, autonomy, models, mcp_tools, ...)  -- as in agents/*.yaml today
oauth_client(project_id, client_id, created_at, rotated_at, revoked_at)
change_request(id, project_id, diff jsonb, state, required_approvals jsonb,
               replay_report jsonb, bundle_revision, created_by, created_at)
approval(change_id, approver, role, decision, comment, at)
audit_log(seq, at, actor, action, object, before jsonb, after jsonb)
outbox(seq, change_id, published_at)
```

- **The audit log is append-only.** It is exported to WORM storage and the
  SIEM.
- **Change states:** `pending_approval → approved → publishing → active`.
  A change can also end in `rejected`, `withdrawn` (by its author or the
  platform team, before it is published), `failed` or `rolled_back`.

## Publishing

The publisher:

1. **Takes approved changes** from the outbox. Changes are batched, at most
   one publish every 30 seconds.
2. **Renders** every project's `data.json` with the shared library. Only the
   changed projects differ, and the output has a stable hash.
3. **Replays** the last N days of decision logs against the new data bundle
   and the active policy bundle (`scripts/policy-replay.py`):
   - decisions change only for the changed projects: continue;
   - decisions change for any other project: stop and mark the change
     `failed`. This is the safety valve.
4. **Builds, signs and uploads** the bundle under its revision, then moves
   `latest`.
5. **Waits for OPA** to report the revision, then marks the change `active`.

**A policy change** goes through the same publisher. Its source is Git, not
the portal: the pull request is reviewed and tested there (CI: `opa test`,
the two-bundle load), and merging it changes nothing yet. Every minute the
publisher checks `main`. For a new commit it:

1. runs `opa test`, and builds and signs the bundle without activating it;
2. renders the records with that commit's `gen-projects.py`;
3. replays recent decisions under the active bundles and under the new pair.
   A policy change is expected to change decisions, so the replay is a
   report for the approvers, not a stop. Two mixed pairs are replayed too
   when the data format changes, because each OPA loads the two bundles on
   its own: the old policy with the new data, and the new policy with the
   old. If either decides a request differently from both full pairs, the
   commit is refused, and the change is staged (first a policy that reads
   both formats);
4. files a change request of kind `policy`, shown in the portal with the
   commit, a link to its diff and the replay.

`portal.rego` decides its approvals: the platform team and security. Once
approved, the publisher activates the records rendered at the commit, if
they differ, then the policy. If either bundle moved while the change waited,
it is checked again first: an unsafe result fails it, and an outcome the
approvers didn't see sends it back to them. A newer commit supersedes a
change still waiting, and a commit whose test fails is filed as `failed`.
A commit under which neither bundle changes (docs, another chart: the same
policy files, the same rendered records, and the same `gen-projects.py` and
the files it reads) is recorded as `skipped`, with no approval; OPA keeps
the active commit.
Before merging, `scripts/policy-replay.py` gives the replay from a checkout.

**Order of operations:**

- **A new project:** create the OAuth client first, then publish the bundle
  that allows it.
- **A removed project:** publish the bundle with status `deleted`, wait until
  it is active, then revoke the client.
- **A rollback:** point `latest` at the previous revision, one action in the
  portal, recorded in the audit log.

## Budgets and reporting

- **Budget alerts:** the registry exports `project_budget_usd{project}` on
  `/metrics`, which Prometheus scrapes through the pod's annotations. One alert
  rule, `GatewayProjectBudgetForecast`, joins it `on(project)` with the last
  24 hours of spend, so the number of rules no longer grows with projects, and
  a budget changed in the registry is the one the alert uses. Built.
- **Usage pages** in the portal read Prometheus (spend, requests),
  agentgateway Analytics and Langfuse. Not built: the PoC portal shows the
  records, changes and publications only.
- **The budget window** stays the rate-limit service's fixed 30-day window
  (`budget.usd_per_30_days`), now sent as an override with unit `month`.

## API

Built in the proof of concept. `{collection}` is `projects`, `agents` or
`exceptions`; every edit creates a change request, and the record changes only
once it is published.

```
GET    /{collection}                  GET    /{collection}/{id}
POST   /{collection}/{id}             create  (body: {"spec": {...}}; a project also
                                               needs "owner_group")
PATCH  /{collection}/{id}             update  (body: {"spec": <JSON merge patch>})
DELETE /{collection}/{id}             delete
GET    /changes/{id}                  the diff, approvals needed and given, replay
                                      report, state, bundle revision
POST   /changes/{id}/approve|reject   (body: {"comment": ...})
POST   /changes/{id}/withdraw         its author or the platform team, before it is published
GET    /publications                  published revisions, newest first
GET    /export                        every record (the format of the seed and the snapshots)
GET    /internal/keys|mirrors         API key ids, for the Vault bootstrap (cluster-internal)
GET    /internal/bundles/{bundle}     the active bundle, for policy-replay.py (cluster-internal)
GET    /metrics                       project_budget_usd, for Prometheus (cluster-internal)
POST   /rollback/{revision}           platform team only
POST   /opa/status                    OPA's status reports (cluster-internal)
GET    /healthz
```

Designed, not built yet: `GET /projects?owner=me`,
`GET /projects/{id}/allowed-models` and `POST /projects/{id}/clients[/rotate|/revoke]`.

### Using it

**In a browser:** `http://registry.test/portal/`. Add `registry.test` to the
`.test` hosts in `/etc/hosts` (README, "Reaching the ingress"). Log in with a
Keycloak account of the realm. The portal shows:

- projects, and the changes to each;
- a form to propose a change (a JSON merge patch over the record) or to
  request a new project;
- every change request with its diff, its approvals and the replay report,
  with approve, reject and withdraw;
- policy changes: each new commit on `main` of `policies/gateway`, with its
  subject, a link to the diff on GitHub and its replay report;
- the published bundles of both kinds, with rollback for the platform team.

It logs in with the authorization code flow and PKCE through the public client
`project-registry`, and calls the API with that token.

**From the command line**, the same API. Through the ingress at
`http://registry.test`, or with a port-forward:

```bash
kubectl -n mini-platform port-forward svc/project-registry 8080:8080
kubectl -n mini-platform port-forward svc/keycloak 8090:80
```

Log in as a Keycloak user of the realm, through the registry's client:

```bash
TOKEN=$(curl -s -H 'Host: keycloak.test' \
  -d grant_type=password -d client_id=project-registry -d username=platform-user \
  --data-urlencode "password=$PASSWORD" \
  http://127.0.0.1:8090/realms/mini-platform/protocol/openid-connect/token | jq -r .access_token)
```

The `Host` header makes the token's issuer `http://keycloak.test/...`, which the
registry checks. The passwords are in Vault: `platform-admin` and `platform-user`
in `mini-platform/keycloak-sso`, `security-reviewer` and `cost-owner` in
`mini-platform/keycloak-registry-users`.

Lower a project's request limit, then let someone else approve it:

```bash
curl -s -X PATCH -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"spec": {"limits": {"requests_per_minute": 30}}}' http://127.0.0.1:8080/projects/admin
curl -s -X POST -H "Authorization: Bearer $OWNER_TOKEN" -H 'Content-Type: application/json' \
  -d '{"comment": "ok"}' http://127.0.0.1:8080/changes/<id>/approve
curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/changes/<id>
```

The change is `active` within about a minute of its last approval. Every
imported project's owner group is `project-owners` (`platform-user`), so a
change `platform-admin` proposes is approved by an owner who isn't its author;
`cost-owner` and `security-reviewer` hold the other two roles.

### Where the records are, and their copies

The projects, agents and exceptions live only in the registry's database. This
repo has their format and the renderer, not a copy: no `projects/*.yaml`, no
generated `policies/gateway-projects/` data, no export pull requests.

- **Copies:** the CronJob `project-registry-snapshot` (03:00 UTC) writes every
  record to `registry-snapshots/<time>.json` and `latest.json` in the bundle
  store, and every published data bundle revision is kept. Neither is a backup
  of the database (approvals, audit log). To take one now:
  `kubectl -n mini-platform create job --from=cronjob/project-registry-snapshot snapshot-now`.
- **An empty registry** (the import job, `registry/importer.py`) loads the
  latest snapshot, or on a new cluster the seed,
  `minikube/gitops/project-registry/files/seed.yaml`: the platform's own
  projects. The seed is read only then; it is not kept current.
- **What reads the records,** from the registry: the Vault bootstrap gets the API
  key ids from `/internal/keys` and `/internal/mirrors` (cluster-internal); the
  publisher applies the registered agents to agentregistry after each publish
  and every hour; `scripts/policy-replay.py` gets the active data bundle from
  `/internal/bundles/gateway-projects`. A new key id still needs the bootstrap
  (`SEED_MISSING_ONLY=true`) to create its key, until callers move to OAuth
  clients.

### Rotating the signing key

OPA verifies each bundle with the one key its config names for it
(`signing.keyid`), whatever key id the signature itself carries. So the
builders and OPA move to a new key in a single change, and the active bundles
are signed again for the new key:

1. Create the new version in Vault: `vault write -f transit/keys/opa-bundles/rotate`.
   The publisher keeps signing with the pinned version (`keyVersion`), so
   nothing changes yet.
2. Publish the new version's public key in a field of its own, next to the old
   one, for example version 2:
   `vault kv patch mini-platform/opa-bundle-signing public_key_v2="$(vault read -format=json transit/keys/opa-bundles | jq -r '.data.keys["2"].public_key')"`.
   Nothing reads it yet: an OPA pod that restarts now still gets version 1's
   key from `public_key`.
3. In one commit, set `signing.keyVersion: 2` and `signing.keyid: opa-bundles-v2`
   in the `project-registry` values, and `signing.keyid: opa-bundles-v2` and
   `signing.publicKeyField: public_key_v2` in the `opa-policy` values, and merge it.
4. The rest is automatic:
   - **Publisher:** it sees that the active bundles are signed with another key
     and signs them again: the same commit, and the same records in a new data
     revision. No approval, since the content is unchanged.
   - **New OPA pods** start with the new key and become ready once the re-signed
     bundles are there.
   - **Old OPA pods** keep the bundles they have loaded and refuse the re-signed
     ones, so the rolling update has no gap.
   - **Publishing:** a change published while the rollout runs reaches the new
     pods only.
5. When the rollout is done, retire the old version:
   `vault write transit/keys/opa-bundles/config min_encryption_version=2 min_decryption_version=2`.
   `min_encryption_version` is what stops a signature with version 1 (Transit
   counts signing as encryption), `min_decryption_version` hides it from reads.
   Version 1 still exists until `transit/keys/opa-bundles/trim`, which
   deletes it for good. The old `public_key` field in KV can stay, since
   nothing reads it.

Done on the cluster on 2026-11-13, from version 1 to 2. A gateway call every
second throughout got 101 of 101 answers. The new OPA pod refused the v1
bundles until both builders had re-signed (about 50 seconds), then took over
from the old pod. That run also found and fixed a flaw in activation: a
change published right after an OPA rollout stayed `publishing`, because the
replaced pod's last report still counted.

## Why OCP goes

Before phase 2, OCP built both bundles from Git and uploaded them to MinIO. In phase 2:

| OCP did | Phase 2 | Why not OCP |
|----------------|---------|-------------|
| Builds bundles from Git | the publisher builds `gateway-policy` from an approved commit, and `gateway-projects` from Postgres | project data no longer comes from Git, and a commit needs an approval first |
| Uploads to the object store | the publisher uploads both | one upload needs no service |
| Pulls HTTP data sources on a timer | the publisher pushes on approved changes | a timer leaves no place for checks before publishing |

And phase 2 needs three things OCP 0.10 doesn't do:

1. **Signing.** OCP has no signing option in its config or its code.
2. **Checks before publishing.** Replay and approval have to pass before a
   bundle goes out. OCP publishes whatever it builds.
3. **Activation status.** This comes from OPA status reports, which don't
   involve OCP.

Retiring OCP also removes:

- its single replica and SQLite state;
- the manual override of `ocp.repo` and `ocp.reference` that deploying a
  branch to the cluster needed. To try a branch now, point the registry's
  `policy.ref` at it: its commits become policy changes like those of `main`.

Distributing bundles through an OCI registry later is `opa build` plus
`oras push`, so it doesn't need OCP either.

## Migration from `projects/*.yaml`

1. **Policy bundle out of OCP.** A build outside OCP signs and uploads
   `gateway-policy`, and OPA verifies signatures on that bundle. OCP keeps
   building `gateway-projects` only. (In the proof of concept, first a
   CronJob, now the registry's policy change requests.)
2. **Import.** Load `projects/*.yaml` into Postgres.
3. **Shadow run.** The publisher renders next to `gen-projects.py`, and every
   CI run compares the two; the output must match byte for byte. Cut over
   after a week without a difference.
4. **Cut over the data.** OPA pulls `gateway-projects` from the publisher's
   location and verifies its signature. OCP is removed.
   `projects/` becomes read-only, with a daily snapshot exported to Git for
   reading and disaster recovery.
5. **Limits to OPA.** Add the limits to OPA's metadata and `limitOverride` to
   the descriptors while the per-project rate-limit config is still there,
   compare the counts, then cut the config down to the default entry.
6. **JWTs.** New projects get only an OAuth client. Existing API keys get an
   end date.

**In the proof of concept**, steps 1 to 5 were done together, without the
week of shadow running:

- The import compared its render with Git once, byte for byte. It matched, so
  it published.
- The limits moved to OPA one deployment after the registry, so OPA already
  returned them when the gateway started reading them.
- `projects/` was then removed from Git: the registry is the records' only
  home, with daily snapshots in the bundle store, and a seed for a new
  cluster.
- Step 6 is the next round.

## Proof of concept

### What was built

- **The registry** (`registry/api.py`, FastAPI on its own PostgreSQL). Every
  edit is a change request.
  - It is validated by rendering the whole data bundle with it, using
    `scripts/gen-projects.py` from this repo at the commit of the active policy
    bundle. That makes it the one validation library, kept in Git.
  - Its approvals come from `data.portal.required_approvals`
    (`policies/gateway/portal.rego`, in the policy bundle) and are checked
    against the caller's Keycloak groups. Nobody approves their own change.
  - Every step goes to the append-only audit log.
- **The publisher** (`registry/publisher.py`) runs in one database transaction:
  1. take approved changes, batched at most every 30 seconds, and apply them;
  2. render the bundle;
  3. replay recent decisions;
  4. build, sign and upload the bundle, then activate it.

  A failure anywhere leaves the records, and what OPA loads, unchanged, and
  marks the changes `failed` with the reason. A change is `active` once every
  ready OPA pod has reported its revision (`registry/activation.py`, checked on
  every report and every round of the publisher).
- **Policy changes** (`registry/policy.py`, in the publisher): every minute it
  checks `main` (`policy.ref`). For a new commit it:
  1. runs `opa test`;
  2. builds and signs `gateway-policy`, but doesn't activate it;
  3. renders the records with that commit's `gen-projects.py`;
  4. replays recent decisions under the active bundles and the new ones;
  5. files a change request of kind `policy`.

  It is approved like any change; `portal.rego` asks for the platform team and
  security. Then the publisher activates the records rendered at that commit
  (if they differ), and then the policy. It is `active` once every ready OPA
  pod reports the commit. A rollback moves one bundle, so it is refused
  when the records would not render the same at the target commit (a data
  format change in between); a revert commit then republishes both. Each OPA
  loads the two bundles on its own, so a commit that changes the data format
  is replayed under both mixed pairs too (old policy with new data, new policy
  with old data); if either decides a request differently from both the old
  and the new pair, the commit is filed as `failed`. Such a change is staged:
  first a policy that reads both formats, then the format change. If either
  bundle is published while the change waits, it is checked again before it
  goes live: an unsafe result fails it, and an outcome the approvers didn't see
  sends it back to them.

  This replaces the first round's policy build, a CronJob that activated every
  commit on `main` within a minute, without an approval or a replay. The build
  runs in the cluster because GitHub Actions can't reach its Vault or MinIO.
  OPA Control Plane is removed too.
- **Signing**: one RSA key in Vault Transit, not exportable. The publisher's
  Vault role (`bundle-signer`) can only sign. `opa build` computes the file
  hashes with a throwaway key, and the token is then re-signed through Transit
  (`registry/bundles.py`). OPA verifies both bundles.
- **The import** (`registry/importer.py`, a PostSync hook): the first load of an
  empty registry, from its latest snapshot or the seed. The first import, from
  `projects/*.yaml` when they were still in Git, rendered byte for byte what
  Git had: 5 projects, 5 agents, 2 exceptions. The seed is those records.
- **Limits from OPA**: the allow decision carries `limits` as dynamic metadata.
  Every descriptor's `limitOverride` reads it, defaulting to 0. The rate-limit
  config is down to the domain and a default entry.
- **Who may propose** a change is policy too (`portal.may_submit`), and a change
  not yet published can be withdrawn by its author or the platform team.
- **The portal** (`registry/static/portal.html`, at `registry.test/portal/`):
  - Keycloak login with PKCE;
  - projects and their changes;
  - proposing a change or a new project;
  - change requests with their diff, approvals and replay report, and the
    buttons to act on them;
  - publications of both bundles, with rollback.
- **The budget metric** `project_budget_usd` and one budget alert rule for all
  projects.
- **Copies of the records**: a daily snapshot into the bundle store (the
  CronJob `project-registry-snapshot`). It replaced a daily export to Git as a
  pull request, and the GitHub token that came with it.
- **Key rotation**: a pinned Transit key version; the publisher re-signs the
  active bundles for a new key. Done on the cluster, version 1 to 2 (see
  "Rotating the signing key").

### Where it differs from this design

- **The replay compares the active and the candidate data bundle.** Both are
  evaluated against the logged inputs, under the active policy. Comparing with
  the logged verdicts, as first written, would blame a project change for
  every verdict a policy or catalog change had flipped since the requests were
  logged, and block every publish for the replay window.
- **Records are documents.** The registry stores each project, agent and
  exception as the JSON of its YAML file (`resource.spec`), not in the
  normalized tables of the data model above. Rendering through
  `gen-projects.py` needs exactly that format.
- **Owners are groups.** Each project has an owner group (`project_owner`). The
  import gives every project `project-owners`. Who may submit is policy
  (`portal.may_submit`), as is who approves.
- **Callers still use API keys.** The OAuth clients, and the check that a JWT
  call and an API key call get the same decision, are the next round.
- **Store layout.** No `latest` pointer: each build is kept under
  `<bundle>/revisions/<revision>/`, and activating one copies it to
  `<bundle>/bundle.tar.gz` (what OPA pulls) and records it in
  `<bundle>/active.json`.

### Checks (all on the cluster, through the gateway)

| Check | Result |
|-------|--------|
| `admin` 60 → 3 requests a minute, then 3 → 120 | 3/min: `admin` gets 429 at once, `open-webui` keeps 200; 120/min: 200 again. Active everywhere 9 s after the last approval. The rate-limit pod never restarted (0 restarts across 7 publishes) |
| Approvals | Lowering a limit: the owner only. Raising: the owner and the cost owner. Security can't approve a cost change (403), and nobody can approve their own (403) |
| Replay | 1,800–1,860 logged decisions replayed per publish; 0 changed for other projects |
| Bad signature | A `gateway-projects` bundle with `admin` edited to 1/min, uploaded straight to MinIO: OPA refuses it (`data.json: digest mismatch`) and keeps the signed one; `admin` keeps its real limit |
| Registry down | API and publisher at 0 pods: the gateway keeps serving models and chat, and OPA's status reports fail quietly |
| Policy build (first round) | A failing `opa test` publishes nothing (tested in the repo); on the cluster the first build replaced OCP's unsigned bundle, which OPA refused for its missing signature |
| Policy changes through the registry | On deploy the registry adopted the active policy commit, then filed the branch's head as a policy change: 1,326 decisions replayed, 0 changed. A newer commit superseded it (`withdrawn`, "superseded by …"). After the approval the change was active everywhere in 15 s, without republishing the unchanged records; the gateway kept answering 200. Rollback to the previous commit and forward again worked through the API; security may not roll back (403). A change approved under the new `portal.rego` needed the platform team and security |
| Key rotation (v1 → v2) | A gateway call every second throughout: 101 of 101 answered. The new OPA pod became ready once both builders had re-signed (about 50 s) |
| Submit rights, withdraw | Security and the cost owner can't propose changes to a project (403); a change nobody could approve was withdrawn by its author |
| Portal login | Authorization code with PKCE, run by script through the ingress: a token the registry accepts, CORS allowed for `registry.test`, refresh works; a wrong verifier is refused |
| Daily export | Run with the real token: clone, render, compare; "nothing to export" while Git matches the registry |

A change that alters another project's decisions can't be produced through
valid project data with the current Rego: every rule reads only the
requesting project's entries, and agents are checked against their project.
The valve is tested with real `opa eval` in the repo (`tests/test_replay.py`);
on the cluster, every publish so far changed nothing for other projects.

### Not built yet

- one OAuth client per project and the JWT path (decision "Callers authenticate
  with JWTs");
- a portal page richer than the PoC's (one page: lists, a JSON merge patch
  editor, approvals; a Backstage plugin later);
- API keys in Vault are still created by the bootstrap, run by a person after a
  new key id (it reads the ids from the registry);
- copies of the bundles to other sites;
- the model choices as the intersection of the catalog and the model
  registry's `prod` versions.


## Spike: limits set by OPA

**Question:** can agentgateway take rate-limit values from the ext_authz
response? Decision 1 depends on it.

**Source checks** (agentgateway v1.7.0, envoyproxy/ratelimit 5ae0682e):

- **Order.** ext_authz runs before remote rate limiting. Gateway-level
  policies merge into the route phase, so they also run after ext_authz.
- **Metadata in CEL.** OPA's gRPC `dynamic_metadata` is readable in CEL as
  `extauthz.*`.
- **Overrides.** Descriptors take `limitOverride`, a CEL expression returning
  `{"unit", "requestsPerUnit"}`, and the installed CRD has the field.
- **The service.** `GetLimit` uses an override for any descriptor in a known
  domain.

**The test:** agentgateway 1.7.0, OPA 1.22.2-envoy, ratelimit and Redis, in
Docker, the same images as the cluster. The cluster was not touched.

| Case | Result |
|------|--------|
| Project a, OPA data rpm 2 | `200 200 429 429` |
| Project b, rpm 5 | five 200s, then 429 |
| Project c, allowed, no limit in the data | 429 from the first call (default 0) |
| Project z, denied by OPA | 403 |
| Client sends `x-rl-rpm: 1000` | no effect, still 429 |
| Change a to 10 and c to 3 through OPA's data API | live at once, no rate-limit restart |
| Rate-limit service stopped, `failClosed` | 500 (the cluster uses `FailOpen` on purpose) |

**Followed up in the proof of concept** (on the cluster, with the registry):

- **Tokens.** A limit of 30 tokens a minute: two 20-token calls went through
  and the third was refused. So the override still applies when the cost is
  counted on the response.
- **Budget.** A budget of 1 micro-USD refused the next call, DeepSeek or the
  free local model, because the project had already spent more than that in
  the 30-day window. Restoring it to $25 let calls through again.
- **Changing a limit mid-window.** The window's count carries over: the cache
  key doesn't include the limit. Lowering a limit below what was already
  counted refuses the next call at once, and raising it lets calls through at
  once.
