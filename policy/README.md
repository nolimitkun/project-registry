# policy/

The policy of [Mini Platform](https://github.com/nolimitkun/mini-platform-deployment)'s AI gateway, in the project registry's repository. OPA decides every model call, Google API call and MCP tool call that agentgateway receives, with what is in this directory. The registry publishes it: whatever renders, tests or builds the policy sees only this directory, so the registry's own code beside it never changes a bundle.

| Path | What |
|---|---|
| `policies/gateway/` | the Rego: the decision (`authz.rego`), the model behind `auto` (`select.rego`, `rankings.rego`), what the decision log keeps (`log_mask.rego`), who proposes and who approves a project registry change (`portal.rego`), and their tests. This directory is the `gateway-policy` bundle; the data classes, autonomy and approvals are the registry's setting records |
| `projects/schema.json`, `agents/schema.json`, `settings/schema.json` | the format of the project registry's project, agent and setting records |
| `scripts/gen-projects.py` | validates records against the schemas and the rules across them, and renders the `gateway-projects` bundle |
| `scripts/gen-settings.py` | validates the setting records (the parameters reviewers decide: data classes, autonomy, who approves what) and renders `data.registry.settings` in the `gateway-projects` bundle |
| `scripts/gen-catalog.py` | validates the catalog's records (written as `catalog/models.yaml` and `catalog/tools.yaml`) and renders `data.registry.catalog` in the `gateway-projects` bundle and the values of `charts/gateway-models` |
| `scripts/render-records.py` | renders a file of records (the format of the registry's `/export`) |
| `scripts/policy-replay.py` | replays recent gateway decisions from Loki against the policy in a checkout |
| `scripts/tools-drift.py` | reports MCP tools that appeared, vanished or changed since they were classified (the registry's tool records) |
| `charts/gateway-models` | the gateway's model routes (an AgentgatewayModel per model, the `auto` models, the Google API routes), templated over the catalog: the project registry packages it at the active policy commit and publishes it to its Helm repository in MinIO, which Argo CD installs |
| `fixtures/records.yaml` | the records CI tests the Rego with: projects and the catalog |

The records themselves are not here: the projects, agents and exceptions, and the
catalog (every model and Google API with its placement, provider settings and price;
every MCP tool with the most it can do; the task classes behind `auto`, the serving
namespaces, the MCP targets) live in the project registry's database,
and change there, approved as `portal.rego` says. So do the policy's parameters that
reviewers decide, as setting records: the placements each data class allows, what each
agent autonomy may do without a human, and who approves each kind of change
(`portal.rego` says what a change does and keeps the floors no setting can lower: a
project's owner for its records, the platform team for the policy, the catalog and the
settings, security for the policy and the settings). This directory has the rules,
their format and the renderers.

## How a change goes live

1. A pull request to this repository, with CI: `policy/scripts/validate.sh` (the test records render, the chart renders with them, the Rego passes `opa check`, `opa fmt` and `opa test`, and both bundles build and load together), and the registry's tests with the policy of the same commit. A change to the registry and to the policy (a new record kind, say) is one pull request.
2. Merged to `main`, nothing changes yet. Within a minute the project registry files the commit as a **policy change request**:
   - it tests the commit with its live records rendered at it;
   - it builds and signs the bundle;
   - it replays recent decisions under the active bundles and under the new ones.

   A commit that changes nothing in `policy/` (the registry's code only) is followed with no request: the same bundle under the new commit. One that changes only files no publish reads (docs, CI, the test fixtures, and the scripts run by hand or in CI: `validate.sh`, `policy-replay.py`, `tools-drift.py`, `render-records.py`; `registry/policy.py` `INERT`), and neither bundle, is recorded as `skipped`.
3. The approvers decide in the registry's portal, where they read the diff file by file. `portal.rego` (the active one) says who approves: the platform team and security. Then the registry publishes the bundle, and OPA verifies its signature and loads it.

**What the gateway takes from here**, through the project registry, not a pin: the
registry packages `charts/gateway-models` at the active policy commit with its catalog
records rendered as values, and publishes it to its Helm repository in MinIO whenever
either changes; the deployment repo's Argo CD application `gateway-models` installs the
newest version. A new model is therefore one approved catalog change in the registry
(plus its serving release in the deployment repo, for a self-hosted one); a change to
the chart in this directory is a policy change.

The deployment repo's CI checks its own wiring against its registry seed (the catalog a
new cluster starts with): its MCP targets, serving namespaces and the semantic router's
decisions against the catalog's settings, and the kagent agents' keys against the seed (`KAGENT_VALUES`,
`KAGENT_RESOURCES`: each agent's ModelConfig reads a `vaultSecrets` copy of one of its keys). The gateway's
API keys themselves the registry writes to Vault from its records.

## Locally

```bash
cd policy
pip install jsonschema pyyaml          # and opa and helm on PATH
./scripts/validate.sh                  # what CI runs
python3 scripts/render-records.py fixtures/records.yaml --out /tmp/gp && opa test policies/gateway /tmp/gp
python3 scripts/tools-drift.py         # needs the cluster: the gateway's MCP tools against the registry's
python3 scripts/policy-replay.py       # needs the cluster: Loki, and the active data from the registry
```

This directory was nolimitkun/gateway-policy until 2026-11-15, and its history came along (`git log -- policy/`); before that the files were in the deployment repo (`policies/`, `catalog/`, `scripts/gen-*.py`).
