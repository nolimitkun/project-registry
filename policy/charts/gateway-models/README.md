# gateway-models

The gateway's model routes, templated over the catalog (the project registry's
`model`, `google_api` and `catalog` records, rendered by `scripts/gen-catalog.py`):

- one `AgentgatewayModel` per model: a KServe release routes to its InferencePool in
  its serving namespace, with the name vLLM serves; Vertex AI and DeepSeek models
  route to their provider;
- `auto` and `auto-<task>`: virtual models that ask OPA which model the caller's
  project gets (`policies/gateway/select.rego`);
- each Google API: an `AgentgatewayBackend` and an `HTTPRoute` under `/google/<name>/`.

Nobody installs this directory as it is. The project registry packages the chart at
the active policy commit with its catalog records rendered as the `catalog` value,
whenever either changes, as version `1.0.<n>`,
and publishes it to its Helm repository in MinIO (bucket `gateway-models`). The
deployment repo's Argo CD application `gateway-models` installs the newest version
with the gateway's own values (`gatewayName`, `gcp`, `kserve`, `auto`).

A change here is a policy change, and a change to the catalog a registry change
request: either is tested, replayed and approved, then live within a few minutes
(Argo CD polls the repository).
