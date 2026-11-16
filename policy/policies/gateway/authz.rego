# Gateway authorization for agentgateway, evaluated by OPA through Envoy's
# ext_authz protocol. The project registry tests each new commit of this
# directory, builds it into a signed bundle and, once the policy change is
# approved, publishes it to MinIO, where the OPA next to the gateway picks it
# up and verifies its signature.
#
# Every API key belongs to a project (the project registry's records, rendered
# into data.projects by scripts/gen-projects.py). A project has a data class, which
# caps the placements it may use (mini-cloud docs/gcp/ai-inference.md); each
# model or Google API has one placement (lib.catalog: the project registry's catalog).
# Anything not explicitly allowed is denied.
package gateway.authz

import rego.v1

import data.gateway.lib

default allow := false

# What agentgateway attaches after checking the API key (agentgateway-config
# policies.yaml, requestMetadata). OPA-Envoy hands the protobuf over as
# protojson, hence the camelCase.
key_metadata := input.attributes.metadataContext.filterMetadata.agentgateway

project_id := key_metadata.project

key_id := key_metadata.key_id

project := data.projects[project_id]

# The key is one the project lists. Dropping a key id from the project file
# revokes it as soon as OPA loads the new bundle.
authenticated if key_id in project.keys

# The registered agent the key belongs to (the registry's agents), if any. Its calls
# get the agent's scope: fewer models and tools than the project, never more.
agent_id := project.agent_keys[key_id]

agent := data.agents[agent_id]

# The models this key may use (lib.scoped).
scope_models := lib.scoped(project_id, key_id)

# Without the query string, so "/v1/models?x" is still "/v1/models".
path := split(input.attributes.request.http.path, "?")[0]

# Model calls: the requested model must be one the project may use.
allow if {
	authenticated
	model_path
	allowed_model(input.parsed_body.model)
}

# Listing models reveals nothing a project can't already ask for.
allow if {
	authenticated
	path == "/v1/models"
}

# A self-hosted model deployment by KServe's own path route,
# /<namespace>/<name>/v1/... in a serving namespace (catalog servingNamespaces):
# the onboarding pipeline evaluating exactly what it deployed, before the
# catalog names it. Only projects with deployments: true, never an agent's key.
allow if {
	authenticated
	deployment_path
	project.deployments
	not agent_id
	"onprem" in lib.placements(project_id)
}

# Google's native APIs (speech, TTS, Vertex) under /google/<api>/.
allow if {
	authenticated
	google_api
	lib.catalog.google_apis[google_api].placement in lib.placements(project_id)
}

# The API a /google/<api>/... path names.
google_api := parts[2] if {
	parts := split(path, "/")
	parts[1] == "google"
	count(parts) > 3
}

google_path if startswith(path, "/google/")

# MCP (the merged endpoint at /mcp). A project with mcp_tools may open
# sessions, list tools and so on; each tools/call must name a catalog tool
# matching one of its patterns. Tool names carry the target as a prefix, e.g.
# grafana_query_prometheus. A name the catalog doesn't list is refused for
# every key: new or renamed tools stay out of reach until someone has
# classified them.
allow if {
	authenticated
	mcp_path
	count(project.mcp_tools) > 0
	agent_may_use_mcp
	not tool_call
}

allow if {
	authenticated
	tool_call
	tool_allowed(input.parsed_body.params.name)
}

tool_allowed(name) if {
	lib.catalog.tools[name]
	some pattern in project.mcp_tools
	glob.match(pattern, [], name)
	agent_allows_tool(name)
}

# The tools this key may call, sent with the allow decision for /mcp: the
# gateway's MCP authorization (agentgateway-config mcp.yaml) keeps only these in
# tools/list, so a project sees the tools it can use. Authorization above still
# decides each call.
listed_tools := sort([t | some t, _ in lib.catalog.tools; tool_allowed(t)])

# An agent's key needs MCP tools of its own; the project's other keys don't.
agent_may_use_mcp if not agent_id

agent_may_use_mcp if count(agent.mcp_tools) > 0

agent_allows_tool(_) if not agent_id

agent_allows_tool(name) if {
	agent_tool_matches(name)
	tool_risk(name) in autonomy_risks[agent.autonomy]
}

agent_tool_matches(name) if {
	some pattern in agent.mcp_tools
	glob.match(pattern, [], name)
}

# What each autonomy lets an agent do without a human (catalog/tools.yaml).
# A supervised agent's write, and any agent's irreversible call, needs an
# approval; there is no approval path through the gateway yet, so they are
# refused with a reason that says so.
# The registry's autonomy setting.
autonomy_risks := lib.settings.autonomy

tool_risk(name) := lib.catalog.tools[name]

mcp_path if {
	parts := split(path, "/")
	parts[1] == "mcp"
}

tool_call if {
	mcp_path
	input.parsed_body.method == "tools/call"
}

deployment_path if {
	parts := split(path, "/")
	count(parts) > 3
	parts[1] in lib.catalog.serving_namespaces
}

model_path if path in {"/v1/chat/completions", "/v1/completions", "/v1/responses", "/v1/messages", "/v1/embeddings"}

allowed_model(m) if m in scope_models

# The gateway's virtual models (agentgateway-config templates/auto.yaml). The
# gateway asks select.rego which model they stand for after this check, and
# it only ever names one of lib.allowed(project), so allowing the name is
# enough when the project has any model at all.
virtual_models := {"auto"} | {sprintf("auto-%s", [t]) | some t, _ in lib.catalog.tasks}

allowed_model(m) if {
	m in virtual_models
	count(scope_models) > 0
}

# Why a request was refused, for the decision log and the 403 body.
reason := "unknown project" if {
	not project
} else := sprintf("key %v is not active for project %v", [key_id, project_id]) if {
	not authenticated
} else := sprintf("project %v may not call model deployments directly", [project_id]) if {
	deployment_path
} else := sprintf("model %v is not allowed for agent %v (project %v)", [input.parsed_body.model, agent_id, project_id]) if {
	model_path
	agent_id
} else := sprintf("model %v is not allowed for project %v (%v data)", [input.parsed_body.model, project_id, project.data_class]) if {
	model_path
} else := sprintf("tool %v is not in the catalog", [input.parsed_body.params.name]) if {
	tool_call
	not lib.catalog.tools[input.parsed_body.params.name]
} else := sprintf("tool %v is %v: agent %v (%v) needs a human approval for it", [input.parsed_body.params.name, tool_risk(input.parsed_body.params.name), agent_id, agent.autonomy]) if {
	tool_call
	agent_tool_matches(input.parsed_body.params.name)
	some pattern in project.mcp_tools
	glob.match(pattern, [], input.parsed_body.params.name)
} else := sprintf("tool %v is not allowed for agent %v (project %v)", [input.parsed_body.params.name, agent_id, project_id]) if {
	tool_call
	agent_id
} else := sprintf("tool %v is not allowed for project %v", [input.parsed_body.params.name, project_id]) if {
	tool_call
} else := sprintf("agent %v may use no MCP tools (project %v)", [agent_id, project_id]) if {
	mcp_path
	agent_id
} else := sprintf("project %v may use no MCP tools", [project_id]) if {
	mcp_path
} else := sprintf("Google API %v is not in the catalog", [google_api]) if {
	google_api
	not lib.catalog.google_apis[google_api]
} else := sprintf("Google API %v is not allowed for project %v (its placement, %v, is not one of the project's: %v)", [google_api, project_id, lib.catalog.google_apis[google_api].placement, concat(", ", sort(lib.placements(project_id)))]) if {
	google_api
} else := "a Google API path is /google/<api>/<the API's own path>" if {
	google_path
} else := "denied"

# The models a project sees in /v1/models: the ones it may name, plus the
# virtual models when it has any. agentgateway answers /v1/models itself with
# every public model; a response transformation (agentgateway-config
# policies.yaml) keeps only the ids OPA lists in this header. Cosmetic only:
# authorization above decides what a project can call.
listed_models_header := "x-allowed-models"

listed_models := scope_models | virtual_models if {
	count(scope_models) > 0
} else := set()

# What OPA-Envoy returns to agentgateway: allow, or a 403 with the reason.
# Headers on an allowed decision are set on the request, replacing any the
# client sent.
decision := {
	"allowed": true,
	"headers": {listed_models_header: concat(",", sort(listed_models))},
	"dynamic_metadata": limits,
} if {
	allow
	path == "/v1/models"
} else := {
	"allowed": true,
	"dynamic_metadata": object.union(limits, {"mcp_tools": listed_tools}),
} if {
	allow
	mcp_path
} else := {"allowed": true, "dynamic_metadata": limits} if allow

# The project's limits travel with the allow decision (docs/project-registry.md
# "Limits travel with the decision"): agentgateway reads them as extauthz.* and
# sends each to the rate-limit service as the descriptor's limitOverride
# (agentgateway-config ratelimit.yaml), so a limit change goes live with the
# bundle, in the same step as the project's access. The service needs no entry
# per project. Absent in the project data: no limit, sent as unlimited (the
# override's requests_per_unit is a uint32). The budget is in micro-USD, what
# the gateway counts (llm.cost.total x 1e6), per fixed 30-day window.
#
# The key's own limits (key_limits) go along as key_*: the gateway counts them per
# (project, key, kind) next to the project's (project, kind), and refuses the call
# when either is used up. Always sent, unlimited when the key has none: the gateway
# refuses a call whose override is missing, so this must be live before the
# gateway's per-key descriptors are.
unlimited := 4000000000

key_limits := object.get(project, ["key_limits", key_id], {})

limits := {
	"requests_per_minute": object.get(project, ["limits", "requests_per_minute"], unlimited),
	"tokens_per_minute": object.get(project, ["limits", "tokens_per_minute"], unlimited),
	"budget_micro_usd": micro_usd(object.get(project, ["budget", "usd_per_30_days"], null)),
	"key_requests_per_minute": object.get(key_limits, ["limits", "requests_per_minute"], unlimited),
	"key_tokens_per_minute": object.get(key_limits, ["limits", "tokens_per_minute"], unlimited),
	"key_budget_micro_usd": micro_usd(object.get(key_limits, ["budget", "usd_per_30_days"], null)),
}

micro_usd(usd) := unlimited if usd == null

else := round(usd * 1000000)

decision := {
	"allowed": false,
	"http_status": 403,
	"body": json.marshal({"error": {"message": reason, "type": "policy_denied"}}),
	"headers": {"content-type": "application/json"},
} if not allow
