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
	parts := split(path, "/")
	parts[1] == "google"
	count(parts) > 3
	lib.catalog.google_apis[parts[2]].placement in lib.placements(project_id)
}

# MCP (the merged endpoint at /mcp). A project with mcp_tools may open
# sessions, list tools and so on; each tools/call must name a tool matching one
# of its patterns. Tool names carry the target as a prefix, e.g.
# grafana_query_prometheus.
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
	some pattern in project.mcp_tools
	glob.match(pattern, [], input.parsed_body.params.name)
	agent_allows_tool(input.parsed_body.params.name)
}

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

# A tool the catalog doesn't list counts as irreversible: new or renamed tools
# stay out of agents' reach until someone has classified them.
tool_risk(name) := lib.catalog.tools[name]

tool_risk(name) := "irreversible" if not lib.catalog.tools[name]

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
} else := {"allowed": true, "dynamic_metadata": limits} if allow

# The project's limits travel with the allow decision (docs/project-registry.md
# "Limits travel with the decision"): agentgateway reads them as extauthz.* and
# sends each to the rate-limit service as the descriptor's limitOverride
# (agentgateway-config ratelimit.yaml), so a limit change goes live with the
# bundle, in the same step as the project's access. The service needs no entry
# per project. Absent in the project data: no limit, sent as unlimited (the
# override's requests_per_unit is a uint32). The budget is in micro-USD, what
# the gateway counts (llm.cost.total x 1e6), per fixed 30-day window.
unlimited := 4000000000

limits := {
	"requests_per_minute": object.get(project, ["limits", "requests_per_minute"], unlimited),
	"tokens_per_minute": object.get(project, ["limits", "tokens_per_minute"], unlimited),
	"budget_micro_usd": budget_micro_usd,
}

budget_micro_usd := round(project.budget.usd_per_30_days * 1000000) if project.budget

else := unlimited

decision := {
	"allowed": false,
	"http_status": 403,
	"body": json.marshal({"error": {"message": reason, "type": "policy_denied"}}),
	"headers": {"content-type": "application/json"},
} if not allow
