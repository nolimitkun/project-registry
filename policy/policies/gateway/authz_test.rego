package gateway.authz_test

import rego.v1

import data.gateway.authz
import data.gateway.lib

# A request with the project's main key (key id = project id).
req(project, path, body) := req_key(project, project, path, body)

req_key(project, key_id, path, body) := with_metadata({"project": project, "key_id": key_id}, path, body)

with_metadata(md, path, body) := {
	"attributes": {
		"request": {"http": {"path": path, "method": "POST"}},
		"metadataContext": {"filterMetadata": {"agentgateway": md}},
	},
	"parsed_body": body,
}

chat(project, model) := req(project, "/v1/chat/completions", {"model": model})

test_internal_project_gets_onprem_and_gemini if {
	authz.allow with input as chat("open-webui", "qwen3.6-27b")
	authz.allow with input as chat("open-webui", "gemini-4-argon")
}

test_internal_project_denied_external_model if {
	not authz.allow with input as chat("open-webui", "deepseek-v4-pro")
}

test_exception_allows_named_model_only if {
	authz.allow with input as chat("kagent", "deepseek-v4-pro")
	not authz.allow with input as chat("kagent", "some-other-model")
}

vault_app := {
	"data_class": "restricted", "placement": ["onprem"], "models_allow": ["*"],
	"keys": ["vault-app"], "mcp_tools": [], "owner": "t",
}

test_restricted_project_is_onprem_only if {
	authz.allow with input as chat("vault-app", "qwen3.6-27b")
		with data.projects["vault-app"] as vault_app
	not authz.allow with input as chat("vault-app", "gemini-3.5-flash")
		with data.projects["vault-app"] as vault_app
	not authz.allow with input as req("vault-app", "/google/speech/v2/projects/p/locations/eu/recognizers/_:recognize", {})
		with data.projects["vault-app"] as vault_app
}

# Even if the generated data listed gcp, the restricted class caps it.
test_data_class_caps_placement if {
	not authz.allow with input as chat("vault-app", "gemini-3.5-flash")
		with data.projects["vault-app"] as object.union(vault_app, {"placement": ["onprem", "gcp"]})
}

test_models_allow_narrows if {
	single := object.union(vault_app, {"data_class": "internal", "placement": ["onprem", "gcp"], "models_allow": ["gemini-3.5-*"]})
	authz.allow with input as chat("vault-app", "gemini-3.5-flash-lite")
		with data.projects["vault-app"] as single
	not authz.allow with input as chat("vault-app", "qwen3.6-27b")
		with data.projects["vault-app"] as single
	not authz.allow with input as chat("vault-app", "gemini-4-argon")
		with data.projects["vault-app"] as single
}

test_key_must_be_listed if {
	authz.allow with input as req_key("open-webui", "open-webui", "/v1/models", {})
	not authz.allow with input as req_key("open-webui", "open-webui-old", "/v1/models", {})
	authz.reason == "key open-webui-old is not active for project open-webui" with input as req_key("open-webui", "open-webui-old", "/v1/models", {})
	authz.allow with input as req_key("open-webui", "open-webui-2", "/v1/models", {})
		with data.projects["open-webui"].keys as ["open-webui", "open-webui-2"]
}

# Keys need both project and key_id: the pre-project {"client": ...} metadata,
# or a project without a key id, is refused.
test_incomplete_key_metadata_denied if {
	not authz.allow with input as with_metadata({"client": "open-webui"}, "/v1/chat/completions", {"model": "qwen3.6-27b"})
	not authz.allow with input as with_metadata({"project": "open-webui"}, "/v1/chat/completions", {"model": "qwen3.6-27b"})
	not authz.allow with input as with_metadata({"key_id": "open-webui"}, "/v1/models", {})
}

test_unknown_project_and_model_denied if {
	not authz.allow with input as chat("stranger", "qwen3.6-27b")
	not authz.allow with input as chat("open-webui", "not-a-model")
	not authz.allow with input as chat("", "qwen3.6-27b")
}

test_google_api_for_gcp_classes if {
	authz.allow with input as req("open-webui", "/google/tts/v1/text:synthesize", {})
	not authz.allow with input as req("open-webui", "/google/unknown/x", {})
	not authz.allow with input as req("open-webui", "/google/tts", {})
}

test_models_listing if {
	authz.allow with input as req("holmes", "/v1/models", {})
	authz.allow with input as req("holmes", "/v1/models?limit=5", {})
}

test_other_paths_denied if {
	not authz.allow with input as req("admin", "/admin", {})
}

test_reason if {
	authz.reason == "model deepseek-v4-pro is not allowed for project open-webui (internal data)" with input as chat("open-webui", "deepseek-v4-pro")
	authz.reason == "unknown project" with input as chat("stranger", "x")
	authz.reason == "unknown project" with input as {"attributes": {"request": {"http": {"path": "/v1/models"}}}}
}

test_decision_shape if {
	authz.decision == {"allowed": true, "dynamic_metadata": open_webui_limits} with input as chat("open-webui", "qwen3.6-27b")
	d := authz.decision with input as chat("open-webui", "deepseek-v4-pro")
	d.allowed == false
	d.http_status == 403
}

mcp(project, body) := req(project, "/mcp", body)

test_mcp_session_and_listing if {
	authz.allow with input as mcp("kagent", {"method": "initialize"})
	authz.allow with input as mcp("kagent", {"method": "tools/list"})
	authz.allow with input as req("kagent", "/mcp", null)
}

test_mcp_tool_calls_by_pattern if {
	authz.allow with input as mcp("kagent", {"method": "tools/call", "params": {"name": "grafana_query_prometheus"}})
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_query_loki_logs"}})
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "kagent-tools_k8s_delete_resource"}})
	authz.reason == "tool kagent-tools_k8s_delete_resource is not allowed for agent holmes (project holmes)" with input as mcp("holmes", {"method": "tools/call", "params": {"name": "kagent-tools_k8s_delete_resource"}})
}

test_mcp_needs_an_entry if {
	not authz.allow with input as mcp("open-webui", {"method": "initialize"})
	authz.reason == "project open-webui may use no MCP tools" with input as mcp("open-webui", {"method": "initialize"})
}

# Every model and Google API in the catalog has a placement some class allows,
# so nothing is routable but unusable by every project.
test_catalog_entries_usable_by_some_class if {
	every m in lib.catalog.models {
		some placements in lib.classes
		m.placement in placements
	}
	every a in lib.catalog.google_apis {
		some placements in lib.classes
		a.placement in placements
	}
}

test_placement_read_from_catalog if {
	not authz.allow with input as chat("open-webui", "qwen3.6-27b")
		with data.registry.catalog.models["qwen3.6-27b"].placement as "external"
	authz.allow with input as chat("open-webui", "new-model")
		with data.registry.catalog.models["new-model"] as {"placement": "onprem", "provider": "OpenAI"}
}

# Every project's generated placement is within its data class.
test_projects_within_their_class if {
	every p in data.projects {
		every pl in p.placement {
			pl in lib.classes[p.data_class]
		}
	}
}

test_virtual_models_allowed_with_any_model if {
	authz.allow with input as chat("open-webui", "auto")
	authz.allow with input as chat("open-webui", "auto-code")
	authz.allow with input as chat("open-webui", "auto-reasoning")
	not authz.allow with input as chat("open-webui", "auto-nosuchtask")

	# A project with no model left may not use them either.
	not authz.allow with input as chat("vault-app", "auto")
		with data.projects["vault-app"] as object.union(vault_app, {"models_allow": ["gemini-*"]})
}

# /v1/models: the decision names exactly what the project may call, so the
# gateway's listing matches authorization.
listed(project) := split(d.headers["x-allowed-models"], ",") if {
	d := authz.decision with input as req(project, "/v1/models", {})
}

test_models_listing_names_allowed_models if {
	l := listed("open-webui")
	"qwen3.6-27b" in l
	"gemini-4-argon" in l
	"auto" in l
	"auto-code" in l
	not "deepseek-v4-pro" in l

	# kagent's exception is listed.
	"deepseek-v4-pro" in listed("kagent")

	# The query string doesn't matter.
	d := authz.decision with input as req("open-webui", "/v1/models?limit=5", {})
	d.headers["x-allowed-models"] == concat(",", listed("open-webui"))
}

test_models_listing_matches_authorization if {
	every project_id, _ in data.projects {
		every m in listed(project_id) {
			authz.allow with input as chat(project_id, m)
		}
	}
}

test_models_listing_empty_without_models if {
	d := authz.decision with input as req("vault-app", "/v1/models", {})
		with data.projects["vault-app"] as object.union(vault_app, {"models_allow": ["gemini-*"]})
	d.headers["x-allowed-models"] == ""
}

test_only_models_listing_gets_the_header if {
	authz.decision == {"allowed": true, "dynamic_metadata": open_webui_limits} with input as chat("open-webui", "qwen3.6-27b")

	# A revoked key is refused, without a model list.
	d := authz.decision with input as req("open-webui", "/v1/models", {})
		with data.projects["open-webui"].keys as []
	d.allowed == false
	not d.headers["x-allowed-models"]
}

# Agents (the registry's agent records): a key in the project's agent_keys gets the agent's
# scope. "kagent-k8s-agent" is limited to DeepSeek; the project's own key
# "kagent" still has everything kagent may use.
test_agent_key_narrows_models if {
	authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "deepseek-v4-pro"})
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "qwen3.6-27b"})
	authz.reason == "model qwen3.6-27b is not allowed for agent kagent-k8s-agent (project kagent)" with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "qwen3.6-27b"})
	authz.allow with input as chat("kagent", "qwen3.6-27b")
}

test_agent_key_lists_only_its_models if {
	d := authz.decision with input as req_key("kagent", "kagent-k8s-agent", "/v1/models", null)
	d.headers["x-allowed-models"] == "auto,auto-code,auto-general,auto-reasoning,deepseek-v4-pro"
}

# An agent never widens its project: a pattern for a model the project can't
# use matches nothing.
test_agent_cannot_widen_project if {
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "gemini-4-argon"})
		with data.agents["kagent-k8s-agent"].models_allow as ["*"]
		with data.projects.kagent.models_allow as ["deepseek-*"]
}

# An agent of another project can't lend its scope through a forged mapping.
test_agent_of_other_project_matches_nothing if {
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "deepseek-v4-pro"})
		with data.agents["kagent-k8s-agent"].project as "holmes"
}

test_agent_without_tools_gets_no_mcp if {
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/mcp", {"method": "initialize"})
	authz.reason == "agent kagent-k8s-agent may use no MCP tools (project kagent)" with input as req_key("kagent", "kagent-k8s-agent", "/mcp", {"method": "initialize"})
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/mcp", {"method": "tools/call", "params": {"name": "grafana_query_prometheus"}})
	authz.allow with input as mcp("kagent", {"method": "tools/call", "params": {"name": "grafana_query_prometheus"}})
}

test_agent_tools_need_agent_and_project_match if {
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_query_loki_logs"}})
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_query_loki_logs"}})
		with data.agents.holmes.mcp_tools as ["grafana_search_*"]
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "kagent-tools_k8s_get"}})
		with data.agents.holmes.mcp_tools as ["*"]
}

# A key the bundle maps to an agent whose data is missing is refused, not
# given the project's scope.
test_agent_key_without_agent_data_is_refused if {
	not authz.allow with input as req_key("kagent", "kagent-k8s-agent", "/v1/chat/completions", {"model": "deepseek-v4-pro"})
		with data.agents as {}
}

# Tool risk (catalog/tools.yaml) against the agent's autonomy. Holmes is
# supervised with grafana_*: reads go through, writes and irreversible calls
# wait for a human.
test_supervised_agent_reads_only if {
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_query_prometheus"}})
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_update_dashboard"}})
	authz.reason == "tool grafana_update_dashboard is write: agent holmes (supervised) needs a human approval for it" with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_update_dashboard"}})
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_delete_snapshot"}})
}

# The registry's autonomy setting decides what each autonomy may do.
test_the_autonomy_setting_decides_what_a_supervised_agent_may_do if {
	writes := {"read-only": ["read"], "supervised": ["read", "write"], "autonomous": ["read", "write"]}
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_update_dashboard"}})
		with data.registry.settings.autonomy as writes
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_delete_snapshot"}})
		with data.registry.settings.autonomy as writes
}

test_autonomous_agent_writes_but_not_irreversible if {
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_update_dashboard"}})
		with data.agents.holmes.autonomy as "autonomous"
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_delete_snapshot"}})
		with data.agents.holmes.autonomy as "autonomous"
	authz.reason == "tool grafana_delete_snapshot is irreversible: agent holmes (autonomous) needs a human approval for it" with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_delete_snapshot"}})
		with data.agents.holmes.autonomy as "autonomous"
}

test_read_only_agent_never_writes if {
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_create_annotation"}})
		with data.agents.holmes.autonomy as "read-only"
	authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_search_dashboards"}})
		with data.agents.holmes.autonomy as "read-only"
}

# A tool the catalog doesn't know is irreversible for agents...
test_unclassified_tool_refused_for_agents if {
	not authz.allow with input as mcp("holmes", {"method": "tools/call", "params": {"name": "grafana_brand_new_tool"}})
		with data.agents.holmes.autonomy as "autonomous"
}

# ...while a project's own key keeps its glob rules (no autonomy to apply).
test_project_key_unaffected_by_tool_risk if {
	authz.allow with input as mcp("kagent", {"method": "tools/call", "params": {"name": "grafana_update_dashboard"}})
}

# The catalog's classes are the three the policy knows.
test_catalog_tool_risks_are_known if {
	every _, risk in lib.catalog.tools {
		risk in {"read", "write", "irreversible"}
	}
}

# The onboarding pipeline's own deployments, by KServe's path route.
deployment_req(project) := req(project, "/model-hprd/qwen-0-5b-989aa798-1a2b3c/v1/chat/completions", {"model": "Qwen/Qwen2.5-0.5B-Instruct@989aa79"})

test_deployments_only_for_projects_that_have_them if {
	authz.allow with input as deployment_req("model-onboarding")
	authz.allow with input as req("model-onboarding", "/model-prod/qwen-0-5b-989aa798-1a2b3c/v1/completions", {"prompt": "x"})
	not authz.allow with input as deployment_req("admin")
	authz.reason == "project admin may not call model deployments directly" with input as deployment_req("admin")
	not authz.allow with input as deployment_req("open-webui")
}

test_deployments_need_a_serving_namespace if {
	not authz.allow with input as req("model-onboarding", "/mini-platform/vllm/v1/chat/completions", {"model": "x"})
	not authz.allow with input as req("model-onboarding", "/model-hprd", {})
}

test_deployments_need_onprem if {
	not authz.allow with input as deployment_req("model-onboarding")
		with data.projects["model-onboarding"].placement as ["gcp"]
}

test_deployments_never_for_agent_keys if {
	not authz.allow with input as req_key("model-onboarding", "kagent-k8s-agent", "/model-hprd/x/v1/chat/completions", {})
		with data.projects["model-onboarding"].agent_keys as {"kagent-k8s-agent": "kagent-k8s-agent"}
		with data.projects["model-onboarding"].keys as ["model-onboarding", "kagent-k8s-agent"]
}

# The catalog's KServe releases are ordinary catalog models.
test_kserve_release_is_an_onprem_model if {
	authz.allow with input as chat("open-webui", "qwen2.5-1.5b")
		with data.registry.catalog.models["qwen2.5-1.5b"] as {"placement": "onprem", "provider": "KServe", "price": {"input": 0, "output": 0}}
}

open_webui_limits := {"requests_per_minute": 120, "tokens_per_minute": 4000000000, "budget_micro_usd": 50000000}

# Limits travel with the allow decision; absent ones are sent as unlimited.
test_limits_in_the_allow_decision if {
	d := authz.decision with input as chat("open-webui", "qwen3.6-27b")
		with data.projects["open-webui"].limits as {"requests_per_minute": 7}
		with data.projects["open-webui"].budget as {"usd_per_30_days": 2.5}
	d.dynamic_metadata == {"requests_per_minute": 7, "tokens_per_minute": 4000000000, "budget_micro_usd": 2500000}
	n := authz.decision with input as chat("open-webui", "qwen3.6-27b")
		with data.projects["open-webui"] as object.remove(data.projects["open-webui"], ["limits", "budget"])
	n.dynamic_metadata == {"requests_per_minute": 4000000000, "tokens_per_minute": 4000000000, "budget_micro_usd": 4000000000}

	# a refused request carries none
	r := authz.decision with input as chat("open-webui", "deepseek-v4-pro")
	not r.dynamic_metadata
}
