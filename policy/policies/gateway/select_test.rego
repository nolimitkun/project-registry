package gateway.select_test

import rego.v1

import data.gateway.lib
import data.gateway.rankings
import data.gateway.select

# Prometheus answers for rankings.rego, mocked: no test touches the network.
prom_result(pairs) := {"status_code": 200, "body": {"status": "success", "data": {
	"resultType": "vector",
	"result": [{"metric": {"gen_ai_request_model": m}, "value": [0, v]} | some m, v in pairs],
}}}

prom_fast_flash(_) := prom_result({"gemini-3.8-flash": "0.12", "qwen3.6-27b": "0.9"})

prom_fast_deepseek(_) := prom_result({"deepseek-v4-pro": "0.05", "qwen3.6-27b": "0.06"})

prom_odd(_) := prom_result({"gemini-3.8-flash": "NaN", "qwen3.6-27b": "+Inf", "deepseek-v4-pro": "1.5"})

prom_down(_) := {"status_code": 0, "error": {"code": "eval_http_send_network_error", "message": "connection refused"}}

prom_500(_) := {"status_code": 500, "body": {"status": "error"}}

# A project for these tests; fields default like gen-projects.py's output.
proj(overrides) := object.union(
	{
		"data_class": "internal", "placement": ["onprem", "gcp"], "models_allow": ["*"],
		"keys": ["t"], "mcp_tools": [], "owner": "t", "routing": "cheapest",
	},
	overrides,
)

pick(p, task) := m if {
	m := select.result.model with input as {"project": "t", "task": task}
		with data.projects.t as p
}

pick_no_task(p) := m if {
	m := select.result.model with input as {"project": "t"}
		with data.projects.t as p
}

test_cheapest if {
	# On-prem Qwen has no per-token charge.
	pick_no_task(proj({})) == "qwen3.6-27b"

	# GCP only: blended (3 x input + output) / 4 makes Flash Lite cheapest.
	pick_no_task(proj({"placement": ["gcp"]})) == "gemini-3.5-flash-lite"
}

test_cheapest_respects_models_allow if {
	pick_no_task(proj({"models_allow": ["gemini-4-*", "gemini-3.8-*"]})) == "gemini-3.8-flash"
}

test_fastest_uses_rankings if {
	select.result.model == "gemini-3.8-flash" with input as {"project": "t"}
		with data.projects.t as proj({"routing": "fastest"})
		with http.send as prom_fast_flash
}

test_fastest_without_rankings_is_cheapest if {
	select.result.model == "qwen3.6-27b" with input as {"project": "t"}
		with data.projects.t as proj({"routing": "fastest"})
		with http.send as prom_down
	select.result.model == "qwen3.6-27b" with input as {"project": "t"}
		with data.projects.t as proj({"routing": "fastest"})
		with http.send as prom_500
}

test_rankings_parse if {
	rankings.latency_ms == {"gemini-3.8-flash": 120, "qwen3.6-27b": 900} with http.send as prom_fast_flash

	# NaN and infinities (too few samples, empty buckets) are left unranked.
	rankings.latency_ms == {"deepseek-v4-pro": 1500} with http.send as prom_odd
	rankings.latency_ms == {} with http.send as prom_down
}

test_rankings_query_targets_the_gateway if {
	contains(rankings.query, `gateway="mini-platform/agentgateway-proxy"`)
	contains(rankings.query, ">= 3")
}

test_semantic_follows_task_prefs_within_allowed if {
	all := proj({"routing": "semantic", "data_class": "public", "placement": ["onprem", "gcp", "external"]})
	internal := proj({"routing": "semantic"})
	onprem := proj({"routing": "semantic", "placement": ["onprem"]})

	pick(all, "code") == "deepseek-v4-pro"
	pick(internal, "code") == "gemini-3.8-flash"
	pick(onprem, "code") == "qwen3.6-27b"
	pick(all, "reasoning") == "gemini-4-argon"
	pick(internal, "general") == "gemini-3.5-flash-lite"
}

test_semantic_without_task_is_cheapest if {
	pick_no_task(proj({"routing": "semantic", "placement": ["gcp"]})) == "gemini-3.5-flash-lite"
	pick(proj({"routing": "semantic", "placement": ["gcp"]}), "no-such-task") == "gemini-3.5-flash-lite"
}

test_semantic_uses_exceptions if {
	# kagent: internal, with a DeepSeek exception.
	select.result.model == "deepseek-v4-pro" with input as {"project": "kagent", "task": "code"}
		with data.projects.kagent.routing as "semantic"
}

test_fixed if {
	pick_no_task(proj({"routing": "fixed:gemini-4-argon"})) == "gemini-4-argon"

	# Not allowed (gen-projects.py refuses this, but the policy holds anyway).
	pick_no_task(proj({"routing": "fixed:deepseek-v4-pro"})) == "qwen3.6-27b"
}

test_no_result if {
	not select.result with input as {"project": "nobody"}
	not select.result with input as {"project": "t"}
		with data.projects.t as proj({"models_allow": ["gemini-*"], "placement": ["onprem"]})
}

# The selection never leaves what authorization allows: for every project,
# as configured and narrowed in ways that rule out the overall cheapest model,
# under every routing rule and every task class.
test_selection_within_allowed if {
	routings := {"cheapest", "fastest", "semantic", "fixed:gemini-4-argon", "fixed:deepseek-v4-pro", "fixed:qwen3.6-27b"}
	narrowing := [{}, {"placement": ["gcp"]}, {"placement": ["external"]}, {"models_allow": ["gemini-4-*", "deepseek-*"]}]
	tasks := object.union({t: true | some t, _ in lib.catalog.tasks}, {"": true})
	every project_id, project in data.projects {
		every overrides in narrowing {
			every routing in routings {
				every task, _ in tasks {
					within_allowed(project_id, object.union(project, object.union(overrides, {"routing": routing})), task) with http.send as prom_down
				}
			}
		}
	}
}

# Either no model at all, or one the project may use.
within_allowed(project_id, variant, task) if {
	projects := object.union(data.projects, {project_id: variant})
	not select.result with input as {"project": project_id, "task": task}
		with data.projects as projects
}

within_allowed(project_id, variant, task) if {
	projects := object.union(data.projects, {project_id: variant})
	m := select.result.model with input as {"project": project_id, "task": task}
		with data.projects as projects
	allowed := lib.allowed(project_id) with data.projects as projects
	m in allowed
}

# "fastest" again, with rankings where the overall fastest model is one most
# narrowed projects may not use.
test_selection_within_allowed_with_rankings if {
	routings := {"fastest"}
	narrowing := [{}, {"placement": ["gcp"]}, {"placement": ["external"]}, {"models_allow": ["gemini-4-*", "deepseek-*"]}]
	every project_id, project in data.projects {
		every overrides in narrowing {
			every routing in routings {
				within_allowed(project_id, object.union(project, object.union(overrides, {"routing": routing})), "") with http.send as prom_fast_deepseek
			}
		}
	}
}

# With an agent's key, "auto" stays within the agent's models.
test_auto_with_agent_key_stays_in_agent_scope if {
	r := select.result with input as {"project": "kagent", "key_id": "kagent-k8s-agent"}
	r.model == "deepseek-v4-pro"
	r2 := select.result with input as {"project": "kagent", "key_id": "kagent"}
	r2.model != "deepseek-v4-pro"
}
