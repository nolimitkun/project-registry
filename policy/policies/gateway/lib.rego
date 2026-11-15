# What a project may use, shared by authorization (authz.rego) and model
# selection (select.rego), so "auto" can only ever pick a model the project
# would also be allowed to name itself.
package gateway.lib

import rego.v1

# The catalog: the project registry's records (models, Google APIs, MCP tools,
# the settings), in the gateway-projects bundle.
catalog := data.registry.catalog

# The parameters reviewers decide: the project registry's setting records (data
# classes, autonomy, approvals), in the gateway-projects bundle.
settings := data.registry.settings

classes := settings.data_classes

# The project's placements, capped by its data class even if the generated
# data says otherwise.
placements(project_id) := {p |
	project := data.projects[project_id]
	some p in project.placement
	p in classes[project.data_class]
}

# Catalog models in one of the project's placements that its models.allow
# patterns match, plus its named exceptions (the registry's exceptions).
allowed(project_id) := by_rule(project_id) | by_exception(project_id)

by_rule(project_id) := {m |
	some m, model in catalog.models
	model.placement in placements(project_id)
	some pattern in data.projects[project_id].models_allow

	# null: no delimiters, so * also matches the dots in "qwen3.6-27b"
	# ([] would default to "."). The same matching as fnmatch in gen-projects.py.
	glob.match(pattern, null, m)
}

# What a key may use: an agent's key (projects' agent_keys, from the
# registry's agents) gets its project's models narrowed by the agent's patterns;
# any other key of the project gets the project's. A key can only ever narrow
# its project, never widen it.
scoped(project_id, key_id) := agent_allowed(project_id, agent_id) if {
	agent_id := data.projects[project_id].agent_keys[key_id]
} else := allowed(project_id)

agent_allowed(project_id, agent_id) := {m |
	agent := data.agents[agent_id]
	agent.project == project_id
	some m in allowed(project_id)
	some pattern in agent.models_allow
	glob.match(pattern, null, m)
}

by_exception(project_id) := {m |
	data.projects[project_id]
	some m in object.get(data.exceptions, project_id, {"models": []}).models
}
