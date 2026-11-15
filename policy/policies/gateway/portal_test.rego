package portal_test

import rego.v1

import data.portal

project := {"project": "p", "owner": "team", "data_class": "internal", "keys": ["p"], "limits": {"requests_per_minute": 60}}

roles(kind, op, before, after) := r if {
	r := portal.required_approvals with input as {
		"change": {"kind": kind, "object_id": "p", "op": op, "before": before, "after": after},
		"requester": "alice",
	}
}

test_lowering_a_limit_needs_the_owner_only if {
	roles("project", "update", project, object.union(project, {"limits": {"requests_per_minute": 30}})) == {"project_owner"}
}

test_raising_or_removing_a_limit_needs_the_cost_owner if {
	roles("project", "update", project, object.union(project, {"limits": {"requests_per_minute": 120}})) == {"project_owner", "cost_owner"}
	roles("project", "update", project, object.remove(project, ["limits"])) == {"project_owner", "cost_owner"}
	roles("project", "update", project, object.union(project, {"budget": {"usd_per_30_days": 10}})) == {"project_owner"}
	budgeted := object.union(project, {"budget": {"usd_per_30_days": 10}})
	roles("project", "update", budgeted, object.union(project, {"budget": {"usd_per_30_days": 20}})) == {"project_owner", "cost_owner"}
}

test_data_class_placement_and_wildcard_tools_need_security if {
	roles("project", "update", project, object.union(project, {"data_class": "public"})) == {"project_owner", "security"}
	roles("project", "update", object.union(project, {"placement": ["onprem"]}), object.union(project, {"placement": ["onprem", "gcp"]})) == {"project_owner", "security"}
	roles("project", "update", project, object.union(project, {"mcp_tools": ["grafana_*"]})) == {"project_owner", "security"}
	roles("project", "update", project, object.union(project, {"mcp_tools": ["grafana_list_dashboards"]})) == {"project_owner"}
}

test_a_new_project_needs_platform_and_security if {
	roles("project", "create", null, project) == {"platform", "security"}
}

test_exceptions_need_security_except_their_removal if {
	exc := {"owner": "team", "why": "x", "models": ["m"]}
	roles("exception", "create", null, exc) == {"project_owner", "security"}
	roles("exception", "delete", exc, null) == {"project_owner"}
}

test_more_agent_autonomy_needs_security if {
	agent := {"agent": "a", "project": "p", "autonomy": "read-only"}
	roles("agent", "update", agent, object.union(agent, {"autonomy": "supervised"})) == {"project_owner", "security"}
	roles("agent", "update", object.union(agent, {"autonomy": "supervised"}), agent) == {"project_owner"}
	roles("agent", "create", null, agent) == {"project_owner"}
}

test_every_change_has_an_approver if {
	every kind in ["project", "agent", "exception"] {
		count(roles(kind, "delete", {"project": "p"}, null)) > 0
	}
}

test_a_policy_change_needs_platform_and_security_not_an_owner if {
	roles("policy", "update", {"commit": "a"}, {"commit": "b", "subject": "x"}) == {"platform", "security"}
}

may(kind, op, groups, owner) := r if {
	r := portal.may_submit with input as {
		"change": {"kind": kind, "object_id": "p", "op": op, "before": null, "after": {}},
		"requester": "bob", "groups": groups, "owner_group": owner,
	}
}

test_owners_and_the_platform_team_may_propose_changes if {
	may("project", "update", ["team-p"], "team-p")
	may("agent", "update", ["team-p"], "team-p")
	may("exception", "create", ["team-p"], "team-p")
	may("project", "update", ["platform-admins"], "team-p")
}

test_others_may_not_propose_changes_to_a_project if {
	not may("project", "update", ["team-q"], "team-p")
	not may("project", "delete", ["security-reviewers", "cost-owners"], "team-p")
	not may("project", "update", [], null)
}

test_anyone_may_ask_for_a_new_project if {
	may("project", "create", [], "team-new")
}

test_a_catalog_change_needs_the_platform_team_and_more_for_what_it_widens if {
	model := {"placement": "onprem", "provider": "KServe", "price": {"input": 0, "output": 0}}
	roles("model", "update", model, object.union(model, {"price": {"input": 1, "output": 1}})) == {"platform", "cost_owner"}
	roles("model", "update", model, object.union(model, {"placement": "gcp"})) == {"platform", "security"}
	roles("model", "create", null, model) == {"platform", "security", "cost_owner"}
	roles("model", "delete", model, null) == {"platform"}
	roles("google_api", "create", null, {"placement": "gcp", "host": "x.googleapis.com"}) == {"platform", "security"}
	roles("tool", "update", {"risk": "write"}, {"risk": "read"}) == {"platform", "security"}
	roles("tool", "update", {"risk": "read"}, {"risk": "write"}) == {"platform"}
	roles("tool", "create", null, {"risk": "irreversible"}) == {"platform"}
	roles("catalog", "update", {"targets": ["a"]}, {"targets": ["a", "b"]}) == {"platform", "security"}
	roles("catalog", "update", {"servingNamespaces": ["a"]}, {"servingNamespaces": ["a", "v1"]}) == {"platform", "security"}
	roles("catalog", "update", {"tasks": ["a"], "targets": ["t"]}, {"tasks": ["a", "b"], "targets": ["t"]}) == {"platform"}
}

test_only_the_platform_team_proposes_catalog_changes if {
	not may("model", "update", ["owners"], "owners")
	may("model", "update", ["platform-admins"], null)
}

# --- the approvals setting: reviewers change who approves a trigger, not the floors ---
no_one := {t: [] | some t in portal.known_triggers}

test_the_approvals_setting_decides_who_approves_a_trigger if {
	raise := object.union(project, {"limits": {"requests_per_minute": 300}})
	r := portal.required_approvals with input as {"change": {"kind": "project", "object_id": "p", "op": "update", "before": project, "after": raise}, "requester": "alice"}
		with data.registry.settings.approvals as object.union(data.registry.settings.approvals, {"project.limit_raised": ["cost_owner", "security"]})
	r == {"project_owner", "cost_owner", "security"}
}

any_change(kind, op) := {"change": {"kind": kind, "object_id": "x", "op": op, "before": {}, "after": {}}, "requester": "alice"}

test_an_empty_approvals_setting_keeps_the_floors if {
	portal.required_approvals == {"project_owner"} with input as any_change("exception", "update")
		with data.registry.settings.approvals as no_one
	portal.required_approvals == {"platform"} with input as any_change("project", "create")
		with data.registry.settings.approvals as no_one
	portal.required_approvals == {"platform"} with input as any_change("model", "create")
		with data.registry.settings.approvals as no_one
	portal.required_approvals == {"platform", "security"} with input as any_change("policy", "update")
		with data.registry.settings.approvals as no_one
	portal.required_approvals == {"platform", "security"} with input as any_change("setting", "update")
		with data.registry.settings.approvals as no_one
}

test_only_the_platform_team_proposes_a_setting if {
	c := {"kind": "setting", "object_id": "approvals", "op": "update", "before": {}, "after": {}}
	not portal.may_submit with input as {"change": c, "requester": "o", "groups": ["project-owners"], "owner_group": "project-owners"}
	portal.may_submit with input as {"change": c, "requester": "a", "groups": ["platform-admins"]}
}

# The autonomy setting may give a level more risks than the order suggests: what an agent
# gains is what counts.
test_moving_an_agent_to_a_level_with_more_risks_needs_security if {
	odd := {"read-only": ["read"], "supervised": ["read", "write"], "autonomous": ["read"]}
	agent := {"agent": "a", "project": "p", "autonomy": "autonomous"}
	r := portal.required_approvals with input as {"change": {"kind": "agent", "object_id": "a", "op": "update", "before": agent, "after": object.union(agent, {"autonomy": "supervised"})}, "requester": "alice"}
		with data.registry.settings.autonomy as odd
	r == {"project_owner", "security"}

	# a higher level still counts when its risks are the same (as before the setting)
	c := portal.required_approvals with input as {"change": {"kind": "agent", "object_id": "a", "op": "create", "before": null, "after": object.union(agent, {"autonomy": "supervised"})}, "requester": "alice"}
		with data.registry.settings.autonomy as {"read-only": ["read"], "supervised": ["read"], "autonomous": ["read", "write"]}
	c == {"project_owner", "security"}
}
