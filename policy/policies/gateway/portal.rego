# Who has to approve a change in the project registry (nolimitkun/project-registry,
# docs/project-registry.md "Approval rules are policy"). The registry asks for
# data.portal.required_approvals with the change as input:
#
#   input.change   {kind: project | agent | exception | policy | model | google_api |
#                   tool | catalog | setting, object_id,
#                   op: create | update | delete, before, after}
#                   before / after: the record (projects/schema.json, agents/schema.json,
#                   or an exception entry); for a policy change (a commit
#                   of policies/gateway), {commit} and {commit, subject, author, ref}
#   input.requester  who submitted it
#
# The answer is a set of roles; one approval per role, none by the requester:
#   project_owner  the project's owner group     security    security-reviewers
#   cost_owner     cost-owners                    platform    platform-admins
# An empty answer would let a change through unapproved, so every change needs at
# least its project's owner (a policy change: the platform team), and the
# registry refuses an answer without roles. The answer for a policy change comes
# from the policy active now, not the one proposed.
package portal

import data.gateway.lib
import rego.v1

change := input.change

before := object.get(change, "before", {}) if change.before != null

else := {}

after := object.get(change, "after", {}) if change.after != null

else := {}

# Three parts. The code says what a change does (its triggers) and keeps the floors no
# setting can lower; the registry's approvals setting says who approves each trigger,
# and reviewers change it in the portal like any record.
required_approvals contains role if {
	some trigger in triggers
	some role in approvals[trigger]
}

required_approvals contains role if some role in floor

# --- the floors, in code: every change needs someone, and a setting can't lower the
# approvals of the policy or of the settings themselves ---
catalog_kinds := {"model", "google_api", "tool", "catalog"}

floor contains "project_owner" if change.kind in {"agent", "exception"}

floor contains "project_owner" if {
	change.kind == "project"
	change.op != "create"
}

floor contains "platform" if {
	change.kind == "project"
	change.op == "create"
}

floor contains "platform" if change.kind in (catalog_kinds | {"policy", "setting"})

floor contains "security" if change.kind in {"policy", "setting"}

# --- who approves each trigger: the registry's approvals setting ---
approvals := lib.settings.approvals

# Every trigger below, by name: what settings/schema.json lists (scripts/validate.sh checks).
known_triggers := {
	"project.create", "project.limit_raised", "project.budget_raised", "project.data_class_changed",
	"project.placement_widened", "mcp_tools.wildcard_added", "exception.set",
	"agent.create_beyond_read_only", "agent.autonomy_raised", "catalog.route_changed",
	"model.price_changed", "tool.risk_lowered", "catalog.access_changed",
}

# --- the triggers: what a change does ---
triggers contains "project.create" if {
	change.kind == "project"
	change.op == "create"
}

# A limit or the budget goes up, or goes away (absent: no limit).
triggers contains "project.limit_raised" if {
	change.kind == "project"
	change.op == "update"
	some field in ["requests_per_minute", "tokens_per_minute"]
	raised(object.get(before, ["limits", field], null), object.get(after, ["limits", field], null))
}

triggers contains "project.budget_raised" if {
	change.kind == "project"
	change.op == "update"
	raised(object.get(before, ["budget", "usd_per_30_days"], null), object.get(after, ["budget", "usd_per_30_days"], null))
}

raised(old, new) if {
	old != null
	new == null
}

raised(old, new) if {
	old != null
	new != null
	new > old
}

# Any change of data class: more sensitive data, or a wider placement.
triggers contains "project.data_class_changed" if {
	change.kind == "project"
	change.op == "update"
	before.data_class != after.data_class
}

triggers contains "project.placement_widened" if {
	change.kind == "project"
	change.op == "update"
	some p in object.get(after, "placement", [])
	not p in object.get(before, "placement", [])
}

triggers contains "mcp_tools.wildcard_added" if {
	change.kind in {"project", "agent"}
	change.op != "delete"
	some t in object.get(after, "mcp_tools", [])
	contains(t, "*")
	not t in object.get(before, "mcp_tools", [])
}

# An exception: models beyond the data class.
triggers contains "exception.set" if {
	change.kind == "exception"
	change.op != "delete"
}

# More autonomy: a higher level, or one the autonomy setting lets call more risks (the
# setting may give a level any risks, so the order alone doesn't say what an agent gains).
autonomy_rank := {"read-only": 0, "supervised": 1, "autonomous": 2}

risks(autonomy) := {r | some r in lib.settings.autonomy[autonomy]}

more_autonomy(old, new) if autonomy_rank[new] > autonomy_rank[old]

more_autonomy(old, new) if count(risks(new) - risks(old)) > 0

triggers contains "agent.create_beyond_read_only" if {
	change.kind == "agent"
	change.op == "create"
	more_autonomy("read-only", after.autonomy)
}

triggers contains "agent.autonomy_raised" if {
	change.kind == "agent"
	change.op == "update"
	more_autonomy(object.get(before, "autonomy", "read-only"), after.autonomy)
}

# A model's or a Google API's placement, a new one, or a model's provider settings
# (where calls go).
triggers contains "catalog.route_changed" if {
	change.kind in {"model", "google_api"}
	change.op != "delete"
	object.remove(before, ["price"]) != object.remove(after, ["price"])
}

triggers contains "model.price_changed" if {
	change.kind == "model"
	change.op != "delete"
	object.get(before, "price", null) != after.price
}

# A tool less risky than before (or a new one other than irreversible).
risk_rank := {"read": 0, "write": 1, "irreversible": 2}

triggers contains "tool.risk_lowered" if {
	change.kind == "tool"
	change.op != "delete"
	risk_rank[after.risk] < risk_rank[object.get(before, "risk", "irreversible")]
}

# The catalog's settings: the MCP targets and the serving namespaces (a path under one
# skips the model allowlist for projects with deployments: true) widen access; the task
# classes only pick among models a project may use already.
triggers contains "catalog.access_changed" if {
	change.kind == "catalog"
	change.op != "delete"
	object.remove(before, ["tasks"]) != object.remove(after, ["tasks"])
}

# --- who may propose a change (approval, above, is a separate question) ---
# The registry asks data.portal.may_submit with input.change, input.requester,
# input.groups (the requester's Keycloak groups) and input.owner_group (the
# project's owner group; for a new project, the one it asks for). Anything but
# true refuses the change (403).
default may_submit := false

# Anyone signed in may ask for a new project: the platform team and security
# approve it.
may_submit if {
	change.kind == "project"
	change.op == "create"
}

# Otherwise the project's owners, for the project and its agents and exceptions
# (not the catalog or the settings: they have no owner group),
may_submit if {
	not change.kind in (catalog_kinds | {"setting"})
	input.owner_group
	input.owner_group in input.groups
}

# and the platform team, for any project. Proposing is not approving: their
# change still needs the approvals above, from someone else.
may_submit if "platform-admins" in input.groups
