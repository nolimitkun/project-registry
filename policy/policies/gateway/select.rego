# Model selection for model "auto": which model a project gets when it lets the
# platform choose. agentgateway asks this through a callout virtual model:
#
#   POST /v1/data/gateway/select/result
#   {"input": {"project": "<id>", "key_id": "<key>", "task": "<class>"}}
#   key_id and task are optional; with the key of a registered agent, the
#   choice stays within the agent's models (lib.scoped)
#   → {"result": {"model": "<name>", "routing": "<rule>"}}
#
# The answer is always one of lib.allowed(project): selection never widens what
# authorization allows. An unknown project, or one with no allowed model, gets
# no result, and the gateway answers 503.
package gateway.select

import rego.v1

import data.gateway.lib
import data.gateway.rankings

project_id := input.project

project := data.projects[project_id]

allowed := lib.scoped(project_id, object.get(input, "key_id", ""))

# What a request costs, blended at three input tokens to one output token, in
# USD per million tokens (the catalog's prices: the registry's model records).
blended_price(m) := ((3 * p.input) + p.output) / 4 if p := lib.catalog.models[m].price

# Median request duration from the gateway's metrics (rankings.rego). Unranked
# models sort after ranked ones.
unranked_ms := 1000000000

latency_ms(m) := t if {
	t := rankings.latency_ms[m]
} else := unranked_ms

# Allowed models from cheapest to dearest; the name breaks ties, so the order
# is stable.
by_price := [m | some pair in sort([[blended_price(m), m] | some m in allowed]); m := pair[1]]

# Allowed models from fastest to slowest, then by price.
by_speed := [m | some t in sort([[latency_ms(m), blended_price(m), m] | some m in allowed]); m := t[2]]

# The task class's preferred models that the project may use, in the catalog's
# order. Empty without a task (the router was skipped or is down).
task_prefs := [m |
	some m in object.get(lib.catalog.tasks, object.get(input, "task", ""), [])
	m in allowed
]

routing := project.routing

fixed_model := trim_prefix(routing, "fixed:") if startswith(routing, "fixed:")

# Candidates in order for the project's routing rule; the first one wins.
ordered := by_price if routing == "cheapest"

ordered := by_speed if routing == "fastest"

ordered := array.concat(task_prefs, by_price) if routing == "semantic"

ordered := array.concat([m | m := fixed_model; m in allowed], by_price) if fixed_model

result := {"model": ordered[0], "routing": routing} if count(ordered) > 0
