# What OPA's decision log keeps of each request. Prompts, tool arguments and
# the client's API key stay out of Loki; the log keeps who asked (the key's
# project and id, from the gateway's metadata), for which model or MCP tool,
# and the verdict. That is also what scripts/policy-replay.py needs to replay
# a decision against a new bundle.
#
# OPA evaluates this against the decision log event, so the request is
# input.input here.
package system.log

import rego.v1

# The parsed body becomes just the fields the policy decides on: the model of
# a model call, and the JSON-RPC method and tool name of an MCP call.
mask contains {"op": "upsert", "path": "/input/parsed_body", "value": kept_body} if {
	is_object(input.input.parsed_body)
}

# Any other body (a JSON-RPC batch is an array, a bare string is possible) is
# dropped whole, as every body was before the model was kept.
mask contains "/input/parsed_body" if {
	"parsed_body" in object.keys(input.input)
	not is_object(input.input.parsed_body)
}

kept_body := object.union(model, mcp)

model := {"model": input.input.parsed_body.model} if {
	input.input.parsed_body.model
} else := {}

mcp := object.union({"method": input.input.parsed_body.method}, tool) if {
	input.input.parsed_body.method
} else := {}

tool := {"params": {"name": input.input.parsed_body.params.name}} if {
	input.input.parsed_body.params.name
} else := {}

mask contains "/input/truncated_body"

mask contains "/input/attributes/request/http/body"

mask contains "/input/attributes/request/http/raw_body"

mask contains "/input/attributes/request/http/headers/authorization"
