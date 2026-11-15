package system.log_test

import rego.v1

import data.system.log

event(body) := {"input": {
	"parsed_body": body,
	"attributes": {"request": {"http": {
		"body": "raw",
		"headers": {"authorization": "Bearer secret"},
	}}},
}}

upsert_value(ops) := v if {
	some op in ops
	is_object(op)
	op.path == "/input/parsed_body"
	v := op.value
}

test_model_call_keeps_only_the_model if {
	ops := log.mask with input as event({
		"model": "qwen3.6-27b",
		"messages": [{"role": "user", "content": "account 123"}],
	})
	upsert_value(ops) == {"model": "qwen3.6-27b"}
}

test_mcp_call_keeps_method_and_tool_name if {
	ops := log.mask with input as event({
		"jsonrpc": "2.0",
		"method": "tools/call",
		"params": {"name": "grafana_query", "arguments": {"q": "secret"}},
	})
	upsert_value(ops) == {"method": "tools/call", "params": {"name": "grafana_query"}}
}

test_mcp_list_keeps_method if {
	ops := log.mask with input as event({"jsonrpc": "2.0", "method": "tools/list"})
	upsert_value(ops) == {"method": "tools/list"}
}

test_no_body_no_upsert if {
	ops := log.mask with input as {"input": {"attributes": {}}}
	not upsert_value(ops)
}

test_key_and_raw_body_always_dropped if {
	ops := log.mask with input as event({})
	"/input/attributes/request/http/headers/authorization" in ops
	"/input/attributes/request/http/body" in ops
	"/input/attributes/request/http/raw_body" in ops
}

test_batch_body_dropped_whole if {
	ops := log.mask with input as event([{
		"jsonrpc": "2.0",
		"method": "tools/call",
		"params": {"name": "grafana_query", "arguments": {"q": "secret"}},
	}])
	"/input/parsed_body" in ops
	not upsert_value(ops)
}

test_string_body_dropped_whole if {
	ops := log.mask with input as event("free text prompt")
	"/input/parsed_body" in ops
}

test_object_body_not_dropped if {
	ops := log.mask with input as event({"model": "qwen3.6-27b"})
	not "/input/parsed_body" in ops
}
