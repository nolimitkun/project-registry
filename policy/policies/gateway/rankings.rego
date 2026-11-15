# How fast each model answers, for "fastest" routing (select.rego): the median
# model request duration over the last six hours, from the gateway's own
# metrics in Prometheus. Only models with at least min_samples requests in that
# window are ranked.
#
# Asked at decision time rather than built into the bundle: a builder that
# pulls them fails the whole bundle build when Prometheus is unreachable (OPA
# Control Plane, which built the bundles before, did), so rankings in the
# bundle would block every policy change, key revocations included, while
# Prometheus is down. Here a Prometheus outage only means no rankings: the request waits
# at most `timeout`, nothing is ranked, and "fastest" falls back to cheapest.
# Authorization never reads this.
#
# Failed calls count too: a model Google throttles (429 after retries) looks
# slow, which is what "fastest" should avoid.
package gateway.rankings

import rego.v1

import data.gateway.lib

prometheus := "http://prometheus-server.mini-platform.svc.cluster.local/api/v1/query"

window := "6h"

min_samples := 3

timeout := "300ms"

# OPA keeps the answer this long (inter-query cache, opa-config), so
# Prometheus sees about one query per OPA replica per interval.
cache_seconds := 120

gateway := "mini-platform/agentgateway-proxy"

query := concat("", [
	`histogram_quantile(0.5, sum by (le, gen_ai_request_model) (rate(agentgateway_gen_ai_server_request_duration_bucket{gateway="`, gateway, `"}[`, window, `])))`,
	` and on (gen_ai_request_model) (sum by (gen_ai_request_model) (increase(agentgateway_gen_ai_server_request_duration_count{gateway="`, gateway, `"}[`, window, `])) >= `, format_int(min_samples, 10), `)`,
])

response := http.send({
	"method": "GET",
	"url": concat("?", [prometheus, urlquery.encode_object({"query": query})]),
	"timeout": timeout,
	"raise_error": false,
	"force_cache": true,
	"force_cache_duration_seconds": cache_seconds,
})

# The metrics' model label -> median request duration in milliseconds. Empty
# when Prometheus is unreachable or answers anything but a vector.
measured := {label: round(to_number(v) * 1000) |
	response.status_code == 200
	some r in response.body.data.result
	label := r.metric.gen_ai_request_model
	v := r.value[1]
	not v in {"NaN", "+Inf", "-Inf"}
}

# The label is the model name the provider got: the catalog name, except for a
# KServe model, whose route replaces it with the name vLLM serves (the catalog's
# served_model). Mapped back here, or select.rego would never find the model.
catalog_name(label) := name if {
	some name, m in lib.catalog.models
	m.served_model == label
} else := label

# catalog model -> median request duration in milliseconds. Two labels can name
# one model (its catalog name from before it moved to KServe, and its served
# name): the faster counts, so the object never gets two values for one key.
latency_ms := {name: min({ms | some label, ms in measured; catalog_name(label) == name}) |
	some label, _ in measured
	name := catalog_name(label)
}
