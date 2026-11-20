package admission_test

import data.admission
import data.system
import rego.v1

registry := {
	"keys": {"holmes": {"project": "holmes", "agent": null}},
	"deployments": {"model-prod/qwen-a": "qwen3.6-27b"},
	"serving_namespaces": ["model-prod", "model-hprd"],
}

review(kind, namespace, obj) := {"request": {"uid": "u1", "kind": {"kind": kind}, "namespace": namespace, "object": obj}}

copy(id) := {"metadata": {"name": "holmes-agentgateway"}, "spec": {
	"path": "agentgateway-client-keys",
	"destination": {"transformation": {"templates": {"OPENAI_API_KEY": {"text": sprintf(`{{ get .Secrets %q }}`, [id])}}}},
}}

test_a_known_key_copy_passes if {
	r := system.main with input as review("VaultStaticSecret", "mini-platform", copy("holmes")) with data.registry as registry
	r.kind == "AdmissionReview"
	r.response == {"uid": "u1", "allowed": true, "warnings": []}
}

test_an_unknown_key_copy_warns if {
	r := admission.response with input as review("VaultStaticSecret", "mini-platform", copy("gone")) with data.registry as registry
	r.allowed
	r.warnings == [`VaultStaticSecret mini-platform/holmes-agentgateway copies gateway key id "gone", which no project or agent in the project registry lists (gateway_key_copy_known)`]
}

test_an_enforced_rule_denies if {
	r := admission.response with input as review("VaultStaticSecret", "mini-platform", copy("gone"))
		with data.registry as registry
		with data.admission.config.enforce as {"gateway_key_copy_known"}
	not r.allowed
	r.status.code == 403
	contains(r.status.message, `gateway key id "gone"`)
}

test_other_secrets_paths_are_not_key_copies if {
	obj := object.union(copy("gone"), {"spec": {"path": "minio-model-serving"}})
	r := admission.response with input as review("VaultStaticSecret", "mini-platform", obj) with data.registry as registry
	r.warnings == []
}

test_a_deployment_must_be_a_catalog_models if {
	ok := admission.response with input as review("LLMInferenceService", "model-prod", {"metadata": {"name": "qwen-a"}}) with data.registry as registry
	ok.warnings == []
	other := admission.response with input as review("LLMInferenceService", "model-prod", {"metadata": {"name": "qwen-b"}}) with data.registry as registry
	other.warnings == ["LLMInferenceService model-prod/qwen-b is no catalog model's deployment (the project registry's catalog) (deployment_catalogued)"]
	elsewhere := admission.response with input as review("LLMInferenceService", "model-onboarding", {"metadata": {"name": "qwen-b"}}) with data.registry as registry
	elsewhere.warnings == []
}

test_only_the_gateway_namespace_reads_the_key_map if {
	pod := {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "envFrom": [{"secretRef": {"name": "agentgateway-api-keys"}}]}]}}
	out := admission.response with input as review("Pod", "model-prod", pod) with data.registry as registry with data.admission.config.enforce as set()
	count(out.warnings) == 1
	home := admission.response with input as review("Pod", "mini-platform", pod) with data.registry as registry
	home.warnings == []
	mounted := {"metadata": {"name": "p"}, "spec": {"volumes": [{"name": "k", "secret": {"secretName": "agentgateway-api-keys"}}]}}
	vol := admission.response with input as review("Pod", "model-hprd", mounted) with data.registry as registry with data.admission.config.enforce as set()
	count(vol.warnings) == 1
}

test_reading_the_key_map_elsewhere_is_denied if {
	pod := {"metadata": {"name": "p"}, "spec": {"containers": [{"name": "c", "env": [{"name": "K", "valueFrom": {"secretKeyRef": {"name": "agentgateway-api-keys", "key": "k"}}}]}]}}
	r := admission.response with input as review("Pod", "model-prod", pod) with data.registry as registry
	not r.allowed
	r.status == {"code": 403, "message": "Pod p in model-prod reads the gateway's key map (agentgateway-api-keys); only mini-platform may"}
	r.warnings == []
	home := admission.response with input as review("Pod", "mini-platform", pod) with data.registry as registry
	home.allowed
}

test_without_registry_data_every_key_copy_warns if {
	r := admission.response with input as review("VaultStaticSecret", "mini-platform", copy("holmes"))
	count(r.warnings) == 1
	r.allowed
}
