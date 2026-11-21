# Kubernetes admission for the platform's namespaces: guardrails against the
# project registry's records (data.platform). Each rule adds findings; a finding
# is a warning, or a denial once its rule is in config.enforce (config.rego).
# Served by the admission OPA fleet, whose bundle OPA Control Plane builds from
# this directory at the registry's active policy commit (registry/ocp.py).
package admission

import data.admission.config
import data.platform
import rego.v1

request := input.request

obj := request.object

name := sprintf("%s/%s", [request.namespace, obj.metadata.name])

# A VaultStaticSecret copying a gateway key out of the clients' map names a key
# id the registry lists: an unknown one gives the client an empty key.
findings contains {"rule": "gateway_key_copy_known", "message": msg} if {
	request.kind.kind == "VaultStaticSecret"
	obj.spec.path == "agentgateway-client-keys"
	some id in copied_key_ids
	not platform.keys[id]
	msg := sprintf("VaultStaticSecret %s copies gateway key id %q, which no project or agent in the project registry lists", [name, id])
}

copied_key_ids contains id if {
	some _, template in object.get(obj.spec, ["destination", "transformation", "templates"], {})
	some match in regex.find_all_string_submatch_n(`get \.Secrets "([^"]+)"`, template.text, -1)
	id := match[1]
}

# A model deployment in a serving namespace is a catalog model's: one the
# catalog doesn't name serves nothing the gateway routes or prices. KServe's
# controller validates each deployment by dry-running a copy of it
# (<deployment>-validation-<suffix>), which is never created: not a deployment.
findings contains {"rule": "deployment_catalogued", "message": msg} if {
	request.kind.kind == "LLMInferenceService"
	request.namespace in platform.serving_namespaces
	not kserve_validation
	not platform.deployments[name]
	msg := sprintf("LLMInferenceService %s is no catalog model's deployment (the project registry's catalog)", [name])
}

kserve_controller := "system:serviceaccount:kserve:llmisvc-controller-manager"

kserve_validation if {
	request.dryRun == true
	request.userInfo.username == kserve_controller
}

# Only the gateway's namespace reads the gateway's key map.
findings contains {"rule": "gateway_keys_private", "message": msg} if {
	request.kind.kind == "Pod"
	request.namespace != platform.gateway_namespace
	uses_secret(obj.spec, "agentgateway-api-keys")
	msg := sprintf("Pod %s in %s reads the gateway's key map (agentgateway-api-keys); only %s may", [obj.metadata.name, request.namespace, platform.gateway_namespace])
}

uses_secret(spec, secret) if {
	some v in object.get(spec, "volumes", [])
	v.secret.secretName == secret
}

uses_secret(spec, secret) if {
	some c in array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", []))
	some e in object.get(c, "envFrom", [])
	e.secretRef.name == secret
}

uses_secret(spec, secret) if {
	some c in array.concat(object.get(spec, "containers", []), object.get(spec, "initContainers", []))
	some e in object.get(c, "env", [])
	e.valueFrom.secretKeyRef.name == secret
}

denials contains f.message if {
	some f in findings
	f.rule in config.enforce
}

warnings contains sprintf("%s (%s)", [f.message, f.rule]) if {
	some f in findings
	not f.rule in config.enforce
}

# The AdmissionReview answer (system.main serves it).
response := {"uid": request.uid, "allowed": true, "warnings": sort(warnings)} if {
	count(denials) == 0
} else := {"uid": request.uid, "allowed": false, "warnings": sort(warnings), "status": {"code": 403, "message": concat("; ", sort(denials))}}
