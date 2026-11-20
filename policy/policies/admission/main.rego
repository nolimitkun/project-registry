# The webhook's entry point: OPA answers POST / with data.system.main (its
# default decision), so the AdmissionReview Kubernetes sends gets one back.
package system

import data.admission
import rego.v1

main := {
	"apiVersion": "admission.k8s.io/v1",
	"kind": "AdmissionReview",
	"response": admission.response,
}
