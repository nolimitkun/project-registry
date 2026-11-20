# What every OPA fleet that OPA Control Plane (OCP) builds shares: the project
# registry's records, as facts. OCP mounts this package into each fleet's bundle
# through a stack (fleet label), and the registry pushes the facts as
# data.registry after each data bundle it activates (registry/ocp.py). The
# gateway's own OPA doesn't use it: its bundles are the registry's, signed.
#
# No .manifest here or in a fleet's directory: OCP takes a source's .manifest
# roots over the ones it computes, which would leave the pushed data out.
package platform

import rego.v1

# key id -> {"project", "agent"}: every gateway key id a project or agent lists.
default keys := {}

keys := data.registry.keys

# "<namespace>/<name>" of each catalog model's deployment -> the model.
default deployments := {}

deployments := data.registry.deployments

# The namespaces the onboarding pipeline deploys models into.
default serving_namespaces := set()

serving_namespaces := {ns | some ns in data.registry.serving_namespaces}

# The namespace whose workloads are the platform's gateway (and may read its keys).
gateway_namespace := "mini-platform"
