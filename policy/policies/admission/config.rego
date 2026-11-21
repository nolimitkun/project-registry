# Which admission rules deny rather than warn. A rule starts as a warning and
# moves here once its warnings show it is right. A change here is a policy
# change, approved like any other.
#
# - gateway_keys_private: its only finding in the fleet's decision logs was a
#   test Pod; the gateway's own Pods are in mini-platform.
# The others stay warnings:
# - deployment_catalogued, by design: the model onboarding pipeline deploys before
#   the catalog names the deployment, in model-hprd to evaluate a model (never
#   catalogued) and in model-prod for each new release, which its promote-catalog
#   step catalogues only after the prod smoke test. A denial would refuse both. As a
#   warning it flags a deployment the catalog never picks up.
# - gateway_key_copy_known: a key copy can land before the registry change that
#   adds its key id.
package admission.config

import rego.v1

enforce := {"gateway_keys_private"}
