# Which admission rules deny rather than warn. A rule starts as a warning and
# moves here once its warnings show it is right. A change here is a policy
# change, approved like any other.
#
# - gateway_keys_private: its only finding in the fleet's decision logs was a
#   test Pod; the gateway's own Pods are in mini-platform.
# The others stay warnings: they depend on the registry's records being current,
# and KServe dry-runs `<deployment>-validation-*` copies that no catalog names.
package admission.config

import rego.v1

enforce := {"gateway_keys_private"}
