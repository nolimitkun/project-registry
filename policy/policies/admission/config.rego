# Which admission rules deny rather than warn. Empty: every finding is a
# warning, until a rule's warnings show it is right. A change here is a policy
# change, approved like any other.
package admission.config

import rego.v1

enforce := set()
