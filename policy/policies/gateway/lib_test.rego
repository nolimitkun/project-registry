package gateway.lib_test

import data.gateway.lib
import rego.v1

test_the_data_classes_setting_caps_placements if {
	lib.placements("p") == {"onprem"} with data.projects.p as {"data_class": "restricted", "placement": ["onprem", "gcp"]}
		with data.registry.settings.data_classes as {"restricted": ["onprem"], "confidential": ["onprem"], "internal": ["onprem", "gcp"], "public": ["onprem", "gcp", "external"]}
	lib.placements("p") == {"onprem", "gcp"} with data.projects.p as {"data_class": "restricted", "placement": ["onprem", "gcp"]}
		with data.registry.settings.data_classes as {"restricted": ["onprem", "gcp"], "confidential": ["onprem"], "internal": ["onprem", "gcp"], "public": ["onprem", "gcp", "external"]}
}
