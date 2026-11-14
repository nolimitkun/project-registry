import json

import pytest

from registry import keys


class FakeKV:
    def __init__(self, data=None):
        self.data, self.writes = dict(data or {}), []

    def kv_get(self, mount, name):
        return dict(self.data[name]) if name in self.data else None

    def kv_put(self, mount, name, data):
        self.writes.append(name)
        self.data[name] = dict(data)


def counter():
    n = iter(range(1000))
    return lambda: f"k{next(n)}"


def gateway_entry(kv, key_id):
    return json.loads(kv.data[keys.GATEWAY][key_id])


def test_new_key_ids_get_keys_the_gateway_knows_first():
    kv = FakeKV()
    out = keys.reconcile(kv, "m", {"admin": "admin", "kagent-k8s-agent": "kagent"}, new_key=counter())
    assert out == {"added": ["admin", "kagent-k8s-agent"], "removed": [], "changed": []}
    assert kv.writes == [keys.GATEWAY, keys.CLIENTS]                            # the gateway's map first
    assert gateway_entry(kv, "kagent-k8s-agent") == {"key": kv.data[keys.CLIENTS]["kagent-k8s-agent"],
                                                     "metadata": {"project": "kagent", "key_id": "kagent-k8s-agent"}}


def test_existing_keys_are_kept_and_nothing_is_written_when_current():
    kv = FakeKV()
    keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter())
    before = dict(kv.data[keys.CLIENTS])
    kv.writes.clear()
    assert keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter()) is None
    assert kv.writes == [] and kv.data[keys.CLIENTS] == before


def test_maps_written_by_the_old_bootstrap_are_adopted_without_rotating():
    old = {keys.GATEWAY: {"admin": '{"key":"A","metadata":{"project":"admin","key_id":"admin"}}'},
           keys.CLIENTS: {"admin": "A", "kagent": "K"}}
    kv = FakeKV(old)
    out = keys.reconcile(kv, "m", {"admin": "admin", "kagent": "kagent"}, new_key=counter())
    assert kv.data[keys.CLIENTS] == {"admin": "A", "kagent": "K"}             # kagent's key from the clients' map
    assert out == {"added": ["kagent"], "removed": [], "changed": []}


def test_a_removed_key_id_is_revoked_in_both_maps():
    kv = FakeKV()
    keys.reconcile(kv, "m", {"admin": "admin", "gone": "admin"}, new_key=counter())
    out = keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter())
    assert out["removed"] == ["gone"]
    assert "gone" not in kv.data[keys.GATEWAY] and "gone" not in kv.data[keys.CLIENTS]


def test_a_client_map_that_drifted_is_mended_from_the_gateways():
    kv = FakeKV()
    keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter())
    kv.data[keys.CLIENTS]["admin"] = "tampered"
    out = keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter())
    assert out["changed"] == ["admin"] and kv.data[keys.CLIENTS]["admin"] == gateway_entry(kv, "admin")["key"]


def test_no_key_ids_never_empties_the_maps():
    kv = FakeKV()
    keys.reconcile(kv, "m", {"admin": "admin"}, new_key=counter())
    with pytest.raises(ValueError):
        keys.reconcile(kv, "m", {}, new_key=counter())
    assert "admin" in kv.data[keys.GATEWAY]


def test_wanted_reads_gen_projects_key_lines():
    assert keys.wanted("admin admin\nkagent-k8s-agent kagent\n\n") == {"admin": "admin", "kagent-k8s-agent": "kagent"}
