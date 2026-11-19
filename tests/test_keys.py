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
    assert out == {"added": ["admin", "kagent-k8s-agent"], "removed": [], "changed": [],
                   "issued": ["admin", "kagent-k8s-agent"]}
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
    assert out == {"added": ["kagent"], "removed": [], "changed": [], "issued": []}     # adopted, not issued


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


def test_each_map_write_is_reported_even_if_the_next_one_fails():
    kv = FakeKV()
    keys.reconcile(kv, "m", {"admin": "admin", "gone": "admin"}, new_key=counter())

    class FailClients(FakeKV):
        def kv_put(self, mount, name, data):
            if name == keys.CLIENTS:
                raise RuntimeError("vault down")
            super().kv_put(mount, name, data)
    failing, seen = FailClients(kv.data), []
    with pytest.raises(RuntimeError):
        keys.reconcile(failing, "m", {"admin": "admin"}, new_key=counter(), wrote=lambda n, d: seen.append((n, d)))
    assert seen == [(keys.GATEWAY, {"added": [], "removed": ["gone"], "changed": [], "issued": []})]   # the revocation is recorded
    seen.clear()
    keys.reconcile(FakeKV(failing.data), "m", {"admin": "admin"}, new_key=counter(),
                   wrote=lambda n, d: seen.append((n, d)))
    assert seen == [(keys.CLIENTS, {"added": [], "removed": ["gone"], "changed": []})]   # then the clients' map


def test_a_key_map_too_big_for_its_secret_is_not_written(monkeypatch, caplog):
    want = {f"project-{i:04d}": f"project-{i:04d}" for i in range(100)}
    kv = FakeKV()
    keys.reconcile(kv, "m", want)                       # real keys: about 165 bytes an entry
    size = keys.secret_bytes(kv.data[keys.GATEWAY])
    assert 140 * 100 < size < 190 * 100
    monkeypatch.setattr(keys, "WARN_AT", size)          # one more key: past the warning
    more = {**want, "project-0100": "project-0100"}
    keys.reconcile(kv, "m", more)
    assert "near the" in caplog.text and "project-0100" in kv.data[keys.GATEWAY]
    monkeypatch.setattr(keys, "LIMIT", size)            # and past the limit: neither map changes
    before = (dict(kv.data[keys.GATEWAY]), dict(kv.data[keys.CLIENTS]))
    with pytest.raises(ValueError, match="not written"):
        keys.reconcile(kv, "m", {**more, "project-0101": "project-0101"})
    assert (kv.data[keys.GATEWAY], kv.data[keys.CLIENTS]) == before


def test_rotating_keeps_the_previous_key_for_the_gateway_only():
    kv, new_key = FakeKV(), counter()
    keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key)
    old = kv.data[keys.CLIENTS]["holmes"]
    out = keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key, rotate={"holmes": True})
    assert out == {"added": ["holmes.previous"], "removed": [], "changed": ["holmes"], "issued": ["holmes"]}
    new = kv.data[keys.CLIENTS]["holmes"]
    assert new != old and kv.data[keys.CLIENTS]["admin"] == gateway_entry(kv, "admin")["key"]
    assert gateway_entry(kv, "holmes") == {"key": new, "metadata": {"project": "holmes", "key_id": "holmes"}}
    assert gateway_entry(kv, "holmes.previous") == {"key": old, "metadata": {"project": "holmes", "key_id": "holmes"}}
    assert "holmes.previous" not in kv.data[keys.CLIENTS]
    # in its grace period the previous key stays; after it, it is dropped
    assert keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key,
                          keep_previous={"holmes"}) is None
    out = keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key)
    assert out["removed"] == ["holmes.previous"] and gateway_entry(kv, "holmes")["key"] == new


def test_rotating_without_a_grace_period_revokes_the_old_key_at_once():
    kv, new_key = FakeKV(), counter()
    keys.reconcile(kv, "m", {"holmes": "holmes"}, new_key=new_key)
    keys.reconcile(kv, "m", {"holmes": "holmes"}, new_key=new_key, rotate={"holmes": True})
    out = keys.reconcile(kv, "m", {"holmes": "holmes"}, new_key=new_key, rotate={"holmes": False},
                         keep_previous={"holmes"})
    assert out["removed"] == ["holmes.previous"] and out["issued"] == ["holmes"]
    assert list(kv.data[keys.GATEWAY]) == ["holmes"]


def test_a_second_rotation_replaces_the_previous_key_and_a_gone_key_id_takes_its_previous_along():
    kv, new_key = FakeKV(), counter()
    keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key)
    keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key, rotate={"holmes": True})
    middle = kv.data[keys.CLIENTS]["holmes"]
    keys.reconcile(kv, "m", {"holmes": "holmes", "admin": "admin"}, new_key=new_key, rotate={"holmes": True},
                   keep_previous={"holmes"})
    assert gateway_entry(kv, "holmes.previous")["key"] == middle
    out = keys.reconcile(kv, "m", {"admin": "admin"}, new_key=new_key, keep_previous={"holmes"},
                         rotate={"holmes": True})                 # a gone key id is not rotated back in
    assert out["removed"] == ["holmes", "holmes.previous"] and list(kv.data[keys.GATEWAY]) == ["admin"]


def test_owners_of_keys():
    records = {"project": {"holmes": {"keys": ["holmes"]}, "kagent": {"keys": ["kagent"]}},
               "agent": {"k8s": {"project": "kagent", "keys": ["kagent-k8s-agent"]}}}
    assert keys.owners(records) == {"holmes": {"project": "holmes", "agent": None},
                                    "kagent": {"project": "kagent", "agent": None},
                                    "kagent-k8s-agent": {"project": "kagent", "agent": "k8s"}}
