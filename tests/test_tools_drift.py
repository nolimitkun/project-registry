import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location("tools_drift", Path(__file__).parent.parent / "policy" / "scripts" / "tools-drift.py")
drift = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drift)


def tool(types):
    return {"description": "Generate a resource (YAML, JSON)", "inputSchema": {"type": "object", "properties": {
        "resource_type": {"type": "string", "description": f"Type of resource ({', '.join(types)})"}}}}


def test_a_reordered_list_is_no_drift():
    a, b = tool(["argo_rollout", "istio_auth_policy", "gateway_api_gateway"]), tool(["gateway_api_gateway", "argo_rollout", "istio_auth_policy"])
    assert drift.fingerprint(a) == drift.fingerprint(b)
    assert drift.fingerprint(a, order_proof=False) != drift.fingerprint(b, order_proof=False)
    assert drift.unchanged(drift.fingerprint(a), b)


def test_a_changed_list_is_drift():
    a, b = tool(["argo_rollout", "istio_auth_policy"]), tool(["argo_rollout", "istio_auth_policy", "argo_analysis_template"])
    assert not drift.unchanged(drift.fingerprint(a), b)
    assert not drift.unchanged(drift.fingerprint(a, order_proof=False), b)


def test_records_from_before_still_match():
    a = tool(["argo_rollout", "istio_auth_policy"])
    assert drift.unchanged(drift.fingerprint(a, order_proof=False), a)
