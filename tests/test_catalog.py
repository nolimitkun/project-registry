"""gen-catalog.py: the Google APIs' gRPC services (streaming speech and TTS)."""
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("gen_catalog", ROOT / "policy/scripts/gen-catalog.py")
gc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gc)

MODELS = {"m": {"placement": "gcp", "provider": "Vertex", "price": {"input": 0, "output": 0}}}
SPEECH = {"host": "eu-speech.googleapis.com", "placement": "gcp", "grpcServices": ["google.cloud.speech.v2.Speech"]}


def errors(apis):
    return [e for e in gc.validate({"models": MODELS, "googleApis": apis}) if e.startswith("googleApis")]


def test_grpc_services_render_for_the_gateway_and_the_policy():
    assert errors({"speech": SPEECH}) == []
    out = gc.render({"models": MODELS, "googleApis": {"speech": SPEECH, "vertex": {"host": "v", "placement": "gcp"}}}, {})
    import json, yaml
    gateway = yaml.safe_load(out[gc.GATEWAY_OUT])["catalog"]["googleApis"]
    assert gateway["speech"]["grpcServices"] == ["google.cloud.speech.v2.Speech"]
    assert "grpcServices" not in gateway["vertex"]
    policy = json.loads(out[gc.REGISTRY_OUT])["google_apis"]
    assert policy["speech"] == {"placement": "gcp", "grpc_services": ["google.cloud.speech.v2.Speech"]}
    assert policy["vertex"] == {"placement": "gcp"}


def test_a_grpc_service_belongs_to_one_api():
    assert errors({"speech": SPEECH, "other": {**SPEECH, "host": "x"}}) == [
        "googleApis.other.grpcServices: google.cloud.speech.v2.Speech is googleApis.speech's already"]


def test_bad_grpc_services_are_refused():
    assert errors({"s": {**SPEECH, "grpcServices": ["Speech"]}}) == [
        "googleApis.s.grpcServices: 'Speech' is not a gRPC service name (package.Service)"]
    assert errors({"s": {**SPEECH, "grpcServices": []}}) == [
        "googleApis.s.grpcServices: must be a non-empty list of distinct gRPC service names"]
    assert errors({"s": {**SPEECH, "http1Only": True}}) == [
        "googleApis.s.grpcServices: gRPC needs HTTP/2, so not with http1Only"]
