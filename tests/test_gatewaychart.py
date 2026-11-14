import io
import tarfile

import yaml

from registry import gatewaychart
from tests.test_bundles import FakeS3


class Checkouts:
    def __init__(self, root):
        self.root = root

    def checkout(self, rev):
        return self.root / rev


def policy_commit(root, rev, models, with_chart=True):
    work = root / rev
    (work / "generated").mkdir(parents=True)
    (work / "generated" / "agentgateway-catalog.yaml").write_text(
        yaml.safe_dump({"catalog": {"models": [{"name": m, "provider": "Deepseek"} for m in models]}}))
    if with_chart:
        chart = work / "charts" / "gateway-models"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text("apiVersion: v2\nname: gateway-models\nversion: 0.0.0\n")
        (chart / "values.yaml").write_text("gatewayName: agentgateway-proxy\ncatalog: {}\n")
        (chart / "templates" / "models.yaml").write_text("{{- range .Values.catalog.models }}\n---\nname: {{ .name }}\n{{- end }}\n")


def unpack(s3, key):
    with tarfile.open(fileobj=io.BytesIO(s3.objects[key]), mode="r:gz") as tar:
        return {m.name: tar.extractfile(m).read() for m in tar.getmembers()}


def test_the_active_policy_is_published_once_as_the_newest_version(tmp_path):
    s3, renderer = FakeS3(), Checkouts(tmp_path)
    repo = gatewaychart.HelmRepo(s3, "gateway-models")
    policy_commit(tmp_path, "a" * 40, ["m1"])
    assert gatewaychart.ensure(repo, renderer, "a" * 40) == "1.0.1"
    assert gatewaychart.ensure(repo, renderer, "a" * 40) is None            # already the newest
    policy_commit(tmp_path, "b" * 40, ["m1", "m2"])
    assert gatewaychart.ensure(repo, renderer, "b" * 40) == "1.0.2"
    index = yaml.safe_load(s3.objects["index.yaml"])
    versions = [e["version"] for e in index["entries"]["gateway-models"]]
    assert versions == ["1.0.2", "1.0.1"]                                   # newest first
    newest = index["entries"]["gateway-models"][0]
    assert newest["urls"] == ["gateway-models-1.0.2.tgz"] and newest["appVersion"] == "b" * 12
    files = unpack(s3, "gateway-models-1.0.2.tgz")
    values = yaml.safe_load(files["gateway-models/values.yaml"])
    assert [m["name"] for m in values["catalog"]["models"]] == ["m1", "m2"]
    assert values["gatewayName"] == "agentgateway-proxy"                     # the chart's defaults stay
    chart = yaml.safe_load(files["gateway-models/Chart.yaml"])
    assert chart["version"] == "1.0.2" and chart["annotations"][gatewaychart.POLICY_ANNOTATION] == "b" * 40
    assert "gateway-models/templates/models.yaml" in files


def test_a_policy_commit_without_the_chart_publishes_nothing(tmp_path):
    s3, renderer = FakeS3(), Checkouts(tmp_path)
    policy_commit(tmp_path, "c" * 40, ["m1"], with_chart=False)
    assert gatewaychart.ensure(gatewaychart.HelmRepo(s3, "gateway-models"), renderer, "c" * 40) is None
    assert "index.yaml" not in s3.objects


def test_a_chart_published_without_a_catalog_digest_is_republished(tmp_path):
    s3, renderer = FakeS3(), Checkouts(tmp_path)
    repo = gatewaychart.HelmRepo(s3, "gateway-models")
    policy_commit(tmp_path, "d" * 40, ["m1"])
    chart = tmp_path / ("d" * 40) / "charts" / "gateway-models"
    repo.publish(chart, {"catalog": {}}, "d" * 12, {gatewaychart.POLICY_ANNOTATION: "d" * 40})   # before the digest
    assert gatewaychart.ensure(repo, renderer, "d" * 40) == "1.0.2"
    assert gatewaychart.ensure(repo, renderer, "d" * 40) is None
