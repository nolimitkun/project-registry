import json
import shutil
import subprocess
import tarfile
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from registry import bundles

OPA = shutil.which("opa") or str(Path(__file__).resolve().parents[1] / ".bin" / "opa")


@pytest.fixture
def signer():
    return bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "opa-bundles")


@pytest.fixture
def src(tmp_path):
    d = tmp_path / "src"
    (d / "x").mkdir(parents=True)
    (d / ".manifest").write_text(json.dumps({"roots": ["x"]}))
    (d / "x" / "data.json").write_text('{"a": 1}')
    (d / "x" / "p.rego").write_text("package x\n\nallow := true\n")
    (d / "x" / "p_test.rego").write_text("package x\n\ntest_allow if allow\n")
    return d


def test_signed_bundle_verifies_and_carries_its_revision(src, signer, tmp_path):
    out = tmp_path / "b.tar.gz"
    payload = bundles.build(src, "rev-7", signer, out, opa=OPA)
    assert payload["keyid"] == "opa-bundles"
    assert {f["name"] for f in payload["files"]} == {"x/p.rego", "data.json", ".manifest"}   # tests left out
    bundles.verify(out, signer.public_pem(), "opa-bundles", opa=OPA)
    with tarfile.open(out) as tar:
        manifest = json.loads(tar.extractfile(bundles._member(tar, ".manifest")).read())
    assert manifest["revision"] == "rev-7" and manifest["roots"] == ["x"]


def test_another_key_or_a_changed_file_fails_verification(src, signer, tmp_path):
    out = tmp_path / "b.tar.gz"
    bundles.build(src, "rev-1", signer, out, opa=OPA)
    other = bundles.LocalKeySigner(rsa.generate_private_key(public_exponent=65537, key_size=2048), "opa-bundles")
    with pytest.raises(subprocess.CalledProcessError):
        bundles.verify(out, other.public_pem(), "opa-bundles", opa=OPA)
    # tamper: same signature, different policy
    tampered = tmp_path / "t.tar.gz"
    with tarfile.open(out) as tar, tarfile.open(tampered, "w:gz") as dst:
        for m in tar.getmembers():
            data = tar.extractfile(m).read()
            if m.name.lstrip("/") == "x/p.rego":
                data = b"package x\n\nallow := false\n"
                m.size = len(data)
            import io
            dst.addfile(m, io.BytesIO(data))
    with pytest.raises(subprocess.CalledProcessError):
        bundles.verify(tampered, signer.public_pem(), "opa-bundles", opa=OPA)


class FakeS3:
    class exceptions:
        class NoSuchKey(Exception):
            pass

    def __init__(self):
        self.objects = {}

    def upload_file(self, path, bucket, key):
        self.objects[key] = Path(path).read_bytes()

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise self.exceptions.NoSuchKey(Key)

    def copy_object(self, Bucket, Key, CopySource):
        self.objects[Key] = self.objects[CopySource["Key"]]

    def put_object(self, Bucket, Key, Body, ContentType=None):
        self.objects[Key] = Body

    def get_object(self, Bucket, Key):
        if Key not in self.objects:
            raise self.exceptions.NoSuchKey(Key)
        import io
        return {"Body": io.BytesIO(self.objects[Key])}

    def download_file(self, bucket, key, path):
        Path(path).write_bytes(self.objects[key])

    def list_objects_v2(self, Bucket, Prefix, Delimiter="/", ContinuationToken=None):
        subs = sorted({Prefix + k[len(Prefix):].split(Delimiter)[0] + Delimiter
                       for k in self.objects if k.startswith(Prefix) and Delimiter in k[len(Prefix):]})
        return {"CommonPrefixes": [{"Prefix": p} for p in subs], "IsTruncated": False}


def test_store_activates_and_rolls_back(tmp_path):
    s3, store = FakeS3(), None
    store = bundles.Store(s3, "opa-bundles")
    assert store.active("gateway-projects") is None
    for rev, body in (("r1", b"one"), ("r2", b"two")):
        (tmp_path / rev).write_bytes(body)
        store.put_revision("gateway-projects", rev, tmp_path / rev)
        store.activate("gateway-projects", rev)
    assert store.active("gateway-projects") == "r2"
    assert s3.objects["gateway-projects/bundle.tar.gz"] == b"two"
    store.activate("gateway-projects", "r1")
    assert s3.objects["gateway-projects/bundle.tar.gz"] == b"one" and store.active("gateway-projects") == "r1"
    with pytest.raises(FakeS3.exceptions.NoSuchKey):
        store.activate("gateway-projects", "missing")
