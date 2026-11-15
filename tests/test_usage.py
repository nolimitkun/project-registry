"""The usage pipeline (registry/usage.py) with an in-memory bucket: no Loki, no MinIO."""
import datetime as dt
import hashlib
import io

import pytest

from registry import usage

UTC = dt.timezone.utc
SERVED = "unsloth/Qwen3.6-27B-NVFP4@ccdaab7e68af2409599b8949a8f2685703c9bae5"


class FakeS3:
    def __init__(self):
        self.objects: dict[tuple[str, str], bytes] = {}

    def put_object(self, Bucket, Key, Body, **_):
        self.objects[(Bucket, Key)] = Body if isinstance(Body, bytes) else Body.read()

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise KeyError(f"NoSuchKey {Key}")
        return {"Body": io.BytesIO(self.objects[(Bucket, Key)])}

    def list_objects_v2(self, Bucket, Prefix, ContinuationToken=None):
        keys = sorted(k for b, k in self.objects if b == Bucket and k.startswith(Prefix))
        return {"Contents": [{"Key": k, "ETag": hashlib.md5(self.objects[(Bucket, k)]).hexdigest()} for k in keys],
                "IsTruncated": False}


def line(ts, **kv):
    fields = {"gateway": "mini-platform/agentgateway-proxy", "route": "internal/llm:request", "http.status": "200",
              "protocol": "llm", "duration": "700ms", **kv}
    return f"{ts}\tinfo\trequest " + " ".join(f"{k}={v}" for k, v in fields.items())


CLOUD = line("2026-11-15T10:05:00.000001Z", **{
    "trace.id": "t1", "span.id": "s1", "project": "admin", "key_id": "admin", "gen_ai.provider.name": "gcp.vertex_ai",
    "gen_ai.request.model": "gemini-3.8-flash", "agw.ai.original_model": "gemini-3.8-flash",
    "gen_ai.usage.input_tokens": "4", "gen_ai.usage.output_tokens": "61", "agw.ai.usage.cost.total": "0.00023175"})
KSERVE = line("2026-11-15T10:06:00Z", **{
    "trace.id": "t2", "span.id": "s2", "project": "kagent", "key_id": "kagent-k8s-agent", "gen_ai.provider.name": "custom",
    "gen_ai.request.model": SERVED, "agw.ai.original_model": "qwen3.6-27b",
    "gen_ai.usage.input_tokens": "16", "gen_ai.usage.output_tokens": "18", "duration": "1.5s"})
AUTO = line("2026-11-15T10:07:00Z", **{
    "trace.id": "t3", "span.id": "s3", "project": "admin", "key_id": "admin", "gen_ai.request.model": "gemini-3.5-flash-lite",
    "agw.ai.original_model": "auto-general", "gen_ai.usage.input_tokens": "2", "gen_ai.usage.output_tokens": "9",
    "agw.ai.usage.cost.total": "0.0000231"})
DENIED = line("2026-11-15T10:08:00Z", **{
    "trace.id": "t4", "span.id": "s4", "project": "open-webui", "key_id": "open-webui", "http.status": "403",
    "protocol": "http", "reason": "DirectResponse", "duration": "1ms"})
OTHER = line("2026-11-15T10:09:00Z", **{"trace.id": "t5", "span.id": "s5", "protocol": "http", "http.path": "/healthz"})

RECORDS = {
    "project": {"admin": {"data_class": "public", "keys": ["admin"], "budget": {"usd_per_30_days": 25},
                          "limits": {"requests_per_minute": 60}, "routing": "semantic"},
                "kagent": {"data_class": "internal", "keys": ["kagent"], "budget": {"usd_per_30_days": 30}},
                "open-webui": {"data_class": "internal", "keys": ["open-webui"]}},
    "agent": {"kagent-k8s-agent": {"project": "kagent", "keys": ["kagent-k8s-agent"]}},
    "model": {"gemini-3.8-flash": {"placement": "gcp", "provider": "VertexAI", "price": {"input": 0.75, "output": 3.75}},
              "gemini-3.5-flash-lite": {"placement": "gcp", "provider": "VertexAI", "price": {"input": 0.3, "output": 2.5}},
              "qwen3.6-27b": {"placement": "onprem", "provider": "KServe", "servedModel": SERVED,
                              "price": {"input": 0, "output": 0}}},
}
OWNERS = {"admin": "platform-team", "kagent": "platform-team", "open-webui": "webui-owners"}
NOW = dt.datetime(2026, 11, 15, 11, 30, tzinfo=UTC)


def loki(lines):
    """lines_of for usage.run: the lines whose time is in [start, end)."""
    def lines_of(start, end):
        for ln in lines:
            t = dt.datetime.fromisoformat(ln.split("\t")[0].replace("Z", "+00:00"))
            if start <= t < end:
                yield "agentgateway-proxy-1", ln
    return lines_of


@pytest.fixture
def bucket():
    return usage.Bucket(FakeS3(), "registry-usage")


def daily(bucket, day="2026-11-15"):
    r = usage.Reader(bucket)
    d = dt.date.fromisoformat(day)
    return r.query("daily", d, d, "SELECT * FROM t ORDER BY project, model, outcome")


def test_parse_reads_the_access_log():
    r = usage.parse(KSERVE, "p")
    assert (r["project"], r["key_id"], r["request_model"], r["original_model"]) == ("kagent", "kagent-k8s-agent", SERVED, "qwen3.6-27b")
    assert (r["input_tokens"], r["output_tokens"], r["cost_usd"], r["duration_ms"]) == (16, 18, None, 1500.0)
    assert usage.parse(CLOUD)["cost_usd"] == pytest.approx(0.00023175)
    assert usage.parse(DENIED)["status"] == 403                    # tied to a project: kept
    assert usage.parse(OTHER) is None                               # no model, no project
    assert usage.parse("2026-11-15T10:00:00Z\tinfo\txds connected") is None
    assert usage.parse(line("2026-11-15T10:00:00Z", project="admin", reason='"a b"'))["reason"] == "a b"


def test_a_run_names_models_as_the_catalog_and_joins_agents_and_budgets(bucket):
    state = usage.run(bucket, loki([CLOUD, KSERVE, AUTO, DENIED, OTHER]), RECORDS, OWNERS, now=NOW, backfill=3)
    assert state["days"] == {"2026-11-15": 4} and state["through"] == "2026-11-15T11:30:00+00:00"   # the run's time
    rows = {(r["project"], r["model"], r["outcome"]): r for r in daily(bucket)}
    assert set(rows) == {("admin", "gemini-3.8-flash", "ok"), ("admin", "gemini-3.5-flash-lite", "ok"),
                         ("kagent", "qwen3.6-27b", "ok"), ("open-webui", None, "denied")}
    q = rows[("kagent", "qwen3.6-27b", "ok")]                       # the served name, back to the catalog's
    assert (q["agent"], q["placement"], q["cost_usd"], q["output_tokens"]) == ("kagent-k8s-agent", "onprem", 0, 18)
    a = rows[("admin", "gemini-3.5-flash-lite", "ok")]              # auto: the model it chose, and the virtual one
    assert (a["virtual_model"], a["agent"], a["placement"]) == ("auto-general", None, "gcp")
    assert rows[("admin", "gemini-3.8-flash", "ok")]["cost_usd"] == pytest.approx(0.00023175)
    assert {r["kind"] for r in rows.values()} == {"model", "other"}   # the 403 never reached a model
    listing = line("2026-11-15T10:10:00Z", **{"trace.id": "t6", "span.id": "s6", "project": "admin", "key_id": "admin",
                                              "http.path": "/v1/models"})
    usage.run(bucket, loki([CLOUD, listing]), RECORDS, OWNERS, now=NOW, backfill=3)
    assert {(r["kind"], r["requests"]) for r in daily(bucket)} == {("model", 1), ("list", 1)}
    dims = usage.Reader(bucket).bucket.get("dims/date=2026-11-15/projects.parquet")
    assert dims                                                     # the day's budgets, for the day's spend


def test_an_mcp_tool_is_named_as_the_catalog_does(bucket):
    # what the gateway logs for tools/call: the tool without its target's prefix
    call = line("2026-11-15T10:13:00Z", **{"trace.id": "m", "span.id": "m", "project": "admin", "key_id": "admin",
                                           "protocol": "mcp", "route": "mini-platform/platform-mcp", "http.path": "/mcp",
                                           "mcp.method.name": "tools/call", "mcp.target": "grafana",
                                           "mcp.resource.type": "tool", "gen_ai.tool.name": "list_datasources"})
    usage.run(bucket, loki([call]), RECORDS, OWNERS, now=NOW, backfill=3)
    [req] = usage.requests_of(usage.Reader(bucket), "admin", dt.date(2026, 11, 15))
    assert (req["kind"], req["mcp_method"], req["mcp_tool"]) == ("mcp", "tools/call", "grafana_list_datasources")


def test_raw_files_from_before_a_column_existed_still_read(bucket, tmp_path):
    usage.run(bucket, loki([CLOUD]), RECORDS, OWNERS, now=NOW, backfill=3)
    # rewrite 10:00's raw file without mcp_target, as an older job wrote it
    con = usage._duck()
    old = tmp_path / "old.parquet"
    (tmp_path / "cur.parquet").write_bytes(bucket.get("raw/date=2026-11-15/hour=10.parquet"))
    con.execute(f"COPY (SELECT * EXCLUDE (mcp_target) FROM read_parquet('{tmp_path / 'cur.parquet'}')) TO '{old}' (FORMAT parquet)")
    bucket.put("raw/date=2026-11-15/hour=10.parquet", old.read_bytes())
    assert usage.transform(bucket, dt.date(2026, 11, 15), tmp_path) == 1


def test_a_providers_429_is_an_error_not_a_limit(bucket):
    ours = line("2026-11-15T10:11:00Z", **{"trace.id": "a", "span.id": "a", "project": "admin", "key_id": "admin",
                                           "http.status": "429", "protocol": "http", "reason": "RateLimit"})
    theirs = line("2026-11-15T10:12:00Z", **{"trace.id": "b", "span.id": "b", "project": "admin", "key_id": "admin",
                                             "http.status": "429", "reason": "Upstream", "agw.ai.original_model": "gemini-4-argon"})
    usage.run(bucket, loki([ours, theirs]), RECORDS, OWNERS, now=NOW, backfill=3)
    assert {r["outcome"] for r in daily(bucket)} == {"limited", "error"}


def test_reruns_and_late_lines_count_each_request_once(bucket):
    usage.run(bucket, loki([CLOUD]), RECORDS, OWNERS, now=NOW, backfill=3)
    # an hour later: the same line again (still within the lookback) and one that came late
    late = line("2026-11-15T10:30:00Z", **{"trace.id": "t9", "span.id": "s9", "project": "admin", "key_id": "admin",
                                          "agw.ai.original_model": "gemini-3.8-flash", "agw.ai.usage.cost.total": "0.001"})
    usage.run(bucket, loki([CLOUD, CLOUD, late]), RECORDS, OWNERS, now=NOW + dt.timedelta(hours=1), backfill=3)
    [row] = daily(bucket)
    assert row["requests"] == 2 and row["cost_usd"] == pytest.approx(0.00123175)


def test_hours_outside_the_lookback_are_extracted_once(bucket):
    usage.run(bucket, loki([CLOUD]), RECORDS, OWNERS, now=NOW, lookback=1, backfill=3)
    # 10:00 is now outside the lookback and already extracted: a line Loki only has now is not read again
    calls = []
    def lines_of(start, end):
        calls.append(start.hour)
        return iter(())
    usage.run(bucket, lines_of, RECORDS, OWNERS, now=NOW + dt.timedelta(hours=2), lookback=1, backfill=4)
    assert 10 not in calls and calls == [12, 13]
    assert daily(bucket)[0]["requests"] == 1


def test_a_day_without_dims_uses_the_earliest_there_are(bucket):
    # extracted on the 15th: the 14th's hours get the 15th's dims (the earliest there are)
    old = line("2026-11-14T23:10:00Z", **{"trace.id": "t7", "span.id": "s7", "project": "kagent", "key_id": "kagent-k8s-agent",
                                          "agw.ai.original_model": "qwen3.6-27b", "gen_ai.request.model": SERVED})
    usage.run(bucket, loki([old]), RECORDS, OWNERS, now=NOW, backfill=14)
    [row] = daily(bucket, "2026-11-14")
    assert (row["agent"], row["model"]) == ("kagent-k8s-agent", "qwen3.6-27b")


def test_dims_name_each_keys_agent():
    d = usage.dims_rows(RECORDS, OWNERS)
    keys = {k["key_id"]: (k["project"], k["agent"]) for k in d["keys"]}
    assert keys == {"admin": ("admin", None), "kagent": ("kagent", None), "open-webui": ("open-webui", None),
                    "kagent-k8s-agent": ("kagent", "kagent-k8s-agent")}
    p = {r["project"]: r for r in d["projects"]}
    assert (p["admin"]["budget_usd_30d"], p["open-webui"]["owner_group"], p["kagent"]["routing"]) == (25, "webui-owners", "cheapest")
