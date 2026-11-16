"""Spend and usage of the AI gateway: its access log as Parquet in MinIO, shaped by DuckDB.

    python -m registry.usage            (an hourly CronJob)

The gateway writes one access log line per request: the project and key (from the
API key's metadata, agentgateway-config policies.yaml), the model, tokens, the cost
it charged (the same number the budgets count), status and duration. Alloy ships the
lines to Loki, which keeps them about a week. Each run:

1. extract: every hour of the last BACKFILL_HOURS that has no raw file yet, and the
   current hour and the LOOKBACK_HOURS before it whatever they have (lines arrive
   late), from Loki into
   raw/date=D/hour=HH.parquet: one file per hour, rewritten whole, so a rerun is
   harmless;
2. dims: today's records (projects with their owner group and budget, keys and the
   agent each belongs to, models with placement and price) into dims/date=D/;
3. transform, with DuckDB, every day an extracted hour belongs to: the day's raw
   hours deduplicated on (trace id, span id), the model named as the catalog names
   it, joined with that day's dims, into fact/date=D/part.parquet (one row per
   request) and daily/date=D/part.parquet (per project, agent, key, kind of
   request, model and outcome: what the portal's Usage page reads);
4. state.json says what has been extracted, and the run records its health as the
   publisher output "usage" (health.py), which the stale-output alert watches.

The dims are per day, so a request is joined with what was true that day: the agent its
key belonged to, the model's placement and served name. The projects' (owner group,
budget, limits) are kept for the record; the Usage page compares spend with the current
budget, the one the rate limit enforces.
Parquet goes through local files and boto3: DuckDB's own S3 support would download
an extension at run time.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import tempfile
import time
from pathlib import Path

import requests

log = logging.getLogger("usage")

UTC = dt.timezone.utc
HOUR = dt.timedelta(hours=1)

# The access log's keys, as columns.
FIELDS = {
    "trace.id": "trace_id", "span.id": "span_id", "project": "project", "key_id": "key_id",
    "protocol": "protocol", "route": "route", "http.status": "status", "http.path": "path",
    "reason": "reason", "gen_ai.provider.name": "provider", "gen_ai.request.model": "request_model",
    "agw.ai.original_model": "original_model", "gen_ai.usage.input_tokens": "input_tokens",
    "gen_ai.usage.output_tokens": "output_tokens", "agw.ai.usage.cost.total": "cost_usd",
    "duration": "duration_ms", "mcp.method.name": "mcp_method", "mcp.target": "mcp_target",
    "gen_ai.tool.name": "mcp_tool",          # without its target's prefix: list_datasources
    # a call OPA refused never reached the LLM or MCP handling: the gateway takes its
    # model or tool (with the target's prefix) from the body (agentgateway-config policies.yaml)
    "refused.model": "refused_model", "refused.tool": "refused_tool",
}
RAW_COLUMNS = {
    "ts": "TIMESTAMPTZ", "pod": "VARCHAR", "trace_id": "VARCHAR", "span_id": "VARCHAR", "project": "VARCHAR",
    "key_id": "VARCHAR", "protocol": "VARCHAR", "route": "VARCHAR", "status": "INTEGER", "path": "VARCHAR",
    "reason": "VARCHAR", "provider": "VARCHAR", "request_model": "VARCHAR", "original_model": "VARCHAR",
    "input_tokens": "BIGINT", "output_tokens": "BIGINT", "cost_usd": "DOUBLE", "duration_ms": "DOUBLE",
    "mcp_method": "VARCHAR", "mcp_target": "VARCHAR", "mcp_tool": "VARCHAR",
    "refused_model": "VARCHAR", "refused_tool": "VARCHAR",
}
PAIR = re.compile(r'([A-Za-z_][\w.]*)=("(?:[^"\\]|\\.)*"|\S*)')
DURATION = re.compile(r"^([0-9.]+)(ns|µs|us|ms|s|m)?$")
SCALE = {"ns": 1e-6, "µs": 1e-3, "us": 1e-3, "ms": 1.0, "s": 1e3, "m": 6e4, None: 1.0}


def parse(line: str, pod: str = "") -> dict | None:
    """One access log line ("<time>\\tinfo\\trequest k=v ..."), as a raw row. None for a line
    that isn't a request, or a request that is neither a model or MCP call nor tied to a
    project (the gateway's other traffic)."""
    head, _, rest = line.partition("\trequest ")
    if not rest:
        return None
    row: dict = {c: None for c in RAW_COLUMNS}
    row["ts"], row["pod"] = head.split("\t", 1)[0], pod
    for key, value in PAIR.findall(rest):
        col = FIELDS.get(key)
        if col is None:
            continue
        if value.startswith('"'):
            value = json.loads(value)
        if col in ("status", "input_tokens", "output_tokens"):
            value = int(value) if value.isdigit() else None
        elif col == "cost_usd":
            try:
                value = float(value)
            except ValueError:
                value = None
        elif col == "duration_ms":
            m = DURATION.match(value)
            value = float(m.group(1)) * SCALE[m.group(2)] if m else None
        row[col] = value
    if row["protocol"] not in ("llm", "mcp") and not row["project"]:
        return None
    return row


# --- storage: a bucket, through boto3 (a dict in the tests) ---

class Bucket:
    def __init__(self, s3, bucket: str, prefix: str = ""):
        self.s3, self.bucket, self.prefix = s3, bucket, prefix

    def put(self, key: str, body: bytes) -> None:
        self.s3.put_object(Bucket=self.bucket, Key=self.prefix + key, Body=body)

    def get(self, key: str) -> bytes | None:
        try:
            return self.s3.get_object(Bucket=self.bucket, Key=self.prefix + key)["Body"].read()
        except Exception as e:
            if "NoSuchKey" in type(e).__name__ or "NoSuchKey" in str(e) or "404" in str(e):
                return None
            raise

    def list(self, prefix: str) -> dict[str, str]:
        """key (without the bucket prefix) -> etag."""
        out, token = {}, None
        while True:
            kw = {"Bucket": self.bucket, "Prefix": self.prefix + prefix}
            if token:
                kw["ContinuationToken"] = token
            page = self.s3.list_objects_v2(**kw)
            for o in page.get("Contents", []):
                out[o["Key"][len(self.prefix):]] = o["ETag"]
            if not page.get("IsTruncated"):
                return out
            token = page["NextContinuationToken"]


def raw_key(hour: dt.datetime) -> str:
    return f"raw/date={hour:%Y-%m-%d}/hour={hour:%H}.parquet"


def _duck():
    import duckdb
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    # within the pod's memory limit (the API's is 512 MiB), whatever DuckDB reads of the host
    con.execute(f"SET memory_limit = '{os.environ.get('USAGE_DUCKDB_MEMORY', '256MB')}'")
    return con


def _to_parquet(con, rows: list[dict], columns: dict[str, str], out: Path, tmp: Path) -> None:
    """Rows (dicts) -> a Parquet file with these column types, through newline-delimited
    JSON: fast, and no Arrow or pandas."""
    src = tmp / (out.name + ".jsonl")
    src.write_text("".join(json.dumps(r, default=str) + "\n" for r in rows))
    cols = ", ".join(f"'{k}': '{v}'" for k, v in columns.items())
    select = ", ".join(columns)
    con.execute(f"COPY (SELECT {select} FROM read_json('{src}', format='newline_delimited', columns={{{cols}}})) "
                f"TO '{out}' (FORMAT parquet)")
    src.unlink()


# --- 1. extract ---

def loki_lines(loki_url: str, selector: str, start: dt.datetime, end: dt.datetime, limit: int = 5000):
    """(pod, line) of every access log line in [start, end), paging forward."""
    query = f'{selector} |= "\\trequest "'
    lo, end_ns, seen = int(start.timestamp() * 1e9), int(end.timestamp() * 1e9), set()
    while lo < end_ns:
        r = requests.get(f"{loki_url.rstrip('/')}/loki/api/v1/query_range", timeout=60, params={
            "query": query, "start": lo, "end": end_ns, "limit": limit, "direction": "forward"})
        r.raise_for_status()
        entries = sorted((int(ts), s["stream"].get("pod", ""), line)
                         for s in r.json()["data"]["result"] for ts, line in s["values"])
        for e in entries:
            if e not in seen:
                seen.add(e)
                yield e[1], e[2]
        if len(entries) < limit:
            return
        # The page was full: go on from its last timestamp (lines at exactly that
        # nanosecond come again and are skipped above).
        lo = entries[-1][0]


def hours_to_extract(bucket: Bucket, now: dt.datetime, lookback: int, backfill: int) -> list[dt.datetime]:
    current = now.replace(minute=0, second=0, microsecond=0)
    have = set(bucket.list("raw/"))
    hours = [current - i * HOUR for i in range(backfill, -1, -1)]
    recent = set(hours[-(lookback + 1):])
    return [h for h in hours if h in recent or raw_key(h) not in have]


def extract(bucket: Bucket, lines_of, hours: list[dt.datetime], tmp: Path) -> None:
    """lines_of(start, end) -> (pod, line) pairs; one raw file per hour."""
    con = _duck()
    for h in hours:
        rows = [r for pod, line in lines_of(h, h + HOUR) if (r := parse(line, pod))]
        out = tmp / f"raw-{h:%Y%m%d%H}.parquet"
        _to_parquet(con, rows, RAW_COLUMNS, out, tmp)
        bucket.put(raw_key(h), out.read_bytes())
        log.info("raw %s: %d requests", raw_key(h), len(rows))


# --- 2. dims ---

DIM_COLUMNS = {
    "projects": {"project": "VARCHAR", "owner_group": "VARCHAR", "data_class": "VARCHAR", "routing": "VARCHAR",
                 "budget_usd_30d": "DOUBLE", "requests_per_minute": "BIGINT", "tokens_per_minute": "BIGINT"},
    "keys": {"key_id": "VARCHAR", "project": "VARCHAR", "agent": "VARCHAR"},
    "models": {"model": "VARCHAR", "placement": "VARCHAR", "provider": "VARCHAR", "served_model": "VARCHAR",
               "price_input": "DOUBLE", "price_output": "DOUBLE"},
}


def dims_rows(records: dict, owners: dict[str, str]) -> dict[str, list[dict]]:
    projects, keys, models = [], [], []
    for pid, p in sorted(records.get("project", {}).items()):
        limits = p.get("limits") or {}
        projects.append({"project": pid, "owner_group": owners.get(pid), "data_class": p.get("data_class"),
                         "routing": p.get("routing") or "cheapest",
                         "budget_usd_30d": (p.get("budget") or {}).get("usd_per_30_days"),
                         "requests_per_minute": limits.get("requests_per_minute"),
                         "tokens_per_minute": limits.get("tokens_per_minute")})
        keys += [{"key_id": k, "project": pid, "agent": None} for k in p.get("keys") or []]
    agent_keys = {k: (a.get("project"), aid) for aid, a in records.get("agent", {}).items() for k in a.get("keys") or []}
    keys = [k for k in keys if k["key_id"] not in agent_keys]
    keys += [{"key_id": k, "project": pid, "agent": aid} for k, (pid, aid) in sorted(agent_keys.items())]
    for name, m in sorted(records.get("model", {}).items()):
        price = m.get("price") or {}
        models.append({"model": name, "placement": m.get("placement"), "provider": m.get("provider"),
                       "served_model": m.get("servedModel"), "price_input": price.get("input"),
                       "price_output": price.get("output")})
    return {"projects": projects, "keys": keys, "models": models}


def write_dims(bucket: Bucket, day: dt.date, dims: dict[str, list[dict]], tmp: Path) -> None:
    con = _duck()
    for name, rows in dims.items():
        out = tmp / f"dims-{name}.parquet"
        _to_parquet(con, rows, DIM_COLUMNS[name], out, tmp)
        bucket.put(f"dims/date={day:%Y-%m-%d}/{name}.parquet", out.read_bytes())


# --- 3. transform ---

FACT_SQL = """
WITH raw AS (
  -- union_by_name: raw files written before a column existed have it as NULL
  SELECT * FROM read_parquet({raw}, union_by_name = true)
), dedup AS (
  -- a line Loki returned twice, or an hour extracted twice: one row per request
  SELECT * FROM raw
  QUALIFY row_number() OVER (PARTITION BY coalesce(trace_id || '/' || span_id, CAST(ts AS VARCHAR) || pod || coalesce(path, ''))
                             ORDER BY ts) = 1
), named AS (
  SELECT d.*,
         CASE WHEN original_model LIKE 'auto%' THEN original_model END AS virtual_model,
         -- the catalog's name: a KServe model's route sends the name vLLM serves, and
         -- auto's original model is the virtual one
         coalesce(served.model,
                  CASE WHEN original_model IS NULL OR original_model LIKE 'auto%' THEN request_model
                       ELSE original_model END,
                  refused_model) AS model
  FROM dedup d LEFT JOIN models served ON served.served_model = d.request_model
)
SELECT ts, CAST(ts AS DATE) AS date, n.project, n.key_id, k.agent, n.protocol,
       -- what the request was: a model call, a list of models (/v1/models: clients probe
       -- it often), an MCP message, or something else the project's key opened. A call
       -- OPA refused never reached the gateway's LLM or MCP handling (protocol http,
       -- reason DirectResponse), so its path tells what it was, and the gateway's
       -- refused.model or refused.tool what it asked for
       CASE WHEN n.protocol = 'mcp' OR n.path = '/mcp' OR n.path LIKE '/mcp/%' THEN 'mcp'
            WHEN n.path LIKE '%/models' THEN 'list'
            WHEN n.protocol = 'llm' OR regexp_matches(coalesce(n.path, ''),
                 '^/v1/(chat/completions|completions|embeddings|messages|responses)$') THEN 'model'
            ELSE 'other' END AS kind,
       n.model, n.virtual_model,
       m.placement, coalesce(m.provider, n.provider) AS provider,
       -- denied and limited: the gateway's own answers (OPA's 403, the rate limit's 429); the
       -- same codes from a provider (reason Upstream, a Vertex quota) are errors
       CASE WHEN status BETWEEN 200 AND 399 THEN 'ok'
            WHEN status = 403 AND reason IS DISTINCT FROM 'Upstream' THEN 'denied'
            WHEN status = 429 AND reason IS DISTINCT FROM 'Upstream' THEN 'limited'
            WHEN status = 401 THEN 'unauthenticated' ELSE 'error' END AS outcome,
       status, reason, coalesce(input_tokens, 0) AS input_tokens, coalesce(output_tokens, 0) AS output_tokens,
       coalesce(cost_usd, 0) AS cost_usd, duration_ms, mcp_method,
       -- a tool as the catalog and the policy name it: its target's prefix, then its name
       CASE WHEN mcp_target IS NOT NULL AND mcp_tool IS NOT NULL THEN mcp_target || '_' || mcp_tool
            ELSE coalesce(mcp_tool, refused_tool) END AS mcp_tool, trace_id
FROM named n
LEFT JOIN keys k ON k.key_id = n.key_id
LEFT JOIN models m ON m.model = n.model
"""

DAILY_SQL = """
SELECT date, project, agent, key_id, kind, model, virtual_model, placement, provider, protocol, outcome,
       count(*) AS requests, sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
       sum(cost_usd) AS cost_usd, sum(duration_ms) AS duration_ms
FROM fact GROUP BY ALL
"""


def _dims_for(bucket: Bucket, con, day: dt.date, tmp: Path) -> None:
    """The dims of `day`, or of the latest day before it that has them, as tables."""
    dates = sorted({k.split("/")[1][5:] for k in bucket.list("dims/")})
    usable = [d for d in dates if d <= f"{day:%Y-%m-%d}"] or dates[:1]
    for name, cols in DIM_COLUMNS.items():
        body = bucket.get(f"dims/date={usable[-1]}/{name}.parquet") if usable else None
        if body is None:
            con.execute(f"CREATE OR REPLACE TABLE {name} ({', '.join(f'{c} {t}' for c, t in cols.items())})")
            continue
        path = tmp / f"d-{name}.parquet"
        path.write_bytes(body)
        con.execute(f"CREATE OR REPLACE TABLE {name} AS SELECT * FROM read_parquet('{path}')")


def transform(bucket: Bucket, day: dt.date, tmp: Path) -> int:
    """fact and daily of one day from its raw hours. Returns the day's requests."""
    keys = sorted(k for k in bucket.list(f"raw/date={day:%Y-%m-%d}/"))
    if not keys:
        return 0
    con = _duck()
    # every raw column, for a day whose files all predate one (union_by_name: NULL)
    schema = tmp / f"raw-schema-{day}.parquet"
    _to_parquet(con, [], RAW_COLUMNS, schema, tmp)
    paths = [str(schema)]
    for k in keys:
        p = tmp / k.replace("/", "_")
        p.write_bytes(bucket.get(k))
        paths.append(str(p))
    _dims_for(bucket, con, day, tmp)
    con.execute("CREATE TABLE fact AS " + FACT_SQL.format(raw="[" + ", ".join(f"'{p}'" for p in paths) + "]"))
    for name, sql in (("fact", "SELECT * FROM fact ORDER BY ts"), ("daily", DAILY_SQL)):
        out = tmp / f"{name}-{day}.parquet"
        con.execute(f"COPY ({sql}) TO '{out}' (FORMAT parquet)")
        bucket.put(f"{name}/date={day:%Y-%m-%d}/part.parquet", out.read_bytes())
    return con.execute("SELECT count(*) FROM fact").fetchone()[0]


# --- a run ---

def run(bucket: Bucket, lines_of, records: dict, owners: dict[str, str], now: dt.datetime | None = None,
        lookback: int = 3, backfill: int = 168) -> dict:
    now = now or dt.datetime.now(UTC)
    hours = hours_to_extract(bucket, now, lookback, backfill)
    with tempfile.TemporaryDirectory() as t:
        tmp = Path(t)
        extract(bucket, lines_of, hours, tmp)
        write_dims(bucket, now.date(), dims_rows(records, owners), tmp)
        counts = {str(d): transform(bucket, d, tmp) for d in sorted({h.date() for h in hours})}
    # complete up to the run: the current hour's lines so far (the next runs take it again)
    state = {"through": now.isoformat(), "hours": len(hours), "days": counts}
    bucket.put("state.json", json.dumps(state, indent=1).encode())
    log.info("usage: %d hours extracted, days %s", len(hours), counts)
    return state


# --- reading, for the API ---

class Reader:
    """The daily and fact files, cached locally by etag; queried with DuckDB."""

    def __init__(self, bucket: Bucket, cache: Path | None = None):
        self.bucket = bucket
        self.cache = cache or Path(tempfile.gettempdir()) / "registry-usage"
        self.cache.mkdir(parents=True, exist_ok=True)
        self.etags: dict[str, str] = {}

    def state(self) -> dict:
        body = self.bucket.get("state.json")
        return json.loads(body) if body else {}

    def files(self, table: str, start: dt.date, end: dt.date) -> list[str]:
        out = []
        for key, etag in sorted(self.bucket.list(f"{table}/").items()):
            day = key.split("/")[1][5:]
            if not (f"{start}" <= day <= f"{end}"):
                continue
            path = self.cache / key.replace("/", "_")
            if self.etags.get(key) != etag or not path.exists():
                body = self.bucket.get(key)
                if body is None:
                    continue
                path.write_bytes(body)
                self.etags[key] = etag
            out.append(str(path))
        return out

    def query(self, table: str, start: dt.date, end: dt.date, sql: str, params: list | None = None) -> list[dict]:
        """sql over `t`, the table's rows of [start, end]; [] without any."""
        paths = self.files(table, start, end)
        if not paths:
            return []
        con = _duck()
        files = "[" + ", ".join(f"'{p}'" for p in paths) + "]"
        con.execute(f"CREATE VIEW t AS SELECT * FROM read_parquet({files}, union_by_name = true) "
                    f"WHERE date BETWEEN DATE '{start}' AND DATE '{end}'")
        cur = con.execute(sql, params or [])
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]


# --- the report the portal's Usage page shows ---

def _where(visible: set[str] | None, project: str | None) -> tuple[str, list]:
    if project is not None:
        return "project = ?", [project]
    if visible is None:
        return "TRUE", []
    if not visible:
        return "FALSE", []
    return f"project IN ({', '.join('?' for _ in visible)})", sorted(visible)


def report(reader: Reader, visible: set[str] | None, start: dt.date, end: dt.date, today: dt.date,
           project: str | None = None, budgets: dict[str, float] | None = None,
           prices: dict[str, dict] | None = None, reference_model: str | None = None) -> dict:
    """Spend and usage of [start, end] for the projects a caller may see (None: all, with
    the requests no project is known for), and each project's spend in the 30 days up to
    `today` against its budget, with a forecast from its last 7 days. Spend is what the
    gateway charged; tokens and requests count model calls."""
    where, params = _where(visible, project)
    q = lambda sql, s=start, e=end: reader.query("daily", s, e, sql.replace("{where}", where), params)  # noqa: E731
    model = "kind = 'model' AND outcome <> 'denied'"     # the model calls OPA let through; denied counts the rest
    totals = q(f"""SELECT coalesce(sum(cost_usd), 0) AS cost_usd,
                          coalesce(sum(requests) FILTER ({model}), 0) AS requests,
                          coalesce(sum(input_tokens + output_tokens) FILTER ({model}), 0) AS tokens,
                          coalesce(sum(requests) FILTER (outcome = 'denied'), 0) AS denied,
                          coalesce(sum(requests) FILTER (outcome = 'limited'), 0) AS limited
                   FROM t WHERE {{where}}""")
    by_day = q(f"""SELECT date, sum(cost_usd) AS cost_usd, coalesce(sum(requests) FILTER ({model}), 0) AS requests,
                          coalesce(sum(input_tokens + output_tokens) FILTER ({model}), 0) AS tokens
                   FROM t WHERE {{where}} GROUP BY date ORDER BY date""")
    by_project = q(f"""SELECT project, sum(cost_usd) AS cost_usd, coalesce(sum(requests) FILTER ({model}), 0) AS requests,
                              coalesce(sum(input_tokens + output_tokens) FILTER ({model}), 0) AS tokens,
                              coalesce(sum(requests) FILTER (outcome = 'denied'), 0) AS denied,
                              coalesce(sum(requests) FILTER (outcome = 'limited'), 0) AS limited
                       FROM t WHERE {{where}} GROUP BY project ORDER BY cost_usd DESC, project""")
    by_model = q(f"""SELECT model, placement, sum(cost_usd) AS cost_usd, sum(requests) AS requests,
                            sum(input_tokens) AS input_tokens, sum(output_tokens) AS output_tokens,
                            coalesce(sum(requests) FILTER (virtual_model IS NOT NULL), 0) AS via_auto
                     FROM t WHERE {{where}} AND {model} AND outcome = 'ok' GROUP BY ALL ORDER BY cost_usd DESC, requests DESC""")
    by_agent = q(f"""SELECT project, agent, key_id, sum(cost_usd) AS cost_usd,
                            coalesce(sum(requests) FILTER ({model}), 0) AS requests,
                            coalesce(sum(input_tokens + output_tokens) FILTER ({model}), 0) AS tokens
                     FROM t WHERE {{where}} GROUP BY ALL ORDER BY cost_usd DESC, requests DESC""")
    # the budget window: the last 30 days up to today, whatever range was asked for
    burn = {r["project"]: r for r in q("""SELECT project, sum(cost_usd) AS cost_30d,
                                                 sum(cost_usd) FILTER (date > ?::DATE - 7) AS cost_7d
                                          FROM t WHERE {where} GROUP BY project""".replace("?::DATE", f"DATE '{today}'"),
                                       today - dt.timedelta(days=29), today)}
    for r in by_project:
        b, spent = (budgets or {}).get(r["project"]), burn.get(r["project"], {})
        r["cost_30d"] = spent.get("cost_30d") or 0
        r["forecast_30d"] = (spent.get("cost_7d") or 0) / 7 * 30
        r["budget_usd_30d"] = b
        r["budget_used"] = r["cost_30d"] / b if b else None
    onprem = q(f"""SELECT coalesce(sum(input_tokens), 0) AS input_tokens, coalesce(sum(output_tokens), 0) AS output_tokens
                   FROM t WHERE {{where}} AND {model} AND placement = 'onprem'""")[0] if by_day else {"input_tokens": 0, "output_tokens": 0}
    ref = (prices or {}).get(reference_model or "") or {}
    onprem["reference_model"] = reference_model if ref else None
    onprem["reference_usd"] = ((onprem["input_tokens"] * ref.get("input", 0) + onprem["output_tokens"] * ref.get("output", 0)) / 1e6
                               if ref else None)
    return {"start": str(start), "end": str(end), "through": reader.state().get("through"),
            "totals": totals[0] if totals else {"cost_usd": 0, "requests": 0, "tokens": 0, "denied": 0, "limited": 0},
            "by_day": by_day, "by_project": by_project, "by_model": by_model, "by_agent": by_agent, "onprem": onprem}


def requests_of(reader: Reader, project: str, day: dt.date, limit: int = 50) -> list[dict]:
    """A project's requests of one day, the dearest first."""
    return reader.query("fact", day, day, """SELECT strftime(ts, '%Y-%m-%dT%H:%M:%SZ') AS ts, key_id, agent, kind, model, virtual_model, outcome, status,
                                                    input_tokens, output_tokens, cost_usd, duration_ms, mcp_method, mcp_tool, trace_id
                                             FROM t WHERE project = ? ORDER BY cost_usd DESC, ts DESC LIMIT ?""",
                        [project, limit])


def main() -> None:
    import boto3

    from . import db as dbm
    from .health import Health
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    env = os.environ
    s3 = boto3.client("s3", endpoint_url=env["S3_ENDPOINT"], region_name=env.get("AWS_REGION", "us-east-1"))
    bucket = Bucket(s3, env["USAGE_BUCKET"])
    db = dbm.DB(env["DATABASE_URL"])
    loki, selector = env["LOKI_URL"], env.get("USAGE_LOKI_SELECTOR", '{namespace="mini-platform", container="agentgateway"}')

    def once():
        with db.tx() as c:
            records = dbm.resources(c)
            owners = {r["project_id"]: r["owner_group"] for r in c.execute("select * from project_owner").fetchall()}
        return run(bucket, lambda a, b: loki_lines(loki, selector, a, b), records, owners,
                   lookback=int(env.get("USAGE_LOOKBACK_HOURS", "3")),
                   backfill=int(env.get("USAGE_BACKFILL_HOURS", "168")))

    if Health(db, write_every=0).run("usage", once) is None:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
