"""How each of the publisher's outputs is doing, for /metrics and an alert.

The publisher's loop keeps several things current: the data bundle, policy commits, the
gateway-models chart, the gateway's key maps, OPA activation, agentregistry. Each round
of each one is a step: it either finishes (whether or not it had anything to do) or
raises. A step records its last success and last failure in publisher_health; the API
serves them as registry_output_last_success_timestamp_seconds{output} (api.py), so an
output that keeps failing alerts instead of only logging.

A failing step waits `retry_after` seconds before its next try. Successes are written
at most once a minute per output: the loop runs every few seconds.
"""
from __future__ import annotations

import logging
import time

log = logging.getLogger("health")


class Health:
    def __init__(self, db, write_every: float = 60):
        self.db, self.write_every = db, write_every
        self.written: dict[str, float] = {}
        self.retry: dict[str, float] = {}

    def run(self, output: str, fn, *args, retry_after: float = 0):
        """Runs one step of an output. Returns fn's result, or None if it failed or is
        waiting to retry. Never raises: the loop goes on with the other outputs."""
        if time.time() < self.retry.get(output, 0):
            return None
        try:
            result = fn(*args)
        except Exception as e:
            log.exception("%s", output)
            self.retry[output] = time.time() + retry_after
            self._write(output, ok=False, error=f"{type(e).__name__}: {e}")
            return None
        self.retry.pop(output, None)
        if time.time() - self.written.get(output, 0) >= self.write_every:
            self._write(output, ok=True)
        return result

    def _write(self, output: str, ok: bool, error: str | None = None) -> None:
        try:
            with self.db.tx() as c:
                if ok:
                    c.execute("""insert into publisher_health (output, last_success) values (%s, now())
                                 on conflict (output) do update set last_success = now()""", (output,))
                else:
                    c.execute("""insert into publisher_health (output, last_failure, last_error)
                                 values (%s, now(), %s)
                                 on conflict (output) do update set last_failure = now(),
                                 last_error = excluded.last_error""", (output, (error or "")[-500:]))
            self.written[output] = time.time() if ok else 0     # after a failure, the next success is written
        except Exception:
            log.exception("recording %s's health", output)      # the database may be what failed


def metrics(c) -> list[str]:
    """Prometheus lines for /metrics."""
    lines = ["# HELP registry_output_last_success_timestamp_seconds When a publisher output last finished a round.",
             "# TYPE registry_output_last_success_timestamp_seconds gauge",
             "# HELP registry_output_last_failure_timestamp_seconds When a publisher output last failed.",
             "# TYPE registry_output_last_failure_timestamp_seconds gauge"]
    for r in c.execute("""select output, extract(epoch from last_success) as ok, extract(epoch from last_failure) as bad
                          from publisher_health order by output""").fetchall():
        if r["ok"] is not None:
            lines.append(f'registry_output_last_success_timestamp_seconds{{output="{r["output"]}"}} {float(r["ok"])}')
        if r["bad"] is not None:
            lines.append(f'registry_output_last_failure_timestamp_seconds{{output="{r["output"]}"}} {float(r["bad"])}')
    return lines
