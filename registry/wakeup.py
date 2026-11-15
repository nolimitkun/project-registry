"""Waking the publisher when a change is approved.

The API sends NOTIFY in the transaction that approves a change (and queues it in the
outbox), so the notice arrives only once that commits. The publisher waits for it
instead of sleeping between rounds; the outbox stays the record of what to publish, so
a lost notice (the publisher restarting, the connection dropping) costs only the wait
until the next round, never a change.
"""
from __future__ import annotations

import logging
import time

import psycopg

log = logging.getLogger("wakeup")

CHANNEL = "registry_publish"


def notify(c) -> None:
    """In the approving transaction: delivered on commit, dropped on rollback."""
    c.execute(f"notify {CHANNEL}")


class Wakeup:
    def __init__(self, dsn: str):
        self.dsn, self.conn = dsn, None

    def wait(self, timeout: float) -> bool:
        """Up to timeout seconds, or until a notice. True if one came. A notice sent while
        the publisher was busy waits on the connection and ends the next wait at once."""
        try:
            if self.conn is None or self.conn.closed:
                self.conn = psycopg.connect(self.dsn, autocommit=True)
                self.conn.execute(f"listen {CHANNEL}")
            for _ in self.conn.notifies(timeout=timeout, stop_after=1):
                return True
            return False
        except psycopg.Error as e:
            log.warning("waiting for approvals: %s; sleeping instead", e)
            self.conn = None
            time.sleep(timeout)
            return False
