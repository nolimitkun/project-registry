"""Postgres schema and queries. Every write goes through a transaction that also
appends to audit_log, which is never updated or deleted from."""
from __future__ import annotations

import json
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb

SCHEMA = """
create table if not exists resource (
  kind text not null check (kind in ('project', 'agent', 'exception')),
  id text not null,
  spec jsonb not null,
  revision bigint not null default 1,
  primary key (kind, id));
-- who may approve as a project's owner (a Keycloak group)
create table if not exists project_owner (project_id text primary key, owner_group text not null);
create table if not exists change_request (
  id bigserial primary key,
  kind text not null, object_id text not null,
  op text not null check (op in ('create', 'update', 'delete')),
  before jsonb, after jsonb,
  state text not null,
  required_approvals jsonb not null,
  replay_report jsonb, bundle_revision text, error text,
  created_by text not null, created_at timestamptz not null default now(),
  updated_at timestamptz not null default now());
create table if not exists approval (
  change_id bigint not null references change_request(id),
  approver text not null, role text not null, decision text not null check (decision in ('approve', 'reject')),
  comment text, at timestamptz not null default now(),
  primary key (change_id, approver));
create table if not exists outbox (seq bigserial primary key, change_id bigint not null references change_request(id),
                                   published_at timestamptz);
create table if not exists publication (
  revision text primary key, seq bigint not null, change_ids bigint[] not null,
  state text not null check (state in ('active', 'superseded', 'rolled_back')),
  policy_revision text not null,
  records jsonb not null,                  -- the records it was rendered from: a rollback restores them
  created_at timestamptz not null default now(), active_at timestamptz);
-- the gateway-policy bundle's publications: a Git commit each (policy.py)
create table if not exists policy_publication (
  revision text primary key, seq bigint not null, change_id bigint references change_request(id),
  state text not null check (state in ('active', 'superseded', 'rolled_back')),
  created_at timestamptz not null default now(), active_at timestamptz);
create table if not exists opa_status (instance_id text primary key, bundles jsonb not null, at timestamptz not null);
alter table opa_status add column if not exists pod text;
create table if not exists audit_log (
  seq bigserial primary key, at timestamptz not null default now(),
  actor text not null, action text not null, object text not null, before jsonb, after jsonb);
create sequence if not exists bundle_seq;
-- the states, as a named constraint so a new state is one migration
alter table change_request drop constraint if exists change_request_state_check;
alter table change_request add constraint change_request_state_check check (state in (
  'pending_approval', 'approved', 'publishing', 'active', 'rejected', 'withdrawn', 'failed', 'rolled_back',
  'skipped'));
"""


class DB:
    def __init__(self, dsn: str):
        self.dsn = dsn

    @contextmanager
    def tx(self):
        with psycopg.connect(self.dsn, row_factory=dict_row) as conn:
            with conn.transaction():
                yield conn

    def migrate(self) -> None:
        with self.tx() as c:
            c.execute(SCHEMA)


def audit(c, actor: str, action: str, obj: str, before=None, after=None) -> None:
    c.execute("insert into audit_log (actor, action, object, before, after) values (%s, %s, %s, %s, %s)",
              (actor, action, obj, Jsonb(before) if before is not None else None,
               Jsonb(after) if after is not None else None))


def resources(c) -> dict[str, dict[str, dict]]:
    out: dict[str, dict[str, dict]] = {"project": {}, "agent": {}, "exception": {}}
    for row in c.execute("select kind, id, spec from resource order by kind, id"):
        out[row["kind"]][row["id"]] = row["spec"]
    return out


def apply_change(c, change: dict) -> None:
    kind, oid = change["kind"], change["object_id"]
    if change["op"] == "delete":
        c.execute("delete from resource where kind = %s and id = %s", (kind, oid))
    else:
        c.execute("""insert into resource (kind, id, spec) values (%s, %s, %s)
                     on conflict (kind, id) do update set spec = excluded.spec, revision = resource.revision + 1""",
                  (kind, oid, Jsonb(change["after"])))


def dumps(value) -> str:
    return json.dumps(value, default=str, sort_keys=True)
