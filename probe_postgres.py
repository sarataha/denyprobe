# /// script
# requires-python = ">=3.10"
# dependencies = ["psycopg[binary]==3.3.9"]
# ///
"""Try forbidden writes as the agent's Postgres role, then check as admin whether anything changed.

Usage:
  SUBJECT_DSN=postgresql://agent@host/db OPERATOR_DSN=postgresql://admin@host/db \
    uv run probe_postgres.py --like public.orders

--like names a real table. The canary is created next to it, in the same schema,
with the same owner and grants, so the probes see the permissions a real table has
without touching its data. Without --like the canary goes in public, owned by the
operator, with no grants.

SUBJECT_DSN is the connection the agent uses (its role, through its real path:
pooler, proxy or MCP server's own DSN). OPERATOR_DSN is an admin connection
used only to set up canaries and read state back. With --like it must be able to
hand the canary to the real table's owner (a superuser, or a member of that role).

The database must carry the comment "denyprobe-scratch", or nothing runs:
  COMMENT ON DATABASE mydb IS 'denyprobe-scratch';
"""

import argparse
import json
import os
import sys

import psycopg
from psycopg.sql import Identifier

GUARD = "denyprobe-scratch"
CANARY = "denyprobe_canary"
NEW_TABLE = "denyprobe_new"
# A denied probe only counts as PASS when Postgres refused it for a permission reason.
# Any other error (missing table, lost connection, timeout) says nothing about permissions.
DENIED_STATES = {
    "42501": "insufficient_privilege",
    "25006": "read_only_sql_transaction",
}


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def probes(schema, table):
    """(name, sql run as the agent, expected). schema and table are quoted SQL."""
    return [
        ("insert row", f"INSERT INTO {table} VALUES (99, 'probe')", "denied"),
        ("update row", f"UPDATE {table} SET v = 'probe'", "denied"),
        ("delete rows", f"DELETE FROM {table}", "denied"),
        ("truncate table", f"TRUNCATE {table}", "denied"),
        ("drop table", f"DROP TABLE {table}", "denied"),
        (f"create table in {schema}", f"CREATE TABLE {schema}.{NEW_TABLE} (id int)", "denied"),
        ("read-only switched off, then insert",
         f"SET TRANSACTION READ WRITE; INSERT INTO {table} VALUES (98, 'probe')", "denied"),
        ("read-only switched off, then delete",
         f"SET TRANSACTION READ WRITE; DELETE FROM {table}", "denied"),
    ]


def snapshot(op, schema, table):
    """State the operator compares before and after each probe."""
    with op.cursor() as c:
        c.execute("SELECT to_regclass(%s) IS NOT NULL", (table,))
        exists = c.fetchone()[0]
        rows = None
        if exists:
            c.execute(f"SELECT coalesce(string_agg(v, ',' ORDER BY id), '') FROM {table}")
            rows = c.fetchone()[0]
        c.execute("SELECT to_regclass(%s) IS NOT NULL", (f"{schema}.{NEW_TABLE}",))
        new_table = c.fetchone()[0]
    return {"canary_exists": exists, "canary_rows": rows, "new_table": new_table}


def resolve(op, ref):
    """(schema, owner) of a real table, resolved by Postgres itself."""
    with op.cursor() as c:
        c.execute("SELECT n.nspname, pg_get_userbyid(c.relowner) FROM pg_class c "
                  "JOIN pg_namespace n ON n.oid = c.relnamespace "
                  "WHERE c.oid = to_regclass(%s)", (ref,))
        row = c.fetchone()
    if not row:
        die(f"--like {ref}: no such table")
    return row


def acl(op, ref):
    """(grantee, privilege) on a table, grantee None for PUBLIC. Reads the ACL itself, so
    grants made by any grantor show up, and a table with default privileges still lists
    the owner's."""
    with op.cursor() as c:
        c.execute("SELECT r.rolname, a.privilege_type FROM pg_class c "
                  "CROSS JOIN LATERAL aclexplode(coalesce(c.relacl, acldefault('r', c.relowner))) a "
                  "LEFT JOIN pg_roles r ON r.oid = a.grantee "
                  "WHERE c.oid = to_regclass(%s) AND (a.grantee = 0 OR r.rolname IS NOT NULL)",
                  (ref,))
        return c.fetchall()


def role(c, name):
    return "PUBLIC" if name is None else Identifier(name).as_string(c)


def cleanup(op, schema, table):
    op.execute(f"DROP TABLE IF EXISTS {table}, {schema}.{NEW_TABLE}")


def reset(op, schema, table, owner, grants):
    with op.transaction(), op.cursor() as c:
        cleanup(op, schema, table)
        c.execute(f"CREATE TABLE {table} (id int PRIMARY KEY, v text)")
        c.execute(f"INSERT INTO {table} VALUES (1, 'a'), (2, 'b')")
        if owner:
            c.execute(f"ALTER TABLE {table} OWNER TO {role(c, owner)}")
        # Drop whatever ALTER DEFAULT PRIVILEGES handed out, so the canary carries only
        # the real table's grants.
        c.execute("SELECT pg_get_userbyid(relowner) FROM pg_class WHERE oid = to_regclass(%s)",
                  (table,))
        canary_owner = c.fetchone()[0]
        for grantee in {g for g, _ in acl(op, table) if g != canary_owner}:
            c.execute(f"REVOKE ALL ON {table} FROM {role(c, grantee)}")
        for grantee, priv in grants:
            c.execute(f"GRANT {priv} ON {table} TO {role(c, grantee)}")


def guard(op):
    with op.cursor() as c:
        c.execute("SELECT shobj_description(oid, 'pg_database') FROM pg_database "
                  "WHERE datname = current_database()")
        if (c.fetchone()[0] or "") != GUARD:
            die(f"database comment is not '{GUARD}'; refusing to run")


def definer_functions(sub):
    """SECURITY DEFINER functions the agent can execute: they run with their owner's rights."""
    with sub.cursor() as c:
        c.execute("""
            SELECT n.nspname || '.' || p.proname, pg_get_userbyid(p.proowner)
            FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE p.prosecdef
              AND n.nspname NOT IN ('pg_catalog', 'information_schema')
              AND has_function_privilege(p.oid, 'EXECUTE')
              AND pg_get_userbyid(p.proowner) <> current_user
            ORDER BY 1""")
        return [{"function": f, "owner": o} for f, o in c.fetchall()]


def error_text(e):
    lines = str(e).strip().splitlines()
    return f"{e.sqlstate or ''} {lines[0] if lines else type(e).__name__}".strip()


def run_probe(sub_dsn, sql):
    """(outcome, sqlstate, error) for sql run as the agent in one transaction."""
    try:
        with psycopg.connect(sub_dsn, autocommit=False, connect_timeout=10) as sub:
            sub.execute(sql)
            sub.commit()
        return "ok", None, ""
    except psycopg.Error as e:
        return "error", e.sqlstate, error_text(e)


def control(sub_dsn, schema_name):
    """Can the agent see the canary? Proves its connection reaches the database the operator
    set up, and not another database, server or replica without it."""
    try:
        with psycopg.connect(sub_dsn, connect_timeout=10) as sub, sub.cursor() as c:
            c.execute("SELECT EXISTS (SELECT 1 FROM pg_class c "
                      "JOIN pg_namespace n ON n.oid = c.relnamespace "
                      "WHERE n.nspname = %s AND c.relname = %s)", (schema_name, CANARY))
            if c.fetchone()[0]:
                return "ok", ""
            return "error", "the agent's connection does not see the canary table"
    except psycopg.Error as e:
        return "error", error_text(e)


def verdict(expected, outcome, sqlstate, changed):
    if changed:
        return "FAIL"
    if outcome == "ok" or sqlstate in DENIED_STATES:
        return "PASS"
    return "UNKNOWN"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--like", metavar="SCHEMA.TABLE",
                    help="real table whose schema, owner and grants the canary copies")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    a = ap.parse_args()

    sub_dsn, op_dsn = os.environ.get("SUBJECT_DSN"), os.environ.get("OPERATOR_DSN")
    if not sub_dsn or not op_dsn:
        die("set SUBJECT_DSN and OPERATOR_DSN")

    results = []
    with psycopg.connect(op_dsn, autocommit=True) as op:
        # autocommit: the operator never holds a lock on the canary while the agent probes it.
        guard(op)
        if a.like:
            schema_name, owner = resolve(op, a.like)
            grants = [g for g in acl(op, a.like) if g[0] != owner]
        else:
            schema_name, owner, grants = "public", None, []
        schema = Identifier(schema_name).as_string(op)
        table = Identifier(schema_name, CANARY).as_string(op)

        try:
            reset(op, schema, table, owner, grants)
            outcome, error = control(sub_dsn, schema_name)
            control_ok = outcome == "ok"
            results.append({"probe": "control: agent sees the canary", "expected": "allowed",
                            "verdict": "PASS" if control_ok else "UNKNOWN",
                            "agent_got": outcome, "error": error, "state_changed": False})
            for name, sql, expected in probes(schema, table):
                reset(op, schema, table, owner, grants)
                before = snapshot(op, schema, table)
                outcome, sqlstate, error = run_probe(sub_dsn, sql)
                after = snapshot(op, schema, table)
                changed = before != after
                v = verdict(expected, outcome, sqlstate, changed) if control_ok else "UNKNOWN"
                results.append({"probe": name, "expected": expected, "verdict": v,
                                "agent_got": outcome, "error": error, "state_changed": changed})
        finally:
            cleanup(op, schema, table)

    with psycopg.connect(sub_dsn, connect_timeout=10) as sub:
        definers = definer_functions(sub)

    if a.json:
        print(json.dumps({"probes": results, "definer_functions": definers}, indent=2))
    else:
        for r in results:
            print(f"{r['verdict']:8} {r['expected']:8} {r['probe']}")
            if r["error"] and r["verdict"] != "PASS":
                print(f"         {r['error']}")
        if definers:
            print("\nNote: the agent can execute these SECURITY DEFINER functions, which run "
                  "with their owner's rights. Check each one only does what you intend:")
            for d in definers:
                print(f"  {d['function']} (owner {d['owner']})")
    sys.exit(1 if any(r["verdict"] in ("FAIL", "UNKNOWN") for r in results) else 0)


if __name__ == "__main__":
    main()
