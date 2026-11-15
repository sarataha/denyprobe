# /// script
# requires-python = ">=3.10"
# dependencies = ["psycopg[binary]==3.3.9"]
# ///
"""Try forbidden writes as the agent's Postgres role, then check as admin whether anything changed.

Usage:
  SUBJECT_DSN=postgresql://agent@host/db OPERATOR_DSN=postgresql://admin@host/db \
    uv run probe_postgres.py --like public.orders

--like names a real table. The canary is created next to it, in the same schema,
with the same grants, so the probes see the permissions a real table has without
touching its data. Without --like the canary goes in public with no extra grants.

SUBJECT_DSN is the connection the agent uses (its role, through its real path:
pooler, proxy or MCP server's own DSN). OPERATOR_DSN is an admin connection
used only to set up canaries and read state back.

The database must carry the comment "denyprobe-scratch", or nothing runs:
  COMMENT ON DATABASE mydb IS 'denyprobe-scratch';
"""

import json
import os
import sys

import psycopg
import psycopg.sql

GUARD = "denyprobe-scratch"


def probes(schema, table):
    """(name, sql run as the agent, expected)"""
    return [
        ("control: read", "SELECT 1", "allowed"),
        ("insert row", f"INSERT INTO {table} VALUES (99, 'probe')", "denied"),
        ("update row", f"UPDATE {table} SET v = 'probe'", "denied"),
        ("delete rows", f"DELETE FROM {table}", "denied"),
        ("truncate table", f"TRUNCATE {table}", "denied"),
        ("drop table", f"DROP TABLE {table}", "denied"),
        (f"create table in {schema}", f"CREATE TABLE {schema}.denyprobe_new (id int)", "denied"),
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
        c.execute("SELECT to_regclass(%s) IS NOT NULL", (f"{schema}.denyprobe_new",))
        new_table = c.fetchone()[0]
    return {"canary_exists": exists, "canary_rows": rows, "new_table": new_table}


def grants_of(op, ref):
    schema, name = ref.split(".", 1)
    with op.cursor() as c:
        c.execute("SELECT grantee, privilege_type FROM information_schema.role_table_grants "
                  "WHERE table_schema = %s AND table_name = %s", (schema, name))
        return c.fetchall()


def cleanup(op, schema, table):
    with op.cursor() as c:
        c.execute(f"DROP TABLE IF EXISTS {table}, {schema}.denyprobe_new")
    op.commit()


def reset(op, schema, table, grants):
    cleanup(op, schema, table)
    with op.cursor() as c:
        c.execute(f"CREATE TABLE {table} (id int PRIMARY KEY, v text)")
        c.execute(f"INSERT INTO {table} VALUES (1, 'a'), (2, 'b')")
        for grantee, priv in grants:
            who = "PUBLIC" if grantee == "PUBLIC" else psycopg.sql.Identifier(grantee).as_string(c)
            c.execute(f"GRANT {priv} ON {table} TO {who}")
    op.commit()


def guard(op):
    with op.cursor() as c:
        c.execute("SELECT shobj_description(oid, 'pg_database') FROM pg_database "
                  "WHERE datname = current_database()")
        if (c.fetchone()[0] or "") != GUARD:
            sys.exit(f"database comment is not '{GUARD}'; refusing to run")


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


def run_probe(sub_dsn, sql):
    try:
        with psycopg.connect(sub_dsn, autocommit=False) as sub:
            sub.execute(sql)
            sub.commit()
        return "ok", ""
    except psycopg.Error as e:
        return "error", f"{e.sqlstate or ''} {str(e).strip().splitlines()[0]}"


def main():
    sub_dsn, op_dsn = os.environ.get("SUBJECT_DSN"), os.environ.get("OPERATOR_DSN")
    if not sub_dsn or not op_dsn:
        sys.exit("set SUBJECT_DSN and OPERATOR_DSN")
    as_json = "--json" in sys.argv
    like = sys.argv[sys.argv.index("--like") + 1] if "--like" in sys.argv else None
    schema = like.split(".", 1)[0] if like else "public"
    table = f"{schema}.denyprobe_canary"

    results = []
    with psycopg.connect(op_dsn) as op:
        guard(op)
        grants = grants_of(op, like) if like else []
        control_ok = True
        for name, sql, expected in probes(schema, table):
            reset(op, schema, table, grants)
            before = snapshot(op, schema, table)
            outcome, error = run_probe(sub_dsn, sql)
            after = snapshot(op, schema, table)
            changed = before != after
            if not control_ok:
                verdict = "UNKNOWN"
            elif expected == "allowed":
                verdict = "PASS" if outcome == "ok" else "UNKNOWN"
                control_ok = verdict == "PASS"
            else:
                verdict = "FAIL" if changed else "PASS"
            results.append({"probe": name, "expected": expected, "verdict": verdict,
                            "agent_got": outcome, "error": error, "state_changed": changed})
        cleanup(op, schema, table)

    with psycopg.connect(sub_dsn) as sub:
        definers = definer_functions(sub)

    if as_json:
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
