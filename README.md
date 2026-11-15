# denyprobe

Check that an agent's credential really can't do what it shouldn't. It tries each forbidden write as the agent, then checks with an admin credential whether anything landed.

Only run it against a scratch target. It refuses to run otherwise.

## GitHub

Pushes canary files to `.github/workflows` and `.github/actions` as the agent.

```
SUBJECT_TOKEN=<agent token> OPERATOR_TOKEN=<admin token> python3 probe.py owner/scratch-repo
```

- The repo needs the topic `denyprobe-scratch`.
- `--git-url` sends the agent's push through a proxy, e.g. `'https://proxy.example/git/{repo}.git'`.
- For a GitHub App token: `APP_ID=... INSTALLATION_ID=... APP_KEY=key.pem ./mint-token.sh`

## Postgres

Tries insert, update, delete, truncate, drop, create, and switching read-only off, as the agent's role.

```
SUBJECT_DSN=<agent dsn> OPERATOR_DSN=<admin dsn> uv run probe_postgres.py --like schema.table
```

- The database needs the comment `denyprobe-scratch`.
- `--like` copies a real table's grants onto a canary table, so real data isn't touched.

## Output

`PASS` blocked, `FAIL` landed, `UNKNOWN` the control check failed. Exits 1 on any `FAIL` or `UNKNOWN`.
