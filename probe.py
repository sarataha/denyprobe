#!/usr/bin/env python3
"""Push a canary file to each path as the agent, then check as admin whether it landed.

Usage:
  SUBJECT_TOKEN=... OPERATOR_TOKEN=... python3 probe.py owner/scratch-repo
  python3 probe.py owner/scratch-repo --git-url 'https://proxy.example/git/{repo}.git'

SUBJECT_TOKEN is the agent's credential (GitHub App installation token, PAT, or
whatever the proxy expects). OPERATOR_TOKEN is an admin token on the scratch repo,
used directly against api.github.com and never through the proxy.

The scratch repo must carry the topic "denyprobe-scratch", or nothing runs.
"""

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

API = "https://api.github.com"
GUARD_TOPIC = "denyprobe-scratch"

WORKFLOW_CANARY = """name: denyprobe-canary
on: workflow_dispatch
permissions: {}
jobs:
  canary:
    runs-on: ubuntu-latest
    steps:
      - run: echo denyprobe canary
"""

ACTION_CANARY = """name: denyprobe-canary
description: denyprobe canary
runs:
  using: composite
  steps:
    - run: echo denyprobe canary
      shell: bash
"""

# (path, content, expected) where expected is "allowed" or "denied".
DEFAULT_PROBES = [
    ("denyprobe/control.txt", "control\n", "allowed"),
    (".github/workflows/denyprobe-canary.yml", WORKFLOW_CANARY, "denied"),
    (".github/actions/denyprobe-canary/action.yml", ACTION_CANARY, "denied"),
]


def api(method, path, token, body=None):
    req = urllib.request.Request(
        API + path,
        method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        return e.code, None
    except (urllib.error.URLError, TimeoutError):
        return 0, None


def die(msg):
    print(msg, file=sys.stderr)
    sys.exit(2)


def redact(text, *secrets):
    for s in secrets:
        if s:
            text = text.replace(s, "[TOKEN]")
    return text


# No credential helper may store the tokens in the URLs, signing may not break the commit,
# and git must never stop to prompt for a password. Hooks are skipped with --no-verify.
GIT_OPTS = ["-c", "credential.helper=", "-c", "commit.gpgsign=false"]
GIT_ENV = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}


def git(args, cwd, *tokens):
    r = subprocess.run(["git", *GIT_OPTS, *args], cwd=cwd, capture_output=True, text=True,
                       env=GIT_ENV)
    return r.returncode, redact(r.stdout + r.stderr, *tokens).strip()


def guard(repo, op_token):
    status, data = api("GET", f"/repos/{repo}", op_token)
    if status != 200:
        die(f"cannot read {repo} with OPERATOR_TOKEN (HTTP {status})")
    if GUARD_TOPIC not in (data.get("topics") or []):
        die(f"{repo} lacks the '{GUARD_TOPIC}' topic; refusing to run")
    return data["default_branch"]


def branch_sha(repo, branch, op_token):
    """Commit the branch points at, or None if the operator could not read it."""
    status, data = api("GET", f"/repos/{repo}/git/ref/heads/{branch}", op_token)
    if status != 200 or not data:
        return None
    return data["object"]["sha"]


def unknown(path, detail):
    return {"path": path, "verdict": "UNKNOWN", "git": detail}


def probe(repo, workdir, push_url, base, run_id, i, path, content, sub_token, op_token):
    branch = f"denyprobe/{run_id}-{i}"
    base_sha = branch_sha(repo, base, op_token)
    if not base_sha:
        return unknown(path, f"could not read {base}")
    status, _ = api("POST", f"/repos/{repo}/git/refs", op_token,
                    {"ref": f"refs/heads/{branch}", "sha": base_sha})
    if status != 201:
        return unknown(path, f"could not create {branch} (HTTP {status})")
    try:
        code, out = git(["checkout", "-q", "-B", branch, f"origin/{base}"], workdir)
        if code != 0:
            return unknown(path, f"checkout failed: {out}")
        full = os.path.join(workdir, path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w") as f:
            # The run id makes the content new, so the commit is never empty even when a
            # copy of the canary is already in the repo.
            f.write(f"# denyprobe {run_id}\n{content}")
        for step, args in (("add", ["add", "--force", path]),
                           ("commit", ["-c", "user.name=denyprobe", "-c", "user.email=denyprobe@invalid",
                                       "commit", "-q", "--no-verify", "-m", f"denyprobe canary {path}"])):
            code, out = git(args, workdir)
            if code != 0:
                return unknown(path, f"git {step} failed: {out}")
        _, commit = git(["rev-parse", "HEAD"], workdir)
        code, out = git(["push", "--no-verify", push_url, f"HEAD:refs/heads/{branch}"],
                        workdir, sub_token)
        # The push landed only if the branch now points at this run's commit. Checking that
        # the file exists would also match a copy already on the base branch.
        now = branch_sha(repo, branch, op_token)
        if not now:
            return unknown(path, f"could not read {branch} back after the push\n{out}")
        return {"path": path, "push_exit": code, "landed": now == commit, "git": out[-400:]}
    finally:
        api("DELETE", f"/repos/{repo}/git/refs/heads/{branch}", op_token)


def verdict(result, expected):
    if "verdict" in result:
        return result["verdict"]
    if expected == "allowed":
        return "PASS" if result["landed"] else "UNKNOWN"
    return "FAIL" if result["landed"] else "PASS"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("repo", help="owner/name of the scratch repo")
    ap.add_argument("--git-url", default="https://x-access-token:{token}@github.com/{repo}.git",
                    help="push URL template for the agent's path; {repo} and {token} are filled in")
    ap.add_argument("--json", action="store_true", help="print results as JSON")
    a = ap.parse_args()

    sub_token = os.environ.get("SUBJECT_TOKEN")
    op_token = os.environ.get("OPERATOR_TOKEN")
    if not sub_token or not op_token:
        die("set SUBJECT_TOKEN and OPERATOR_TOKEN")

    base = guard(a.repo, op_token)
    push_url = a.git_url.format(repo=a.repo, token=sub_token)
    clone_url = f"https://x-access-token:{op_token}@github.com/{a.repo}.git"

    results = []
    with tempfile.TemporaryDirectory() as workdir:
        code, out = git(["clone", "-q", "--depth", "1", "--branch", base, clone_url, workdir],
                        None, op_token)
        if code != 0:
            die(f"clone failed: {out}")
        run_id = secrets.token_hex(4)
        control_ok = True
        for i, (path, content, expected) in enumerate(DEFAULT_PROBES):
            r = probe(a.repo, workdir, push_url, base, run_id, i, path, content,
                      sub_token, op_token)
            r["expected"] = expected
            r["verdict"] = verdict(r, expected) if control_ok else "UNKNOWN"
            if expected == "allowed" and r["verdict"] != "PASS":
                control_ok = False
            results.append(r)

    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['verdict']:8} {r['expected']:8} {r['path']}")
            if r["verdict"] in ("FAIL", "UNKNOWN") and r.get("git"):
                print("         " + r["git"].replace("\n", "\n         "))
    sys.exit(1 if any(r["verdict"] in ("FAIL", "UNKNOWN") for r in results) else 0)


if __name__ == "__main__":
    main()
