#!/usr/bin/env python3
"""Core logic for the workflow-change-guard composite GitHub Action.

Reads a `git diff --name-status base...head` listing, finds changes under
`.github/workflows/`, and fails when the PR author is not on the trusted
allowlist (`.workflow-guard.yml`).

Separately, it scans the changed workflow files' contents for suspicious
patterns (curl|bash, raw-IP exfil, secret dumping) and emits warnings —
heuristics warn, they never fail the run on their own.

Exit codes: 0 = pass, 1 = guard failed.
"""

import argparse
import json
import os
import re
import subprocess
import sys

import mini_yaml

WORKFLOWS_PREFIX = ".github/workflows/"

# --- Suspicious-content heuristics (warn only) -------------------------------

PIPE_TO_SHELL = re.compile(
    r"\b(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(bash|sh|zsh|dash)\b", re.IGNORECASE
)
RAW_IP_URL = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?(?:/|$|\s|\"|')")
SECRET_ECHO = re.compile(
    r"\b(echo|printf|printenv|env)\b[^\n|]*\$\{\{\s*secrets\.", re.IGNORECASE
)
SECRET_TO_FILE = re.compile(
    r"\$\{\{\s*secrets\.[^}]+\}\}\s*(>>?)\s*\S+", re.IGNORECASE
)


def scan_heuristics(path, content):
    """Return a list of warning strings for suspicious workflow content."""
    warnings = []
    if PIPE_TO_SHELL.search(content):
        warnings.append(
            "%s: downloads and pipes a remote script to a shell (curl|wget ... | bash)" % path
        )
    for match in RAW_IP_URL.finditer(content):
        warnings.append(
            "%s: URL uses a raw IP address (%s) — possible exfiltration endpoint"
            % (path, match.group(0).rstrip("/ \t\"'"))
        )
    if SECRET_ECHO.search(content):
        warnings.append(
            "%s: echoes a ${{ secrets.* }} value to logs — secrets can leak in CI output"
            % path
        )
    if SECRET_TO_FILE.search(content):
        warnings.append(
            "%s: writes a ${{ secrets.* }} value to a file — check where it goes"
            % path
        )
    return warnings


# --- Diff handling ------------------------------------------------------------


def parse_name_status(diff_text):
    """Parse `git diff --name-status` output into [(status, path), ...]."""
    changes = []
    for line in diff_text.splitlines():
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        status = parts[0].strip()
        # Handle renames: "R100\told\tnew" — treat the new path as modified.
        path = parts[-1].strip()
        changes.append((status[0], path))
    return changes


def workflow_changes(changes):
    """Filter changes to files under .github/workflows/."""
    return [
        (status, path)
        for status, path in changes
        if path == ".github/workflows" or path.startswith(WORKFLOWS_PREFIX)
    ]


# --- Allowlist ----------------------------------------------------------------


def load_trusted_users(allowlist_path):
    """Return (trusted_entries, error). Entries are usernames or 'org/team'."""
    if not os.path.exists(allowlist_path):
        return [], "allowlist file not found: %s" % allowlist_path
    try:
        data = mini_yaml.load(allowlist_path) or {}
    except Exception as exc:  # noqa: BLE001
        return [], "could not parse allowlist %s: %s" % (allowlist_path, exc)
    users = data.get("trusted_users") or []
    if not isinstance(users, list):
        return [], "allowlist %s: 'trusted_users' must be a list" % allowlist_path
    return [str(u).strip() for u in users if str(u).strip()], None


def is_team_member(org, team, username, token):
    """Check GitHub team membership via the gh CLI. Returns True/False/None."""
    if not token:
        return None
    try:
        proc = subprocess.run(
            ["gh", "api", "orgs/%s/teams/%s/memberships/%s" % (org, team, username)],
            env={**os.environ, "GH_TOKEN": token},
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode == 0:
        try:
            return json.loads(proc.stdout).get("state") == "active"
        except ValueError:
            return None
    return None  # 404 or other error -> membership unknown, treat as untrusted


def is_trusted(author, trusted_entries, token=None):
    """True if author matches a username or a verified org/team entry."""
    author = (author or "").strip().lower()
    for entry in trusted_entries:
        entry = entry.strip()
        if "/" in entry and not entry.startswith("@"):
            org, _, team = entry.partition("/")
            if org and team and is_team_member(org, team, author, token) is True:
                return True
        elif entry.lstrip("@").lower() == author:
            return True
    return False


# --- Evaluation ---------------------------------------------------------------


def evaluate(author, diff_text, trusted_entries, fail_on_add=True,
             scan_dir=None, token=None):
    """Run the guard. Returns (exit_code, messages).

    messages is a list of (level, text) where level is 'error' or 'warning'.
    """
    messages = []
    changes = parse_name_status(diff_text)
    wf = workflow_changes(changes)

    trusted = is_trusted(author, trusted_entries, token)
    if wf and not trusted:
        failing = [(s, p) for s, p in wf if fail_on_add or s != "A"]
        if failing:
            detail = ", ".join(
                "%s (%s)" % (p, {"A": "added", "M": "modified",
                                 "D": "deleted", "R": "renamed"}.get(s, s))
                for s, p in failing
            )
            messages.append((
                "error",
                "Workflow guard failed: PR author '%s' is not on the allowlist "
                "but changed workflow files: %s. "
                "If this change is legitimate, ask a trusted maintainer to "
                "approve it, or add the author to .workflow-guard.yml."
                % (author, detail),
            ))
        elif not fail_on_add:
            messages.append((
                "warning",
                "PR author '%s' is not on the allowlist but only ADDED new "
                "workflow files (fail-on-add is off): %s"
                % (author, ", ".join(p for _, p in wf)),
            ))

    # Heuristic scan of the changed workflow files' current content (warn only).
    if scan_dir:
        for _, path in wf:
            full = os.path.join(scan_dir, path)
            if os.path.isfile(full):
                try:
                    with open(full, "r", encoding="utf-8", errors="replace") as fh:
                        content = fh.read()
                except OSError:
                    continue
                for warning in scan_heuristics(path, content):
                    messages.append(("warning", warning))

    exit_code = 1 if any(level == "error" for level, _ in messages) else 0
    return exit_code, messages


def emit_github_annotations(messages):
    for level, text in messages:
        annotation = "::error::" if level == "error" else "::warning::"
        print("%s%s" % (annotation, text.replace("\n", " ")))


def main(argv=None):
    parser = argparse.ArgumentParser(description="workflow-change-guard core logic")
    parser.add_argument("--author", required=True, help="PR author login")
    parser.add_argument("--allowlist-path", default=".workflow-guard.yml")
    parser.add_argument("--fail-on-add", default="true",
                        help="'true' or 'false'")
    parser.add_argument("--diff-file", default=None,
                        help="file with `git diff --name-status` output (default: stdin)")
    parser.add_argument("--scan-dir", default=None,
                        help="repo root to scan changed workflow contents in")
    args = parser.parse_args(argv)

    if args.diff_file:
        with open(args.diff_file, "r", encoding="utf-8") as fh:
            diff_text = fh.read()
    else:
        diff_text = sys.stdin.read()

    trusted_entries, error = load_trusted_users(args.allowlist_path)
    if error:
        print("::error::workflow-change-guard: %s" % error)
        return 1

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    exit_code, messages = evaluate(
        args.author,
        diff_text,
        trusted_entries,
        fail_on_add=args.fail_on_add.lower() != "false",
        scan_dir=args.scan_dir,
        token=token,
    )
    emit_github_annotations(messages)
    if exit_code == 0 and not messages:
        print("workflow-change-guard: no untrusted workflow changes. OK.")
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
