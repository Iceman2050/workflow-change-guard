# workflow-change-guard

Fail CI when `.github/workflows/` files are added or modified by someone **not** on your trusted allowlist.

## The problem: the GhostAction campaign (October 2026)

In October 2026, attackers compromised roughly **1,900 GitHub accounts** belonging to maintainers of popular projects. Using those accounts, they pushed a malicious workflow file — `.github/workflows/security-audit.yml` — into **30,000+ repositories**.

The payload looked like a routine "security audit" job, but it quietly exfiltrated repository secrets and CI credentials. Most victims never noticed: the file arrived as a normal-looking commit from a trusted maintainer, and nothing in the CI pipeline questioned *who* was allowed to change workflow files in the first place.

`workflow-change-guard` closes that gap. It is a composite GitHub Action that runs on every pull request and **fails the build** when workflow files are added or modified by a PR author who isn't on your allowlist.

## 30-second setup

1. Add a `.workflow-guard.yml` file to your repo root listing who may touch workflows:

```yaml
trusted_users:
  - your-github-username
  - octo-org/security-team  # your GitHub org / team
```

2. Use the action in a workflow (e.g. `.github/workflows/guard.yml`):

```yaml
name: guard
on:
  pull_request:
    paths:
      - '.github/workflows/**'
      - '.workflow-guard.yml'

jobs:
  workflow-guard:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: read
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: Iceman2050/workflow-change-guard@v1
```

3. Done. Any PR from an untrusted author that touches `.github/workflows/` now fails.

## What it checks

- **Allowlist enforcement (fail):** every file added/modified/deleted under `.github/workflows/` in the PR must come from an author on the allowlist. Entries can be plain usernames (`alice`) or org teams (`myorg/security-team`, verified via the GitHub API).
- **Suspicious-content heuristics (warn only):** changed workflow files are scanned for
  - `curl … | bash` / `wget … | sh` style remote-script execution,
  - URLs pointing at raw IP addresses (exfiltration endpoints),
  - `${{ secrets.* }}` values echoed into logs or redirected to files.
  
  Heuristics **warn but never fail** — they are tripwires for reviewers, not verdicts.

### Inputs

| Input | Default | Description |
|---|---|---|
| `allowlist-path` | `.workflow-guard.yml` | Path to the allowlist config, relative to repo root |
| `fail-on-add` | `true` | Fail when an untrusted author *adds* a new workflow file. Set to `false` to downgrade adds to warnings |
| `github-token` | `${{ github.token }}` | Token used to verify `org/team` allowlist entries |

## Example failing output

When a PR from `mallory` adds `.github/workflows/security-audit.yml` and she isn't allowlisted:

```
::error::Workflow guard failed: PR author 'mallory' is not on the allowlist
but changed workflow files: .github/workflows/security-audit.yml (added).
If this change is legitimate, ask a trusted maintainer to approve it,
or add the author to .workflow-guard.yml.
```

And when a workflow contains a suspicious pattern (warns, doesn't fail):

```
::warning::.github/workflows/security-audit.yml: downloads and pipes a remote
script to a shell (curl|wget ... | bash)
::warning::.github/workflows/security-audit.yml: URL uses a raw IP address
(http://192.0.2.55) — possible exfiltration endpoint
```

## How it works

The composite action (`action.yml`) diffs the PR base against the head
(`git diff --name-status base...head`), then runs `guard.py` (stdlib-only
Python, zero dependencies) with the PR author's login. No compiled JS, no
npm, no third-party actions — it's deliberately readable so you can audit
it in five minutes.

Core logic is tested locally with fixture diffs — see `tests/` (run with
`python3 -m unittest discover -s tests`).

## Limitations

- This guards **pull requests**. Direct pushes to protected branches should be blocked with branch protection rules requiring PRs.
- Team entries (`org/team`) need a token with `read:org` scope; without one they simply don't match.
- Heuristics are deliberately conservative — a legit `curl` to a pinned release asset won't match the pipe-to-shell pattern, but review warnings anyway.

## License

MIT — see [LICENSE](LICENSE).

---

## Built by Ingenious AI

This action is part of the Ingenious AI security toolkit — defenses built for the real attacks hitting open source right now. Get early access to our platforms:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
