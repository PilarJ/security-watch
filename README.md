# security-watch

Self-hosted watchdog for a chosen set of GitHub repositories. It keeps dependencies up to date, finds vulnerabilities, files them as GitHub issues and can let [Claude Code](https://claude.com/claude-code) open pull requests with fixes.

Runs as two Docker containers on any machine (a home server, a Mac mini, a VPS). Everything is pulled from GitHub, so no local working copies are needed.

| Service | What it does |
|---|---|
| **renovate** | [Renovate](https://docs.renovatebot.com/) runs every hour. It opens PRs for dependency updates (minor/patch grouped into one PR, at night on weekdays) and **immediately** opens separate PRs for security fixes. Major versions wait for approval in the *Dependency Dashboard* issue. |
| **watcher** | Once a day it clones each repo and scans it with [osv-scanner](https://github.com/google/osv-scanner) (vulnerable dependencies), [semgrep](https://semgrep.dev/) (vulnerable code) and [Trivy](https://trivy.dev/) (Dockerfile/Kubernetes/Terraform misconfigurations, leaked secrets and, optionally, published container images). Findings become issues labelled `security-watch`, and resolved findings are closed automatically. Depending on configuration it runs Claude Code to fix a finding and open a PR. |

AI never merges anything. Every PR goes through your review.

Optional **Slack** and **Telegram** notifications tell you when something needs attention.

## What gets scanned

| Scanner | Finds | Issue title example |
|---|---|---|
| osv-scanner | vulnerable dependencies in lockfiles | `[security] [CVSS 9.8 critical] Vulnerable dependency guzzlehttp/guzzle 6.5.0 (GHSA-…)` |
| semgrep | injection, XSS, eval, insecure crypto… in your code | `[security] [high] tainted-sql-string in src/Repo.php:42` |
| Trivy fs | IaC misconfigurations (Dockerfile, compose, k8s, Terraform, Helm) and secrets | `[security] [critical] Secret (GitHub Personal Access Token) in config.php:4` |
| Trivy image | OS and library packages inside your published images, end-of-life base OS | `[security] [CVSS 9.1 critical] openssl 3.0.2 in image app:latest (CVE-…)` |

Issue titles start with the CVSS score and rating (critical ≥ 9.0, high ≥ 7.0, medium ≥ 4.0) where a score exists, otherwise with the scanner's severity. Titles of open issues are updated when the score changes, so you can sort and filter by severity directly on GitHub.

Trivy image scanning pulls images from the registry. For private images set `TRIVY_USERNAME`/`TRIVY_PASSWORD` (for GHCR: your username and `GITHUB_TOKEN`). Trivy is pinned by digest, because Trivy release artifacts were compromised in March 2026 ([CVE-2026-33634](https://nvd.nist.gov/vuln/detail/CVE-2026-33634)).

## Supported stacks

- **Renovate** supports 90+ package managers (npm, composer, pip/poetry, Go modules, Maven/Gradle, Cargo, Bundler, NuGet, Docker, GitHub Actions, …).
- **osv-scanner** reads lockfiles of all major ecosystems.
- **Trivy** misconfiguration checks cover Dockerfile, Docker Compose, Kubernetes, Helm, Terraform, CloudFormation and Ansible.
- **semgrep** rulesets are configurable globally (`SEMGREP_CONFIGS`) or per repo (`semgrep_configs`), e.g. `p/php`, `p/python`, `p/javascript`, `p/golang`, `p/java`. See the [registry](https://semgrep.dev/explore).
- **AI fixes** can edit code in any language. To *run* tooling (upgrade a dependency, run tests), the toolchain has to be in the watcher image. Out of the box it includes Node (npm/yarn/pnpm), PHP (composer) and Python (pip). Extend `watcher/Dockerfile` for other stacks and allow the commands via `ai_allowed_commands`.

## Configuration: `repos.json`

```bash
cp repos.example.json repos.json
```

```json
{
  "repos": [
    { "repo": "your-user/web-app", "renovate": true, "security_scan": true, "ai_fix": "auto" },
    { "repo": "your-org/api", "ai_fix": "on_label", "semgrep_configs": ["p/default", "p/secrets", "p/python"] }
  ]
}
```

| Key | Default | |
|---|---|---|
| `repo` | – | `owner/name` |
| `renovate` | `true` | Renovate update PRs |
| `security_scan` | `true` | daily scan → issues |
| `ai_fix` | `"off"` | `off` · `on_label` (AI fixes only issues you label `ai-fix`) · `auto` (AI fixes new code findings on its own) |
| `ai_fix_dependencies` | `false` | let AI also fix vulnerable dependencies (by default left to Renovate) |
| `semgrep_configs` | `SEMGREP_CONFIGS` env | list of semgrep rulesets |
| `semgrep_severity` | `["ERROR"]` | add `"WARNING"` for more findings |
| `ai_allowed_commands` | `[]` | extra shell commands the AI may run, e.g. `["pytest", "go"]` |
| `ai_language` | `AI_LANGUAGE` env | language of AI-written PR descriptions for this repo, e.g. `"Czech"` |
| `trivy_fs` | `true` | Trivy filesystem scan (misconfigurations + secrets) |
| `trivy_fs_scanners` | `["misconfig", "secret"]` | add `"vuln"` / `"license"` if you want them from Trivy too |
| `trivy_images` | `[]` | published images to scan, e.g. `["ghcr.io/me/app:latest"]` |
| `trivy_severity` | `["HIGH", "CRITICAL"]` | minimum Trivy severities |
| `trivy_ignore_unfixed` | `false` | skip image vulnerabilities without an available fix |
| `max_new_issues_per_run` | `10` | protects against an issue flood on the first scan |
| `max_ai_fixes_per_run` | `2` | caps AI cost per run |
| `notify` | `true` | set `false` to mute notifications for this repo |
| `renovate_config` | `{}` | extra Renovate config for this repo only, e.g. `{"constraints": {"php": "8.2.*"}}` when `require.php` is open-ended and lock files must be generated with the PHP version you actually run |

Changes to `repos.json` are picked up without a restart.

### Issue labels

- `ai-fix`: add it manually and AI will attempt a fix (works in both `on_label` and `auto` mode, and retries after a previous failure)
- `ai-pr-opened`: AI opened a PR (the PR contains `Closes #…`, so merging closes the issue)
- `ai-failed`: AI made no change; the reason is in a comment
- Closing an issue as **Not planned** marks the finding as ignored (false positive)

## Notifications

Slack, Telegram, both or neither. Configure them in `.env`:

| Channel | Setup |
|---|---|
| Slack | Create an [Incoming Webhook](https://api.slack.com/messaging/webhooks) for a channel and set `SLACK_WEBHOOK_URL`. |
| Telegram | Create a bot with [@BotFather](https://t.me/BotFather) and set `TELEGRAM_BOT_TOKEN`. Send the bot a message (or add it to a group), open `https://api.telegram.org/bot<TOKEN>/getUpdates` and set `TELEGRAM_CHAT_ID` to the `chat.id` value. |

| Event | Sent when | Default |
|---|---|---|
| `new_findings` | the scan opened new issues (one message per repo, with links) | ✅ |
| `reopened` | a previously fixed finding came back | ✅ |
| `resolved` | findings disappeared and their issues were closed | – |
| `ai_pr` | AI opened a fix PR that needs review | ✅ |
| `ai_failed` | AI couldn't fix an issue | ✅ |
| `renovate_security` | Renovate opened a new security update PR | ✅ |
| `errors` | a scanner or the watcher failed | ✅ |
| `self_update` | security-watch updated itself (see below) | ✅ |

Choose events with `NOTIFY_EVENTS=new_findings,ai_pr` (or `all`). Mute a single repo with `"notify": false` in `repos.json`. Check the setup with:

```bash
docker compose run --rm watcher --test-notify
```

There is no separate dashboard. GitHub is the dashboard: filter issues by the `security-watch` label, and Renovate keeps a *Dependency Dashboard* issue in every repo.

## Setup

1. **GitHub token**: *Settings → Developer settings → Personal access tokens*.
   - Classic PAT with scopes `repo` and `workflow`, or
   - fine-grained token with *Contents*, *Issues*, *Pull requests* and *Workflows* read/write. A fine-grained token covers one owner only, so use a classic PAT if your repos span several users/organizations.
2. **Claude authentication** (only for AI fixes): `ANTHROPIC_API_KEY`, or run `claude setup-token` and put the result into `CLAUDE_CODE_OAUTH_TOKEN`.
3. Start it:
   ```bash
   make setup        # creates .env and repos.json from the examples - fill them in
   make up           # build and start in the background
   make autostart    # make sure Docker starts after a reboot
   make logs
   ```

Both containers use `restart: unless-stopped`, so they come back after a crash or a reboot once the Docker daemon is running. `make autostart` handles that per OS:

- **Linux:** enables the `docker` systemd service at boot.
- **macOS:** Docker Desktop only runs while a user is logged in. Enable *Start Docker Desktop when you sign in* and, on a headless machine, automatic login. If Colima is installed, `make autostart` installs a LaunchAgent for the current user instead (no `brew services`, so it also works when Homebrew belongs to a different admin account); on a headless machine enable automatic login for that user.

### Commands

Run `make` to list them.

| Command | |
|---|---|
| `make setup` | create `.env` and `repos.json` from the examples |
| `make up` / `make down` / `make restart` | start / stop / recreate (after editing `.env`) |
| `make logs` | follow logs (`SERVICE=watcher` or `SERVICE=renovate` to filter) |
| `make status` | container status |
| `make scan` | scan all repos now **without** writing to GitHub (dry run) |
| `make scan-now` | real scan now (`REPO=owner/name` for one repo) |
| `make test-notify` | send a test Slack/Telegram notification |
| `make renovate` | run Renovate once right now |
| `make update` | `git pull`, pull new images, rebuild and restart |
| `make autostart` | start Docker at boot (see above) |
| `make autoupdate` / `make autoupdate-off` | install / remove the nightly self-update cron job |
| `make self-update` | run the self-update now |

Without `make`, the same works directly with Docker Compose, e.g. `docker compose run --rm watcher --scan-local /src` to scan a mounted local directory.

### Keeping security-watch itself up to date

`make autoupdate` installs a cron job (04:30 every night) that runs `scripts/self-update.sh`:

1. fast-forwards this checkout to the latest commit (skipped if you have local changes or the branch diverged)
2. pulls newer images and rebuilds the watcher with fresh base images
3. recreates containers **only if something changed**, sends a `self_update` notification and logs to `state/self-update.log`

The cron job runs as your user, so `git fetch` uses your normal Git credentials. For a private fork over HTTPS, run `gh auth setup-git` once.

The tool versions pinned in the watcher (semgrep, osv-scanner, Claude Code, base images) are covered by this repo's `renovate.json`. Add your own copy of security-watch to `repos.json` and Renovate will open a grouped PR when a new version comes out. Merge it and the nightly self-update deploys it.

### Environment variables (`.env`)

| Variable | Default | |
|---|---|---|
| `GITHUB_TOKEN` | – | required |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | – | required for AI fixes |
| `CLAUDE_MODEL` | Claude Code default | model for AI fixes |
| `AI_LANGUAGE` | `English` | default language of AI-written summaries (per repo: `ai_language`) |
| `SEMGREP_CONFIGS` | `p/default` | comma-separated rulesets |
| `TRIVY_USERNAME` / `TRIVY_PASSWORD` | – | registry login for private images |
| `SCAN_INTERVAL_HOURS` | `24` | how often to scan |
| `LOOP_MINUTES` | `15` | how often to check for `ai-fix` labels |
| `RENOVATE_INTERVAL_SECONDS` | `3600` | pause between Renovate runs |
| `RENOVATE_TIMEZONE` | `UTC` | timezone for the Renovate schedule |
| `CLAUDE_TIMEOUT_SECONDS` | `1800` | max duration of one AI fix |
| `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` | `security-watch` | author of AI fix commits |
| `SLACK_WEBHOOK_URL` | – | Slack notifications |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | – | Telegram notifications |
| `NOTIFY_EVENTS` | all except `resolved` | which events to send |

## Security notes

- The AI runs inside the container **without** the GitHub token. It can only read and edit files and run allow-listed commands. The wrapper does the commit and push.
- Scanner output is passed to the AI explicitly as data, not instructions. AI fixes are still meant for repositories you trust.
- Secrets are reported redacted, and AI never auto-fixes them or image findings (rotation and rebuilds need a human; the `ai-fix` label still forces an attempt).
- Code snippets of secret-type findings are not copied into issues. A leaked credential has to be **revoked**; removing it from the code is not enough.
- `.env` and `repos.json` are git-ignored.

## License

MIT
