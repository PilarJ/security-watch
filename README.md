# security-watch

Self-hosted watchdog for a chosen set of GitHub repositories. It keeps dependencies up to date, finds vulnerabilities, files them as GitHub issues and can let [Claude Code](https://claude.com/claude-code) open pull requests with fixes.

Runs as two Docker containers on any machine (a home server, a Mac mini, a VPS). Everything is pulled from GitHub, so no local working copies are needed.

| Service | What it does |
|---|---|
| **renovate** | [Renovate](https://docs.renovatebot.com/) runs every hour. It opens PRs for dependency updates (minor/patch grouped into one PR, at night on weekdays) and **immediately** opens separate PRs for security fixes. Major versions wait for approval in the *Dependency Dashboard* issue. |
| **watcher** | Once a day it clones each repo and scans it with [osv-scanner](https://github.com/google/osv-scanner) (vulnerable dependencies) and [semgrep](https://semgrep.dev/) (vulnerable code, severity ERROR by default). Findings become issues labelled `security-watch`, and resolved findings are closed automatically. Depending on configuration it runs Claude Code to fix a finding and open a PR. |

AI never merges anything. Every PR goes through your review.

## Supported stacks

- **Renovate** supports 90+ package managers (npm, composer, pip/poetry, Go modules, Maven/Gradle, Cargo, Bundler, NuGet, Docker, GitHub Actions, …).
- **osv-scanner** reads lockfiles of all major ecosystems.
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
| `max_new_issues_per_run` | `10` | protects against an issue flood on the first scan |
| `max_ai_fixes_per_run` | `2` | caps AI cost per run |

Changes to `repos.json` are picked up without a restart.

### Issue labels

- `ai-fix`: add it manually and AI will attempt a fix (works in both `on_label` and `auto` mode, and retries after a previous failure)
- `ai-pr-opened`: AI opened a PR (the PR contains `Closes #…`, so merging closes the issue)
- `ai-failed`: AI made no change; the reason is in a comment
- Closing an issue as **Not planned** marks the finding as ignored (false positive)

## Setup

1. **GitHub token**: *Settings → Developer settings → Personal access tokens*.
   - Classic PAT with scopes `repo` and `workflow`, or
   - fine-grained token with *Contents*, *Issues*, *Pull requests* and *Workflows* read/write. A fine-grained token covers one owner only, so use a classic PAT if your repos span several users/organizations.
2. **Claude authentication** (only for AI fixes): `ANTHROPIC_API_KEY`, or run `claude setup-token` and put the result into `CLAUDE_CODE_OAUTH_TOKEN`.
3. Start it:
   ```bash
   cp .env.example .env              # fill it in
   cp repos.example.json repos.json  # list your repositories
   docker compose up -d --build
   docker compose logs -f
   ```

Containers use `restart: unless-stopped`, so they come back after a reboot once Docker is running.

### Useful commands

```bash
# scan right now, without writing anything to GitHub
docker compose run --rm watcher --once --force-scan --dry-run

# real scan of a single repo right now
docker compose run --rm watcher --once --force-scan --repo your-user/web-app

# scan a local directory (no GitHub needed)
docker compose run --rm -v "$PWD/../my-project:/src:ro" watcher --scan-local /src

# manual Renovate run
docker compose run --rm renovate renovate

# update tools
docker compose pull && docker compose up -d --build
```

### Environment variables (`.env`)

| Variable | Default | |
|---|---|---|
| `GITHUB_TOKEN` | – | required |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` | – | required for AI fixes |
| `CLAUDE_MODEL` | Claude Code default | model for AI fixes |
| `AI_LANGUAGE` | `English` | language of AI-written summaries |
| `SEMGREP_CONFIGS` | `p/default,p/secrets` | comma-separated rulesets |
| `SCAN_INTERVAL_HOURS` | `24` | how often to scan |
| `LOOP_MINUTES` | `15` | how often to check for `ai-fix` labels |
| `RENOVATE_INTERVAL_SECONDS` | `3600` | pause between Renovate runs |
| `RENOVATE_TIMEZONE` | `UTC` | timezone for the Renovate schedule |
| `CLAUDE_TIMEOUT_SECONDS` | `1800` | max duration of one AI fix |
| `GIT_AUTHOR_NAME` / `GIT_AUTHOR_EMAIL` | `security-watch` | author of AI fix commits |

## Security notes

- The AI runs inside the container **without** the GitHub token. It can only read and edit files and run allow-listed commands. The wrapper does the commit and push.
- Scanner output is passed to the AI explicitly as data, not instructions. AI fixes are still meant for repositories you trust.
- Code snippets of secret-type findings are not copied into issues. A leaked credential has to be **revoked**; removing it from the code is not enough.
- `.env` and `repos.json` are git-ignored.

## License

MIT
