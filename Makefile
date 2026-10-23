# security-watch - common commands. Run `make` to list them.
COMPOSE ?= docker compose
.DEFAULT_GOAL := help
.PHONY: help setup check up down restart logs status scan scan-now test-notify renovate update self-update autoupdate autoupdate-off autostart

help: ## List available commands
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "  First run:  make setup  ->  edit .env and repos.json  ->  make up  ->  make autostart  ->  make autoupdate"

setup: ## Create .env and repos.json from the examples
	@test -f .env || { cp .env.example .env && echo "Created .env - fill in GITHUB_TOKEN (and Claude / notification settings)"; }
	@test -f repos.json || { cp repos.example.json repos.json && echo "Created repos.json - list the repositories to watch"; }
	@mkdir -p state
	@echo "Setup done."

check:
	@test -f .env || { echo "Missing .env - run 'make setup' first"; exit 1; }
	@test -f repos.json || { echo "Missing repos.json - run 'make setup' first"; exit 1; }
	@grep -qE '^GITHUB_TOKEN=.+' .env || { echo "GITHUB_TOKEN is empty in .env"; exit 1; }

up: check ## Build and start everything in the background
	$(COMPOSE) up -d --build
	@$(COMPOSE) ps

down: ## Stop and remove the containers
	$(COMPOSE) down

restart: check ## Restart the containers (e.g. after editing .env)
	$(COMPOSE) up -d --force-recreate

logs: ## Follow logs (SERVICE=watcher|renovate to filter)
	$(COMPOSE) logs -f --tail=200 $(SERVICE)

status: ## Show container status
	$(COMPOSE) ps

scan: check ## Scan all repos now WITHOUT writing to GitHub (dry run)
	$(COMPOSE) run --rm watcher --once --force-scan --dry-run $(if $(REPO),--repo $(REPO))

scan-now: check ## Scan now for real (REPO=owner/name for a single repo)
	$(COMPOSE) run --rm watcher --once --force-scan $(if $(REPO),--repo $(REPO))

test-notify: check ## Send a test Slack/Telegram notification
	$(COMPOSE) run --rm watcher --test-notify

renovate: check ## Run Renovate once right now
	$(COMPOSE) run --rm renovate renovate

update: check ## Pull new images, rebuild and restart
	git pull --ff-only || true
	$(COMPOSE) pull
	$(COMPOSE) up -d --build

autostart: ## Make sure Docker (and therefore security-watch) starts after a reboot
	@case "$$(uname -s)" in \
	  Linux) \
	    echo "Enabling the Docker service at boot (sudo)..."; \
	    sudo systemctl enable --now docker && echo "Done. Containers restart automatically (restart: unless-stopped)." ;; \
	  Darwin) \
	    if command -v colima >/dev/null 2>&1; then \
	      ./scripts/colima-autostart.sh; \
	    else \
	      echo "macOS: Docker runs inside Docker Desktop, which starts when a user logs in."; \
	      echo "  1. Docker Desktop -> Settings -> General -> enable 'Start Docker Desktop when you sign in'"; \
	      echo "  2. For a headless server: System Settings -> Users & Groups -> 'Automatically log in as' this user"; \
	      echo "  (Alternative: install colima + docker + docker-compose, then run make autostart again)"; \
	    fi ;; \
	  *) echo "Unknown OS - make sure the Docker daemon starts at boot." ;; \
	esac

self-update: ## Run the self-update now (git pull + newer images, restart only if changed)
	@./scripts/self-update.sh; tail -n 15 state/self-update.log

autoupdate: ## Install a nightly cron job (04:30) that runs the self-update
	@line="30 4 * * * $(CURDIR)/scripts/self-update.sh # security-watch"; \
	( crontab -l 2>/dev/null | grep -v '# security-watch$$'; echo "$$line" ) | crontab - \
	  && echo "Installed cron job: $$line" && echo "Log: state/self-update.log"

autoupdate-off: ## Remove the nightly self-update cron job
	@( crontab -l 2>/dev/null | grep -v '# security-watch$$' ) | crontab - && echo "Cron job removed."
