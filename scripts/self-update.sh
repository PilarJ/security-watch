#!/usr/bin/env bash
# Self-update for security-watch. Meant to run from cron (see `make autoupdate`).
#  1. pulls new commits of this repository (fast-forward only, never over local changes)
#  2. pulls newer images and rebuilds the watcher (picks up base image security fixes)
#  3. recreates containers only if something actually changed
set -uo pipefail

cd "$(dirname "$0")/.."
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:$PATH"
COMPOSE="${COMPOSE:-docker compose}"
mkdir -p state
LOG="state/self-update.log"
exec >>"$LOG" 2>&1
echo "=== $(date '+%Y-%m-%d %H:%M:%S') self-update"

changes=()

# --- 1. code
if git rev-parse --git-dir >/dev/null 2>&1; then
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if ! git fetch --quiet origin "$branch"; then
    echo "git fetch failed - skipping code update"
  elif [ -n "$(git status --porcelain --untracked-files=no)" ]; then
    echo "local changes in tracked files - skipping code update"
  else
    before="$(git rev-parse HEAD)"
    if git merge --ff-only --quiet "origin/$branch"; then
      after="$(git rev-parse HEAD)"
      if [ "$before" != "$after" ]; then
        echo "code updated ${before:0:7} -> ${after:0:7}"
        changes+=("code ${before:0:7} → ${after:0:7}: $(git log --format=%s -1)")
      fi
    else
      echo "branch diverged from origin/$branch - skipping code update"
    fi
  fi
fi

# --- 2. images
ids() { $COMPOSE images -q 2>/dev/null | sort | tr '\n' ' '; }
before_ids="$(ids)"
$COMPOSE pull --quiet --ignore-buildable 2>/dev/null || $COMPOSE pull --quiet renovate
$COMPOSE build --pull --quiet watcher
$COMPOSE up -d --remove-orphans
after_ids="$(ids)"
if [ "$before_ids" != "$after_ids" ]; then
  echo "images updated"
  changes+=("container images updated")
fi

# --- 3. report
if [ ${#changes[@]} -gt 0 ]; then
  msg="$(printf '%s\n' "${changes[@]}")"
  echo "$msg"
  $COMPOSE run --rm --no-deps watcher --notify-event self_update --notify-text "$msg" || true
else
  echo "nothing to update"
fi
# Each `build --pull` leaves the previous watcher image dangling - drop them so the disk does not fill up.
docker image prune -f >/dev/null 2>&1 || true
