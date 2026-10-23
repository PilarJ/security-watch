#!/usr/bin/env bash
# Starts Colima at login of the CURRENT user via a per-user LaunchAgent (see `make autostart`).
# Does the same as `brew services start colima`, but works when Homebrew is owned by another
# account (brew refuses to run as a non-owner, and its service would start the wrong user's Colima).
set -euo pipefail

label="com.security-watch.colima"
plist="$HOME/Library/LaunchAgents/$label.plist"
colima="$(command -v colima)"
bindir="$(dirname "$colima")"

mkdir -p "$HOME/Library/LaunchAgents" "$HOME/Library/Logs"
cat >"$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array><string>$colima</string><string>start</string><string>-f</string></array>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>$bindir:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string></dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>StandardOutPath</key><string>$HOME/Library/Logs/colima-autostart.log</string>
  <key>StandardErrorPath</key><string>$HOME/Library/Logs/colima-autostart.log</string>
</dict>
</plist>
EOF
echo "Wrote $plist"

domain="gui/$(id -u)"
launchctl bootout "$domain/$label" 2>/dev/null || true
if launchctl bootstrap "$domain" "$plist" 2>/dev/null; then
  echo "Loaded. Colima starts whenever $(id -un) logs in; containers restart automatically."
else
  echo "Could not load it now (no GUI session, e.g. over SSH) - it loads at the next login of $(id -un)."
fi
echo "Headless server: System Settings -> Users & Groups -> 'Automatically log in as' $(id -un)"
