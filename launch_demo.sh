#!/usr/bin/env bash

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_PYTHON="$PROJECT_ROOT/.venv/bin/python"

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "Missing virtual environment at $PROJECT_ROOT/.venv"
  echo "Create it first with:"
  echo "  python3 -m venv .venv"
  echo "  source .venv/bin/activate"
  echo "  pip install Flask Pillow"
  exit 1
fi

"$VENV_PYTHON" "$PROJECT_ROOT/labs/local_ctf/generate_demo_assets.py"

osascript - "$PROJECT_ROOT" <<'EOF'
on run argv
    set projectRoot to item 1 of argv
    set hostsCmd to "cd " & quoted form of projectRoot & "; source .venv/bin/activate; python labs/local_ctf/start_hosts.py"
    set webCmd to "cd " & quoted form of projectRoot & "; source .venv/bin/activate; python run_web.py"
    set attackerCmd to "cd " & quoted form of projectRoot & "; source .venv/bin/activate; clear; echo 'Attacker terminal ready.'; echo 'Try:'; echo '  python labs/local_ctf/scanner.py --images'; echo '  python labs/local_ctf/collector.py labs/local_ctf/loot'; exec zsh"

    tell application "Terminal"
        activate
        do script hostsCmd
        delay 1
        do script webCmd
        delay 1
        do script attackerCmd
    end tell
end run
EOF

echo "Demo launcher started."
echo "Hosts should be on ports 8001-8004."
echo "Web app should be at http://127.0.0.1:5000"
