#!/usr/bin/env bash
set -e

if [ -d .git ]; then
  if command -v git >/dev/null 2>&1; then
    git pull --ff-only || git pull
  else
    echo "Git not found; skipping auto-update."
  fi
else
  echo "No .git folder; skipping auto-update."
fi

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

echo "Install/update complete. Run ./run.sh to start."
