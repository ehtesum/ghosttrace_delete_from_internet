#!/usr/bin/env bash
set -e

echo "Starting GhostTrace v4..."
if [ -d "venv" ]; then
    source venv/bin/activate
elif [ -d ".venv" ]; then
    source .venv/bin/activate
fi

exec python3 app.py "$@"
