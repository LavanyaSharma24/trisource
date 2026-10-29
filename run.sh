#!/usr/bin/env bash
# run.sh — one-command start for TriSource (front-end + .evtx ingestion backend).
#
#   ./run.sh                 -> http://localhost:8000
#   PORT=9000 ./run.sh       -> another port
#   HOST=0.0.0.0 ./run.sh    -> reachable from other machines on your network
#
# First run creates .venv/ and installs requirements.txt; later runs reinstall
# only when requirements.txt has changed. Needs Python 3.10+.
set -euo pipefail
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
VENV=".venv"
STAMP="$VENV/.requirements-installed"

if [ ! -x "$VENV/bin/python" ]; then
  echo "• creating virtualenv in $VENV"
  "$PYTHON" -m venv "$VENV"
fi
if [ ! -f "$STAMP" ] || [ requirements.txt -nt "$STAMP" ]; then
  echo "• installing requirements"
  "$VENV/bin/python" -m pip install --quiet --upgrade pip
  "$VENV/bin/python" -m pip install --quiet -r requirements.txt
  touch "$STAMP"
fi

PORT="${PORT:-8000}"
HOST="${HOST:-127.0.0.1}"
echo "• TriSource running at http://localhost:$PORT   (Ctrl+C to stop)"
exec "$VENV/bin/python" -m uvicorn backend.app:app --host "$HOST" --port "$PORT"
