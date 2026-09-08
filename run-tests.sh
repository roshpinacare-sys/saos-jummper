#!/usr/bin/env bash
# Single entry point. Must pass from a fresh clone with nothing installed.
set -euo pipefail
cd "$(dirname "$0")"
echo "== unittest (43 assertions) =="
python3 -m unittest tests.test_jumpper -v
echo
echo "== end-to-end demo (live read-only witness) =="
python3 scripts/demo_end_to_end.py
