#!/usr/bin/env bash
set -Eeuo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

if [[ "${MESSIS_ENV:-}" != "test" ]]; then
  echo "BLOCKED: MESSIS_ENV must equal test." >&2
  exit 2
fi

if [[ -z "${TEST_DATABASE_URL:-}" ]]; then
  echo "BLOCKED: TEST_DATABASE_URL is required." >&2
  exit 2
fi

PYTHON="$PROJECT_ROOT/.venv/bin/python"
PYTEST="$PROJECT_ROOT/.venv/bin/pytest"

[[ -x "$PYTHON" ]] || {
  echo "BLOCKED: $PYTHON is unavailable." >&2
  exit 2
}

if [[ ! -x "$PYTEST" ]]; then
  PYTEST="$PYTHON -m pytest"
fi

"$PYTHON" scripts/validate_test_database.py

echo "Running Messis isolated test suite..."
if [[ "$PYTEST" == *" "* ]]; then
  exec $PYTEST -q "$@"
else
  exec "$PYTEST" -q "$@"
fi
