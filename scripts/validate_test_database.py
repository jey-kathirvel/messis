#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.test_database_safety import (  # noqa: E402
    UnsafeTestDatabaseError,
    load_safe_test_database,
)

try:
    safe_db = load_safe_test_database()
except UnsafeTestDatabaseError as exc:
    print(f"TEST DATABASE SAFETY: BLOCKED — {exc}", file=sys.stderr)
    raise SystemExit(2)

print("TEST DATABASE SAFETY: PASSED")
print(f"Target: {safe_db.redacted_description}")
