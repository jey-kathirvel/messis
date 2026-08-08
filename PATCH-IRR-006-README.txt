Messis AI - PATCH-IRR-006 Irrigation Execution & Field Operations

Scope
-----
- Mobile-first start, pause, resume, complete and supervisor approval workflow
- Opening and closing meter/tank readings with planned-versus-actual comparison
- Automatic runtime and water calculation when final values are omitted
- Leakage and pump issue alerts, pump status updates and generated runtime logs
- Zone last/next irrigation date updates after completion
- Execution dashboard, history and date-range printable report
- Owner isolation and audit-log events for every lifecycle transition

Migration
---------
The migration additively introduces execution status, pause tracking and
supervisor approval columns and indexes. Existing records are preserved.

Deployment
----------
Run ./apply_patch.sh from /opt/messis after the branch is fast-forwarded.
The script creates application and PostgreSQL backups before migration.

Rollback
--------
Restore the application snapshot and previous Git commit. Additive columns may
remain safely; destructive automatic database rollback is intentionally omitted.
