Messis AI - PATCH-IRR-005 Smart Irrigation Scheduler & Calendar

Scope
-----
- Owner-isolated scheduler CRUD and monthly calendar
- Farm, zone, water source, pump and worker assignment
- Daily, weekly and monthly recurrence generation
- Zone, pump and worker time-conflict detection
- Schedule status workflow, dashboard metrics and period reports
- IrrigationAlert foundation for rejected schedule conflicts

Deployment
----------
1. The apply script backs up PostgreSQL and affected application files.
2. Deploy the irrigationmgmt branch.
3. Run: ./apply_patch.sh
4. Confirm /health, /irrigation/schedules and systemctl status messis.service.

Migration
---------
The migration is additive and idempotent. Four nullable/defaulted recurrence
columns and two indexes are added to irrigation_schedules. No existing records
are deleted or rewritten.

Rollback
--------
Restore the application backup and previous Git commit. The additive database
columns may safely remain in place; dropping them is intentionally not automated.
