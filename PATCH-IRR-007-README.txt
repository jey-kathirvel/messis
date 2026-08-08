Messis AI - PATCH-IRR-007 Fertigation Management

Scope
-----
- Fertilizer product catalogue, safety profiles, expiry and stock ledger
- Fertigation plans linked to farm, zone and optional irrigation schedule
- Automatic tank batch and per-batch fertilizer calculations
- Safe concentration, expiry and available-stock enforcement
- Ordered mixing recipe, agronomist reference and safety instructions
- Draft, submission, approval, rejection and field completion workflow
- Atomic stock deduction, stock movement history and lifecycle audit events
- Responsive dashboards, field recipe, inventory and date-range reports

Migration
---------
Additive plan workflow columns and fertilizer_stock_movements are created
idempotently. Existing farm, irrigation, execution and product data is preserved.

Deployment
----------
Fast-forward irrigationmgmt and run ./apply_patch.sh from /opt/messis.
The script backs up PostgreSQL and affected application files first.
