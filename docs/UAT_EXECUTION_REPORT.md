# Messis AI UAT Execution Report

Patch: `PATCH-UAT-001`  
Executed: 2026-07-31  
Mode: non-destructive audit  
Production: `https://messis.ads-ai.in`

## Executive Result

**Overall status: PASS WITH HIGH-PRIORITY DEFECTS**

The deployed application is available, authenticates correctly with the approved test account, preserves owner isolation in tested dashboard and farm paths, and serves the implemented farm/tree/activity foundation without HTTP 500 responses during smoke testing. No critical authentication failure, cross-user data leak, or production database corruption was observed.

Four high-severity engineering/security findings require remediation before expanding financial and harvest modules: CSRF protection, controlled signup, reproducible dependencies, and safe test isolation.

## Current Inventory

| Item | Result |
|---|---|
| Application routes | 56 business/public routes plus framework documentation/static routes |
| SQLAlchemy models/tables | `users`, `farms`, `audit_logs`, `coconut_trees`, `tree_activities` |
| Jinja templates | 22 |
| Legacy validation scripts exercised | 32 |
| Main application size | Approximately 7,750 lines |
| Production branch | `main`, aligned to baseline commit but with deployed uncommitted feature files |
| Uvicorn service | Active |
| Apache service | Active |

## Execution Summary

| Area | Status | Evidence |
|---|---|---|
| Login page and signup page | PASS | HTTP 200 |
| Valid login and redirect | PASS | HTTP 303 to `/dashboard`; session cookie issued |
| Authenticated dashboard | PASS | HTTP 200 |
| Logout/session invalidation | PASS | Logout 303; subsequent dashboard 303 |
| Unauthenticated protection | PASS | Dashboard and farms redirect to login |
| Owner isolation | PASS | Two-user dashboard check and direct foreign farm access (404) |
| Farm list/detail | PASS | HTTP 200 for owned farm |
| Farm validation | PASS | Invalid negative/empty form returns 422; no mutation |
| Coconut-tree list/API | PASS | HTTP 200 |
| Tree detail/activity live traversal | SKIPPED | Existing tested farm has no individual tree records |
| Tree/activity isolated regression coverage | PASS/PARTIAL | PATCH-005A and PATCH-005B source/helper/template tests passed |
| Jinja compilation | PASS | 22 of 22 templates compiled |
| JavaScript syntax | PASS | `node --check app/static/js/app.js` |
| Static CSS | PASS | HTTP 200 |
| Missing route | PASS | HTTP 404 |
| HTTP 500 smoke condition | PASS | None observed |
| Security headers | PASS | HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy |
| Recent service errors | PASS | No unexplained traceback or HTTP 500 in reviewed logs |
| Legacy isolated suite | PARTIAL | 23 passed, 9 failed due unsafe/non-portable test setup |
| CSRF protection | FAIL | No CSRF token generation/validation found |
| Dependency reproducibility | FAIL | Direct runtime packages missing from `requirements.txt` |
| Mutation audit coverage | PARTIAL | Farm duplication lacks direct audit call |

## Production Smoke Test Result

The final `scripts/messis_uat_smoke_test.sh` run passed:

- login, health, CSS and signup pages
- unauthenticated redirects
- successful login redirect and session cookie
- authenticated dashboard and farms list
- farm create page and non-mutating validation failure
- owned farm detail
- coconut-tree list and API
- logout and session invalidation

Tree detail/activity live traversal was skipped because the selected existing farm contains no individual coconut-tree records. Activity route structure, authorization, templates and prior regression helpers were still inspected.

## Authorization and Isolation Review

- Every dashboard, farm, tree and activity route declares `Depends(current_user)`.
- Owned-farm helpers combine resource ID with authenticated owner ID.
- Nested tree ownership is checked through the owning farm.
- Activity access is nested through an owned farm and tree.
- Dashboard aggregation filters farms using the current user's ID.
- Direct access to another user's farm returned HTTP 404.
- Rendering one user's dashboard did not reveal another user's farm name.

## Regression Suite Review

The legacy suite was not run against production because several scripts explicitly create and delete database records. In an isolated SQLite database:

- 23 scripts passed, including the current coconut-tree and activity source/helper/template validations.
- Nine older farm CRUD scripts failed at successful creation assertions due environment/database portability assumptions.
- This is recorded as test-infrastructure debt rather than evidence that production farm creation is broken; the production non-mutating validation path and existing real farm navigation passed.

## Operational Review

- `messis.service`: active.
- Apache: active.
- Local and public health endpoints: HTTP 200.
- Public HTTPS and static assets: reachable.
- Recent logs show expected 200, 303, 404, 405 and validation 422 responses; no application traceback or HTTP 500 was observed during the final run.
- Timestamped backups exist for the recent signup, isolation and agriculture UI deployments.

## Production Data Safety

No valid create, edit, delete, import, bulk update, status update, signup, or financial action was executed during this UAT patch. The only production POSTs were login, logout and deliberately invalid farm creation, which returned 422 before persistence.

## Conclusion

The implemented foundation is usable and owner isolation passed the available two-user checks. `PATCH-UAT-FIX-001` should address the highest-severity authentication boundary as one logical group: CSRF protection, signup control/throttling decision, and removal of the prefilled account identifier. Do not begin that patch until explicitly approved.
