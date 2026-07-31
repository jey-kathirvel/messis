# PATCH-UAT-FIX-001 Execution Report

Executed: 2026-07-31  
Defects: UAT-001, UAT-002, UAT-008  
Result: PASS

## Changes

- Added production same-origin enforcement for every POST, PUT, PATCH and DELETE request.
- Rejects `Sec-Fetch-Site: cross-site` before other bypass mechanisms.
- Validates Origin or Referer against the current/public trusted origin.
- Requires `X-Messis-CSRF: 1` for trusted CLI/API callers without browser origin headers.
- Added a private server-held registration code for account creation.
- Uses constant-time registration-code comparison.
- Audits rejected registration codes without logging the supplied or configured code.
- Throttles rejected registrations per IP using database audit history.
- Removed the prefilled production account identifier from the login form.
- Updated the UAT smoke test to send a valid same-origin header.

## Configuration

New optional settings:

- `SIGNUP_ACCESS_CODE` - configured privately on production; never committed.
- `SIGNUP_MAX_ATTEMPTS` - default 5.
- `SIGNUP_WINDOW_SECONDS` - default 900.
- `CSRF_TRUSTED_ORIGINS` - optional comma-separated additional origins.

If `SIGNUP_ACCESS_CODE` is absent, registration fails closed with HTTP 503.

## Validation

- Python compilation: PASS.
- Static security-boundary test: PASS.
- Runtime CSRF decision test: PASS.
- Isolated registration integration test: PASS.
- Cross-site production login POST: HTTP 403.
- Same-origin authenticated UAT smoke test: PASS.
- Registration-code field: present.
- Production registration configuration: present, value not exposed.
- Prefilled account identifier: absent.
- Service health: active, HTTP 200.
- Existing farm/tree authenticated workflow: PASS.

## Database

No schema change. Rejected signup attempts use the existing `audit_logs` table.

## Rollback

Restore application files and `.env` from the timestamped patch backup, restart `messis.service`, then verify `/health` and login. No database rollback is required.
