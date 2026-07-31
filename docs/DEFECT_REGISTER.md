# Messis AI Defect Register

Audit patch: `PATCH-UAT-001`  
Status date: 2026-07-31

Status values: **Open**, **Fixed**, **Retested**, **Deferred**.

| ID | Severity | Area | Finding | Evidence/Impact | Status | Recommended patch |
|---|---|---|---|---|---|---|
| UAT-001 | High | Security | State-changing HTML forms and APIs had no CSRF validation. | Production now rejects cross-site unsafe methods using Origin/Referer/Sec-Fetch-Site validation; trusted non-browser clients require `X-Messis-CSRF: 1`. Cross-site production probe returned 403. | Retested | PATCH-UAT-FIX-001 |
| UAT-002 | High | Authentication | Public `/auth/set-passcode` created active owner accounts without an approval boundary or signup throttling. | Signup now requires a server-held registration code, uses constant-time comparison, audits rejections and throttles rejected attempts by IP. | Retested | PATCH-UAT-FIX-001 |
| UAT-003 | High | Deployment | `requirements.txt` omitted direct runtime dependencies used by the application. | Fourteen direct packages are now pinned; a clean Python 3.12 environment installed successfully, all imports/application modules compiled, `pip check` passed, and production versions match. | Retested | PATCH-UAT-FIX-002 |
| UAT-004 | High | Test safety | Nine legacy regression scripts require the production credential file and perform create/delete/commit operations. They are not safely isolated by default. | Running the suite naively can modify production data. The safety review blocked the first production attempt. | Open | PATCH-UAT-FIX-003 |
| UAT-005 | Medium | Test portability | Nine farm regression scripts fail against isolated SQLite because their setup assumes the production environment/database behavior. | 23 scripts pass in isolation; nine cannot currently provide safe regression coverage without a PostgreSQL test database or fixtures. | Open | PATCH-UAT-FIX-003 |
| UAT-006 | Medium | Audit logging | `duplicate_farm` is a state-changing route without a direct `audit()` call. | Farm duplication is not represented consistently in the audit trail. | Retested | PATCH-UAT-FIX-004 |
| UAT-007 | Medium | Credentials/operations | The protected initial credential file no longer identifies a current account; the handover test account succeeds. | Automated smoke testing fails unless credentials are supplied explicitly. No credential value is recorded here. | Open | PATCH-UAT-FIX-003 |
| UAT-008 | Medium | Authentication UI | The login page pre-populated a known user ID. | The field is now empty; production content check confirms the identifier is absent. | Retested | PATCH-UAT-FIX-001 |
| UAT-009 | Medium | Versioning | FastAPI/health report version `0.3.1`, while the README/handover target `v0.5.0-tree-activities`. | Operational health and release documentation disagree. | Retested | PATCH-DEPLOY-008 |
| UAT-010 | Medium | Farm lifecycle | Farms have no active/archive state or `updated_at`; the current UI supports hard deletion. | Does not meet the planned safe-archive business rule and can remove related trees/activities through cascade deletion. | Deferred | PATCH-FARM-001 |
| UAT-011 | Medium | UI resilience | Many standalone pages load Tailwind/Chart.js/fonts from CDNs rather than shared local assets. | A CDN outage or restrictive network can degrade the UI and charts. | Deferred | PATCH-UI-001 |
| UAT-012 | Low | Static assets | `/favicon.ico` repeatedly returns HTTP 404. | Avoidable log noise and missing browser identity asset. | Retested | PATCH-UAT-FIX-005 |
| UAT-013 | Low | HTTP behavior | `HEAD /` returns HTTP 405 even though `GET /` succeeds. | Some uptime tools use HEAD and may report a false failure. | Retested | PATCH-UAT-FIX-005 |
| UAT-014 | Low | Information disclosure | Public responses include `Server: uvicorn`. | Reveals backend server technology through the reverse proxy. | Open | PATCH-DEPLOY-009 |

## Confirmed Passes

- All business routes except the documented public authentication/health routes require `current_user`.
- Direct cross-user farm access returns 404.
- A second user's dashboard does not contain the first user's farm.
- Dashboard farm and tree totals use `Farm.owner_id == user.id`.
- Login passcodes use Argon2 hashes; no plaintext passcode field exists.
- Account lockout state is present and active accounts are checked.
- Invalid farm creation returns HTTP 422 without creating a record.
- All 22 Jinja templates compile.
- Public HTTPS includes HSTS, clickjacking, MIME-sniffing, referrer and permissions security headers.
- Uvicorn and Apache services are active.

## Planned Capability Gaps (Not UAT Defects Yet)

The handover intentionally schedules harvest cycles, detailed harvest records, expenses, sales, profitability, centralized reports, value-added products, role-based users, automated backup/restore, monitoring, and final certification for later phases. Their absence is not classified as a current regression.
