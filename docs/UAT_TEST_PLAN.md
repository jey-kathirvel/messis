# Messis AI UAT Test Plan

Patch: `PATCH-UAT-001`  
Scope: audit only; no defect remediation  
Target: `https://messis.ads-ai.in`

## Objectives

Validate the current FastAPI/PostgreSQL/Jinja application before new business modules are added. The plan covers authentication, authorization, owner isolation, farm CRUD, coconut-tree management, tree activities, dashboard calculations, audit logging, responsive UI, JavaScript/static assets, routing, Apache, HTTPS, and service health.

## Safety Rules

- Do not delete or modify production business records.
- Use only GET requests and deliberately invalid POST payloads in production smoke tests.
- Run legacy write-capable tests only against an isolated temporary database.
- Never print credentials, hashes, database URLs, or secret keys.
- Record defects during this patch; do not fix them.

## Test Environment

| Layer | Target |
|---|---|
| Public application | `https://messis.ads-ai.in` |
| Reverse proxy | Apache over HTTPS |
| Application service | `messis.service`, Uvicorn on `127.0.0.1:8080` |
| Production database | PostgreSQL, read-only inspection |
| Isolated regression database | Temporary SQLite database |

## Test Cases

| ID | Area | Test | Expected |
|---|---|---|---|
| AUTH-001 | Login | GET login page | HTTP 200 and login form |
| AUTH-002 | Login | Valid login POST | HTTP 303 and session cookie |
| AUTH-003 | Session | Authenticated dashboard | HTTP 200 |
| AUTH-004 | Logout | Logout then revisit dashboard | HTTP 303 to login |
| AUTH-005 | Lockout | Static/code inspection | Attempts counted and timed lockout configured |
| AUTHZ-001 | Protected routes | Access dashboard/farms without session | HTTP 303 to login |
| AUTHZ-002 | Owner isolation | Inspect every protected query/helper | Farm ownership applied before nested access |
| AUTHZ-003 | Cross-user dashboard | Render zero-farm user dashboard | No other owner's farm name or totals |
| FARM-001 | Farm list | Authenticated GET | HTTP 200, owner-scoped records |
| FARM-002 | Validation | Submit empty/negative invalid farm | HTTP 422, no record created |
| FARM-003 | Detail | Open owned farm | HTTP 200 |
| FARM-004 | CRUD | Static and isolated regression tests | Create/edit/delete paths and validation present |
| TREE-001 | Trees | List and detail owned farm trees | HTTP 200 or documented empty skip |
| TREE-002 | API | List owned farm trees | HTTP 200 JSON |
| TREE-003 | Features | Inspect import/export/bulk/labels/QR/report routes | Routes protected and templates compile |
| ACT-001 | Activities | List owned tree activities | HTTP 200 or documented empty skip |
| ACT-002 | API | Activity list/summary routes | Protected and owner-scoped |
| ACT-003 | Workflow | Validate status-transition regression scripts | Pass in isolated environment |
| DASH-001 | Metrics | Compare query predicates | Counts and totals restricted by owner ID |
| AUDIT-001 | Audit trail | Inspect mutations | Authentication and business mutations create logs |
| UI-001 | Templates | Compile every Jinja template | No syntax error |
| UI-002 | Responsive | Inspect mobile breakpoints and principal pages | No obvious clipping; touch controls available |
| JS-001 | JavaScript | Parse application JavaScript | Syntax passes |
| ROUTE-001 | Links | Compare literal links/actions to route inventory | No unresolved internal literal route |
| HTTP-001 | Errors | Exercise smoke-test endpoints | No HTTP 500 |
| HTTP-002 | Missing route | GET unknown URL | HTTP 404 |
| STATIC-001 | Assets | GET application CSS | HTTP 200 |
| OPS-001 | Service | Check Uvicorn systemd service | Active |
| OPS-002 | Proxy | Check Apache service and public HTTPS | Active and HTTP 200 |
| OPS-003 | Logs | Review recent service errors | No unexplained traceback/HTTP 500 |
| SEC-001 | Headers | Inspect HTTPS response headers | HSTS, frame, content-type, referrer and permissions policies |
| SEC-002 | CSRF | Inspect state-changing forms/routes | CSRF protection present |
| DEP-001 | Dependencies | Compare imports with requirements | Runtime dependencies reproducible |

## Execution Commands

```bash
python -m py_compile app/main.py app/models.py app/security.py app/config.py
node --check app/static/js/app.js
TEST_CREDENTIAL_FILE=/secure/path/to/credentials scripts/messis_uat_smoke_test.sh
```

Legacy regression scripts must never run against production. Set an isolated `DATABASE_URL`, initialize schema and seed a disposable test owner first.

## Exit Criteria

- All planned areas have an evidence-backed status.
- Every failure is recorded in `docs/DEFECT_REGISTER.md` with severity and recommended patch grouping.
- No production record is created, changed, or deleted by UAT.
- No defect is fixed during `PATCH-UAT-001`.
