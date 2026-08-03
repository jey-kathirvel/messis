import shutil
import secrets
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from pathlib import Path
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request as URLRequest
from urllib.request import urlopen

from secrets import compare_digest
from urllib.parse import quote, urlsplit

from fastapi import Depends, FastAPI, Form, HTTPException, Request, File, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import AuditLog, Buyer, CoconutTree, Expense, ExpenseCategory, Farm, HarvestCycle, HarvestRecord, Sale, SalePayment, User, Vendor
from app.security import hash_passcode, valid_passcode, verify_passcode
from app.version import APP_VERSION, RELEASE_NAME

BASE_DIR = Path(__file__).resolve().parent
settings = get_settings()

app = FastAPI(title="Messis AI", version=APP_VERSION)

app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_max_age_seconds,
    same_site="lax",
    https_only=settings.app_env == "production",
)

app.mount(
    "/static",
    StaticFiles(directory=BASE_DIR / "static"),
    name="static",
)

templates = Jinja2Templates(directory=BASE_DIR / "templates")

SAFE_HTTP_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}


def normalize_origin(value: str) -> str | None:
    try:
        parsed = urlsplit(value.strip())
    except ValueError:
        return None

    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None

    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


def csrf_request_allowed(
    method: str,
    scheme: str,
    host: str,
    headers,
) -> bool:
    if method.upper() in SAFE_HTTP_METHODS:
        return True

    if settings.app_env != "production":
        return True

    fetch_site = headers.get("sec-fetch-site", "").lower()
    if fetch_site == "cross-site":
        return False

    expected_origins = {
        f"{scheme.lower()}://{host.lower()}",
        *(
            origin
            for item in settings.csrf_trusted_origins.split(",")
            if (origin := normalize_origin(item))
        ),
    }

    origin = headers.get("origin")
    if origin:
        return normalize_origin(origin) in expected_origins

    referer = headers.get("referer")
    if referer:
        return normalize_origin(referer) in expected_origins

    # Custom headers require a browser CORS preflight and are suitable for
    # trusted CLI/API clients that do not send Origin or Referer.
    return headers.get("x-messis-csrf") == "1"


@app.middleware("http")
async def enforce_csrf(request: Request, call_next):
    if not csrf_request_allowed(
        request.method,
        request.url.scheme,
        request.headers.get("host", ""),
        request.headers,
    ):
        return PlainTextResponse(
            "Cross-site request blocked.",
            status_code=403,
        )

    return await call_next(request)


@app.on_event("startup")
def startup() -> None:
    Base.metadata.create_all(bind=engine)


def audit(
    db: Session,
    request: Request,
    event: str,
    owner_id: int | None = None,
    detail: str | None = None,
) -> None:
    forwarded_for = request.headers.get("x-forwarded-for")

    if forwarded_for:
        ip_address = forwarded_for.split(",")[0].strip()
    elif request.client:
        ip_address = request.client.host
    else:
        ip_address = None

    db.add(
        AuditLog(
            owner_id=owner_id,
            event_type=event,
            ip_address=ip_address,
            detail=detail,
        )
    )


def current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    user_id = request.session.get("user_id")

    if not isinstance(user_id, int):
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    user = db.get(User, user_id)

    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(
            status_code=401,
            detail="Authentication required",
        )

    return user


def normalize_optional_text(value: str | None) -> str | None:
    if value is None:
        return None

    normalized = value.strip()
    return normalized or None


def parse_acreage(value: str) -> tuple[Decimal | None, str | None]:
    normalized = value.strip()

    if not normalized:
        return None, None

    try:
        acreage = Decimal(normalized)
    except InvalidOperation:
        return None, "Acreage must be a valid number."

    if not acreage.is_finite():
        return None, "Acreage must be a valid number."

    if acreage < 0:
        return None, "Acreage cannot be negative."

    if acreage > Decimal("1000000"):
        return None, "Acreage exceeds the supported limit."

    return acreage, None


def validate_farm_form(
    name: str,
    location: str,
    acreage: str,
    total_trees: int,
    notes: str,
) -> tuple[dict[str, str], Decimal | None]:
    errors: dict[str, str] = {}

    normalized_name = name.strip()
    normalized_location = location.strip()
    normalized_notes = notes.strip()

    if not normalized_name:
        errors["name"] = "Farm name is required."
    elif len(normalized_name) > 150:
        errors["name"] = "Farm name cannot exceed 150 characters."

    if len(normalized_location) > 255:
        errors["location"] = "Location cannot exceed 255 characters."

    parsed_acreage, acreage_error = parse_acreage(acreage)

    if acreage_error:
        errors["acreage"] = acreage_error

    if total_trees < 0:
        errors["total_trees"] = "Total trees cannot be negative."
    elif total_trees > 10_000_000:
        errors["total_trees"] = "Total trees exceeds the supported limit."

    if len(normalized_notes) > 5000:
        errors["notes"] = "Notes cannot exceed 5000 characters."

    return errors, parsed_acreage


@app.exception_handler(401)
def authentication_error(
    request: Request,
    exc: HTTPException,
) -> RedirectResponse:
    return RedirectResponse(
        url="/?error=" + quote("Please sign in to continue."),
        status_code=303,
    )



# PATCH-AUTH-003A.1: SECURE LOGOUT BACKEND


@app.post(
    "/logout",
    include_in_schema=False,
)
def secure_logout(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    session_user_id = request.session.get(
        "user_id"
    )

    if isinstance(session_user_id, int):
        try:
            audit(
                db,
                request,
                "user_logged_out",
                session_user_id,
                "User ended the authenticated session.",
            )

            db.commit()
        except SQLAlchemyError:
            db.rollback()

    request.session.clear()

    response = RedirectResponse(
        url="/?success="
        + quote(
            "You have been logged out securely."
        ),
        status_code=303,
    )

    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
        secure=(
            settings.app_env == "production"
        ),
        httponly=True,
        samesite="lax",
    )

    response.headers[
        "Cache-Control"
    ] = (
        "no-store, no-cache, must-revalidate, "
        "max-age=0"
    )

    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    response.headers["Clear-Site-Data"] = (
        '"cache"'
    )

    return response


@app.get(
    "/favicon.ico",
    include_in_schema=False,
)
def favicon() -> FileResponse:
    return FileResponse(
        BASE_DIR / "static" / "favicon.svg",
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=86400",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.head(
    "/favicon.ico",
    include_in_schema=False,
)
def favicon_head() -> Response:
    return Response(
        status_code=200,
        media_type="image/svg+xml",
        headers={
            "Cache-Control": "public, max-age=86400",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.head(
    "/",
    include_in_schema=False,
)
def login_head() -> Response:
    return Response(
        status_code=200,
        headers={
            "Cache-Control": "no-store",
        },
    )


@app.exception_handler(404)
def not_found_error(
    request: Request,
    exc: HTTPException,
) -> HTMLResponse:
    del exc

    return templates.TemplateResponse(
        request=request,
        name="errors/404.html",
        context={},
        status_code=404,
        headers={
            "Cache-Control": "no-store",
        },
    )


@app.exception_handler(500)
def internal_server_error(
    request: Request,
    exc: Exception,
) -> HTMLResponse:
    del exc

    return templates.TemplateResponse(
        request=request,
        name="errors/500.html",
        context={},
        status_code=500,
        headers={
            "Cache-Control": "no-store",
        },
    )


@app.get("/health", response_class=JSONResponse)
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "application": "Messis AI",
        "subtitle": "Smart Agriculture Management System",
        "version": APP_VERSION,
        "release": RELEASE_NAME,
        "database": "connected",
        "authentication": "enabled",
    }


@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse(
            "/dashboard",
            status_code=303,
        )

    return templates.TemplateResponse(
        request=request,
        name="auth/login.html",
        context={
            "page_title": "Secure Login",
            "error_message": request.query_params.get("error"),
            "success_message": request.query_params.get("success"),
        },
    )


@app.get("/auth/set-passcode", response_class=HTMLResponse)
def set_passcode_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)

    return templates.TemplateResponse(
        request=request,
        name="auth/set_passcode.html",
        context={
            "error_message": request.query_params.get("error"),
            "form_values": {},
        },
    )


@app.post("/auth/set-passcode", response_class=HTMLResponse)
def set_passcode(
    request: Request,
    username: str = Form(...),
    mobile_number: str = Form(...),
    passcode: str = Form(...),
    confirm_passcode: str = Form(...),
    registration_code: str = Form(""),
    db: Session = Depends(get_db),
):
    normalized_username = username.strip()
    normalized_mobile = "".join(mobile_number.split())
    normalized_registration_code = (
        registration_code.strip()
    )
    client_key = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "unknown")
    )
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=settings.signup_window_seconds)
    recent_attempt_count = db.scalar(
        select(func.count(AuditLog.id)).where(
            AuditLog.event_type == "account_registration_rejected",
            AuditLog.ip_address == client_key,
            AuditLog.created_at >= window_start,
        )
    ) or 0
    form_values = {
        "username": normalized_username,
        "mobile_number": normalized_mobile,
    }

    error_message = None
    error_status = 400
    if recent_attempt_count >= settings.signup_max_attempts:
        error_message = "Too many registration attempts. Try again later."
        error_status = 429
    # PATCH-AUTH-003B.1: OPTIONAL REGISTRATION CODE
    elif (
        normalized_registration_code
        and (
            not settings.signup_access_code
            or not compare_digest(
                normalized_registration_code,
                settings.signup_access_code,
            )
        )
    ):
        audit(
            db,
            request,
            "account_registration_rejected",
            detail="Invalid registration code",
        )
        db.commit()
        error_message = "Invalid registration code."
    elif not normalized_username:
        error_message = "Username is required."
    elif len(normalized_username) > 50:
        error_message = "Username cannot exceed 50 characters."
    elif not normalized_mobile.isdigit() or not 10 <= len(normalized_mobile) <= 15:
        error_message = "Mobile number must contain 10 to 15 digits."
    elif not valid_passcode(passcode):
        error_message = "Passcode must contain exactly six digits."
    elif passcode != confirm_passcode:
        error_message = "Passcodes do not match."
    elif db.scalar(
        select(User.id).where(
            or_(
                User.user_id == normalized_username,
                User.mobile_number == normalized_username,
                User.user_id == normalized_mobile,
                User.mobile_number == normalized_mobile,
            )
        )
    ):
        error_message = "Username or mobile number is already registered."

    if error_message:
        return templates.TemplateResponse(
            request=request,
            name="auth/set_passcode.html",
            context={
                "error_message": error_message,
                "form_values": form_values,
            },
            status_code=error_status,
        )

    user = User(
        user_id=normalized_username,
        mobile_number=normalized_mobile,
        display_name=normalized_username,
        passcode_hash=hash_passcode(passcode),
        role="owner",
        is_active=True,
    )
    db.add(user)

    try:
        db.flush()
        audit(db, request, "account_created", user.id)
        db.commit()
    except IntegrityError:
        db.rollback()
        return templates.TemplateResponse(
            request=request,
            name="auth/set_passcode.html",
            context={
                "error_message": (
                    "Username or mobile number is already registered."
                ),
                "form_values": form_values,
            },
            status_code=409,
        )

    return RedirectResponse(
        "/?success=" + quote("Passcode set. You can now sign in."),
        status_code=303,
    )


@app.post("/auth/login")
def login(
    request: Request,
    user_id: str = Form(...),
    passcode: str = Form(...),
    db: Session = Depends(get_db),
):
    normalized_user_id = user_id.strip()

    if not valid_passcode(passcode):
        return RedirectResponse(
            "/?error="
            + quote("Passcode must contain exactly six digits."),
            status_code=303,
        )

    user = db.scalar(
        select(User).where(
            or_(
                User.user_id == normalized_user_id,
                User.mobile_number == normalized_user_id,
            )
        )
    )

    now = datetime.now(timezone.utc)

    if not user or not user.is_active:
        audit(
            db,
            request,
            "login_failed",
            detail="Unknown or inactive account",
        )
        db.commit()

        return RedirectResponse(
            "/?error=" + quote("Invalid User ID or passcode."),
            status_code=303,
        )

    if user.locked_until:
        locked_until = user.locked_until

        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)

        if locked_until > now:
            return RedirectResponse(
                "/?error="
                + quote("Account temporarily locked. Try again later."),
                status_code=303,
            )

        user.failed_attempts = 0
        user.locked_until = None

    if not verify_passcode(user.passcode_hash, passcode):
        user.failed_attempts += 1

        if user.failed_attempts >= settings.login_max_attempts:
            user.locked_until = now + timedelta(
                minutes=settings.login_lock_minutes
            )

        audit(
            db,
            request,
            "login_failed",
            user.id,
            f"Attempt {user.failed_attempts}",
        )

        db.commit()

        message = (
            f"Too many attempts. Account locked for "
            f"{settings.login_lock_minutes} minutes."
            if user.locked_until
            else "Invalid User ID or passcode."
        )

        return RedirectResponse(
            "/?error=" + quote(message),
            status_code=303,
        )

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    audit(
        db,
        request,
        "login_success",
        user.id,
    )

    db.commit()

    request.session.clear()
    request.session.update(
        {
            "user_id": user.id,
            "owner_id": user.id,
            "role": user.role,
        }
    )

    return RedirectResponse(
        "/dashboard",
        status_code=303,
    )


@app.post("/auth/logout")
def logout(
    request: Request,
    db: Session = Depends(get_db),
):
    owner_id = request.session.get("owner_id")

    if isinstance(owner_id, int):
        audit(
            db,
            request,
            "logout",
            owner_id,
        )
        db.commit()

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303,
    )


@app.get("/dashboard", response_class=HTMLResponse)
@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
def dashboard(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return business_dashboard_page(
        request=request,
        farm_id=farm_id,
        date_from=date_from,
        date_to=date_to,
        user=user,
        db=db,
    )


@app.get("/farms", response_class=HTMLResponse)
def farm_list(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(Farm.created_at.desc(), Farm.id.desc())
    ).all()

    farm_count = len(farms)

    total_trees = sum(
        int(farm.total_trees or 0)
        for farm in farms
    )

    total_acreage = sum(
        (
            Decimal(str(farm.acreage))
            if farm.acreage is not None
            else Decimal("0")
        )
        for farm in farms
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/list.html",
        context={
            "page_title": "Farms",
            "current_user": user,
            "farms": farms,
            "farm_count": farm_count,
            "total_trees": total_trees,
            "total_acreage": total_acreage,
            "success_message": request.query_params.get("success"),
            "error_message": request.query_params.get("error"),
        },
    )


@app.get("/farms/new", response_class=HTMLResponse)
def farm_create_page(
    request: Request,
    user: User = Depends(current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="farms/form.html",
        context={
            "page_title": "Add Farm",
            "current_user": user,
            "form_action": "/farms/new",
            "submit_label": "Create Farm",
            "farm": None,
            "form_data": {
                "name": "",
                "location": "",
                "acreage": "",
                "total_trees": "0",
                "notes": "",
            },
            "errors": {},
        },
    )


@app.post("/farms/new", response_class=HTMLResponse)
def farm_create(
    request: Request,
    name: str = Form(...),
    location: str = Form(""),
    acreage: str = Form(""),
    total_trees: int = Form(0),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    errors, parsed_acreage = validate_farm_form(
        name=name,
        location=location,
        acreage=acreage,
        total_trees=total_trees,
        notes=notes,
    )

    form_data = {
        "name": name,
        "location": location,
        "acreage": acreage,
        "total_trees": str(total_trees),
        "notes": notes,
    }

    if errors:
        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Add Farm",
                "current_user": user,
                "form_action": "/farms/new",
                "submit_label": "Create Farm",
                "farm": None,
                "form_data": form_data,
                "errors": errors,
            },
            status_code=422,
        )

    duplicate_farm = db.scalar(
        select(Farm).where(
            Farm.owner_id == user.id,
            func.lower(Farm.name) == name.strip().lower(),
        )
    )

    if duplicate_farm:
        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Add Farm",
                "current_user": user,
                "form_action": "/farms/new",
                "submit_label": "Create Farm",
                "farm": None,
                "form_data": form_data,
                "errors": {
                    "name": "A farm with this name already exists."
                },
            },
            status_code=409,
        )

    farm = Farm(
        owner_id=user.id,
        name=name.strip(),
        location=normalize_optional_text(location),
        acreage=parsed_acreage,
        total_trees=total_trees,
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(farm)
        db.flush()

        audit(
            db,
            request,
            "farm_created",
            user.id,
            (
                f"Farm ID: {farm.id}; "
                f"Name: {farm.name}; "
                f"Trees: {farm.total_trees}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Add Farm",
                "current_user": user,
                "form_action": "/farms/new",
                "submit_label": "Create Farm",
                "farm": None,
                "form_data": form_data,
                "errors": {
                    "form": (
                        "Unable to create the farm. "
                        "Please try again."
                    )
                },
            },
            status_code=500,
        )

    return RedirectResponse(
        "/farms?success="
        + quote(f"{farm.name} was created successfully."),
        status_code=303,
    )


def get_owned_farm(
    farm_id: int,
    user: User,
    db: Session,
) -> Farm:
    farm = db.scalar(
        select(Farm).where(
            Farm.id == farm_id,
            Farm.owner_id == user.id,
        )
    )

    if farm is None:
        raise HTTPException(
            status_code=404,
            detail="Farm not found",
        )

    return farm


@app.get(
    "/farms/{farm_id}/edit",
    response_class=HTMLResponse,
)
def farm_edit_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = get_owned_farm(
        farm_id=farm_id,
        user=user,
        db=db,
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/form.html",
        context={
            "page_title": "Edit Farm",
            "current_user": user,
            "form_action": f"/farms/{farm.id}/edit",
            "submit_label": "Update Farm",
            "form_heading": "Edit farm",
            "form_description": (
                "Update farm identity, location, acreage, "
                "tree population and operational notes."
            ),
            "farm": farm,
            "form_data": {
                "name": farm.name or "",
                "location": farm.location or "",
                "acreage": (
                    str(farm.acreage)
                    if farm.acreage is not None
                    else ""
                ),
                "total_trees": str(farm.total_trees or 0),
                "notes": farm.notes or "",
            },
            "errors": {},
        },
    )


@app.post(
    "/farms/{farm_id}/edit",
    response_class=HTMLResponse,
)
def farm_edit(
    farm_id: int,
    request: Request,
    name: str = Form(...),
    location: str = Form(""),
    acreage: str = Form(""),
    total_trees: int = Form(0),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = get_owned_farm(
        farm_id=farm_id,
        user=user,
        db=db,
    )

    errors, parsed_acreage = validate_farm_form(
        name=name,
        location=location,
        acreage=acreage,
        total_trees=total_trees,
        notes=notes,
    )

    form_data = {
        "name": name,
        "location": location,
        "acreage": acreage,
        "total_trees": str(total_trees),
        "notes": notes,
    }

    if errors:
        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Edit Farm",
                "current_user": user,
                "form_action": f"/farms/{farm.id}/edit",
                "submit_label": "Update Farm",
                "form_heading": "Edit farm",
                "form_description": (
                    "Update farm identity, location, acreage, "
                    "tree population and operational notes."
                ),
                "farm": farm,
                "form_data": form_data,
                "errors": errors,
            },
            status_code=422,
        )

    duplicate_farm = db.scalar(
        select(Farm).where(
            Farm.owner_id == user.id,
            Farm.id != farm.id,
            func.lower(Farm.name) == name.strip().lower(),
        )
    )

    if duplicate_farm is not None:
        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Edit Farm",
                "current_user": user,
                "form_action": f"/farms/{farm.id}/edit",
                "submit_label": "Update Farm",
                "form_heading": "Edit farm",
                "form_description": (
                    "Update farm identity, location, acreage, "
                    "tree population and operational notes."
                ),
                "farm": farm,
                "form_data": form_data,
                "errors": {
                    "name": (
                        "A farm with this name already exists."
                    )
                },
            },
            status_code=409,
        )

    previous_name = farm.name
    previous_location = farm.location
    previous_acreage = farm.acreage
    previous_total_trees = farm.total_trees
    previous_notes = farm.notes

    farm.name = name.strip()
    farm.location = normalize_optional_text(location)
    farm.acreage = parsed_acreage
    farm.total_trees = total_trees
    farm.notes = normalize_optional_text(notes)

    try:
        audit(
            db,
            request,
            "farm_updated",
            user.id,
            (
                f"Farm ID: {farm.id}; "
                f"Name: {previous_name} -> {farm.name}; "
                f"Location: {previous_location} -> "
                f"{farm.location}; "
                f"Acreage: {previous_acreage} -> "
                f"{farm.acreage}; "
                f"Trees: {previous_total_trees} -> "
                f"{farm.total_trees}; "
                f"Notes changed: "
                f"{previous_notes != farm.notes}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="farms/form.html",
            context={
                "page_title": "Edit Farm",
                "current_user": user,
                "form_action": f"/farms/{farm.id}/edit",
                "submit_label": "Update Farm",
                "form_heading": "Edit farm",
                "form_description": (
                    "Update farm identity, location, acreage, "
                    "tree population and operational notes."
                ),
                "farm": farm,
                "form_data": form_data,
                "errors": {
                    "form": (
                        "Unable to update the farm. "
                        "Please try again."
                    )
                },
            },
            status_code=500,
        )

    return RedirectResponse(
        "/farms?success="
        + quote(f"{farm.name} was updated successfully."),
        status_code=303,
    )


@app.get(
    "/farms/{farm_id}/delete",
    response_class=HTMLResponse,
)
def farm_delete_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = get_owned_farm(
        farm_id=farm_id,
        user=user,
        db=db,
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/delete.html",
        context={
            "page_title": "Delete Farm",
            "current_user": user,
            "farm": farm,
        },
    )


@app.post("/farms/{farm_id}/delete")
def farm_delete(
    farm_id: int,
    request: Request,
    confirmation_name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = get_owned_farm(
        farm_id=farm_id,
        user=user,
        db=db,
    )

    if confirmation_name.strip() != farm.name:
        return templates.TemplateResponse(
            request=request,
            name="farms/delete.html",
            context={
                "page_title": "Delete Farm",
                "current_user": user,
                "farm": farm,
                "error_message": (
                    "Farm name confirmation does not match."
                ),
            },
            status_code=422,
        )

    deleted_farm_name = farm.name
    deleted_farm_id = farm.id

    try:
        audit(
            db,
            request,
            "farm_deleted",
            user.id,
            (
                f"Farm ID: {deleted_farm_id}; "
                f"Name: {deleted_farm_name}; "
                f"Location: {farm.location}; "
                f"Acreage: {farm.acreage}; "
                f"Trees: {farm.total_trees}"
            ),
        )

        db.delete(farm)
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="farms/delete.html",
            context={
                "page_title": "Delete Farm",
                "current_user": user,
                "farm": farm,
                "error_message": (
                    "Unable to delete the farm. "
                    "Please try again."
                ),
            },
            status_code=500,
        )

    return RedirectResponse(
        "/farms?success="
        + quote(
            f"{deleted_farm_name} was deleted successfully."
        ),
        status_code=303,
    )


@app.get("/farms/export.csv")
def export_farms_csv(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    import csv
    import io
    from datetime import datetime

    from fastapi.responses import StreamingResponse

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(
            func.lower(Farm.name),
            Farm.id,
        )
    ).all()

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    writer.writerow(
        [
            "Farm ID",
            "Farm Name",
            "Location",
            "Acreage",
            "Total Trees",
            "Trees Per Acre",
            "Notes",
            "Created At",
        ]
    )

    for farm in farms:
        try:
            acreage_value = (
                float(farm.acreage)
                if farm.acreage not in (None, "")
                else None
            )
        except (TypeError, ValueError):
            acreage_value = None

        total_trees = int(farm.total_trees or 0)

        trees_per_acre = (
            round(total_trees / acreage_value, 2)
            if acreage_value is not None
            and acreage_value > 0
            else ""
        )

        writer.writerow(
            [
                farm.id,
                farm.name or "",
                farm.location or "",
                farm.acreage or "",
                total_trees,
                trees_per_acre,
                farm.notes or "",
                (
                    farm.created_at.isoformat()
                    if farm.created_at is not None
                    else ""
                ),
            ]
        )

    csv_content = output.getvalue()
    output.close()

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"messis_farms_{timestamp}.csv"

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )



@app.get(
    "/farms/analytics",
    response_class=HTMLResponse,
)
def farm_analytics_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(
            func.lower(Farm.name),
            Farm.id,
        )
    ).all()

    total_farms = len(farms)
    total_trees = 0
    total_acreage = 0.0
    farms_with_acreage = 0
    location_counts: dict[str, int] = {}
    farm_chart_labels: list[str] = []
    farm_chart_trees: list[int] = []
    farm_chart_acreage: list[float] = []

    for farm in farms:
        tree_count = int(farm.total_trees or 0)
        total_trees += tree_count

        try:
            acreage_value = (
                float(farm.acreage)
                if farm.acreage not in (None, "")
                else 0.0
            )
        except (TypeError, ValueError):
            acreage_value = 0.0

        if acreage_value > 0:
            total_acreage += acreage_value
            farms_with_acreage += 1

        location_name = (
            farm.location.strip()
            if farm.location
            and farm.location.strip()
            else "Not specified"
        )

        location_counts[location_name] = (
            location_counts.get(location_name, 0) + 1
        )

        farm_chart_labels.append(farm.name)
        farm_chart_trees.append(tree_count)
        farm_chart_acreage.append(
            round(acreage_value, 2)
        )

    average_trees_per_farm = (
        round(total_trees / total_farms, 1)
        if total_farms > 0
        else 0
    )

    average_acreage = (
        round(total_acreage / farms_with_acreage, 2)
        if farms_with_acreage > 0
        else 0
    )

    trees_per_acre = (
        round(total_trees / total_acreage, 1)
        if total_acreage > 0
        else 0
    )

    locations = sorted(
        location_counts.items(),
        key=lambda item: (
            -item[1],
            item[0].lower(),
        ),
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/analytics.html",
        context={
            "page_title": "Farm Analytics",
            "current_user": user,
            "farms": farms,
            "total_farms": total_farms,
            "total_trees": total_trees,
            "total_acreage": round(total_acreage, 2),
            "average_trees_per_farm": (
                average_trees_per_farm
            ),
            "average_acreage": average_acreage,
            "trees_per_acre": trees_per_acre,
            "locations": locations,
            "farm_chart_labels": farm_chart_labels,
            "farm_chart_trees": farm_chart_trees,
            "farm_chart_acreage": farm_chart_acreage,
        },
    )



@app.get(
    "/farms/report",
    response_class=HTMLResponse,
)
def farm_portfolio_report(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from datetime import datetime

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(
            func.lower(Farm.name),
            Farm.id,
        )
    ).all()

    report_rows: list[dict[str, object]] = []
    total_trees = 0
    total_acreage = 0.0
    farms_with_acreage = 0

    for farm in farms:
        tree_count = int(farm.total_trees or 0)

        try:
            acreage_value = (
                float(farm.acreage)
                if farm.acreage not in (None, "")
                else 0.0
            )
        except (TypeError, ValueError):
            acreage_value = 0.0

        density = (
            round(tree_count / acreage_value, 1)
            if acreage_value > 0
            else None
        )

        total_trees += tree_count

        if acreage_value > 0:
            total_acreage += acreage_value
            farms_with_acreage += 1

        report_rows.append(
            {
                "farm": farm,
                "tree_count": tree_count,
                "acreage_value": round(
                    acreage_value,
                    2,
                ),
                "density": density,
            }
        )

    average_trees_per_farm = (
        round(total_trees / len(farms), 1)
        if farms
        else 0
    )

    average_acreage = (
        round(
            total_acreage / farms_with_acreage,
            2,
        )
        if farms_with_acreage > 0
        else 0
    )

    overall_density = (
        round(total_trees / total_acreage, 1)
        if total_acreage > 0
        else 0
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/report.html",
        context={
            "page_title": "Farm Portfolio Report",
            "current_user": user,
            "report_rows": report_rows,
            "generated_at": datetime.now(),
            "total_farms": len(farms),
            "total_trees": total_trees,
            "total_acreage": round(
                total_acreage,
                2,
            ),
            "average_trees_per_farm": (
                average_trees_per_farm
            ),
            "average_acreage": average_acreage,
            "overall_density": overall_density,
        },
    )



@app.get(
    "/farms/search",
    response_class=HTMLResponse,
)
def farm_search_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from sqlalchemy import or_

    search_query = (
        request.query_params.get("q", "").strip()
    )

    location_filter = (
        request.query_params
        .get("location", "")
        .strip()
    )

    sort_by = (
        request.query_params
        .get("sort", "name_asc")
        .strip()
    )

    statement = select(Farm).where(
        Farm.owner_id == user.id
    )

    if search_query:
        search_pattern = f"%{search_query}%"

        statement = statement.where(
            or_(
                Farm.name.ilike(search_pattern),
                Farm.location.ilike(search_pattern),
                Farm.notes.ilike(search_pattern),
            )
        )

    if location_filter:
        statement = statement.where(
            func.lower(Farm.location)
            == location_filter.lower()
        )

    sort_options = {
        "name_asc": (
            func.lower(Farm.name).asc(),
            Farm.id.asc(),
        ),
        "name_desc": (
            func.lower(Farm.name).desc(),
            Farm.id.desc(),
        ),
        "newest": (
            Farm.created_at.desc(),
            Farm.id.desc(),
        ),
        "oldest": (
            Farm.created_at.asc(),
            Farm.id.asc(),
        ),
        "trees_desc": (
            Farm.total_trees.desc(),
            func.lower(Farm.name).asc(),
        ),
        "trees_asc": (
            Farm.total_trees.asc(),
            func.lower(Farm.name).asc(),
        ),
        "acreage_desc": (
            Farm.acreage.desc(),
            func.lower(Farm.name).asc(),
        ),
        "acreage_asc": (
            Farm.acreage.asc(),
            func.lower(Farm.name).asc(),
        ),
    }

    selected_sort = (
        sort_by
        if sort_by in sort_options
        else "name_asc"
    )

    statement = statement.order_by(
        *sort_options[selected_sort]
    )

    farms = db.scalars(statement).all()

    all_locations = db.scalars(
        select(Farm.location)
        .where(
            Farm.owner_id == user.id,
            Farm.location.is_not(None),
            Farm.location != "",
        )
        .group_by(Farm.location)
        .order_by(Farm.location.asc())
    ).all()

    total_trees = sum(
        int(farm.total_trees or 0)
        for farm in farms
    )

    total_acreage = 0.0

    for farm in farms:
        try:
            acreage_value = float(farm.acreage or 0)
        except (TypeError, ValueError):
            acreage_value = 0.0

        total_acreage += acreage_value

    return templates.TemplateResponse(
        request=request,
        name="farms/search.html",
        context={
            "page_title": "Search Farms",
            "current_user": user,
            "farms": farms,
            "search_query": search_query,
            "location_filter": location_filter,
            "selected_sort": selected_sort,
            "locations": all_locations,
            "result_count": len(farms),
            "total_trees": total_trees,
            "total_acreage": round(
                total_acreage,
                2,
            ),
        },
    )




@app.get(
    "/farms/{farm_id}/print",
    response_class=HTMLResponse,
)
def print_farm_profile(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    from datetime import datetime

    farm = db.scalar(
        select(Farm).where(
            Farm.id == farm_id,
            Farm.owner_id == user.id,
        )
    )

    if farm is None:
        raise HTTPException(
            status_code=404,
            detail="Farm not found",
        )

    tree_count = int(farm.total_trees or 0)

    try:
        acreage_value = (
            float(farm.acreage)
            if farm.acreage not in (None, "")
            else 0.0
        )
    except (TypeError, ValueError):
        acreage_value = 0.0

    trees_per_acre = (
        round(tree_count / acreage_value, 1)
        if acreage_value > 0
        else 0
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/print.html",
        context={
            "page_title": f"{farm.name} Farm Profile",
            "current_user": user,
            "farm": farm,
            "tree_count": tree_count,
            "acreage_value": round(
                acreage_value,
                2,
            ),
            "trees_per_acre": trees_per_acre,
            "generated_at": datetime.now(),
        },
    )


@app.post(
    "/farms/{farm_id}/duplicate",
)
def duplicate_farm(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    source_farm = db.scalar(
        select(Farm).where(
            Farm.id == farm_id,
            Farm.owner_id == user.id,
        )
    )

    if source_farm is None:
        raise HTTPException(
            status_code=404,
            detail="Farm not found",
        )

    base_name = f"Copy of {source_farm.name}"
    duplicate_name = base_name
    copy_number = 2

    while db.scalar(
        select(Farm.id).where(
            Farm.owner_id == user.id,
            func.lower(Farm.name)
            == duplicate_name.lower(),
        )
    ) is not None:
        duplicate_name = (
            f"{base_name} ({copy_number})"
        )
        copy_number += 1

    duplicated_farm = Farm(
        owner_id=user.id,
        name=duplicate_name,
        location=source_farm.location,
        acreage=source_farm.acreage,
        total_trees=source_farm.total_trees,
        notes=source_farm.notes,
    )

    try:
        db.add(duplicated_farm)
        db.flush()

        audit(
            db,
            request,
            "farm_duplicated",
            user.id,
            (
                f"Source farm ID: {source_farm.id}; "
                f"Source name: {source_farm.name}; "
                f"Duplicated farm ID: {duplicated_farm.id}; "
                f"Duplicated name: {duplicated_farm.name}; "
                f"Trees: {duplicated_farm.total_trees}"
            ),
        )

        db.commit()
        db.refresh(duplicated_farm)
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                f"/farms/{source_farm.id}"
                "?error="
                + quote(
                    "Unable to duplicate the farm. "
                    "Please try again."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=f"/farms/{duplicated_farm.id}",
        status_code=303,
    )


@app.get(
    "/farms/{farm_id}",
    response_class=HTMLResponse,
)
def farm_detail_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = get_owned_farm(
        farm_id=farm_id,
        user=user,
        db=db,
    )

    return templates.TemplateResponse(
        request=request,
        name="farms/detail.html",
        context={
            "page_title": farm.name,
            "current_user": user,
            "farm": farm,
        },
    )



# PATCH-HARVEST-001B: HARVEST CYCLE BACKEND

HARVEST_STATUSES = {
    "Planned",
    "Due Soon",
    "Due",
    "Overdue",
    "In Progress",
    "Completed",
    "Cancelled",
}


def harvest_cycle_status(
    planned_date: date,
    minimum_due_date: date,
    maximum_due_date: date,
    current_date: date | None = None,
) -> str:
    today = current_date or date.today()

    if today < minimum_due_date:
        if (minimum_due_date - today).days <= 7:
            return "Due Soon"
        return "Planned"

    if minimum_due_date <= today < planned_date:
        return "Due Soon"

    if today == planned_date:
        return "Due"

    if planned_date < today <= maximum_due_date:
        return "Due"

    return "Overdue"


def next_harvest_window(
    previous_harvest_date: date,
    interval_days: int = 47,
) -> tuple[date, date, date]:
    if interval_days < 45 or interval_days > 50:
        raise ValueError(
            "Harvest interval must be between 45 and 50 days."
        )

    minimum_due = previous_harvest_date + timedelta(days=45)
    planned = previous_harvest_date + timedelta(
        days=interval_days
    )
    maximum_due = previous_harvest_date + timedelta(days=50)

    return minimum_due, planned, maximum_due


def get_owned_harvest_cycle(
    cycle_id: int,
    user: User,
    db: Session,
) -> HarvestCycle:
    cycle = db.scalar(
        select(HarvestCycle).where(
            HarvestCycle.id == cycle_id,
            HarvestCycle.owner_id == user.id,
        )
    )

    if cycle is None:
        raise HTTPException(
            status_code=404,
            detail="Harvest cycle not found.",
        )

    return cycle


@app.get(
    "/harvests",
    response_class=JSONResponse,
)
def harvest_cycle_list(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    cycles = db.scalars(
        select(HarvestCycle)
        .where(HarvestCycle.owner_id == user.id)
        .order_by(
            HarvestCycle.planned_harvest_date.asc(),
            HarvestCycle.id.desc(),
        )
    ).all()

    today = date.today()
    changed = False

    items = []

    for cycle in cycles:
        if cycle.status not in {
            "Completed",
            "Cancelled",
            "In Progress",
        }:
            calculated_status = harvest_cycle_status(
                planned_date=cycle.planned_harvest_date,
                minimum_due_date=cycle.minimum_due_date,
                maximum_due_date=cycle.maximum_due_date,
                current_date=today,
            )

            if cycle.status != calculated_status:
                cycle.status = calculated_status
                changed = True

        items.append(
            {
                "id": cycle.id,
                "farm_id": cycle.farm_id,
                "cycle_number": cycle.cycle_number,
                "previous_harvest_date": (
                    cycle.previous_harvest_date.isoformat()
                    if cycle.previous_harvest_date
                    else None
                ),
                "minimum_due_date": (
                    cycle.minimum_due_date.isoformat()
                ),
                "planned_harvest_date": (
                    cycle.planned_harvest_date.isoformat()
                ),
                "maximum_due_date": (
                    cycle.maximum_due_date.isoformat()
                ),
                "actual_harvest_date": (
                    cycle.actual_harvest_date.isoformat()
                    if cycle.actual_harvest_date
                    else None
                ),
                "harvest_interval_days": (
                    cycle.harvest_interval_days
                ),
                "status": cycle.status,
                "assigned_worker": cycle.assigned_worker,
                "notes": cycle.notes,
            }
        )

    if changed:
        db.commit()

    return {
        "count": len(items),
        "items": items,
    }


@app.post(
    "/farms/{farm_id}/harvests",
    response_class=JSONResponse,
)
def create_harvest_cycle(
    farm_id: int,
    request: Request,
    previous_harvest_date: date = Form(...),
    harvest_interval_days: int = Form(47),
    assigned_worker: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    if harvest_interval_days < 45 or harvest_interval_days > 50:
        raise HTTPException(
            status_code=422,
            detail=(
                "Harvest interval must be between "
                "45 and 50 days."
            ),
        )

    minimum_due, planned, maximum_due = next_harvest_window(
        previous_harvest_date=previous_harvest_date,
        interval_days=harvest_interval_days,
    )

    latest_cycle_number = db.scalar(
        select(
            func.coalesce(
                func.max(HarvestCycle.cycle_number),
                0,
            )
        ).where(
            HarvestCycle.farm_id == farm.id,
            HarvestCycle.owner_id == user.id,
        )
    ) or 0

    existing_open_cycle = db.scalar(
        select(HarvestCycle.id).where(
            HarvestCycle.farm_id == farm.id,
            HarvestCycle.owner_id == user.id,
            HarvestCycle.status.notin_(
                ["Completed", "Cancelled"]
            ),
        )
    )

    if existing_open_cycle is not None:
        raise HTTPException(
            status_code=409,
            detail=(
                "This farm already has an active "
                "harvest cycle."
            ),
        )

    cycle = HarvestCycle(
        farm_id=farm.id,
        owner_id=user.id,
        cycle_number=int(latest_cycle_number) + 1,
        previous_harvest_date=previous_harvest_date,
        minimum_due_date=minimum_due,
        planned_harvest_date=planned,
        maximum_due_date=maximum_due,
        harvest_interval_days=harvest_interval_days,
        status=harvest_cycle_status(
            planned_date=planned,
            minimum_due_date=minimum_due,
            maximum_due_date=maximum_due,
        ),
        assigned_worker=normalize_optional_text(
            assigned_worker
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(cycle)
        db.flush()

        audit(
            db,
            request,
            "harvest_cycle_created",
            user.id,
            (
                f"Harvest cycle ID: {cycle.id}; "
                f"Farm ID: {farm.id}; "
                f"Cycle: {cycle.cycle_number}; "
                f"Previous harvest: "
                f"{previous_harvest_date}; "
                f"Planned harvest: {planned}; "
                f"Window: {minimum_due} to "
                f"{maximum_due}"
            ),
        )

        db.commit()
        db.refresh(cycle)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create harvest cycle.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": cycle.id,
            "farm_id": cycle.farm_id,
            "cycle_number": cycle.cycle_number,
            "previous_harvest_date": (
                cycle.previous_harvest_date.isoformat()
            ),
            "minimum_due_date": (
                cycle.minimum_due_date.isoformat()
            ),
            "planned_harvest_date": (
                cycle.planned_harvest_date.isoformat()
            ),
            "maximum_due_date": (
                cycle.maximum_due_date.isoformat()
            ),
            "harvest_interval_days": (
                cycle.harvest_interval_days
            ),
            "status": cycle.status,
            "assigned_worker": cycle.assigned_worker,
            "notes": cycle.notes,
        },
    )


@app.get(
    "/harvests/{cycle_id}",
    response_class=JSONResponse,
)
def harvest_cycle_detail(
    cycle_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    cycle = get_owned_harvest_cycle(
        cycle_id=cycle_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=cycle.farm_id,
        owner_id=user.id,
    )

    if cycle.status not in {
        "Completed",
        "Cancelled",
        "In Progress",
    }:
        calculated_status = harvest_cycle_status(
            planned_date=cycle.planned_harvest_date,
            minimum_due_date=cycle.minimum_due_date,
            maximum_due_date=cycle.maximum_due_date,
        )

        if cycle.status != calculated_status:
            cycle.status = calculated_status
            db.commit()

    return {
        "id": cycle.id,
        "farm": {
            "id": farm.id,
            "name": farm.name,
        },
        "cycle_number": cycle.cycle_number,
        "previous_harvest_date": (
            cycle.previous_harvest_date.isoformat()
            if cycle.previous_harvest_date
            else None
        ),
        "minimum_due_date": (
            cycle.minimum_due_date.isoformat()
        ),
        "planned_harvest_date": (
            cycle.planned_harvest_date.isoformat()
        ),
        "maximum_due_date": (
            cycle.maximum_due_date.isoformat()
        ),
        "actual_harvest_date": (
            cycle.actual_harvest_date.isoformat()
            if cycle.actual_harvest_date
            else None
        ),
        "harvest_interval_days": (
            cycle.harvest_interval_days
        ),
        "status": cycle.status,
        "assigned_worker": cycle.assigned_worker,
        "notes": cycle.notes,
        "created_at": (
            cycle.created_at.isoformat()
            if cycle.created_at
            else None
        ),
        "updated_at": (
            cycle.updated_at.isoformat()
            if cycle.updated_at
            else None
        ),
    }



# PATCH-HARVEST-001C: HARVEST CYCLE UI


@app.get(
    "/harvests/manage",
    response_class=HTMLResponse,
)
def harvest_management_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    cycles = db.scalars(
        select(HarvestCycle)
        .where(HarvestCycle.owner_id == user.id)
        .order_by(
            HarvestCycle.planned_harvest_date.asc(),
            HarvestCycle.id.desc(),
        )
    ).all()

    farm_names = {
        farm.id: farm.name
        for farm in farms
    }

    today = date.today()
    changed = False
    rows = []

    for cycle in cycles:
        if cycle.status not in {
            "Completed",
            "Cancelled",
            "In Progress",
        }:
            calculated_status = harvest_cycle_status(
                cycle.planned_harvest_date,
                cycle.minimum_due_date,
                cycle.maximum_due_date,
                today,
            )

            if cycle.status != calculated_status:
                cycle.status = calculated_status
                changed = True

        rows.append(
            {
                "cycle": cycle,
                "farm_name": farm_names.get(
                    cycle.farm_id,
                    "Farm",
                ),
            }
        )

    if changed:
        db.commit()

    totals = {
        "total": len(cycles),
        "upcoming": sum(
            cycle.status in {"Planned", "Due Soon"}
            for cycle in cycles
        ),
        "due": sum(
            cycle.status == "Due"
            for cycle in cycles
        ),
        "overdue": sum(
            cycle.status == "Overdue"
            for cycle in cycles
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="harvests/list.html",
        context={
            "current_user": user,
            "farms": farms,
            "cycles": rows,
            "totals": totals,
        },
    )


@app.get(
    "/farms/{farm_id}/harvests/new",
    response_class=HTMLResponse,
)
def harvest_cycle_create_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    return templates.TemplateResponse(
        request=request,
        name="harvests/form.html",
        context={
            "current_user": user,
            "farm": farm,
            "error_message": None,
            "form_data": {
                "previous_harvest_date": "",
                "harvest_interval_days": 47,
                "assigned_worker": "",
                "notes": "",
            },
        },
    )


@app.post(
    "/farms/{farm_id}/harvests/new",
    response_class=HTMLResponse,
)
def harvest_cycle_create_html(
    farm_id: int,
    request: Request,
    previous_harvest_date: date = Form(...),
    harvest_interval_days: int = Form(47),
    assigned_worker: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    form_data = {
        "previous_harvest_date": (
            previous_harvest_date.isoformat()
        ),
        "harvest_interval_days": (
            harvest_interval_days
        ),
        "assigned_worker": assigned_worker,
        "notes": notes,
    }

    if not 45 <= harvest_interval_days <= 50:
        return templates.TemplateResponse(
            request=request,
            name="harvests/form.html",
            context={
                "current_user": user,
                "farm": farm,
                "error_message": (
                    "Harvest interval must be between "
                    "45 and 50 days."
                ),
                "form_data": form_data,
            },
            status_code=422,
        )

    open_cycle = db.scalar(
        select(HarvestCycle.id).where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.farm_id == farm.id,
            HarvestCycle.status.notin_(
                ["Completed", "Cancelled"]
            ),
        )
    )

    if open_cycle is not None:
        return templates.TemplateResponse(
            request=request,
            name="harvests/form.html",
            context={
                "current_user": user,
                "farm": farm,
                "error_message": (
                    "This farm already has an active "
                    "harvest cycle."
                ),
                "form_data": form_data,
            },
            status_code=409,
        )

    minimum_due, planned, maximum_due = (
        next_harvest_window(
            previous_harvest_date,
            harvest_interval_days,
        )
    )

    latest_number = db.scalar(
        select(
            func.coalesce(
                func.max(HarvestCycle.cycle_number),
                0,
            )
        ).where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.farm_id == farm.id,
        )
    ) or 0

    cycle = HarvestCycle(
        farm_id=farm.id,
        owner_id=user.id,
        cycle_number=int(latest_number) + 1,
        previous_harvest_date=previous_harvest_date,
        minimum_due_date=minimum_due,
        planned_harvest_date=planned,
        maximum_due_date=maximum_due,
        harvest_interval_days=harvest_interval_days,
        status=harvest_cycle_status(
            planned,
            minimum_due,
            maximum_due,
        ),
        assigned_worker=normalize_optional_text(
            assigned_worker
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(cycle)
        db.flush()

        audit(
            db,
            request,
            "harvest_cycle_created",
            user.id,
            (
                f"Harvest cycle ID: {cycle.id}; "
                f"Farm ID: {farm.id}; "
                f"Planned: {planned}"
            ),
        )

        db.commit()
        db.refresh(cycle)
    except SQLAlchemyError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name="harvests/form.html",
            context={
                "current_user": user,
                "farm": farm,
                "error_message": (
                    "Unable to create the harvest cycle."
                ),
                "form_data": form_data,
            },
            status_code=500,
        )

    return RedirectResponse(
        url=f"/harvests/{cycle.id}/view",
        status_code=303,
    )


@app.get(
    "/harvests/{cycle_id}/view",
    response_class=HTMLResponse,
)
def harvest_cycle_detail_page(
    cycle_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    cycle = get_owned_harvest_cycle(
        cycle_id=cycle_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=cycle.farm_id,
        owner_id=user.id,
    )

    if cycle.status not in {
        "Completed",
        "Cancelled",
        "In Progress",
    }:
        status = harvest_cycle_status(
            cycle.planned_harvest_date,
            cycle.minimum_due_date,
            cycle.maximum_due_date,
        )

        if cycle.status != status:
            cycle.status = status
            db.commit()

    return templates.TemplateResponse(
        request=request,
        name="harvests/detail.html",
        context={
            "current_user": user,
            "farm": farm,
            "cycle": cycle,
        },
    )



# PATCH-HARVEST-002B: HARVEST RECORDING BACKEND


def parse_non_negative_decimal(
    value: object,
    field_name: str,
) -> Decimal:
    try:
        parsed = Decimal(str(value or "0").strip())
    except (InvalidOperation, ValueError):
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} must be a valid number.",
        )

    if not parsed.is_finite() or parsed < 0:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} cannot be negative.",
        )

    return parsed.quantize(Decimal("0.01"))


def require_owned_harvest_record(
    record_id: int,
    user: User,
    db: Session,
) -> HarvestRecord:
    record = db.scalar(
        select(HarvestRecord).where(
            HarvestRecord.id == record_id,
            HarvestRecord.owner_id == user.id,
        )
    )

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Harvest record not found.",
        )

    return record


@app.get(
    "/harvest-records",
    response_class=JSONResponse,
)
def harvest_record_list(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    records = db.scalars(
        select(HarvestRecord)
        .where(HarvestRecord.owner_id == user.id)
        .order_by(
            HarvestRecord.harvest_date.desc(),
            HarvestRecord.id.desc(),
        )
    ).all()

    items = []

    for record in records:
        farm = db.scalar(
            select(Farm).where(
                Farm.id == record.farm_id,
                Farm.owner_id == user.id,
            )
        )

        items.append(
            {
                "id": record.id,
                "farm_id": record.farm_id,
                "farm_name": farm.name if farm else None,
                "harvest_cycle_id": record.harvest_cycle_id,
                "harvest_date": record.harvest_date.isoformat(),
                "trees_harvested": record.trees_harvested,
                "mature_coconuts": record.mature_coconuts,
                "tender_coconuts": record.tender_coconuts,
                "damaged_coconuts": record.damaged_coconuts,
                "total_coconuts": record.total_coconuts,
                "estimated_weight_kg": (
                    str(record.estimated_weight_kg)
                    if record.estimated_weight_kg is not None
                    else None
                ),
                "labour_count": record.labour_count,
                "total_harvest_cost": (
                    str(record.total_harvest_cost)
                ),
                "buyer_or_destination": (
                    record.buyer_or_destination
                ),
            }
        )

    return {
        "count": len(items),
        "items": items,
    }


@app.post(
    "/farms/{farm_id}/harvest-records",
    response_class=JSONResponse,
)
def create_harvest_record(
    farm_id: int,
    request: Request,
    harvest_date: date = Form(...),
    harvest_cycle_id: int | None = Form(None),
    trees_harvested: int = Form(0),
    mature_coconuts: int = Form(0),
    tender_coconuts: int = Form(0),
    damaged_coconuts: int = Form(0),
    estimated_weight_kg: str = Form(""),
    labour_count: int = Form(0),
    labour_cost: str = Form("0"),
    climbing_cost: str = Form("0"),
    transport_cost: str = Form("0"),
    other_cost: str = Form("0"),
    buyer_or_destination: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    for field_name, value in {
        "trees_harvested": trees_harvested,
        "mature_coconuts": mature_coconuts,
        "tender_coconuts": tender_coconuts,
        "damaged_coconuts": damaged_coconuts,
        "labour_count": labour_count,
    }.items():
        if value < 0:
            raise HTTPException(
                status_code=422,
                detail=f"{field_name} cannot be negative.",
            )

    if trees_harvested > int(farm.total_trees or 0):
        raise HTTPException(
            status_code=422,
            detail=(
                "Trees harvested cannot exceed "
                "the farm total tree count."
            ),
        )

    cycle = None

    if harvest_cycle_id is not None:
        cycle = db.scalar(
            select(HarvestCycle).where(
                HarvestCycle.id == harvest_cycle_id,
                HarvestCycle.farm_id == farm.id,
                HarvestCycle.owner_id == user.id,
            )
        )

        if cycle is None:
            raise HTTPException(
                status_code=404,
                detail="Harvest cycle not found.",
            )

        if cycle.status == "Cancelled":
            raise HTTPException(
                status_code=409,
                detail=(
                    "A cancelled harvest cycle "
                    "cannot be completed."
                ),
            )

    weight = (
        parse_non_negative_decimal(
            estimated_weight_kg,
            "Estimated weight",
        )
        if estimated_weight_kg.strip()
        else None
    )

    parsed_labour_cost = parse_non_negative_decimal(
        labour_cost,
        "Labour cost",
    )
    parsed_climbing_cost = parse_non_negative_decimal(
        climbing_cost,
        "Climbing cost",
    )
    parsed_transport_cost = parse_non_negative_decimal(
        transport_cost,
        "Transport cost",
    )
    parsed_other_cost = parse_non_negative_decimal(
        other_cost,
        "Other cost",
    )

    total_coconuts = (
        mature_coconuts
        + tender_coconuts
        + damaged_coconuts
    )

    total_harvest_cost = (
        parsed_labour_cost
        + parsed_climbing_cost
        + parsed_transport_cost
        + parsed_other_cost
    )

    record = HarvestRecord(
        owner_id=user.id,
        farm_id=farm.id,
        harvest_cycle_id=(
            cycle.id if cycle is not None else None
        ),
        harvest_date=harvest_date,
        trees_harvested=trees_harvested,
        mature_coconuts=mature_coconuts,
        tender_coconuts=tender_coconuts,
        damaged_coconuts=damaged_coconuts,
        total_coconuts=total_coconuts,
        estimated_weight_kg=weight,
        labour_count=labour_count,
        labour_cost=parsed_labour_cost,
        climbing_cost=parsed_climbing_cost,
        transport_cost=parsed_transport_cost,
        other_cost=parsed_other_cost,
        total_harvest_cost=total_harvest_cost,
        buyer_or_destination=normalize_optional_text(
            buyer_or_destination
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(record)
        db.flush()

        if cycle is not None:
            cycle.status = "Completed"
            cycle.actual_harvest_date = harvest_date

        audit(
            db,
            request,
            "harvest_record_created",
            user.id,
            (
                f"Harvest record ID: {record.id}; "
                f"Farm ID: {farm.id}; "
                f"Cycle ID: {record.harvest_cycle_id}; "
                f"Harvest date: {harvest_date}; "
                f"Trees: {trees_harvested}; "
                f"Total coconuts: {total_coconuts}; "
                f"Total cost: {total_harvest_cost}"
            ),
        )

        db.commit()
        db.refresh(record)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create harvest record.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": record.id,
            "farm_id": record.farm_id,
            "harvest_cycle_id": record.harvest_cycle_id,
            "harvest_date": record.harvest_date.isoformat(),
            "trees_harvested": record.trees_harvested,
            "mature_coconuts": record.mature_coconuts,
            "tender_coconuts": record.tender_coconuts,
            "damaged_coconuts": record.damaged_coconuts,
            "total_coconuts": record.total_coconuts,
            "estimated_weight_kg": (
                str(record.estimated_weight_kg)
                if record.estimated_weight_kg is not None
                else None
            ),
            "labour_count": record.labour_count,
            "labour_cost": str(record.labour_cost),
            "climbing_cost": str(record.climbing_cost),
            "transport_cost": str(record.transport_cost),
            "other_cost": str(record.other_cost),
            "total_harvest_cost": (
                str(record.total_harvest_cost)
            ),
            "buyer_or_destination": (
                record.buyer_or_destination
            ),
            "notes": record.notes,
        },
    )


@app.get(
    "/harvest-records/{record_id}",
    response_class=JSONResponse,
)
def harvest_record_detail(
    record_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    record = require_owned_harvest_record(
        record_id=record_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=record.farm_id,
        owner_id=user.id,
    )

    yield_per_tree = (
        round(
            record.total_coconuts
            / record.trees_harvested,
            2,
        )
        if record.trees_harvested > 0
        else 0
    )

    damaged_percentage = (
        round(
            record.damaged_coconuts
            / record.total_coconuts
            * 100,
            2,
        )
        if record.total_coconuts > 0
        else 0
    )

    cost_per_coconut = (
        (
            record.total_harvest_cost
            / Decimal(record.total_coconuts)
        ).quantize(Decimal("0.01"))
        if record.total_coconuts > 0
        else Decimal("0.00")
    )

    return {
        "id": record.id,
        "farm": {
            "id": farm.id,
            "name": farm.name,
        },
        "harvest_cycle_id": record.harvest_cycle_id,
        "harvest_date": record.harvest_date.isoformat(),
        "trees_harvested": record.trees_harvested,
        "mature_coconuts": record.mature_coconuts,
        "tender_coconuts": record.tender_coconuts,
        "damaged_coconuts": record.damaged_coconuts,
        "total_coconuts": record.total_coconuts,
        "estimated_weight_kg": (
            str(record.estimated_weight_kg)
            if record.estimated_weight_kg is not None
            else None
        ),
        "labour_count": record.labour_count,
        "labour_cost": str(record.labour_cost),
        "climbing_cost": str(record.climbing_cost),
        "transport_cost": str(record.transport_cost),
        "other_cost": str(record.other_cost),
        "total_harvest_cost": (
            str(record.total_harvest_cost)
        ),
        "buyer_or_destination": (
            record.buyer_or_destination
        ),
        "notes": record.notes,
        "metrics": {
            "yield_per_tree": yield_per_tree,
            "damaged_percentage": damaged_percentage,
            "cost_per_coconut": str(cost_per_coconut),
        },
    }



# PATCH-HARVEST-002C: HARVEST RECORDING UI


@app.get(
    "/harvest-records/manage",
    response_class=HTMLResponse,
)
def harvest_record_management_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    records = db.scalars(
        select(HarvestRecord)
        .where(HarvestRecord.owner_id == user.id)
        .order_by(
            HarvestRecord.harvest_date.desc(),
            HarvestRecord.id.desc(),
        )
    ).all()

    farm_names = {
        farm.id: farm.name
        for farm in farms
    }

    rows = [
        {
            "record": record,
            "farm_name": farm_names.get(
                record.farm_id,
                "Farm",
            ),
        }
        for record in records
    ]

    totals = {
        "records": len(records),
        "coconuts": sum(
            int(record.total_coconuts or 0)
            for record in records
        ),
        "trees": sum(
            int(record.trees_harvested or 0)
            for record in records
        ),
        "cost": sum(
            Decimal(record.total_harvest_cost or 0)
            for record in records
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="harvest_records/list.html",
        context={
            "current_user": user,
            "farms": farms,
            "records": rows,
            "totals": totals,
        },
    )


@app.get(
    "/farms/{farm_id}/harvest-records/new",
    response_class=HTMLResponse,
)
def harvest_record_create_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    cycles = db.scalars(
        select(HarvestCycle)
        .where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.farm_id == farm.id,
            HarvestCycle.status.notin_(
                ["Completed", "Cancelled"]
            ),
        )
        .order_by(
            HarvestCycle.planned_harvest_date.asc()
        )
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="harvest_records/form.html",
        context={
            "current_user": user,
            "farm": farm,
            "cycles": cycles,
            "error_message": None,
            "form_data": {
                "harvest_date": date.today().isoformat(),
                "harvest_cycle_id": "",
                "trees_harvested": 0,
                "mature_coconuts": 0,
                "tender_coconuts": 0,
                "damaged_coconuts": 0,
                "estimated_weight_kg": "",
                "labour_count": 0,
                "labour_cost": "0",
                "climbing_cost": "0",
                "transport_cost": "0",
                "other_cost": "0",
                "buyer_or_destination": "",
                "notes": "",
            },
        },
    )


@app.post(
    "/farms/{farm_id}/harvest-records/new",
    response_class=HTMLResponse,
)
def harvest_record_create_html(
    farm_id: int,
    request: Request,
    harvest_date: date = Form(...),
    harvest_cycle_id: str = Form(""),
    trees_harvested: int = Form(0),
    mature_coconuts: int = Form(0),
    tender_coconuts: int = Form(0),
    damaged_coconuts: int = Form(0),
    estimated_weight_kg: str = Form(""),
    labour_count: int = Form(0),
    labour_cost: str = Form("0"),
    climbing_cost: str = Form("0"),
    transport_cost: str = Form("0"),
    other_cost: str = Form("0"),
    buyer_or_destination: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    cycles = db.scalars(
        select(HarvestCycle)
        .where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.farm_id == farm.id,
            HarvestCycle.status.notin_(
                ["Completed", "Cancelled"]
            ),
        )
        .order_by(
            HarvestCycle.planned_harvest_date.asc()
        )
    ).all()

    form_data = {
        "harvest_date": harvest_date.isoformat(),
        "harvest_cycle_id": harvest_cycle_id,
        "trees_harvested": trees_harvested,
        "mature_coconuts": mature_coconuts,
        "tender_coconuts": tender_coconuts,
        "damaged_coconuts": damaged_coconuts,
        "estimated_weight_kg": estimated_weight_kg,
        "labour_count": labour_count,
        "labour_cost": labour_cost,
        "climbing_cost": climbing_cost,
        "transport_cost": transport_cost,
        "other_cost": other_cost,
        "buyer_or_destination": buyer_or_destination,
        "notes": notes,
    }

    def render_error(
        message: str,
        status_code: int = 422,
    ):
        return templates.TemplateResponse(
            request=request,
            name="harvest_records/form.html",
            context={
                "current_user": user,
                "farm": farm,
                "cycles": cycles,
                "error_message": message,
                "form_data": form_data,
            },
            status_code=status_code,
        )

    numeric_values = {
        "Trees harvested": trees_harvested,
        "Mature coconuts": mature_coconuts,
        "Tender coconuts": tender_coconuts,
        "Damaged coconuts": damaged_coconuts,
        "Labour count": labour_count,
    }

    for label, value in numeric_values.items():
        if value < 0:
            return render_error(
                f"{label} cannot be negative."
            )

    if trees_harvested > int(farm.total_trees or 0):
        return render_error(
            "Trees harvested cannot exceed the farm total."
        )

    cycle = None

    if harvest_cycle_id.strip():
        try:
            selected_cycle_id = int(
                harvest_cycle_id.strip()
            )
        except ValueError:
            return render_error(
                "Invalid harvest cycle."
            )

        cycle = db.scalar(
            select(HarvestCycle).where(
                HarvestCycle.id == selected_cycle_id,
                HarvestCycle.farm_id == farm.id,
                HarvestCycle.owner_id == user.id,
            )
        )

        if cycle is None:
            return render_error(
                "Harvest cycle not found.",
                404,
            )

    try:
        weight = (
            parse_non_negative_decimal(
                estimated_weight_kg,
                "Estimated weight",
            )
            if estimated_weight_kg.strip()
            else None
        )

        parsed_labour = parse_non_negative_decimal(
            labour_cost,
            "Labour cost",
        )
        parsed_climbing = parse_non_negative_decimal(
            climbing_cost,
            "Climbing cost",
        )
        parsed_transport = parse_non_negative_decimal(
            transport_cost,
            "Transport cost",
        )
        parsed_other = parse_non_negative_decimal(
            other_cost,
            "Other cost",
        )
    except HTTPException as exc:
        return render_error(str(exc.detail))

    total_coconuts = (
        mature_coconuts
        + tender_coconuts
        + damaged_coconuts
    )

    total_cost = (
        parsed_labour
        + parsed_climbing
        + parsed_transport
        + parsed_other
    )

    record = HarvestRecord(
        owner_id=user.id,
        farm_id=farm.id,
        harvest_cycle_id=(
            cycle.id if cycle else None
        ),
        harvest_date=harvest_date,
        trees_harvested=trees_harvested,
        mature_coconuts=mature_coconuts,
        tender_coconuts=tender_coconuts,
        damaged_coconuts=damaged_coconuts,
        total_coconuts=total_coconuts,
        estimated_weight_kg=weight,
        labour_count=labour_count,
        labour_cost=parsed_labour,
        climbing_cost=parsed_climbing,
        transport_cost=parsed_transport,
        other_cost=parsed_other,
        total_harvest_cost=total_cost,
        buyer_or_destination=normalize_optional_text(
            buyer_or_destination
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(record)
        db.flush()

        if cycle is not None:
            cycle.status = "Completed"
            cycle.actual_harvest_date = harvest_date

        audit(
            db,
            request,
            "harvest_record_created",
            user.id,
            (
                f"Harvest record ID: {record.id}; "
                f"Farm ID: {farm.id}; "
                f"Total coconuts: {total_coconuts}; "
                f"Total cost: {total_cost}"
            ),
        )

        db.commit()
        db.refresh(record)
    except SQLAlchemyError:
        db.rollback()

        return render_error(
            "Unable to save harvest record.",
            500,
        )

    return RedirectResponse(
        url=f"/harvest-records/{record.id}/view",
        status_code=303,
    )


@app.get(
    "/harvest-records/{record_id}/view",
    response_class=HTMLResponse,
)
def harvest_record_detail_page(
    record_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    record = require_owned_harvest_record(
        record_id=record_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=record.farm_id,
        owner_id=user.id,
    )

    metrics = {
        "yield_per_tree": (
            round(
                record.total_coconuts
                / record.trees_harvested,
                2,
            )
            if record.trees_harvested > 0
            else 0
        ),
        "damaged_percentage": (
            round(
                record.damaged_coconuts
                / record.total_coconuts
                * 100,
                2,
            )
            if record.total_coconuts > 0
            else 0
        ),
        "cost_per_coconut": (
            (
                record.total_harvest_cost
                / Decimal(record.total_coconuts)
            ).quantize(Decimal("0.01"))
            if record.total_coconuts > 0
            else Decimal("0.00")
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="harvest_records/detail.html",
        context={
            "current_user": user,
            "farm": farm,
            "record": record,
            "metrics": metrics,
        },
    )



# PATCH-EXPENSE-001B: EXPENSE MANAGEMENT BACKEND

EXPENSE_PAYMENT_MODES = {
    "Cash",
    "UPI",
    "Bank Transfer",
    "Credit",
    "Other",
}


def require_owned_expense(
    expense_id: int,
    user: User,
    db: Session,
) -> Expense:
    expense = db.scalar(
        select(Expense).where(
            Expense.id == expense_id,
            Expense.owner_id == user.id,
        )
    )

    if expense is None:
        raise HTTPException(
            status_code=404,
            detail="Expense not found.",
        )

    return expense


def require_available_expense_category(
    category_id: int,
    user: User,
    db: Session,
) -> ExpenseCategory:
    category = db.scalar(
        select(ExpenseCategory).where(
            ExpenseCategory.id == category_id,
            ExpenseCategory.is_active.is_(True),
            or_(
                ExpenseCategory.owner_id.is_(None),
                ExpenseCategory.owner_id == user.id,
            ),
        )
    )

    if category is None:
        raise HTTPException(
            status_code=404,
            detail="Expense category not found.",
        )

    return category


def require_owned_vendor(
    vendor_id: int,
    user: User,
    db: Session,
) -> Vendor:
    vendor = db.scalar(
        select(Vendor).where(
            Vendor.id == vendor_id,
            Vendor.owner_id == user.id,
            Vendor.is_active.is_(True),
        )
    )

    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail="Vendor not found.",
        )

    return vendor


@app.get(
    "/expense-categories",
    response_class=JSONResponse,
)
def expense_category_list(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    categories = db.scalars(
        select(ExpenseCategory)
        .where(
            ExpenseCategory.is_active.is_(True),
            or_(
                ExpenseCategory.owner_id.is_(None),
                ExpenseCategory.owner_id == user.id,
            ),
        )
        .order_by(
            ExpenseCategory.is_system.desc(),
            func.lower(ExpenseCategory.name),
        )
    ).all()

    return {
        "count": len(categories),
        "items": [
            {
                "id": category.id,
                "name": category.name,
                "is_system": category.is_system,
            }
            for category in categories
        ],
    }


@app.post(
    "/expense-categories",
    response_class=JSONResponse,
)
def create_expense_category(
    request: Request,
    name: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_name = name.strip()

    if not normalized_name:
        raise HTTPException(
            status_code=422,
            detail="Category name is required.",
        )

    if len(normalized_name) > 100:
        raise HTTPException(
            status_code=422,
            detail="Category name cannot exceed 100 characters.",
        )

    duplicate = db.scalar(
        select(ExpenseCategory.id).where(
            ExpenseCategory.owner_id == user.id,
            func.lower(ExpenseCategory.name)
            == normalized_name.lower(),
        )
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="This expense category already exists.",
        )

    category = ExpenseCategory(
        owner_id=user.id,
        name=normalized_name,
        is_system=False,
        is_active=True,
    )

    try:
        db.add(category)
        db.flush()

        audit(
            db,
            request,
            "expense_category_created",
            user.id,
            (
                f"Category ID: {category.id}; "
                f"Name: {category.name}"
            ),
        )

        db.commit()
        db.refresh(category)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create expense category.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": category.id,
            "name": category.name,
            "is_system": category.is_system,
        },
    )


@app.get(
    "/vendors",
    response_class=JSONResponse,
)
def vendor_list(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vendors = db.scalars(
        select(Vendor)
        .where(
            Vendor.owner_id == user.id,
            Vendor.is_active.is_(True),
        )
        .order_by(func.lower(Vendor.name))
    ).all()

    return {
        "count": len(vendors),
        "items": [
            {
                "id": vendor.id,
                "name": vendor.name,
                "mobile_number": vendor.mobile_number,
                "email": vendor.email,
                "address": vendor.address,
                "notes": vendor.notes,
            }
            for vendor in vendors
        ],
    }


@app.post(
    "/vendors",
    response_class=JSONResponse,
)
def create_vendor(
    request: Request,
    name: str = Form(...),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_name = name.strip()

    if not normalized_name:
        raise HTTPException(
            status_code=422,
            detail="Vendor name is required.",
        )

    if len(normalized_name) > 160:
        raise HTTPException(
            status_code=422,
            detail="Vendor name cannot exceed 160 characters.",
        )

    duplicate = db.scalar(
        select(Vendor.id).where(
            Vendor.owner_id == user.id,
            func.lower(Vendor.name) == normalized_name.lower(),
        )
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="This vendor already exists.",
        )

    vendor = Vendor(
        owner_id=user.id,
        name=normalized_name,
        mobile_number=normalize_optional_text(
            mobile_number
        ),
        email=normalize_optional_text(email),
        address=normalize_optional_text(address),
        notes=normalize_optional_text(notes),
        is_active=True,
    )

    try:
        db.add(vendor)
        db.flush()

        audit(
            db,
            request,
            "vendor_created",
            user.id,
            (
                f"Vendor ID: {vendor.id}; "
                f"Name: {vendor.name}"
            ),
        )

        db.commit()
        db.refresh(vendor)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create vendor.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": vendor.id,
            "name": vendor.name,
            "mobile_number": vendor.mobile_number,
            "email": vendor.email,
            "address": vendor.address,
            "notes": vendor.notes,
        },
    )


@app.get(
    "/expenses",
    response_class=JSONResponse,
)
def expense_list(
    farm_id: int | None = None,
    category_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    statement = select(Expense).where(
        Expense.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Expense.farm_id == farm_id
        )

    if category_id is not None:
        require_available_expense_category(
            category_id=category_id,
            user=user,
            db=db,
        )
        statement = statement.where(
            Expense.category_id == category_id
        )

    if date_from is not None:
        statement = statement.where(
            Expense.expense_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            Expense.expense_date <= date_to
        )

    expenses = db.scalars(
        statement.order_by(
            Expense.expense_date.desc(),
            Expense.id.desc(),
        )
    ).all()

    category_ids = {
        expense.category_id
        for expense in expenses
    }

    vendor_ids = {
        expense.vendor_id
        for expense in expenses
        if expense.vendor_id is not None
    }

    farm_ids = {
        expense.farm_id
        for expense in expenses
        if expense.farm_id is not None
    }

    categories = {
        category.id: category.name
        for category in db.scalars(
            select(ExpenseCategory).where(
                ExpenseCategory.id.in_(category_ids)
            )
        ).all()
    } if category_ids else {}

    vendors = {
        vendor.id: vendor.name
        for vendor in db.scalars(
            select(Vendor).where(
                Vendor.id.in_(vendor_ids),
                Vendor.owner_id == user.id,
            )
        ).all()
    } if vendor_ids else {}

    farms = {
        farm.id: farm.name
        for farm in db.scalars(
            select(Farm).where(
                Farm.id.in_(farm_ids),
                Farm.owner_id == user.id,
            )
        ).all()
    } if farm_ids else {}

    total_amount = sum(
        Decimal(expense.amount or 0)
        for expense in expenses
    )

    return {
        "count": len(expenses),
        "total_amount": str(total_amount),
        "items": [
            {
                "id": expense.id,
                "farm_id": expense.farm_id,
                "farm_name": farms.get(expense.farm_id),
                "category_id": expense.category_id,
                "category_name": categories.get(
                    expense.category_id
                ),
                "vendor_id": expense.vendor_id,
                "vendor_name": vendors.get(
                    expense.vendor_id
                ),
                "expense_date": (
                    expense.expense_date.isoformat()
                ),
                "description": expense.description,
                "amount": str(expense.amount),
                "payment_mode": expense.payment_mode,
                "reference_number": (
                    expense.reference_number
                ),
                "is_recurring": expense.is_recurring,
                "notes": expense.notes,
            }
            for expense in expenses
        ],
    }


@app.post(
    "/expenses",
    response_class=JSONResponse,
)
def create_expense(
    request: Request,
    expense_date: date = Form(...),
    category_id: int = Form(...),
    description: str = Form(...),
    amount: str = Form(...),
    farm_id: int | None = Form(None),
    vendor_id: int | None = Form(None),
    payment_mode: str = Form("Cash"),
    reference_number: str = Form(""),
    is_recurring: bool = Form(False),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_description = description.strip()

    if not normalized_description:
        raise HTTPException(
            status_code=422,
            detail="Expense description is required.",
        )

    if len(normalized_description) > 255:
        raise HTTPException(
            status_code=422,
            detail=(
                "Expense description cannot exceed "
                "255 characters."
            ),
        )

    parsed_amount = parse_non_negative_decimal(
        amount,
        "Expense amount",
    )

    if parsed_amount <= 0:
        raise HTTPException(
            status_code=422,
            detail="Expense amount must be greater than zero.",
        )

    if payment_mode not in EXPENSE_PAYMENT_MODES:
        raise HTTPException(
            status_code=422,
            detail="Invalid payment mode.",
        )

    category = require_available_expense_category(
        category_id=category_id,
        user=user,
        db=db,
    )

    farm = None

    if farm_id is not None:
        farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

    vendor = None

    if vendor_id is not None:
        vendor = require_owned_vendor(
            vendor_id=vendor_id,
            user=user,
            db=db,
        )

    expense = Expense(
        owner_id=user.id,
        farm_id=farm.id if farm else None,
        category_id=category.id,
        vendor_id=vendor.id if vendor else None,
        expense_date=expense_date,
        description=normalized_description,
        amount=parsed_amount,
        payment_mode=payment_mode,
        reference_number=normalize_optional_text(
            reference_number
        ),
        is_recurring=bool(is_recurring),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(expense)
        db.flush()

        audit(
            db,
            request,
            "expense_created",
            user.id,
            (
                f"Expense ID: {expense.id}; "
                f"Date: {expense.expense_date}; "
                f"Category: {category.name}; "
                f"Farm ID: {expense.farm_id}; "
                f"Amount: {expense.amount}; "
                f"Payment mode: {expense.payment_mode}"
            ),
        )

        db.commit()
        db.refresh(expense)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create expense.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": expense.id,
            "expense_date": expense.expense_date.isoformat(),
            "farm_id": expense.farm_id,
            "category_id": expense.category_id,
            "category_name": category.name,
            "vendor_id": expense.vendor_id,
            "description": expense.description,
            "amount": str(expense.amount),
            "payment_mode": expense.payment_mode,
            "reference_number": (
                expense.reference_number
            ),
            "is_recurring": expense.is_recurring,
            "notes": expense.notes,
        },
    )


@app.get(
    "/expenses/{expense_id}",
    response_class=JSONResponse,
)
def expense_detail(
    expense_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    expense = require_owned_expense(
        expense_id=expense_id,
        user=user,
        db=db,
    )

    category = require_available_expense_category(
        category_id=expense.category_id,
        user=user,
        db=db,
    )

    farm = None

    if expense.farm_id is not None:
        farm = require_owned_farm(
            db=db,
            farm_id=expense.farm_id,
            owner_id=user.id,
        )

    vendor = None

    if expense.vendor_id is not None:
        vendor = db.scalar(
            select(Vendor).where(
                Vendor.id == expense.vendor_id,
                Vendor.owner_id == user.id,
            )
        )

    return {
        "id": expense.id,
        "expense_date": expense.expense_date.isoformat(),
        "farm": (
            {
                "id": farm.id,
                "name": farm.name,
            }
            if farm
            else None
        ),
        "category": {
            "id": category.id,
            "name": category.name,
        },
        "vendor": (
            {
                "id": vendor.id,
                "name": vendor.name,
            }
            if vendor
            else None
        ),
        "description": expense.description,
        "amount": str(expense.amount),
        "payment_mode": expense.payment_mode,
        "reference_number": expense.reference_number,
        "is_recurring": expense.is_recurring,
        "notes": expense.notes,
        "created_at": (
            expense.created_at.isoformat()
            if expense.created_at
            else None
        ),
        "updated_at": (
            expense.updated_at.isoformat()
            if expense.updated_at
            else None
        ),
    }


@app.post(
    "/expenses/{expense_id}/delete",
    response_class=JSONResponse,
)
def delete_expense(
    expense_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    expense = require_owned_expense(
        expense_id=expense_id,
        user=user,
        db=db,
    )

    deleted_detail = (
        f"Expense ID: {expense.id}; "
        f"Date: {expense.expense_date}; "
        f"Farm ID: {expense.farm_id}; "
        f"Amount: {expense.amount}; "
        f"Description: {expense.description}"
    )

    try:
        audit(
            db,
            request,
            "expense_deleted",
            user.id,
            deleted_detail,
        )

        db.delete(expense)
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to delete expense.",
        )

    return {
        "status": "deleted",
        "expense_id": expense_id,
    }



# PATCH-EXPENSE-001C: EXPENSE MANAGEMENT UI


@app.get(
    "/expenses/manage",
    response_class=HTMLResponse,
)
def expense_management_page(
    request: Request,
    farm_id: int | None = None,
    category_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    categories = db.scalars(
        select(ExpenseCategory)
        .where(
            ExpenseCategory.is_active.is_(True),
            or_(
                ExpenseCategory.owner_id.is_(None),
                ExpenseCategory.owner_id == user.id,
            ),
        )
        .order_by(func.lower(ExpenseCategory.name))
    ).all()

    statement = select(Expense).where(
        Expense.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Expense.farm_id == farm_id
        )

    if category_id is not None:
        require_available_expense_category(
            category_id=category_id,
            user=user,
            db=db,
        )
        statement = statement.where(
            Expense.category_id == category_id
        )

    if date_from is not None:
        statement = statement.where(
            Expense.expense_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            Expense.expense_date <= date_to
        )

    expenses = db.scalars(
        statement.order_by(
            Expense.expense_date.desc(),
            Expense.id.desc(),
        )
    ).all()

    farm_names = {
        farm.id: farm.name
        for farm in farms
    }

    category_names = {
        category.id: category.name
        for category in categories
    }

    vendor_ids = {
        expense.vendor_id
        for expense in expenses
        if expense.vendor_id is not None
    }

    vendors = {
        vendor.id: vendor.name
        for vendor in db.scalars(
            select(Vendor).where(
                Vendor.owner_id == user.id,
                Vendor.id.in_(vendor_ids),
            )
        ).all()
    } if vendor_ids else {}

    rows = [
        {
            "expense": expense,
            "farm_name": farm_names.get(expense.farm_id),
            "category_name": category_names.get(
                expense.category_id,
                "Category",
            ),
            "vendor_name": vendors.get(expense.vendor_id),
        }
        for expense in expenses
    ]

    today = date.today()
    month_start = today.replace(day=1)

    totals = {
        "count": len(expenses),
        "amount": sum(
            Decimal(expense.amount or 0)
            for expense in expenses
        ),
        "month_amount": sum(
            Decimal(expense.amount or 0)
            for expense in expenses
            if expense.expense_date >= month_start
        ),
        "recurring": sum(
            bool(expense.is_recurring)
            for expense in expenses
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="expenses/list.html",
        context={
            "current_user": user,
            "farms": farms,
            "categories": categories,
            "expenses": rows,
            "totals": totals,
            "filters": {
                "farm_id": farm_id or "",
                "category_id": category_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else ""
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else ""
                ),
            },
        },
    )


@app.get(
    "/expenses/new",
    response_class=HTMLResponse,
)
def expense_create_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    categories = db.scalars(
        select(ExpenseCategory)
        .where(
            ExpenseCategory.is_active.is_(True),
            or_(
                ExpenseCategory.owner_id.is_(None),
                ExpenseCategory.owner_id == user.id,
            ),
        )
        .order_by(func.lower(ExpenseCategory.name))
    ).all()

    vendors = db.scalars(
        select(Vendor)
        .where(
            Vendor.owner_id == user.id,
            Vendor.is_active.is_(True),
        )
        .order_by(func.lower(Vendor.name))
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="expenses/form.html",
        context={
            "current_user": user,
            "farms": farms,
            "categories": categories,
            "vendors": vendors,
            "payment_modes": sorted(
                EXPENSE_PAYMENT_MODES
            ),
            "error_message": None,
            "form_data": {
                "expense_date": date.today().isoformat(),
                "farm_id": "",
                "category_id": "",
                "custom_category_name": "",
                "vendor_name": "",
                "description": "",
                "amount": "",
                "payment_mode": "Cash",
                "reference_number": "",
                "is_recurring": False,
                "notes": "",
            },
        },
    )


@app.post(
    "/expenses/new",
    response_class=HTMLResponse,
)
def expense_create_html(
    request: Request,
    expense_date: date = Form(...),
    category_id: str = Form(...),
    custom_category_name: str = Form(""),
    description: str = Form(...),
    amount: str = Form(...),
    farm_id: str = Form(""),
    vendor_name: str = Form(""),
    payment_mode: str = Form("Cash"),
    reference_number: str = Form(""),
    is_recurring: bool = Form(False),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    categories = db.scalars(
        select(ExpenseCategory)
        .where(
            ExpenseCategory.is_active.is_(True),
            or_(
                ExpenseCategory.owner_id.is_(None),
                ExpenseCategory.owner_id == user.id,
            ),
        )
        .order_by(func.lower(ExpenseCategory.name))
    ).all()

    vendors = db.scalars(
        select(Vendor)
        .where(
            Vendor.owner_id == user.id,
            Vendor.is_active.is_(True),
        )
        .order_by(func.lower(Vendor.name))
    ).all()

    form_data = {
        "expense_date": expense_date.isoformat(),
        "farm_id": farm_id,
        "category_id": category_id,
        "custom_category_name": custom_category_name,
        "vendor_name": vendor_name,
        "description": description,
        "amount": amount,
        "payment_mode": payment_mode,
        "reference_number": reference_number,
        "is_recurring": is_recurring,
        "notes": notes,
    }

    def render_error(
        message: str,
        status_code: int = 422,
    ):
        return templates.TemplateResponse(
            request=request,
            name="expenses/form.html",
            context={
                "current_user": user,
                "farms": farms,
                "categories": categories,
                "vendors": vendors,
                "payment_modes": sorted(
                    EXPENSE_PAYMENT_MODES
                ),
                "error_message": message,
                "form_data": form_data,
            },
            status_code=status_code,
        )

    normalized_description = description.strip()

    if not normalized_description:
        return render_error(
            "Expense description is required."
        )

    try:
        parsed_amount = parse_non_negative_decimal(
            amount,
            "Expense amount",
        )
    except HTTPException as exc:
        return render_error(str(exc.detail))

    if parsed_amount <= 0:
        return render_error(
            "Expense amount must be greater than zero."
        )

    if payment_mode not in EXPENSE_PAYMENT_MODES:
        return render_error("Invalid payment mode.")

    normalized_custom_category = (
        custom_category_name.strip()
    )

    if category_id == "__other__":
        if not normalized_custom_category:
            return render_error(
                "Enter the new expense category name."
            )

        if len(normalized_custom_category) > 100:
            return render_error(
                "Category name cannot exceed 100 characters."
            )

        category = db.scalar(
            select(ExpenseCategory).where(
                ExpenseCategory.owner_id == user.id,
                func.lower(ExpenseCategory.name)
                == normalized_custom_category.lower(),
            )
        )

        if category is None:
            category = ExpenseCategory(
                owner_id=user.id,
                name=normalized_custom_category,
                is_system=False,
                is_active=True,
            )

            db.add(category)
            db.flush()

            audit(
                db,
                request,
                "expense_category_created",
                user.id,
                (
                    f"Category ID: {category.id}; "
                    f"Name: {category.name}; "
                    "Created from expense form"
                ),
            )
    else:
        try:
            selected_category_id = int(category_id)
        except (TypeError, ValueError):
            return render_error(
                "Select a valid expense category."
            )

        try:
            category = require_available_expense_category(
                category_id=selected_category_id,
                user=user,
                db=db,
            )
        except HTTPException:
            return render_error(
                "Expense category not found.",
                404,
            )

    farm = None

    if farm_id.strip():
        try:
            selected_farm_id = int(farm_id)
        except ValueError:
            return render_error("Invalid farm.")

        try:
            farm = require_owned_farm(
                db=db,
                farm_id=selected_farm_id,
                owner_id=user.id,
            )
        except HTTPException:
            return render_error("Farm not found.", 404)

    vendor = None
    normalized_vendor_name = vendor_name.strip()

    if normalized_vendor_name:
        if len(normalized_vendor_name) > 160:
            return render_error(
                "Vendor name cannot exceed 160 characters."
            )

        vendor = db.scalar(
            select(Vendor).where(
                Vendor.owner_id == user.id,
                func.lower(Vendor.name)
                == normalized_vendor_name.lower(),
            )
        )

        if vendor is None:
            vendor = Vendor(
                owner_id=user.id,
                name=normalized_vendor_name,
                is_active=True,
            )

            db.add(vendor)
            db.flush()

            audit(
                db,
                request,
                "vendor_created",
                user.id,
                (
                    f"Vendor ID: {vendor.id}; "
                    f"Name: {vendor.name}; "
                    "Created from expense form"
                ),
            )
        elif not vendor.is_active:
            vendor.is_active = True

    expense = Expense(
        owner_id=user.id,
        farm_id=farm.id if farm else None,
        category_id=category.id,
        vendor_id=vendor.id if vendor else None,
        expense_date=expense_date,
        description=normalized_description,
        amount=parsed_amount,
        payment_mode=payment_mode,
        reference_number=normalize_optional_text(
            reference_number
        ),
        is_recurring=bool(is_recurring),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(expense)
        db.flush()

        audit(
            db,
            request,
            "expense_created",
            user.id,
            (
                f"Expense ID: {expense.id}; "
                f"Date: {expense.expense_date}; "
                f"Category: {category.name}; "
                f"Amount: {expense.amount}"
            ),
        )

        db.commit()
        db.refresh(expense)
    except SQLAlchemyError:
        db.rollback()

        return render_error(
            "Unable to save expense.",
            500,
        )

    return RedirectResponse(
        url=f"/expenses/{expense.id}/view",
        status_code=303,
    )


@app.get(
    "/expenses/{expense_id}/view",
    response_class=HTMLResponse,
)
def expense_detail_page(
    expense_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    expense = require_owned_expense(
        expense_id=expense_id,
        user=user,
        db=db,
    )

    category = require_available_expense_category(
        category_id=expense.category_id,
        user=user,
        db=db,
    )

    farm = None

    if expense.farm_id is not None:
        farm = require_owned_farm(
            db=db,
            farm_id=expense.farm_id,
            owner_id=user.id,
        )

    vendor = None

    if expense.vendor_id is not None:
        vendor = db.scalar(
            select(Vendor).where(
                Vendor.id == expense.vendor_id,
                Vendor.owner_id == user.id,
            )
        )

    return templates.TemplateResponse(
        request=request,
        name="expenses/detail.html",
        context={
            "current_user": user,
            "expense": expense,
            "category": category,
            "farm": farm,
            "vendor": vendor,
        },
    )


@app.post(
    "/expenses/{expense_id}/delete-ui",
)
def expense_delete_html(
    expense_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    expense = require_owned_expense(
        expense_id=expense_id,
        user=user,
        db=db,
    )

    deleted_detail = (
        f"Expense ID: {expense.id}; "
        f"Date: {expense.expense_date}; "
        f"Amount: {expense.amount}; "
        f"Description: {expense.description}"
    )

    try:
        audit(
            db,
            request,
            "expense_deleted",
            user.id,
            deleted_detail,
        )

        db.delete(expense)
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to delete expense.",
        )

    return RedirectResponse(
        url="/expenses/manage",
        status_code=303,
    )



# PATCH-SALES-001B: SALES MANAGEMENT BACKEND

SALE_PRODUCT_TYPES = {
    "Mature Coconut",
    "Tender Coconut",
    "Copra",
    "Coconut Husk",
    "Coconut Shell",
    "Coconut Oil",
    "Seedling",
    "Other",
}

SALE_UNITS = {
    "Number",
    "Kilogram",
    "Quintal",
    "Litre",
    "Bag",
    "Lot",
}

SALE_PAYMENT_MODES = {
    "Cash",
    "UPI",
    "Bank Transfer",
    "Cheque",
    "Other",
}


def require_owned_buyer(
    buyer_id: int,
    user: User,
    db: Session,
) -> Buyer:
    buyer = db.scalar(
        select(Buyer).where(
            Buyer.id == buyer_id,
            Buyer.owner_id == user.id,
            Buyer.is_active.is_(True),
        )
    )

    if buyer is None:
        raise HTTPException(
            status_code=404,
            detail="Buyer not found.",
        )

    return buyer


def require_owned_sale(
    sale_id: int,
    user: User,
    db: Session,
) -> Sale:
    sale = db.scalar(
        select(Sale).where(
            Sale.id == sale_id,
            Sale.owner_id == user.id,
        )
    )

    if sale is None:
        raise HTTPException(
            status_code=404,
            detail="Sale not found.",
        )

    return sale


def sale_payment_status(
    net_amount: Decimal,
    paid_amount: Decimal,
    payment_due_date: date | None = None,
) -> str:
    if paid_amount >= net_amount:
        return "Paid"

    if (
        payment_due_date is not None
        and payment_due_date < date.today()
    ):
        return "Overdue"

    if paid_amount > 0:
        return "Partially Paid"

    return "Unpaid"


@app.get(
    "/buyers",
    response_class=JSONResponse,
)
def buyer_list(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    buyers = db.scalars(
        select(Buyer)
        .where(
            Buyer.owner_id == user.id,
            Buyer.is_active.is_(True),
        )
        .order_by(func.lower(Buyer.name))
    ).all()

    return {
        "count": len(buyers),
        "items": [
            {
                "id": buyer.id,
                "name": buyer.name,
                "mobile_number": buyer.mobile_number,
                "email": buyer.email,
                "address": buyer.address,
                "notes": buyer.notes,
            }
            for buyer in buyers
        ],
    }


@app.post(
    "/buyers",
    response_class=JSONResponse,
)
def create_buyer(
    request: Request,
    name: str = Form(...),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_name = name.strip()

    if not normalized_name:
        raise HTTPException(
            status_code=422,
            detail="Buyer name is required.",
        )

    if len(normalized_name) > 160:
        raise HTTPException(
            status_code=422,
            detail="Buyer name cannot exceed 160 characters.",
        )

    duplicate = db.scalar(
        select(Buyer.id).where(
            Buyer.owner_id == user.id,
            func.lower(Buyer.name) == normalized_name.lower(),
        )
    )

    if duplicate is not None:
        raise HTTPException(
            status_code=409,
            detail="This buyer already exists.",
        )

    buyer = Buyer(
        owner_id=user.id,
        name=normalized_name,
        mobile_number=normalize_optional_text(
            mobile_number
        ),
        email=normalize_optional_text(email),
        address=normalize_optional_text(address),
        notes=normalize_optional_text(notes),
        is_active=True,
    )

    try:
        db.add(buyer)
        db.flush()

        audit(
            db,
            request,
            "buyer_created",
            user.id,
            (
                f"Buyer ID: {buyer.id}; "
                f"Name: {buyer.name}"
            ),
        )

        db.commit()
        db.refresh(buyer)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create buyer.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": buyer.id,
            "name": buyer.name,
            "mobile_number": buyer.mobile_number,
            "email": buyer.email,
            "address": buyer.address,
            "notes": buyer.notes,
        },
    )


@app.get(
    "/sales",
    response_class=JSONResponse,
)
def sale_list(
    farm_id: int | None = None,
    buyer_id: int | None = None,
    payment_status: str | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    statement = select(Sale).where(
        Sale.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Sale.farm_id == farm_id
        )

    if buyer_id is not None:
        require_owned_buyer(
            buyer_id=buyer_id,
            user=user,
            db=db,
        )
        statement = statement.where(
            Sale.buyer_id == buyer_id
        )

    if payment_status:
        if payment_status not in {
            "Unpaid",
            "Partially Paid",
            "Paid",
            "Overdue",
        }:
            raise HTTPException(
                status_code=422,
                detail="Invalid payment status.",
            )

        statement = statement.where(
            Sale.payment_status == payment_status
        )

    if date_from is not None:
        statement = statement.where(
            Sale.sale_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            Sale.sale_date <= date_to
        )

    sales = db.scalars(
        statement.order_by(
            Sale.sale_date.desc(),
            Sale.id.desc(),
        )
    ).all()

    farm_ids = {
        sale.farm_id
        for sale in sales
    }

    buyer_ids = {
        sale.buyer_id
        for sale in sales
        if sale.buyer_id is not None
    }

    farms = {
        farm.id: farm.name
        for farm in db.scalars(
            select(Farm).where(
                Farm.owner_id == user.id,
                Farm.id.in_(farm_ids),
            )
        ).all()
    } if farm_ids else {}

    buyers = {
        buyer.id: buyer.name
        for buyer in db.scalars(
            select(Buyer).where(
                Buyer.owner_id == user.id,
                Buyer.id.in_(buyer_ids),
            )
        ).all()
    } if buyer_ids else {}

    today = date.today()
    changed = False

    for sale in sales:
        current_status = sale_payment_status(
            Decimal(sale.net_amount),
            Decimal(sale.paid_amount),
            sale.payment_due_date,
        )

        if sale.payment_status != current_status:
            sale.payment_status = current_status
            changed = True

    if changed:
        db.commit()

    total_net = sum(
        Decimal(sale.net_amount or 0)
        for sale in sales
    )

    total_paid = sum(
        Decimal(sale.paid_amount or 0)
        for sale in sales
    )

    total_balance = sum(
        Decimal(sale.balance_amount or 0)
        for sale in sales
    )

    return {
        "count": len(sales),
        "total_net_amount": str(total_net),
        "total_paid_amount": str(total_paid),
        "total_balance_amount": str(total_balance),
        "as_of_date": today.isoformat(),
        "items": [
            {
                "id": sale.id,
                "farm_id": sale.farm_id,
                "farm_name": farms.get(sale.farm_id),
                "harvest_record_id": (
                    sale.harvest_record_id
                ),
                "buyer_id": sale.buyer_id,
                "buyer_name": buyers.get(sale.buyer_id),
                "sale_date": sale.sale_date.isoformat(),
                "product_type": sale.product_type,
                "quantity": str(sale.quantity),
                "unit": sale.unit,
                "rate": str(sale.rate),
                "gross_amount": str(sale.gross_amount),
                "net_amount": str(sale.net_amount),
                "paid_amount": str(sale.paid_amount),
                "balance_amount": str(sale.balance_amount),
                "payment_status": sale.payment_status,
                "payment_due_date": (
                    sale.payment_due_date.isoformat()
                    if sale.payment_due_date
                    else None
                ),
            }
            for sale in sales
        ],
    }


@app.post(
    "/sales",
    response_class=JSONResponse,
)
def create_sale(
    request: Request,
    sale_date: date = Form(...),
    farm_id: int = Form(...),
    product_type: str = Form(...),
    quantity: str = Form(...),
    unit: str = Form("Number"),
    rate: str = Form(...),
    harvest_record_id: int | None = Form(None),
    buyer_id: int | None = Form(None),
    transport_deduction: str = Form("0"),
    commission_deduction: str = Form("0"),
    other_deduction: str = Form("0"),
    paid_amount: str = Form("0"),
    payment_due_date: date | None = Form(None),
    reference_number: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    normalized_product = product_type.strip()

    if normalized_product not in SALE_PRODUCT_TYPES:
        raise HTTPException(
            status_code=422,
            detail="Invalid product type.",
        )

    if unit not in SALE_UNITS:
        raise HTTPException(
            status_code=422,
            detail="Invalid sale unit.",
        )

    parsed_quantity = parse_non_negative_decimal(
        quantity,
        "Quantity",
    )
    parsed_rate = parse_non_negative_decimal(
        rate,
        "Rate",
    )

    if parsed_quantity <= 0:
        raise HTTPException(
            status_code=422,
            detail="Quantity must be greater than zero.",
        )

    deductions = {
        "transport": parse_non_negative_decimal(
            transport_deduction,
            "Transport deduction",
        ),
        "commission": parse_non_negative_decimal(
            commission_deduction,
            "Commission deduction",
        ),
        "other": parse_non_negative_decimal(
            other_deduction,
            "Other deduction",
        ),
    }

    parsed_paid_amount = parse_non_negative_decimal(
        paid_amount,
        "Paid amount",
    )

    buyer = None

    if buyer_id is not None:
        buyer = require_owned_buyer(
            buyer_id=buyer_id,
            user=user,
            db=db,
        )

    harvest_record = None

    if harvest_record_id is not None:
        harvest_record = db.scalar(
            select(HarvestRecord).where(
                HarvestRecord.id == harvest_record_id,
                HarvestRecord.owner_id == user.id,
                HarvestRecord.farm_id == farm.id,
            )
        )

        if harvest_record is None:
            raise HTTPException(
                status_code=404,
                detail="Harvest record not found.",
            )

    gross_amount = (
        parsed_quantity * parsed_rate
    ).quantize(Decimal("0.01"))

    total_deductions = (
        deductions["transport"]
        + deductions["commission"]
        + deductions["other"]
    )

    if total_deductions > gross_amount:
        raise HTTPException(
            status_code=422,
            detail=(
                "Total deductions cannot exceed "
                "the gross amount."
            ),
        )

    net_amount = gross_amount - total_deductions

    if parsed_paid_amount > net_amount:
        raise HTTPException(
            status_code=422,
            detail=(
                "Paid amount cannot exceed "
                "the net sale amount."
            ),
        )

    balance_amount = net_amount - parsed_paid_amount

    status = sale_payment_status(
        net_amount,
        parsed_paid_amount,
        payment_due_date,
    )

    sale = Sale(
        owner_id=user.id,
        farm_id=farm.id,
        harvest_record_id=(
            harvest_record.id
            if harvest_record
            else None
        ),
        buyer_id=buyer.id if buyer else None,
        sale_date=sale_date,
        product_type=normalized_product,
        quantity=parsed_quantity,
        unit=unit,
        rate=parsed_rate,
        gross_amount=gross_amount,
        transport_deduction=deductions["transport"],
        commission_deduction=deductions["commission"],
        other_deduction=deductions["other"],
        net_amount=net_amount,
        paid_amount=parsed_paid_amount,
        balance_amount=balance_amount,
        payment_status=status,
        payment_due_date=payment_due_date,
        reference_number=normalize_optional_text(
            reference_number
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(sale)
        db.flush()

        if parsed_paid_amount > 0:
            initial_payment = SalePayment(
                owner_id=user.id,
                sale_id=sale.id,
                payment_date=sale_date,
                amount=parsed_paid_amount,
                payment_mode="Cash",
                notes="Initial sale payment",
            )
            db.add(initial_payment)

        audit(
            db,
            request,
            "sale_created",
            user.id,
            (
                f"Sale ID: {sale.id}; "
                f"Farm ID: {sale.farm_id}; "
                f"Buyer ID: {sale.buyer_id}; "
                f"Product: {sale.product_type}; "
                f"Quantity: {sale.quantity} {sale.unit}; "
                f"Net amount: {sale.net_amount}; "
                f"Paid: {sale.paid_amount}; "
                f"Balance: {sale.balance_amount}"
            ),
        )

        db.commit()
        db.refresh(sale)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to create sale.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": sale.id,
            "farm_id": sale.farm_id,
            "harvest_record_id": (
                sale.harvest_record_id
            ),
            "buyer_id": sale.buyer_id,
            "sale_date": sale.sale_date.isoformat(),
            "product_type": sale.product_type,
            "quantity": str(sale.quantity),
            "unit": sale.unit,
            "rate": str(sale.rate),
            "gross_amount": str(sale.gross_amount),
            "transport_deduction": str(
                sale.transport_deduction
            ),
            "commission_deduction": str(
                sale.commission_deduction
            ),
            "other_deduction": str(
                sale.other_deduction
            ),
            "net_amount": str(sale.net_amount),
            "paid_amount": str(sale.paid_amount),
            "balance_amount": str(sale.balance_amount),
            "payment_status": sale.payment_status,
            "payment_due_date": (
                sale.payment_due_date.isoformat()
                if sale.payment_due_date
                else None
            ),
            "reference_number": (
                sale.reference_number
            ),
            "notes": sale.notes,
        },
    )


@app.get(
    "/sales/{sale_id}",
    response_class=JSONResponse,
)
def sale_detail(
    sale_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=sale.farm_id,
        owner_id=user.id,
    )

    buyer = None

    if sale.buyer_id is not None:
        buyer = db.scalar(
            select(Buyer).where(
                Buyer.id == sale.buyer_id,
                Buyer.owner_id == user.id,
            )
        )

    payments = db.scalars(
        select(SalePayment)
        .where(
            SalePayment.owner_id == user.id,
            SalePayment.sale_id == sale.id,
        )
        .order_by(
            SalePayment.payment_date.desc(),
            SalePayment.id.desc(),
        )
    ).all()

    current_status = sale_payment_status(
        Decimal(sale.net_amount),
        Decimal(sale.paid_amount),
        sale.payment_due_date,
    )

    if sale.payment_status != current_status:
        sale.payment_status = current_status
        db.commit()

    return {
        "id": sale.id,
        "farm": {
            "id": farm.id,
            "name": farm.name,
        },
        "buyer": (
            {
                "id": buyer.id,
                "name": buyer.name,
            }
            if buyer
            else None
        ),
        "harvest_record_id": sale.harvest_record_id,
        "sale_date": sale.sale_date.isoformat(),
        "product_type": sale.product_type,
        "quantity": str(sale.quantity),
        "unit": sale.unit,
        "rate": str(sale.rate),
        "gross_amount": str(sale.gross_amount),
        "transport_deduction": str(
            sale.transport_deduction
        ),
        "commission_deduction": str(
            sale.commission_deduction
        ),
        "other_deduction": str(
            sale.other_deduction
        ),
        "net_amount": str(sale.net_amount),
        "paid_amount": str(sale.paid_amount),
        "balance_amount": str(sale.balance_amount),
        "payment_status": sale.payment_status,
        "payment_due_date": (
            sale.payment_due_date.isoformat()
            if sale.payment_due_date
            else None
        ),
        "reference_number": sale.reference_number,
        "notes": sale.notes,
        "payments": [
            {
                "id": payment.id,
                "payment_date": (
                    payment.payment_date.isoformat()
                ),
                "amount": str(payment.amount),
                "payment_mode": payment.payment_mode,
                "reference_number": (
                    payment.reference_number
                ),
                "notes": payment.notes,
            }
            for payment in payments
        ],
    }


@app.post(
    "/sales/{sale_id}/payments",
    response_class=JSONResponse,
)
def create_sale_payment(
    sale_id: int,
    request: Request,
    payment_date: date = Form(...),
    amount: str = Form(...),
    payment_mode: str = Form("Cash"),
    reference_number: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    parsed_amount = parse_non_negative_decimal(
        amount,
        "Payment amount",
    )

    if parsed_amount <= 0:
        raise HTTPException(
            status_code=422,
            detail="Payment amount must be greater than zero.",
        )

    if payment_mode not in SALE_PAYMENT_MODES:
        raise HTTPException(
            status_code=422,
            detail="Invalid payment mode.",
        )

    current_balance = Decimal(
        sale.balance_amount or 0
    )

    if parsed_amount > current_balance:
        raise HTTPException(
            status_code=422,
            detail=(
                "Payment amount cannot exceed "
                "the current balance."
            ),
        )

    payment = SalePayment(
        owner_id=user.id,
        sale_id=sale.id,
        payment_date=payment_date,
        amount=parsed_amount,
        payment_mode=payment_mode,
        reference_number=normalize_optional_text(
            reference_number
        ),
        notes=normalize_optional_text(notes),
    )

    new_paid_amount = (
        Decimal(sale.paid_amount or 0)
        + parsed_amount
    )

    new_balance_amount = (
        Decimal(sale.net_amount)
        - new_paid_amount
    )

    try:
        db.add(payment)
        db.flush()

        sale.paid_amount = new_paid_amount
        sale.balance_amount = new_balance_amount
        sale.payment_status = sale_payment_status(
            Decimal(sale.net_amount),
            new_paid_amount,
            sale.payment_due_date,
        )

        audit(
            db,
            request,
            "sale_payment_created",
            user.id,
            (
                f"Payment ID: {payment.id}; "
                f"Sale ID: {sale.id}; "
                f"Amount: {payment.amount}; "
                f"Mode: {payment.payment_mode}; "
                f"Balance: {sale.balance_amount}"
            ),
        )

        db.commit()
        db.refresh(payment)
        db.refresh(sale)
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to record sale payment.",
        )

    return JSONResponse(
        status_code=201,
        content={
            "id": payment.id,
            "sale_id": payment.sale_id,
            "payment_date": (
                payment.payment_date.isoformat()
            ),
            "amount": str(payment.amount),
            "payment_mode": payment.payment_mode,
            "reference_number": (
                payment.reference_number
            ),
            "sale_paid_amount": str(sale.paid_amount),
            "sale_balance_amount": str(
                sale.balance_amount
            ),
            "sale_payment_status": (
                sale.payment_status
            ),
        },
    )


@app.post(
    "/sales/{sale_id}/delete",
    response_class=JSONResponse,
)
def delete_sale(
    sale_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    detail = (
        f"Sale ID: {sale.id}; "
        f"Date: {sale.sale_date}; "
        f"Product: {sale.product_type}; "
        f"Net amount: {sale.net_amount}; "
        f"Paid: {sale.paid_amount}; "
        f"Balance: {sale.balance_amount}"
    )

    try:
        audit(
            db,
            request,
            "sale_deleted",
            user.id,
            detail,
        )

        db.delete(sale)
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail="Unable to delete sale.",
        )

    return {
        "status": "deleted",
        "sale_id": sale_id,
    }



# PATCH-SALES-001C: SALES MANAGEMENT UI


@app.get(
    "/sales/manage",
    response_class=HTMLResponse,
)
def sales_management_page(
    request: Request,
    farm_id: int | None = None,
    buyer_id: int | None = None,
    payment_status: str | None = None,
    date_from: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    buyers = db.scalars(
        select(Buyer)
        .where(
            Buyer.owner_id == user.id,
            Buyer.is_active.is_(True),
        )
        .order_by(func.lower(Buyer.name))
    ).all()

    statement = select(Sale).where(
        Sale.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Sale.farm_id == farm_id
        )

    if buyer_id is not None:
        require_owned_buyer(
            buyer_id=buyer_id,
            user=user,
            db=db,
        )
        statement = statement.where(
            Sale.buyer_id == buyer_id
        )

    if payment_status:
        statement = statement.where(
            Sale.payment_status == payment_status
        )

    if date_from is not None:
        statement = statement.where(
            Sale.sale_date >= date_from
        )

    sales = db.scalars(
        statement.order_by(
            Sale.sale_date.desc(),
            Sale.id.desc(),
        )
    ).all()

    farm_names = {
        farm.id: farm.name
        for farm in farms
    }

    buyer_names = {
        buyer.id: buyer.name
        for buyer in buyers
    }

    rows = [
        {
            "sale": sale,
            "farm_name": farm_names.get(
                sale.farm_id,
                "Farm",
            ),
            "buyer_name": buyer_names.get(
                sale.buyer_id
            ),
        }
        for sale in sales
    ]

    totals = {
        "count": len(sales),
        "net": sum(
            Decimal(sale.net_amount or 0)
            for sale in sales
        ),
        "paid": sum(
            Decimal(sale.paid_amount or 0)
            for sale in sales
        ),
        "balance": sum(
            Decimal(sale.balance_amount or 0)
            for sale in sales
        ),
    }

    return templates.TemplateResponse(
        request=request,
        name="sales/list.html",
        context={
            "current_user": user,
            "farms": farms,
            "buyers": buyers,
            "sales": rows,
            "totals": totals,
            "payment_statuses": [
                "Unpaid",
                "Partially Paid",
                "Paid",
                "Overdue",
            ],
            "filters": {
                "farm_id": farm_id or "",
                "buyer_id": buyer_id or "",
                "payment_status": payment_status or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else ""
                ),
            },
        },
    )


@app.get(
    "/sales/new",
    response_class=HTMLResponse,
)
def sale_create_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    buyers = db.scalars(
        select(Buyer)
        .where(
            Buyer.owner_id == user.id,
            Buyer.is_active.is_(True),
        )
        .order_by(func.lower(Buyer.name))
    ).all()

    harvest_records = db.scalars(
        select(HarvestRecord)
        .where(HarvestRecord.owner_id == user.id)
        .order_by(
            HarvestRecord.harvest_date.desc()
        )
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="sales/form.html",
        context={
            "current_user": user,
            "farms": farms,
            "buyers": buyers,
            "harvest_records": harvest_records,
            "product_types": sorted(
                SALE_PRODUCT_TYPES
            ),
            "units": sorted(SALE_UNITS),
            "error_message": None,
            "form_data": {
                "sale_date": date.today().isoformat(),
                "farm_id": "",
                "harvest_record_id": "",
                "buyer_id": "",
                "product_type": "Mature Coconut",
                "quantity": "",
                "unit": "Number",
                "rate": "",
                "transport_deduction": "0",
                "commission_deduction": "0",
                "other_deduction": "0",
                "paid_amount": "0",
                "payment_due_date": "",
                "reference_number": "",
                "notes": "",
            },
        },
    )


@app.post(
    "/sales/new",
)
def sale_create_html(
    request: Request,
    sale_date: date = Form(...),
    farm_id: int = Form(...),
    product_type: str = Form(...),
    quantity: str = Form(...),
    unit: str = Form("Number"),
    rate: str = Form(...),
    harvest_record_id: str = Form(""),
    buyer_id: str = Form(""),
    transport_deduction: str = Form("0"),
    commission_deduction: str = Form("0"),
    other_deduction: str = Form("0"),
    paid_amount: str = Form("0"),
    payment_due_date: str = Form(""),
    reference_number: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    parsed_quantity = parse_non_negative_decimal(
        quantity,
        "Quantity",
    )
    parsed_rate = parse_non_negative_decimal(
        rate,
        "Rate",
    )
    transport = parse_non_negative_decimal(
        transport_deduction,
        "Transport deduction",
    )
    commission = parse_non_negative_decimal(
        commission_deduction,
        "Commission deduction",
    )
    other = parse_non_negative_decimal(
        other_deduction,
        "Other deduction",
    )
    paid = parse_non_negative_decimal(
        paid_amount,
        "Paid amount",
    )

    gross = (
        parsed_quantity * parsed_rate
    ).quantize(Decimal("0.01"))

    deductions = transport + commission + other
    net = gross - deductions

    if parsed_quantity <= 0 or net < 0 or paid > net:
        raise HTTPException(
            status_code=422,
            detail="Invalid sale amounts.",
        )

    buyer = None

    if buyer_id.strip():
        buyer = require_owned_buyer(
            buyer_id=int(buyer_id),
            user=user,
            db=db,
        )

    harvest_record = None

    if harvest_record_id.strip():
        harvest_record = db.scalar(
            select(HarvestRecord).where(
                HarvestRecord.id == int(
                    harvest_record_id
                ),
                HarvestRecord.owner_id == user.id,
                HarvestRecord.farm_id == farm.id,
            )
        )

        if harvest_record is None:
            raise HTTPException(
                status_code=404,
                detail="Harvest record not found.",
            )

    due_date = (
        date.fromisoformat(payment_due_date)
        if payment_due_date.strip()
        else None
    )

    sale = Sale(
        owner_id=user.id,
        farm_id=farm.id,
        harvest_record_id=(
            harvest_record.id
            if harvest_record
            else None
        ),
        buyer_id=buyer.id if buyer else None,
        sale_date=sale_date,
        product_type=product_type,
        quantity=parsed_quantity,
        unit=unit,
        rate=parsed_rate,
        gross_amount=gross,
        transport_deduction=transport,
        commission_deduction=commission,
        other_deduction=other,
        net_amount=net,
        paid_amount=paid,
        balance_amount=net - paid,
        payment_status=sale_payment_status(
            net,
            paid,
            due_date,
        ),
        payment_due_date=due_date,
        reference_number=normalize_optional_text(
            reference_number
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(sale)
        db.flush()

        if paid > 0:
            db.add(
                SalePayment(
                    owner_id=user.id,
                    sale_id=sale.id,
                    payment_date=sale_date,
                    amount=paid,
                    payment_mode="Cash",
                    notes="Initial sale payment",
                )
            )

        audit(
            db,
            request,
            "sale_created",
            user.id,
            (
                f"Sale ID: {sale.id}; "
                f"Farm ID: {farm.id}; "
                f"Net: {net}; Balance: {net - paid}"
            ),
        )

        db.commit()
        db.refresh(sale)
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to save sale.",
        )

    return RedirectResponse(
        url=f"/sales/{sale.id}/view",
        status_code=303,
    )


@app.get(
    "/sales/{sale_id}/view",
    response_class=HTMLResponse,
)
def sale_detail_page(
    sale_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=sale.farm_id,
        owner_id=user.id,
    )

    buyer = None

    if sale.buyer_id is not None:
        buyer = db.scalar(
            select(Buyer).where(
                Buyer.id == sale.buyer_id,
                Buyer.owner_id == user.id,
            )
        )

    payments = db.scalars(
        select(SalePayment)
        .where(
            SalePayment.owner_id == user.id,
            SalePayment.sale_id == sale.id,
        )
        .order_by(
            SalePayment.payment_date.desc()
        )
    ).all()

    return templates.TemplateResponse(
        request=request,
        name="sales/detail.html",
        context={
            "current_user": user,
            "sale": sale,
            "farm": farm,
            "buyer": buyer,
            "payments": payments,
        },
    )


@app.get(
    "/sales/{sale_id}/payments/new",
    response_class=HTMLResponse,
)
def sale_payment_create_page(
    sale_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    farm = require_owned_farm(
        db=db,
        farm_id=sale.farm_id,
        owner_id=user.id,
    )

    return templates.TemplateResponse(
        request=request,
        name="sales/payment.html",
        context={
            "current_user": user,
            "sale": sale,
            "farm": farm,
            "payment_modes": sorted(
                SALE_PAYMENT_MODES
            ),
            "error_message": None,
            "form_data": {
                "payment_date": date.today().isoformat(),
                "amount": "",
                "payment_mode": "Cash",
                "reference_number": "",
                "notes": "",
            },
        },
    )


@app.post(
    "/sales/{sale_id}/payments/new",
)
def sale_payment_create_html(
    sale_id: int,
    request: Request,
    payment_date: date = Form(...),
    amount: str = Form(...),
    payment_mode: str = Form("Cash"),
    reference_number: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    parsed_amount = parse_non_negative_decimal(
        amount,
        "Payment amount",
    )

    if (
        parsed_amount <= 0
        or parsed_amount > Decimal(
            sale.balance_amount or 0
        )
    ):
        raise HTTPException(
            status_code=422,
            detail="Invalid payment amount.",
        )

    payment = SalePayment(
        owner_id=user.id,
        sale_id=sale.id,
        payment_date=payment_date,
        amount=parsed_amount,
        payment_mode=payment_mode,
        reference_number=normalize_optional_text(
            reference_number
        ),
        notes=normalize_optional_text(notes),
    )

    try:
        db.add(payment)
        db.flush()

        sale.paid_amount = (
            Decimal(sale.paid_amount or 0)
            + parsed_amount
        )
        sale.balance_amount = (
            Decimal(sale.net_amount)
            - Decimal(sale.paid_amount)
        )
        sale.payment_status = sale_payment_status(
            Decimal(sale.net_amount),
            Decimal(sale.paid_amount),
            sale.payment_due_date,
        )

        audit(
            db,
            request,
            "sale_payment_created",
            user.id,
            (
                f"Sale ID: {sale.id}; "
                f"Amount: {parsed_amount}; "
                f"Balance: {sale.balance_amount}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to save payment.",
        )

    return RedirectResponse(
        url=f"/sales/{sale.id}/view",
        status_code=303,
    )


@app.post(
    "/sales/{sale_id}/delete-ui",
)
def sale_delete_html(
    sale_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    sale = require_owned_sale(
        sale_id=sale_id,
        user=user,
        db=db,
    )

    try:
        audit(
            db,
            request,
            "sale_deleted",
            user.id,
            (
                f"Sale ID: {sale.id}; "
                f"Net: {sale.net_amount}"
            ),
        )

        db.delete(sale)
        db.commit()
    except SQLAlchemyError:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to delete sale.",
        )

    return RedirectResponse(
        url="/sales/manage",
        status_code=303,
    )



# PATCH-PROFIT-001A: FARM PROFITABILITY BACKEND


def decimal_or_zero(value: object) -> Decimal:
    if value is None:
        return Decimal("0.00")

    return Decimal(str(value)).quantize(
        Decimal("0.01")
    )


def profitability_percentage(
    profit: Decimal,
    total_cost: Decimal,
) -> Decimal:
    if total_cost <= 0:
        return Decimal("0.00")

    return (
        profit
        / total_cost
        * Decimal("100")
    ).quantize(Decimal("0.01"))


def calculate_farm_profitability(
    farm: Farm,
    owner_id: int,
    db: Session,
    date_from: date | None = None,
    date_to: date | None = None,
) -> dict[str, object]:
    sale_statement = select(
        func.coalesce(
            func.sum(Sale.net_amount),
            0,
        )
    ).where(
        Sale.owner_id == owner_id,
        Sale.farm_id == farm.id,
    )

    expense_statement = select(
        func.coalesce(
            func.sum(Expense.amount),
            0,
        )
    ).where(
        Expense.owner_id == owner_id,
        Expense.farm_id == farm.id,
    )

    harvest_cost_statement = select(
        func.coalesce(
            func.sum(
                HarvestRecord.total_harvest_cost
            ),
            0,
        )
    ).where(
        HarvestRecord.owner_id == owner_id,
        HarvestRecord.farm_id == farm.id,
    )

    coconut_statement = select(
        func.coalesce(
            func.sum(
                HarvestRecord.total_coconuts
            ),
            0,
        )
    ).where(
        HarvestRecord.owner_id == owner_id,
        HarvestRecord.farm_id == farm.id,
    )

    harvested_tree_statement = select(
        func.coalesce(
            func.sum(
                HarvestRecord.trees_harvested
            ),
            0,
        )
    ).where(
        HarvestRecord.owner_id == owner_id,
        HarvestRecord.farm_id == farm.id,
    )

    if date_from is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date >= date_from
        )
        expense_statement = expense_statement.where(
            Expense.expense_date >= date_from
        )
        harvest_cost_statement = (
            harvest_cost_statement.where(
                HarvestRecord.harvest_date >= date_from
            )
        )
        coconut_statement = coconut_statement.where(
            HarvestRecord.harvest_date >= date_from
        )
        harvested_tree_statement = (
            harvested_tree_statement.where(
                HarvestRecord.harvest_date >= date_from
            )
        )

    if date_to is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date <= date_to
        )
        expense_statement = expense_statement.where(
            Expense.expense_date <= date_to
        )
        harvest_cost_statement = (
            harvest_cost_statement.where(
                HarvestRecord.harvest_date <= date_to
            )
        )
        coconut_statement = coconut_statement.where(
            HarvestRecord.harvest_date <= date_to
        )
        harvested_tree_statement = (
            harvested_tree_statement.where(
                HarvestRecord.harvest_date <= date_to
            )
        )

    revenue = decimal_or_zero(
        db.scalar(sale_statement)
    )

    operating_expense = decimal_or_zero(
        db.scalar(expense_statement)
    )

    harvest_cost = decimal_or_zero(
        db.scalar(harvest_cost_statement)
    )

    total_coconuts = int(
        db.scalar(coconut_statement) or 0
    )

    harvested_trees = int(
        db.scalar(harvested_tree_statement) or 0
    )

    total_cost = (
        operating_expense + harvest_cost
    ).quantize(Decimal("0.01"))

    net_profit = (
        revenue - total_cost
    ).quantize(Decimal("0.01"))

    total_farm_trees = int(
        farm.total_trees or 0
    )

    revenue_per_tree = (
        revenue / Decimal(total_farm_trees)
    ).quantize(Decimal("0.01")) if total_farm_trees > 0 else Decimal("0.00")

    cost_per_tree = (
        total_cost / Decimal(total_farm_trees)
    ).quantize(Decimal("0.01")) if total_farm_trees > 0 else Decimal("0.00")

    profit_per_tree = (
        net_profit / Decimal(total_farm_trees)
    ).quantize(Decimal("0.01")) if total_farm_trees > 0 else Decimal("0.00")

    revenue_per_coconut = (
        revenue / Decimal(total_coconuts)
    ).quantize(Decimal("0.01")) if total_coconuts > 0 else Decimal("0.00")

    cost_per_coconut = (
        total_cost / Decimal(total_coconuts)
    ).quantize(Decimal("0.01")) if total_coconuts > 0 else Decimal("0.00")

    profit_per_coconut = (
        net_profit / Decimal(total_coconuts)
    ).quantize(Decimal("0.01")) if total_coconuts > 0 else Decimal("0.00")

    yield_per_harvested_tree = (
        Decimal(total_coconuts)
        / Decimal(harvested_trees)
    ).quantize(Decimal("0.01")) if harvested_trees > 0 else Decimal("0.00")

    return {
        "farm_id": farm.id,
        "farm_name": farm.name,
        "total_farm_trees": total_farm_trees,
        "harvested_trees": harvested_trees,
        "total_coconuts": total_coconuts,
        "revenue": revenue,
        "operating_expense": operating_expense,
        "harvest_cost": harvest_cost,
        "total_cost": total_cost,
        "net_profit": net_profit,
        "profitability_percentage": (
            profitability_percentage(
                net_profit,
                total_cost,
            )
        ),
        "revenue_per_tree": revenue_per_tree,
        "cost_per_tree": cost_per_tree,
        "profit_per_tree": profit_per_tree,
        "revenue_per_coconut": (
            revenue_per_coconut
        ),
        "cost_per_coconut": cost_per_coconut,
        "profit_per_coconut": (
            profit_per_coconut
        ),
        "yield_per_harvested_tree": (
            yield_per_harvested_tree
        ),
    }


@app.get(
    "/profitability",
    response_class=JSONResponse,
)
def profitability_summary(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "From date cannot be later "
                "than to date."
            ),
        )

    farm_statement = select(Farm).where(
        Farm.owner_id == user.id
    )

    if farm_id is not None:
        farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

        farms = [farm]
    else:
        farms = db.scalars(
            farm_statement.order_by(
                func.lower(Farm.name)
            )
        ).all()

    farm_results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=date_from,
            date_to=date_to,
        )
        for farm in farms
    ]

    total_revenue = sum(
        item["revenue"]
        for item in farm_results
    )

    total_operating_expense = sum(
        item["operating_expense"]
        for item in farm_results
    )

    total_harvest_cost = sum(
        item["harvest_cost"]
        for item in farm_results
    )

    total_cost = sum(
        item["total_cost"]
        for item in farm_results
    )

    net_profit = sum(
        item["net_profit"]
        for item in farm_results
    )

    total_coconuts = sum(
        int(item["total_coconuts"])
        for item in farm_results
    )

    return {
        "date_from": (
            date_from.isoformat()
            if date_from
            else None
        ),
        "date_to": (
            date_to.isoformat()
            if date_to
            else None
        ),
        "farm_count": len(farm_results),
        "summary": {
            "revenue": str(
                total_revenue.quantize(
                    Decimal("0.01")
                )
            ),
            "operating_expense": str(
                total_operating_expense.quantize(
                    Decimal("0.01")
                )
            ),
            "harvest_cost": str(
                total_harvest_cost.quantize(
                    Decimal("0.01")
                )
            ),
            "total_cost": str(
                total_cost.quantize(
                    Decimal("0.01")
                )
            ),
            "net_profit": str(
                net_profit.quantize(
                    Decimal("0.01")
                )
            ),
            "profitability_percentage": str(
                profitability_percentage(
                    net_profit,
                    total_cost,
                )
            ),
            "total_coconuts": total_coconuts,
            "profit_per_coconut": str(
                (
                    net_profit
                    / Decimal(total_coconuts)
                ).quantize(
                    Decimal("0.01")
                )
                if total_coconuts > 0
                else Decimal("0.00")
            ),
        },
        "farms": [
            {
                key: (
                    str(value)
                    if isinstance(value, Decimal)
                    else value
                )
                for key, value in item.items()
            }
            for item in farm_results
        ],
    }


@app.get(
    "/farms/{farm_id}/profitability",
    response_class=JSONResponse,
)
def farm_profitability_detail(
    farm_id: int,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail=(
                "From date cannot be later "
                "than to date."
            ),
        )

    result = calculate_farm_profitability(
        farm=farm,
        owner_id=user.id,
        db=db,
        date_from=date_from,
        date_to=date_to,
    )

    return {
        key: (
            str(value)
            if isinstance(value, Decimal)
            else value
        )
        for key, value in result.items()
    }



# PATCH-PROFIT-001B: FARM PROFITABILITY UI


@app.get(
    "/profitability/manage",
    response_class=HTMLResponse,
)
def profitability_management_page(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail="From date cannot be later than to date.",
        )

    all_farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        farms_for_result = [selected_farm]
    else:
        farms_for_result = all_farms

    results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=date_from,
            date_to=date_to,
        )
        for farm in farms_for_result
    ]

    total_revenue = sum(
        item["revenue"]
        for item in results
    )

    total_cost = sum(
        item["total_cost"]
        for item in results
    )

    net_profit = sum(
        item["net_profit"]
        for item in results
    )

    summary = {
        "revenue": total_revenue,
        "total_cost": total_cost,
        "net_profit": net_profit,
        "profitability_percentage": (
            profitability_percentage(
                net_profit,
                total_cost,
            )
        ),
    }

    query_parts = []

    if date_from is not None:
        query_parts.append(
            f"date_from={date_from.isoformat()}"
        )

    if date_to is not None:
        query_parts.append(
            f"date_to={date_to.isoformat()}"
        )

    return templates.TemplateResponse(
        request=request,
        name="profitability/summary.html",
        context={
            "current_user": user,
            "farms": all_farms,
            "results": results,
            "summary": summary,
            "query_string": "&".join(query_parts),
            "filters": {
                "farm_id": farm_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else ""
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else ""
                ),
            },
        },
    )


@app.get(
    "/farms/{farm_id}/profitability/view",
    response_class=HTMLResponse,
)
def farm_profitability_detail_page(
    farm_id: int,
    request: Request,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail="From date cannot be later than to date.",
        )

    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    result = calculate_farm_profitability(
        farm=farm,
        owner_id=user.id,
        db=db,
        date_from=date_from,
        date_to=date_to,
    )

    query_parts = []

    if date_from is not None:
        query_parts.append(
            f"date_from={date_from.isoformat()}"
        )

    if date_to is not None:
        query_parts.append(
            f"date_to={date_to.isoformat()}"
        )

    return templates.TemplateResponse(
        request=request,
        name="profitability/farm.html",
        context={
            "current_user": user,
            "result": result,
            "date_from": (
                date_from.isoformat()
                if date_from
                else None
            ),
            "date_to": (
                date_to.isoformat()
                if date_to
                else None
            ),
            "query_string": "&".join(query_parts),
        },
    )



# PATCH-DASHBOARD-001A: BUSINESS DASHBOARD


@app.get(
    "/business-dashboard",
    response_class=HTMLResponse,
)
def business_dashboard_page(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail="From date cannot be later than to date.",
        )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        result_farms = [selected_farm]
    else:
        result_farms = farms

    farm_results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=date_from,
            date_to=date_to,
        )
        for farm in result_farms
    ]

    sale_statement = select(Sale).where(
        Sale.owner_id == user.id
    )

    expense_statement = select(Expense).where(
        Expense.owner_id == user.id
    )

    harvest_statement = select(HarvestRecord).where(
        HarvestRecord.owner_id == user.id
    )

    cycle_statement = select(HarvestCycle).where(
        HarvestCycle.owner_id == user.id
    )

    if farm_id is not None:
        sale_statement = sale_statement.where(
            Sale.farm_id == farm_id
        )
        expense_statement = expense_statement.where(
            Expense.farm_id == farm_id
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.farm_id == farm_id
        )
        cycle_statement = cycle_statement.where(
            HarvestCycle.farm_id == farm_id
        )

    if date_from is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date >= date_from
        )
        expense_statement = expense_statement.where(
            Expense.expense_date >= date_from
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.harvest_date >= date_from
        )

    if date_to is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date <= date_to
        )
        expense_statement = expense_statement.where(
            Expense.expense_date <= date_to
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.harvest_date <= date_to
        )

    sales = db.scalars(
        sale_statement.order_by(
            Sale.sale_date.desc(),
            Sale.id.desc(),
        )
    ).all()

    expenses = db.scalars(
        expense_statement.order_by(
            Expense.expense_date.desc(),
            Expense.id.desc(),
        )
    ).all()

    harvest_records = db.scalars(
        harvest_statement.order_by(
            HarvestRecord.harvest_date.desc(),
            HarvestRecord.id.desc(),
        )
    ).all()

    cycles = db.scalars(
        cycle_statement.order_by(
            HarvestCycle.planned_harvest_date.asc()
        )
    ).all()

    total_revenue = sum(
        Decimal(sale.net_amount or 0)
        for sale in sales
    )

    operating_expense = sum(
        Decimal(expense.amount or 0)
        for expense in expenses
    )

    harvest_cost = sum(
        Decimal(record.total_harvest_cost or 0)
        for record in harvest_records
    )

    total_cost = operating_expense + harvest_cost
    net_profit = total_revenue - total_cost

    total_coconuts = sum(
        int(record.total_coconuts or 0)
        for record in harvest_records
    )

    outstanding = sum(
        Decimal(sale.balance_amount or 0)
        for sale in sales
    )

    unpaid_sales = sum(
        Decimal(sale.balance_amount or 0) > 0
        for sale in sales
    )

    today = date.today()

    harvest_alerts = []

    farm_names = {
        farm.id: farm.name
        for farm in farms
    }

    for cycle in cycles:
        if cycle.status in {
            "Completed",
            "Cancelled",
        }:
            continue

        calculated_status = harvest_cycle_status(
            cycle.planned_harvest_date,
            cycle.minimum_due_date,
            cycle.maximum_due_date,
            today,
        )

        if cycle.status != calculated_status:
            cycle.status = calculated_status

        if calculated_status in {
            "Due Soon",
            "Due",
            "Overdue",
        }:
            harvest_alerts.append(
                {
                    "farm_name": farm_names.get(
                        cycle.farm_id,
                        "Farm",
                    ),
                    "planned_date": (
                        cycle.planned_harvest_date
                    ),
                    "status": calculated_status,
                }
            )

    if cycles:
        db.commit()

    recent_activity = []

    for sale in sales[:5]:
        recent_activity.append(
            {
                "kind": "sale",
                "sort_date": sale.sale_date,
                "title": sale.product_type,
                "subtitle": (
                    farm_names.get(
                        sale.farm_id,
                        "Farm",
                    )
                    + " · Sale"
                ),
                "amount": Decimal(
                    sale.net_amount or 0
                ),
            }
        )

    for expense in expenses[:5]:
        recent_activity.append(
            {
                "kind": "expense",
                "sort_date": expense.expense_date,
                "title": expense.description,
                "subtitle": (
                    farm_names.get(
                        expense.farm_id,
                        "General",
                    )
                    + " · Expense"
                ),
                "amount": Decimal(
                    expense.amount or 0
                ),
            }
        )

    recent_activity.sort(
        key=lambda item: item["sort_date"],
        reverse=True,
    )

    recent_activity = recent_activity[:8]

    selected_tree_total = sum(
        int(farm.total_trees or 0)
        for farm in result_farms
    )

    kpis = {
        "revenue": total_revenue,
        "sale_count": len(sales),
        "operating_expense": operating_expense,
        "harvest_cost": harvest_cost,
        "total_cost": total_cost,
        "net_profit": net_profit,
        "profitability_percentage": (
            profitability_percentage(
                net_profit,
                total_cost,
            )
        ),
        "outstanding": outstanding,
        "unpaid_sales": unpaid_sales,
        "total_coconuts": total_coconuts,
        "harvest_count": len(harvest_records),
        "profit_per_coconut": (
            net_profit
            / Decimal(total_coconuts)
        ).quantize(
            Decimal("0.01")
        )
        if total_coconuts > 0
        else Decimal("0.00"),
        "harvests_due": sum(
            item["status"] in {"Due Soon", "Due", "Overdue"}
            for item in harvest_alerts
        ),
        "harvests_overdue": sum(
            item["status"] == "Overdue"
            for item in harvest_alerts
        ),
        "farm_count": len(result_farms),
        "total_trees": selected_tree_total,
    }

    if date_from or date_to:
        period_label = (
            f"{date_from.isoformat() if date_from else 'Beginning'}"
            f" to "
            f"{date_to.isoformat() if date_to else 'Today'}"
        )
    else:
        period_label = "All-time overview"

    return templates.TemplateResponse(
        request=request,
        name="dashboard/business.html",
        context={
            "current_user": user,
            "farms": farms,
            "farm_results": farm_results,
            "kpis": kpis,
            "harvest_alerts": harvest_alerts[:6],
            "recent_activity": recent_activity,
            "period_label": period_label,
            "filters": {
                "farm_id": farm_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else ""
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else ""
                ),
            },
        },
    )



# PATCH-REPORTS-001A: BUSINESS REPORTS BACKEND


def validate_report_dates(
    date_from: date | None,
    date_to: date | None,
) -> None:
    if (
        date_from is not None
        and date_to is not None
        and date_from > date_to
    ):
        raise HTTPException(
            status_code=422,
            detail="From date cannot be later than to date.",
        )


def report_period_label(
    date_from: date | None,
    date_to: date | None,
) -> str:
    start = (
        date_from.isoformat()
        if date_from
        else "Beginning"
    )

    end = (
        date_to.isoformat()
        if date_to
        else "Today"
    )

    return f"{start} to {end}"


def csv_download_response(
    filename: str,
    headers: list[str],
    rows: list[list[object]],
) -> StreamingResponse:
    output = io.StringIO()
    output.write("\ufeff")

    writer = csv.writer(output)
    writer.writerow(headers)

    for row in rows:
        writer.writerow(
            [
                "" if value is None else value
                for value in row
            ]
        )

    content = output.getvalue().encode("utf-8")
    output.close()

    return StreamingResponse(
        iter([content]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )


@app.get(
    "/reports/summary",
    response_class=JSONResponse,
)
def business_report_summary(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        report_farms = [farm]
    else:
        report_farms = farms

    farm_results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=date_from,
            date_to=date_to,
        )
        for farm in report_farms
    ]

    sale_statement = select(Sale).where(
        Sale.owner_id == user.id
    )

    expense_statement = select(Expense).where(
        Expense.owner_id == user.id
    )

    harvest_statement = select(HarvestRecord).where(
        HarvestRecord.owner_id == user.id
    )

    if farm_id is not None:
        sale_statement = sale_statement.where(
            Sale.farm_id == farm_id
        )
        expense_statement = expense_statement.where(
            Expense.farm_id == farm_id
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.farm_id == farm_id
        )

    if date_from is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date >= date_from
        )
        expense_statement = expense_statement.where(
            Expense.expense_date >= date_from
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.harvest_date >= date_from
        )

    if date_to is not None:
        sale_statement = sale_statement.where(
            Sale.sale_date <= date_to
        )
        expense_statement = expense_statement.where(
            Expense.expense_date <= date_to
        )
        harvest_statement = harvest_statement.where(
            HarvestRecord.harvest_date <= date_to
        )

    sales = db.scalars(
        sale_statement.order_by(
            Sale.sale_date.desc(),
            Sale.id.desc(),
        )
    ).all()

    expenses = db.scalars(
        expense_statement.order_by(
            Expense.expense_date.desc(),
            Expense.id.desc(),
        )
    ).all()

    harvests = db.scalars(
        harvest_statement.order_by(
            HarvestRecord.harvest_date.desc(),
            HarvestRecord.id.desc(),
        )
    ).all()

    total_revenue = sum(
        Decimal(sale.net_amount or 0)
        for sale in sales
    )

    operating_expense = sum(
        Decimal(expense.amount or 0)
        for expense in expenses
    )

    harvest_cost = sum(
        Decimal(record.total_harvest_cost or 0)
        for record in harvests
    )

    total_cost = operating_expense + harvest_cost
    net_profit = total_revenue - total_cost

    total_coconuts = sum(
        int(record.total_coconuts or 0)
        for record in harvests
    )

    total_paid = sum(
        Decimal(sale.paid_amount or 0)
        for sale in sales
    )

    outstanding = sum(
        Decimal(sale.balance_amount or 0)
        for sale in sales
    )

    return {
        "period": report_period_label(
            date_from=date_from,
            date_to=date_to,
        ),
        "filters": {
            "farm_id": farm_id,
            "date_from": (
                date_from.isoformat()
                if date_from
                else None
            ),
            "date_to": (
                date_to.isoformat()
                if date_to
                else None
            ),
        },
        "summary": {
            "farm_count": len(report_farms),
            "sale_count": len(sales),
            "expense_count": len(expenses),
            "harvest_count": len(harvests),
            "total_revenue": str(
                total_revenue.quantize(
                    Decimal("0.01")
                )
            ),
            "operating_expense": str(
                operating_expense.quantize(
                    Decimal("0.01")
                )
            ),
            "harvest_cost": str(
                harvest_cost.quantize(
                    Decimal("0.01")
                )
            ),
            "total_cost": str(
                total_cost.quantize(
                    Decimal("0.01")
                )
            ),
            "net_profit": str(
                net_profit.quantize(
                    Decimal("0.01")
                )
            ),
            "profitability_percentage": str(
                profitability_percentage(
                    net_profit,
                    total_cost,
                )
            ),
            "total_coconuts": total_coconuts,
            "total_paid": str(
                total_paid.quantize(
                    Decimal("0.01")
                )
            ),
            "outstanding": str(
                outstanding.quantize(
                    Decimal("0.01")
                )
            ),
            "profit_per_coconut": str(
                (
                    net_profit
                    / Decimal(total_coconuts)
                ).quantize(
                    Decimal("0.01")
                )
                if total_coconuts > 0
                else Decimal("0.00")
            ),
        },
        "farms": [
            {
                key: (
                    str(value)
                    if isinstance(value, Decimal)
                    else value
                )
                for key, value in result.items()
            }
            for result in farm_results
        ],
    }


@app.get(
    "/reports/sales.csv",
)
def sales_report_csv(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    statement = select(Sale).where(
        Sale.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Sale.farm_id == farm_id
        )

    if date_from is not None:
        statement = statement.where(
            Sale.sale_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            Sale.sale_date <= date_to
        )

    sales = db.scalars(
        statement.order_by(
            Sale.sale_date.asc(),
            Sale.id.asc(),
        )
    ).all()

    farm_ids = {
        sale.farm_id
        for sale in sales
    }

    buyer_ids = {
        sale.buyer_id
        for sale in sales
        if sale.buyer_id is not None
    }

    farms = {
        farm.id: farm.name
        for farm in db.scalars(
            select(Farm).where(
                Farm.owner_id == user.id,
                Farm.id.in_(farm_ids),
            )
        ).all()
    } if farm_ids else {}

    buyers = {
        buyer.id: buyer.name
        for buyer in db.scalars(
            select(Buyer).where(
                Buyer.owner_id == user.id,
                Buyer.id.in_(buyer_ids),
            )
        ).all()
    } if buyer_ids else {}

    rows = [
        [
            sale.id,
            sale.sale_date.isoformat(),
            farms.get(sale.farm_id, ""),
            buyers.get(sale.buyer_id, ""),
            sale.product_type,
            sale.quantity,
            sale.unit,
            sale.rate,
            sale.gross_amount,
            sale.transport_deduction,
            sale.commission_deduction,
            sale.other_deduction,
            sale.net_amount,
            sale.paid_amount,
            sale.balance_amount,
            sale.payment_status,
            (
                sale.payment_due_date.isoformat()
                if sale.payment_due_date
                else ""
            ),
            sale.reference_number,
            sale.notes,
        ]
        for sale in sales
    ]

    return csv_download_response(
        filename=(
            "messis-sales-report-"
            f"{date.today().isoformat()}.csv"
        ),
        headers=[
            "Sale ID",
            "Sale Date",
            "Farm",
            "Buyer",
            "Product",
            "Quantity",
            "Unit",
            "Rate",
            "Gross Amount",
            "Transport Deduction",
            "Commission Deduction",
            "Other Deduction",
            "Net Amount",
            "Paid Amount",
            "Balance Amount",
            "Payment Status",
            "Payment Due Date",
            "Reference Number",
            "Notes",
        ],
        rows=rows,
    )


@app.get(
    "/reports/expenses.csv",
)
def expenses_report_csv(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    statement = select(Expense).where(
        Expense.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            Expense.farm_id == farm_id
        )

    if date_from is not None:
        statement = statement.where(
            Expense.expense_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            Expense.expense_date <= date_to
        )

    expenses = db.scalars(
        statement.order_by(
            Expense.expense_date.asc(),
            Expense.id.asc(),
        )
    ).all()

    farm_ids = {
        expense.farm_id
        for expense in expenses
        if expense.farm_id is not None
    }

    category_ids = {
        expense.category_id
        for expense in expenses
    }

    vendor_ids = {
        expense.vendor_id
        for expense in expenses
        if expense.vendor_id is not None
    }

    farms = {
        farm.id: farm.name
        for farm in db.scalars(
            select(Farm).where(
                Farm.owner_id == user.id,
                Farm.id.in_(farm_ids),
            )
        ).all()
    } if farm_ids else {}

    categories = {
        category.id: category.name
        for category in db.scalars(
            select(ExpenseCategory).where(
                ExpenseCategory.id.in_(category_ids)
            )
        ).all()
    } if category_ids else {}

    vendors = {
        vendor.id: vendor.name
        for vendor in db.scalars(
            select(Vendor).where(
                Vendor.owner_id == user.id,
                Vendor.id.in_(vendor_ids),
            )
        ).all()
    } if vendor_ids else {}

    rows = [
        [
            expense.id,
            expense.expense_date.isoformat(),
            farms.get(expense.farm_id, "General"),
            categories.get(
                expense.category_id,
                "",
            ),
            vendors.get(expense.vendor_id, ""),
            expense.description,
            expense.amount,
            expense.payment_mode,
            expense.reference_number,
            "Yes" if expense.is_recurring else "No",
            expense.notes,
        ]
        for expense in expenses
    ]

    return csv_download_response(
        filename=(
            "messis-expense-report-"
            f"{date.today().isoformat()}.csv"
        ),
        headers=[
            "Expense ID",
            "Expense Date",
            "Farm",
            "Category",
            "Vendor",
            "Description",
            "Amount",
            "Payment Mode",
            "Reference Number",
            "Recurring",
            "Notes",
        ],
        rows=rows,
    )


@app.get(
    "/reports/harvests.csv",
)
def harvests_report_csv(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    statement = select(HarvestRecord).where(
        HarvestRecord.owner_id == user.id
    )

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )
        statement = statement.where(
            HarvestRecord.farm_id == farm_id
        )

    if date_from is not None:
        statement = statement.where(
            HarvestRecord.harvest_date >= date_from
        )

    if date_to is not None:
        statement = statement.where(
            HarvestRecord.harvest_date <= date_to
        )

    records = db.scalars(
        statement.order_by(
            HarvestRecord.harvest_date.asc(),
            HarvestRecord.id.asc(),
        )
    ).all()

    farm_ids = {
        record.farm_id
        for record in records
    }

    farms = {
        farm.id: farm.name
        for farm in db.scalars(
            select(Farm).where(
                Farm.owner_id == user.id,
                Farm.id.in_(farm_ids),
            )
        ).all()
    } if farm_ids else {}

    rows = [
        [
            record.id,
            record.harvest_date.isoformat(),
            farms.get(record.farm_id, ""),
            record.harvest_cycle_id,
            record.trees_harvested,
            record.mature_coconuts,
            record.tender_coconuts,
            record.damaged_coconuts,
            record.total_coconuts,
            record.estimated_weight_kg,
            record.labour_count,
            record.labour_cost,
            record.climbing_cost,
            record.transport_cost,
            record.other_cost,
            record.total_harvest_cost,
            record.buyer_or_destination,
            record.notes,
        ]
        for record in records
    ]

    return csv_download_response(
        filename=(
            "messis-harvest-report-"
            f"{date.today().isoformat()}.csv"
        ),
        headers=[
            "Harvest ID",
            "Harvest Date",
            "Farm",
            "Harvest Cycle ID",
            "Trees Harvested",
            "Mature Coconuts",
            "Tender Coconuts",
            "Damaged Coconuts",
            "Total Coconuts",
            "Estimated Weight Kg",
            "Labour Count",
            "Labour Cost",
            "Climbing Cost",
            "Transport Cost",
            "Other Cost",
            "Total Harvest Cost",
            "Buyer or Destination",
            "Notes",
        ],
        rows=rows,
    )


@app.get(
    "/reports/profitability.csv",
)
def profitability_report_csv(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    if farm_id is not None:
        farms = [
            require_owned_farm(
                db=db,
                farm_id=farm_id,
                owner_id=user.id,
            )
        ]
    else:
        farms = db.scalars(
            select(Farm)
            .where(Farm.owner_id == user.id)
            .order_by(func.lower(Farm.name))
        ).all()

    results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=date_from,
            date_to=date_to,
        )
        for farm in farms
    ]

    rows = [
        [
            result["farm_id"],
            result["farm_name"],
            result["total_farm_trees"],
            result["harvested_trees"],
            result["total_coconuts"],
            result["revenue"],
            result["operating_expense"],
            result["harvest_cost"],
            result["total_cost"],
            result["net_profit"],
            result["profitability_percentage"],
            result["revenue_per_tree"],
            result["cost_per_tree"],
            result["profit_per_tree"],
            result["revenue_per_coconut"],
            result["cost_per_coconut"],
            result["profit_per_coconut"],
            result["yield_per_harvested_tree"],
        ]
        for result in results
    ]

    return csv_download_response(
        filename=(
            "messis-profitability-report-"
            f"{date.today().isoformat()}.csv"
        ),
        headers=[
            "Farm ID",
            "Farm Name",
            "Registered Trees",
            "Harvested Trees",
            "Total Coconuts",
            "Revenue",
            "Operating Expense",
            "Harvest Cost",
            "Total Cost",
            "Net Profit",
            "Return on Cost Percentage",
            "Revenue per Tree",
            "Cost per Tree",
            "Profit per Tree",
            "Revenue per Coconut",
            "Cost per Coconut",
            "Profit per Coconut",
            "Yield per Harvested Tree",
        ],
        rows=rows,
    )



# PATCH-REPORTS-001B: REPORT CENTER UI


@app.get(
    "/reports",
    response_class=HTMLResponse,
)
def reports_center(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    validate_report_dates(
        date_from=date_from,
        date_to=date_to,
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

    query_parts = []

    if farm_id is not None:
        query_parts.append(
            f"farm_id={farm_id}"
        )

    if date_from is not None:
        query_parts.append(
            f"date_from={date_from.isoformat()}"
        )

    if date_to is not None:
        query_parts.append(
            f"date_to={date_to.isoformat()}"
        )

    query_string = "&".join(query_parts)
    suffix = f"?{query_string}" if query_string else ""

    return templates.TemplateResponse(
        request=request,
        name="reports/index.html",
        context={
            "current_user": user,
            "farms": farms,
            "filters": {
                "farm_id": farm_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else ""
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else ""
                ),
            },
            "urls": {
                "summary": (
                    "/reports/summary" + suffix
                ),
                "sales": (
                    "/reports/sales.csv" + suffix
                ),
                "expenses": (
                    "/reports/expenses.csv" + suffix
                ),
                "harvests": (
                    "/reports/harvests.csv" + suffix
                ),
                "profitability": (
                    "/reports/profitability.csv" + suffix
                ),
            },
        },
    )



# PATCH-ANALYTICS-001A: YIELD AND FINANCIAL TREND ANALYTICS


def analytics_month_start(value: date) -> date:
    return value.replace(day=1)


def analytics_add_months(
    value: date,
    months: int,
) -> date:
    month_index = (
        value.year * 12
        + value.month
        - 1
        + months
    )

    year = month_index // 12
    month = month_index % 12 + 1

    return date(
        year=year,
        month=month,
        day=1,
    )


def analytics_month_key(value: date) -> str:
    return value.strftime("%Y-%m")


def analytics_month_label(value: date) -> str:
    return value.strftime("%b %Y")


def analytics_default_period() -> tuple[date, date]:
    today = date.today()
    current_month = analytics_month_start(today)

    return (
        analytics_add_months(
            current_month,
            -11,
        ),
        today,
    )


def analytics_resolve_period(
    date_from: date | None,
    date_to: date | None,
) -> tuple[date, date]:
    default_from, default_to = (
        analytics_default_period()
    )

    resolved_from = date_from or default_from
    resolved_to = date_to or default_to

    if resolved_from > resolved_to:
        raise HTTPException(
            status_code=422,
            detail=(
                "From date cannot be later "
                "than to date."
            ),
        )

    maximum_months = 60

    month_difference = (
        (
            resolved_to.year
            - resolved_from.year
        )
        * 12
        + resolved_to.month
        - resolved_from.month
    )

    if month_difference >= maximum_months:
        raise HTTPException(
            status_code=422,
            detail=(
                "Analytics period cannot exceed "
                "60 months."
            ),
        )

    return resolved_from, resolved_to


def analytics_month_series(
    date_from: date,
    date_to: date,
) -> list[date]:
    months: list[date] = []

    current = analytics_month_start(date_from)
    final_month = analytics_month_start(date_to)

    while current <= final_month:
        months.append(current)
        current = analytics_add_months(
            current,
            1,
        )

    return months


def analytics_decimal(
    value: object,
) -> Decimal:
    if value is None:
        return Decimal("0.00")

    return Decimal(str(value)).quantize(
        Decimal("0.01")
    )


def analytics_safe_divide(
    numerator: Decimal,
    denominator: Decimal,
) -> Decimal:
    if denominator == 0:
        return Decimal("0.00")

    return (
        numerator / denominator
    ).quantize(Decimal("0.01"))


@app.get(
    "/analytics/trends",
    response_class=JSONResponse,
)
def analytics_trends(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    resolved_from, resolved_to = (
        analytics_resolve_period(
            date_from=date_from,
            date_to=date_to,
        )
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

        analytics_farms = [selected_farm]
    else:
        analytics_farms = farms

    selected_farm_ids = {
        farm.id
        for farm in analytics_farms
    }

    months = analytics_month_series(
        date_from=resolved_from,
        date_to=resolved_to,
    )

    month_data: dict[str, dict[str, object]] = {}

    for month in months:
        key = analytics_month_key(month)

        month_data[key] = {
            "month": key,
            "label": analytics_month_label(month),
            "mature_coconuts": 0,
            "tender_coconuts": 0,
            "damaged_coconuts": 0,
            "total_coconuts": 0,
            "trees_harvested": 0,
            "harvest_cost": Decimal("0.00"),
            "sales_revenue": Decimal("0.00"),
            "paid_amount": Decimal("0.00"),
            "outstanding_amount": Decimal("0.00"),
            "operating_expense": Decimal("0.00"),
        }

    harvest_statement = (
        select(HarvestRecord)
        .where(
            HarvestRecord.owner_id == user.id,
            HarvestRecord.harvest_date
            >= resolved_from,
            HarvestRecord.harvest_date
            <= resolved_to,
        )
        .order_by(
            HarvestRecord.harvest_date.asc(),
            HarvestRecord.id.asc(),
        )
    )

    sale_statement = (
        select(Sale)
        .where(
            Sale.owner_id == user.id,
            Sale.sale_date >= resolved_from,
            Sale.sale_date <= resolved_to,
        )
        .order_by(
            Sale.sale_date.asc(),
            Sale.id.asc(),
        )
    )

    expense_statement = (
        select(Expense)
        .where(
            Expense.owner_id == user.id,
            Expense.expense_date
            >= resolved_from,
            Expense.expense_date
            <= resolved_to,
        )
        .order_by(
            Expense.expense_date.asc(),
            Expense.id.asc(),
        )
    )

    if farm_id is not None:
        harvest_statement = (
            harvest_statement.where(
                HarvestRecord.farm_id == farm_id
            )
        )

        sale_statement = sale_statement.where(
            Sale.farm_id == farm_id
        )

        expense_statement = (
            expense_statement.where(
                Expense.farm_id == farm_id
            )
        )

    harvests = db.scalars(
        harvest_statement
    ).all()

    sales = db.scalars(
        sale_statement
    ).all()

    expenses = db.scalars(
        expense_statement
    ).all()

    for record in harvests:
        key = analytics_month_key(
            record.harvest_date
        )

        bucket = month_data.get(key)

        if bucket is None:
            continue

        bucket["mature_coconuts"] += int(
            record.mature_coconuts or 0
        )

        bucket["tender_coconuts"] += int(
            record.tender_coconuts or 0
        )

        bucket["damaged_coconuts"] += int(
            record.damaged_coconuts or 0
        )

        bucket["total_coconuts"] += int(
            record.total_coconuts or 0
        )

        bucket["trees_harvested"] += int(
            record.trees_harvested or 0
        )

        bucket["harvest_cost"] += (
            analytics_decimal(
                record.total_harvest_cost
            )
        )

    for sale in sales:
        key = analytics_month_key(
            sale.sale_date
        )

        bucket = month_data.get(key)

        if bucket is None:
            continue

        bucket["sales_revenue"] += (
            analytics_decimal(
                sale.net_amount
            )
        )

        bucket["paid_amount"] += (
            analytics_decimal(
                sale.paid_amount
            )
        )

        bucket["outstanding_amount"] += (
            analytics_decimal(
                sale.balance_amount
            )
        )

    for expense in expenses:
        key = analytics_month_key(
            expense.expense_date
        )

        bucket = month_data.get(key)

        if bucket is None:
            continue

        bucket["operating_expense"] += (
            analytics_decimal(
                expense.amount
            )
        )

    monthly_rows: list[dict[str, object]] = []

    for month in months:
        key = analytics_month_key(month)
        bucket = month_data[key]

        harvest_cost = analytics_decimal(
            bucket["harvest_cost"]
        )

        sales_revenue = analytics_decimal(
            bucket["sales_revenue"]
        )

        paid_amount = analytics_decimal(
            bucket["paid_amount"]
        )

        outstanding_amount = analytics_decimal(
            bucket["outstanding_amount"]
        )

        operating_expense = analytics_decimal(
            bucket["operating_expense"]
        )

        total_cost = (
            operating_expense
            + harvest_cost
        ).quantize(Decimal("0.01"))

        net_profit = (
            sales_revenue
            - total_cost
        ).quantize(Decimal("0.01"))

        total_coconuts = int(
            bucket["total_coconuts"]
        )

        trees_harvested = int(
            bucket["trees_harvested"]
        )

        yield_per_tree = (
            analytics_safe_divide(
                Decimal(total_coconuts),
                Decimal(trees_harvested),
            )
        )

        damage_percentage = (
            analytics_safe_divide(
                Decimal(
                    int(
                        bucket[
                            "damaged_coconuts"
                        ]
                    )
                    * 100
                ),
                Decimal(total_coconuts),
            )
        )

        monthly_rows.append(
            {
                "month": bucket["month"],
                "label": bucket["label"],
                "yield": {
                    "mature_coconuts": int(
                        bucket[
                            "mature_coconuts"
                        ]
                    ),
                    "tender_coconuts": int(
                        bucket[
                            "tender_coconuts"
                        ]
                    ),
                    "damaged_coconuts": int(
                        bucket[
                            "damaged_coconuts"
                        ]
                    ),
                    "total_coconuts": (
                        total_coconuts
                    ),
                    "trees_harvested": (
                        trees_harvested
                    ),
                    "yield_per_tree": str(
                        yield_per_tree
                    ),
                    "damage_percentage": str(
                        damage_percentage
                    ),
                },
                "financial": {
                    "sales_revenue": str(
                        sales_revenue
                    ),
                    "operating_expense": str(
                        operating_expense
                    ),
                    "harvest_cost": str(
                        harvest_cost
                    ),
                    "total_cost": str(
                        total_cost
                    ),
                    "net_profit": str(
                        net_profit
                    ),
                    "paid_amount": str(
                        paid_amount
                    ),
                    "outstanding_amount": str(
                        outstanding_amount
                    ),
                },
            }
        )

    farm_comparison: list[dict[str, object]] = []

    for farm in analytics_farms:
        result = calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=resolved_from,
            date_to=resolved_to,
        )

        farm_comparison.append(
            {
                key: (
                    str(value)
                    if isinstance(
                        value,
                        Decimal,
                    )
                    else value
                )
                for key, value in result.items()
            }
        )

    farm_comparison.sort(
        key=lambda item: Decimal(
            str(item["net_profit"])
        ),
        reverse=True,
    )

    total_revenue = sum(
        (
            analytics_decimal(
                sale.net_amount
            )
            for sale in sales
        ),
        Decimal("0.00"),
    )

    total_paid = sum(
        (
            analytics_decimal(
                sale.paid_amount
            )
            for sale in sales
        ),
        Decimal("0.00"),
    )

    total_outstanding = sum(
        (
            analytics_decimal(
                sale.balance_amount
            )
            for sale in sales
        ),
        Decimal("0.00"),
    )

    total_operating_expense = sum(
        (
            analytics_decimal(
                expense.amount
            )
            for expense in expenses
        ),
        Decimal("0.00"),
    )

    total_harvest_cost = sum(
        (
            analytics_decimal(
                record.total_harvest_cost
            )
            for record in harvests
        ),
        Decimal("0.00"),
    )

    total_cost = (
        total_operating_expense
        + total_harvest_cost
    ).quantize(Decimal("0.01"))

    total_profit = (
        total_revenue - total_cost
    ).quantize(Decimal("0.01"))

    total_coconuts = sum(
        int(record.total_coconuts or 0)
        for record in harvests
    )

    total_trees_harvested = sum(
        int(record.trees_harvested or 0)
        for record in harvests
    )

    total_damaged = sum(
        int(record.damaged_coconuts or 0)
        for record in harvests
    )

    best_month = None

    if monthly_rows:
        best_month_row = max(
            monthly_rows,
            key=lambda item: Decimal(
                item["financial"][
                    "net_profit"
                ]
            ),
        )

        best_month = {
            "month": best_month_row["month"],
            "label": best_month_row["label"],
            "net_profit": (
                best_month_row[
                    "financial"
                ]["net_profit"]
            ),
        }

    selected_farm = None

    if farm_id is not None:
        selected_farm = {
            "id": analytics_farms[0].id,
            "name": analytics_farms[0].name,
        }

    return {
        "period": {
            "date_from": (
                resolved_from.isoformat()
            ),
            "date_to": (
                resolved_to.isoformat()
            ),
            "month_count": len(months),
        },
        "filter": {
            "farm": selected_farm,
            "all_farms": farm_id is None,
        },
        "summary": {
            "farm_count": len(
                selected_farm_ids
            ),
            "harvest_count": len(harvests),
            "sale_count": len(sales),
            "expense_count": len(expenses),
            "total_coconuts": total_coconuts,
            "total_trees_harvested": (
                total_trees_harvested
            ),
            "yield_per_tree": str(
                analytics_safe_divide(
                    Decimal(total_coconuts),
                    Decimal(
                        total_trees_harvested
                    ),
                )
            ),
            "damage_percentage": str(
                analytics_safe_divide(
                    Decimal(
                        total_damaged * 100
                    ),
                    Decimal(total_coconuts),
                )
            ),
            "total_revenue": str(
                total_revenue.quantize(
                    Decimal("0.01")
                )
            ),
            "total_paid": str(
                total_paid.quantize(
                    Decimal("0.01")
                )
            ),
            "total_outstanding": str(
                total_outstanding.quantize(
                    Decimal("0.01")
                )
            ),
            "operating_expense": str(
                total_operating_expense.quantize(
                    Decimal("0.01")
                )
            ),
            "harvest_cost": str(
                total_harvest_cost.quantize(
                    Decimal("0.01")
                )
            ),
            "total_cost": str(total_cost),
            "net_profit": str(total_profit),
            "profitability_percentage": str(
                profitability_percentage(
                    total_profit,
                    total_cost,
                )
            ),
            "profit_per_coconut": str(
                analytics_safe_divide(
                    total_profit,
                    Decimal(total_coconuts),
                )
            ),
            "best_month": best_month,
        },
        "monthly": monthly_rows,
        "farm_comparison": farm_comparison,
    }


@app.get(
    "/analytics/farm-comparison",
    response_class=JSONResponse,
)
def analytics_farm_comparison(
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    resolved_from, resolved_to = (
        analytics_resolve_period(
            date_from=date_from,
            date_to=date_to,
        )
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    results = [
        calculate_farm_profitability(
            farm=farm,
            owner_id=user.id,
            db=db,
            date_from=resolved_from,
            date_to=resolved_to,
        )
        for farm in farms
    ]

    results.sort(
        key=lambda item: item["net_profit"],
        reverse=True,
    )

    return {
        "period": {
            "date_from": (
                resolved_from.isoformat()
            ),
            "date_to": (
                resolved_to.isoformat()
            ),
        },
        "farm_count": len(results),
        "items": [
            {
                key: (
                    str(value)
                    if isinstance(
                        value,
                        Decimal,
                    )
                    else value
                )
                for key, value in result.items()
            }
            for result in results
        ],
    }



# PATCH-ANALYTICS-001B: ANALYTICS DASHBOARD UI


def analytics_chart_percentage(
    value: object,
    maximum: Decimal,
) -> Decimal:
    parsed_value = abs(
        Decimal(str(value or 0))
    )

    if maximum <= 0:
        return Decimal("0.00")

    percentage = (
        parsed_value
        / maximum
        * Decimal("100")
    ).quantize(Decimal("0.01"))

    if parsed_value > 0 and percentage < 2:
        return Decimal("2.00")

    return min(
        percentage,
        Decimal("100.00"),
    )


@app.get(
    "/analytics/manage",
    response_class=HTMLResponse,
)
def analytics_management_page(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    analytics_data = analytics_trends(
        farm_id=farm_id,
        date_from=date_from,
        date_to=date_to,
        user=user,
        db=db,
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    monthly = analytics_data["monthly"]

    maximum_financial = max(
        [
            abs(
                Decimal(
                    row["financial"][
                        "sales_revenue"
                    ]
                )
            )
            for row in monthly
        ]
        + [
            abs(
                Decimal(
                    row["financial"][
                        "total_cost"
                    ]
                )
            )
            for row in monthly
        ]
        + [
            abs(
                Decimal(
                    row["financial"][
                        "net_profit"
                    ]
                )
            )
            for row in monthly
        ]
        + [Decimal("0.00")]
    )

    maximum_yield = max(
        [
            Decimal(
                row["yield"][
                    "mature_coconuts"
                ]
            )
            for row in monthly
        ]
        + [
            Decimal(
                row["yield"][
                    "tender_coconuts"
                ]
            )
            for row in monthly
        ]
        + [
            Decimal(
                row["yield"][
                    "damaged_coconuts"
                ]
            )
            for row in monthly
        ]
        + [Decimal("0.00")]
    )

    maximum_payment = max(
        [
            Decimal(
                row["financial"][
                    "paid_amount"
                ]
            )
            for row in monthly
        ]
        + [
            Decimal(
                row["financial"][
                    "outstanding_amount"
                ]
            )
            for row in monthly
        ]
        + [Decimal("0.00")]
    )

    for row in monthly:
        financial = row["financial"]
        yield_data = row["yield"]

        row["chart"] = {
            "revenue_height": str(
                analytics_chart_percentage(
                    financial["sales_revenue"],
                    maximum_financial,
                )
            ),
            "cost_height": str(
                analytics_chart_percentage(
                    financial["total_cost"],
                    maximum_financial,
                )
            ),
            "profit_height": str(
                analytics_chart_percentage(
                    financial["net_profit"],
                    maximum_financial,
                )
            ),
            "mature_height": str(
                analytics_chart_percentage(
                    yield_data[
                        "mature_coconuts"
                    ],
                    maximum_yield,
                )
            ),
            "tender_height": str(
                analytics_chart_percentage(
                    yield_data[
                        "tender_coconuts"
                    ],
                    maximum_yield,
                )
            ),
            "damaged_height": str(
                analytics_chart_percentage(
                    yield_data[
                        "damaged_coconuts"
                    ],
                    maximum_yield,
                )
            ),
            "paid_height": str(
                analytics_chart_percentage(
                    financial["paid_amount"],
                    maximum_payment,
                )
            ),
            "outstanding_height": str(
                analytics_chart_percentage(
                    financial[
                        "outstanding_amount"
                    ],
                    maximum_payment,
                )
            ),
        }

    resolved_period = analytics_data["period"]

    return templates.TemplateResponse(
        request=request,
        name="analytics/index.html",
        context={
            "current_user": user,
            "farms": farms,
            "summary": analytics_data[
                "summary"
            ],
            "monthly": monthly,
            "farm_comparison": analytics_data[
                "farm_comparison"
            ],
            "period": resolved_period,
            "filters": {
                "farm_id": farm_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else resolved_period[
                        "date_from"
                    ]
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else resolved_period[
                        "date_to"
                    ]
                ),
            },
        },
    )



# PATCH-AI-001A: FARM RECOMMENDATION ENGINE FOUNDATION


MESSIS_RECOMMENDATION_PRIORITIES = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def recommendation_item(
    code: str,
    category: str,
    priority: str,
    title: str,
    message: str,
    action: str,
    action_url: str | None = None,
    metric: dict[str, object] | None = None,
) -> dict[str, object]:
    return {
        "code": code,
        "category": category,
        "priority": priority,
        "priority_score": (
            MESSIS_RECOMMENDATION_PRIORITIES[
                priority
            ]
        ),
        "title": title,
        "message": message,
        "recommended_action": action,
        "action_url": action_url,
        "metric": metric,
    }


def recommendation_decimal(
    value: object,
) -> Decimal:
    if value is None:
        return Decimal("0.00")

    return Decimal(str(value)).quantize(
        Decimal("0.01")
    )


def farm_recommendation_engine(
    farm: Farm,
    user: User,
    db: Session,
    date_from: date,
    date_to: date,
) -> dict[str, object]:
    analytics = analytics_trends(
        farm_id=farm.id,
        date_from=date_from,
        date_to=date_to,
        user=user,
        db=db,
    )

    summary = analytics["summary"]
    monthly = analytics["monthly"]

    recommendations: list[
        dict[str, object]
    ] = []

    total_trees = int(
        farm.total_trees or 0
    )

    total_coconuts = int(
        summary["total_coconuts"] or 0
    )

    harvest_count = int(
        summary["harvest_count"] or 0
    )

    sale_count = int(
        summary["sale_count"] or 0
    )

    expense_count = int(
        summary["expense_count"] or 0
    )

    yield_per_tree = recommendation_decimal(
        summary["yield_per_tree"]
    )

    damage_percentage = (
        recommendation_decimal(
            summary["damage_percentage"]
        )
    )

    revenue = recommendation_decimal(
        summary["total_revenue"]
    )

    total_cost = recommendation_decimal(
        summary["total_cost"]
    )

    net_profit = recommendation_decimal(
        summary["net_profit"]
    )

    outstanding = recommendation_decimal(
        summary["total_outstanding"]
    )

    profitability = recommendation_decimal(
        summary[
            "profitability_percentage"
        ]
    )

    profit_per_coconut = (
        recommendation_decimal(
            summary["profit_per_coconut"]
        )
    )

    today = date.today()

    active_cycles = db.scalars(
        select(HarvestCycle)
        .where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.farm_id == farm.id,
        )
        .order_by(
            HarvestCycle.planned_harvest_date.asc()
        )
    ).all()

    overdue_cycles = []

    due_cycles = []

    for cycle in active_cycles:
        if cycle.status in {
            "Completed",
            "Cancelled",
        }:
            continue

        current_status = harvest_cycle_status(
            cycle.planned_harvest_date,
            cycle.minimum_due_date,
            cycle.maximum_due_date,
            today,
        )

        if current_status == "Overdue":
            overdue_cycles.append(cycle)
        elif current_status in {
            "Due Soon",
            "Due",
        }:
            due_cycles.append(cycle)

    if overdue_cycles:
        recommendations.append(
            recommendation_item(
                code="HARVEST_OVERDUE",
                category="Harvest",
                priority="critical",
                title="Harvest activity is overdue",
                message=(
                    f"{len(overdue_cycles)} harvest "
                    "cycle(s) have crossed the "
                    "recommended harvest window."
                ),
                action=(
                    "Review the overdue cycles and "
                    "record or reschedule the harvest."
                ),
                action_url="/harvests/manage",
                metric={
                    "overdue_cycles": (
                        len(overdue_cycles)
                    ),
                },
            )
        )
    elif due_cycles:
        recommendations.append(
            recommendation_item(
                code="HARVEST_DUE",
                category="Harvest",
                priority="high",
                title="Prepare for the next harvest",
                message=(
                    f"{len(due_cycles)} harvest "
                    "cycle(s) are due or approaching "
                    "the planned date."
                ),
                action=(
                    "Confirm labour, climbers, "
                    "transport, and buyer readiness."
                ),
                action_url="/harvests/manage",
                metric={
                    "due_cycles": len(due_cycles),
                },
            )
        )

    if harvest_count == 0:
        recommendations.append(
            recommendation_item(
                code="NO_HARVEST_DATA",
                category="Data",
                priority="high",
                title="Harvest records are missing",
                message=(
                    "No completed harvest record was "
                    "found for the selected period."
                ),
                action=(
                    "Record harvested trees, coconut "
                    "quantity, damage, and harvest cost."
                ),
                action_url=(
                    "/harvest-records/manage"
                ),
            )
        )

    if total_trees > 0 and harvest_count > 0:
        if yield_per_tree < Decimal("8.00"):
            recommendations.append(
                recommendation_item(
                    code="LOW_YIELD_PER_TREE",
                    category="Yield",
                    priority="high",
                    title="Yield per tree is low",
                    message=(
                        "Average yield is "
                        f"{yield_per_tree} coconuts "
                        "per harvested tree."
                    ),
                    action=(
                        "Review irrigation frequency, "
                        "soil nutrition, pest symptoms, "
                        "and harvest timing."
                    ),
                    action_url=(
                        "/analytics/manage"
                        f"?farm_id={farm.id}"
                    ),
                    metric={
                        "yield_per_tree": str(
                            yield_per_tree
                        ),
                        "reference_level": "8.00",
                    },
                )
            )
        elif yield_per_tree >= Decimal("20.00"):
            recommendations.append(
                recommendation_item(
                    code="STRONG_YIELD",
                    category="Yield",
                    priority="info",
                    title="Yield performance is strong",
                    message=(
                        "Average yield reached "
                        f"{yield_per_tree} coconuts "
                        "per harvested tree."
                    ),
                    action=(
                        "Continue the present farm "
                        "practice and document what "
                        "worked well."
                    ),
                    action_url=(
                        "/analytics/manage"
                        f"?farm_id={farm.id}"
                    ),
                    metric={
                        "yield_per_tree": str(
                            yield_per_tree
                        ),
                    },
                )
            )

    if damage_percentage > Decimal("10.00"):
        recommendations.append(
            recommendation_item(
                code="HIGH_DAMAGE_RATE",
                category="Crop Quality",
                priority="high",
                title="Coconut damage rate is high",
                message=(
                    f"{damage_percentage}% of recorded "
                    "coconuts were damaged."
                ),
                action=(
                    "Inspect pest or disease symptoms, "
                    "handling methods, storage, and "
                    "harvest maturity."
                ),
                action_url=(
                    "/harvest-records/manage"
                ),
                metric={
                    "damage_percentage": str(
                        damage_percentage
                    ),
                    "recommended_maximum": "10.00",
                },
            )
        )
    elif (
        harvest_count > 0
        and damage_percentage <= Decimal("3.00")
    ):
        recommendations.append(
            recommendation_item(
                code="GOOD_CROP_QUALITY",
                category="Crop Quality",
                priority="info",
                title="Crop damage is under control",
                message=(
                    "Recorded damage is "
                    f"{damage_percentage}%."
                ),
                action=(
                    "Maintain the current harvesting "
                    "and handling controls."
                ),
                metric={
                    "damage_percentage": str(
                        damage_percentage
                    ),
                },
            )
        )

    if revenue > 0 and net_profit < 0:
        recommendations.append(
            recommendation_item(
                code="NEGATIVE_PROFIT",
                category="Finance",
                priority="critical",
                title="Farm is operating at a loss",
                message=(
                    f"Revenue is ₹{revenue}, while "
                    f"total cost is ₹{total_cost}."
                ),
                action=(
                    "Review the highest expense "
                    "categories, harvest cost, sale "
                    "rate, and deductions."
                ),
                action_url=(
                    "/profitability/manage"
                    f"?farm_id={farm.id}"
                ),
                metric={
                    "revenue": str(revenue),
                    "total_cost": str(total_cost),
                    "net_profit": str(net_profit),
                },
            )
        )
    elif (
        revenue > 0
        and profitability < Decimal("20.00")
    ):
        recommendations.append(
            recommendation_item(
                code="LOW_PROFITABILITY",
                category="Finance",
                priority="high",
                title="Profit margin needs attention",
                message=(
                    "Return on cost is "
                    f"{profitability}%."
                ),
                action=(
                    "Compare buyer rates, reduce "
                    "avoidable deductions, and review "
                    "farm-wise operating expenses."
                ),
                action_url=(
                    "/profitability/manage"
                    f"?farm_id={farm.id}"
                ),
                metric={
                    "profitability_percentage": str(
                        profitability
                    ),
                },
            )
        )
    elif (
        net_profit > 0
        and profitability >= Decimal("50.00")
    ):
        recommendations.append(
            recommendation_item(
                code="HEALTHY_PROFITABILITY",
                category="Finance",
                priority="info",
                title="Farm profitability is healthy",
                message=(
                    "Return on cost is "
                    f"{profitability}%."
                ),
                action=(
                    "Preserve the successful expense "
                    "and sales practices."
                ),
                action_url=(
                    "/profitability/manage"
                    f"?farm_id={farm.id}"
                ),
                metric={
                    "profitability_percentage": str(
                        profitability
                    ),
                    "net_profit": str(net_profit),
                },
            )
        )

    if outstanding > 0:
        outstanding_ratio = (
            (
                outstanding
                / revenue
                * Decimal("100")
            ).quantize(Decimal("0.01"))
            if revenue > 0
            else Decimal("100.00")
        )

        priority = (
            "high"
            if outstanding_ratio
            >= Decimal("40.00")
            else "medium"
        )

        recommendations.append(
            recommendation_item(
                code="OUTSTANDING_COLLECTION",
                category="Sales",
                priority=priority,
                title="Sale payment collection is pending",
                message=(
                    f"₹{outstanding} remains "
                    "outstanding, representing "
                    f"{outstanding_ratio}% of revenue."
                ),
                action=(
                    "Follow up with buyers and record "
                    "received payments."
                ),
                action_url="/sales/manage",
                metric={
                    "outstanding": str(
                        outstanding
                    ),
                    "outstanding_percentage": str(
                        outstanding_ratio
                    ),
                },
            )
        )

    if sale_count == 0 and total_coconuts > 0:
        recommendations.append(
            recommendation_item(
                code="HARVEST_WITHOUT_SALE",
                category="Sales",
                priority="high",
                title="Harvest recorded without sales",
                message=(
                    f"{total_coconuts} coconuts were "
                    "recorded, but no sale was entered "
                    "for the period."
                ),
                action=(
                    "Record the sale or destination "
                    "of the harvested produce."
                ),
                action_url="/sales/new",
                metric={
                    "total_coconuts": (
                        total_coconuts
                    ),
                },
            )
        )

    if expense_count == 0 and harvest_count > 0:
        recommendations.append(
            recommendation_item(
                code="MISSING_OPERATING_EXPENSES",
                category="Data",
                priority="medium",
                title="Operating expenses may be incomplete",
                message=(
                    "Harvest activity exists, but no "
                    "daily operating expense was "
                    "recorded for the period."
                ),
                action=(
                    "Review labour, fertilizer, "
                    "irrigation, maintenance, and "
                    "transport expenses."
                ),
                action_url="/expenses/new",
            )
        )

    if (
        total_coconuts > 0
        and profit_per_coconut <= 0
    ):
        recommendations.append(
            recommendation_item(
                code="NON_PROFITABLE_UNIT",
                category="Finance",
                priority="high",
                title="Profit per coconut is not positive",
                message=(
                    "Calculated profit per coconut is "
                    f"₹{profit_per_coconut}."
                ),
                action=(
                    "Review sale rates, deductions, "
                    "harvest cost, and operating cost "
                    "per coconut."
                ),
                action_url=(
                    "/profitability/manage"
                    f"?farm_id={farm.id}"
                ),
                metric={
                    "profit_per_coconut": str(
                        profit_per_coconut
                    ),
                },
            )
        )

    recent_yield = [
        int(
            row["yield"][
                "total_coconuts"
            ]
        )
        for row in monthly[-3:]
    ]

    if (
        len(recent_yield) == 3
        and recent_yield[0] > 0
        and recent_yield[1] < recent_yield[0]
        and recent_yield[2] < recent_yield[1]
    ):
        decline = (
            Decimal(
                recent_yield[0]
                - recent_yield[2]
            )
            / Decimal(recent_yield[0])
            * Decimal("100")
        ).quantize(Decimal("0.01"))

        recommendations.append(
            recommendation_item(
                code="DECLINING_YIELD_TREND",
                category="Yield",
                priority="high",
                title="Yield has declined for three periods",
                message=(
                    "Recorded monthly yield fell from "
                    f"{recent_yield[0]} to "
                    f"{recent_yield[2]} coconuts."
                ),
                action=(
                    "Inspect water availability, soil "
                    "nutrition, pest pressure, and "
                    "tree health."
                ),
                action_url=(
                    "/analytics/manage"
                    f"?farm_id={farm.id}"
                ),
                metric={
                    "decline_percentage": str(
                        decline
                    ),
                    "previous_yield": (
                        recent_yield[0]
                    ),
                    "latest_yield": (
                        recent_yield[2]
                    ),
                },
            )
        )

    if not recommendations:
        recommendations.append(
            recommendation_item(
                code="NO_IMMEDIATE_RISK",
                category="General",
                priority="info",
                title="No immediate risk detected",
                message=(
                    "The available farm records do not "
                    "show a major operational or "
                    "financial warning."
                ),
                action=(
                    "Continue entering harvest, "
                    "expense, sales, and payment data "
                    "regularly."
                ),
                action_url="/dashboard",
            )
        )

    recommendations.sort(
        key=lambda item: (
            int(item["priority_score"]),
            item["category"],
            item["title"],
        ),
        reverse=True,
    )

    priority_counts = {
        priority: sum(
            item["priority"] == priority
            for item in recommendations
        )
        for priority in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )
    }

    return {
        "farm": {
            "id": farm.id,
            "name": farm.name,
            "total_trees": total_trees,
        },
        "period": {
            "date_from": date_from.isoformat(),
            "date_to": date_to.isoformat(),
        },
        "summary": {
            "recommendation_count": len(
                recommendations
            ),
            "priority_counts": priority_counts,
            "total_coconuts": total_coconuts,
            "yield_per_tree": str(
                yield_per_tree
            ),
            "damage_percentage": str(
                damage_percentage
            ),
            "revenue": str(revenue),
            "total_cost": str(total_cost),
            "net_profit": str(net_profit),
            "outstanding": str(outstanding),
            "profitability_percentage": str(
                profitability
            ),
            "profit_per_coconut": str(
                profit_per_coconut
            ),
        },
        "recommendations": recommendations,
    }


@app.get(
    "/ai/recommendations",
    response_class=JSONResponse,
)
def all_farm_recommendations(
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    resolved_from, resolved_to = (
        analytics_resolve_period(
            date_from=date_from,
            date_to=date_to,
        )
    )

    if farm_id is not None:
        farms = [
            require_owned_farm(
                db=db,
                farm_id=farm_id,
                owner_id=user.id,
            )
        ]
    else:
        farms = db.scalars(
            select(Farm)
            .where(Farm.owner_id == user.id)
            .order_by(func.lower(Farm.name))
        ).all()

    farm_results = [
        farm_recommendation_engine(
            farm=farm,
            user=user,
            db=db,
            date_from=resolved_from,
            date_to=resolved_to,
        )
        for farm in farms
    ]

    all_items = [
        {
            **item,
            "farm_id": result["farm"]["id"],
            "farm_name": result["farm"]["name"],
        }
        for result in farm_results
        for item in result["recommendations"]
    ]

    all_items.sort(
        key=lambda item: (
            int(item["priority_score"]),
            item["farm_name"],
            item["title"],
        ),
        reverse=True,
    )

    return {
        "period": {
            "date_from": (
                resolved_from.isoformat()
            ),
            "date_to": (
                resolved_to.isoformat()
            ),
        },
        "farm_count": len(farm_results),
        "recommendation_count": len(
            all_items
        ),
        "priority_counts": {
            priority: sum(
                item["priority"] == priority
                for item in all_items
            )
            for priority in (
                "critical",
                "high",
                "medium",
                "low",
                "info",
            )
        },
        "recommendations": all_items,
        "farms": farm_results,
    }


@app.get(
    "/ai/farms/{farm_id}/recommendations",
    response_class=JSONResponse,
)
def farm_recommendations(
    farm_id: int,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    resolved_from, resolved_to = (
        analytics_resolve_period(
            date_from=date_from,
            date_to=date_to,
        )
    )

    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    return farm_recommendation_engine(
        farm=farm,
        user=user,
        db=db,
        date_from=resolved_from,
        date_to=resolved_to,
    )



# PATCH-AI-001B: RECOMMENDATION CENTER UI


@app.get(
    "/ai/manage",
    response_class=HTMLResponse,
)
def recommendation_management_page(
    request: Request,
    farm_id: int | None = None,
    date_from: date | None = None,
    date_to: date | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    resolved_from, resolved_to = (
        analytics_resolve_period(
            date_from=date_from,
            date_to=date_to,
        )
    )

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

        analysed_farms = [selected_farm]
    else:
        analysed_farms = farms

    farm_results = [
        farm_recommendation_engine(
            farm=farm,
            user=user,
            db=db,
            date_from=resolved_from,
            date_to=resolved_to,
        )
        for farm in analysed_farms
    ]

    all_recommendations = [
        item
        for result in farm_results
        for item in result["recommendations"]
    ]

    priority_counts = {
        priority: sum(
            item["priority"] == priority
            for item in all_recommendations
        )
        for priority in (
            "critical",
            "high",
            "medium",
            "low",
            "info",
        )
    }

    category_totals: dict[str, int] = {}

    for item in all_recommendations:
        category = str(
            item.get("category") or "General"
        )

        category_totals[category] = (
            category_totals.get(category, 0)
            + 1
        )

    category_counts = sorted(
        category_totals.items(),
        key=lambda item: (
            item[1],
            item[0],
        ),
        reverse=True,
    )

    return templates.TemplateResponse(
        request=request,
        name="ai/recommendations.html",
        context={
            "current_user": user,
            "farms": farms,
            "farm_results": farm_results,
            "farm_count": len(farm_results),
            "recommendation_count": len(
                all_recommendations
            ),
            "priority_counts": priority_counts,
            "category_counts": category_counts,
            "period": {
                "date_from": (
                    resolved_from.isoformat()
                ),
                "date_to": (
                    resolved_to.isoformat()
                ),
            },
            "filters": {
                "farm_id": farm_id or "",
                "date_from": (
                    date_from.isoformat()
                    if date_from
                    else resolved_from.isoformat()
                ),
                "date_to": (
                    date_to.isoformat()
                    if date_to
                    else resolved_to.isoformat()
                ),
            },
        },
    )



# PATCH-WEATHER-001A: WEATHER DATA FOUNDATION


MESSIS_WEATHER_PROVIDER = "Open-Meteo"

MESSIS_WEATHER_PROVIDER_URL = (
    "https://api.open-meteo.com/v1/forecast"
)

MESSIS_WEATHER_CODES = {
    0: "Clear sky",
    1: "Mainly clear",
    2: "Partly cloudy",
    3: "Overcast",
    45: "Fog",
    48: "Depositing rime fog",
    51: "Light drizzle",
    53: "Moderate drizzle",
    55: "Dense drizzle",
    56: "Light freezing drizzle",
    57: "Dense freezing drizzle",
    61: "Slight rain",
    63: "Moderate rain",
    65: "Heavy rain",
    66: "Light freezing rain",
    67: "Heavy freezing rain",
    71: "Slight snowfall",
    73: "Moderate snowfall",
    75: "Heavy snowfall",
    77: "Snow grains",
    80: "Slight rain showers",
    81: "Moderate rain showers",
    82: "Violent rain showers",
    85: "Slight snow showers",
    86: "Heavy snow showers",
    95: "Thunderstorm",
    96: "Thunderstorm with slight hail",
    99: "Thunderstorm with heavy hail",
}


def weather_decimal(
    value: object,
) -> Decimal:
    if value is None:
        return Decimal("0.00")

    try:
        return Decimal(str(value)).quantize(
            Decimal("0.01")
        )
    except Exception:
        return Decimal("0.00")


def weather_code_description(
    code: object,
) -> str:
    try:
        parsed_code = int(code)
    except (TypeError, ValueError):
        return "Unknown"

    return MESSIS_WEATHER_CODES.get(
        parsed_code,
        "Unknown",
    )


def validate_weather_coordinates(
    latitude: float,
    longitude: float,
) -> None:
    if not -90 <= latitude <= 90:
        raise HTTPException(
            status_code=422,
            detail=(
                "Latitude must be between "
                "-90 and 90."
            ),
        )

    if not -180 <= longitude <= 180:
        raise HTTPException(
            status_code=422,
            detail=(
                "Longitude must be between "
                "-180 and 180."
            ),
        )


def fetch_weather_forecast(
    latitude: float,
    longitude: float,
    forecast_days: int = 7,
) -> dict[str, object]:
    validate_weather_coordinates(
        latitude=latitude,
        longitude=longitude,
    )

    if forecast_days < 1 or forecast_days > 16:
        raise HTTPException(
            status_code=422,
            detail=(
                "Forecast days must be between "
                "1 and 16."
            ),
        )

    parameters = {
        "latitude": f"{latitude:.6f}",
        "longitude": f"{longitude:.6f}",
        "timezone": "auto",
        "forecast_days": str(forecast_days),
        "current": ",".join(
            [
                "temperature_2m",
                "relative_humidity_2m",
                "apparent_temperature",
                "precipitation",
                "rain",
                "weather_code",
                "cloud_cover",
                "wind_speed_10m",
                "wind_direction_10m",
                "wind_gusts_10m",
            ]
        ),
        "daily": ",".join(
            [
                "weather_code",
                "temperature_2m_max",
                "temperature_2m_min",
                "apparent_temperature_max",
                "apparent_temperature_min",
                "precipitation_sum",
                "rain_sum",
                "precipitation_probability_max",
                "wind_speed_10m_max",
                "wind_gusts_10m_max",
                "sunrise",
                "sunset",
                "et0_fao_evapotranspiration",
            ]
        ),
    }

    url = (
        MESSIS_WEATHER_PROVIDER_URL
        + "?"
        + urlencode(parameters)
    )

    request = URLRequest(
        url=url,
        headers={
            "Accept": "application/json",
            "User-Agent": (
                "Messis-AI/0.5 "
                "(Smart Agriculture Management)"
            ),
        },
        method="GET",
    )

    try:
        with urlopen(
            request,
            timeout=12,
        ) as response:
            payload = json.loads(
                response.read().decode("utf-8")
            )
    except HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Weather provider returned "
                f"HTTP {exc.code}."
            ),
        ) from exc
    except URLError as exc:
        raise HTTPException(
            status_code=503,
            detail=(
                "Weather provider is currently "
                "unavailable."
            ),
        ) from exc
    except TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail="Weather provider timed out.",
        ) from exc
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
    ) as exc:
        raise HTTPException(
            status_code=502,
            detail=(
                "Weather provider returned an "
                "invalid response."
            ),
        ) from exc

    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=502,
            detail=(
                "Weather provider returned an "
                "unexpected response."
            ),
        )

    if payload.get("error"):
        raise HTTPException(
            status_code=502,
            detail=str(
                payload.get("reason")
                or "Weather provider error."
            ),
        )

    return payload


def build_weather_advisories(
    current: dict[str, object],
    daily_rows: list[dict[str, object]],
) -> list[dict[str, object]]:
    advisories: list[dict[str, object]] = []

    current_temperature = weather_decimal(
        current.get("temperature_2m")
    )

    current_wind = weather_decimal(
        current.get("wind_speed_10m")
    )

    current_gust = weather_decimal(
        current.get("wind_gusts_10m")
    )

    maximum_temperature = max(
        (
            weather_decimal(
                row.get("temperature_max")
            )
            for row in daily_rows
        ),
        default=Decimal("0.00"),
    )

    maximum_rain_probability = max(
        (
            weather_decimal(
                row.get(
                    "precipitation_probability"
                )
            )
            for row in daily_rows
        ),
        default=Decimal("0.00"),
    )

    forecast_rain = sum(
        (
            weather_decimal(
                row.get("rain_sum")
            )
            for row in daily_rows
        ),
        Decimal("0.00"),
    )

    maximum_gust = max(
        (
            weather_decimal(
                row.get("wind_gust_max")
            )
            for row in daily_rows
        ),
        default=Decimal("0.00"),
    )

    total_et0 = sum(
        (
            weather_decimal(
                row.get("evapotranspiration")
            )
            for row in daily_rows
        ),
        Decimal("0.00"),
    )

    if (
        current_temperature >= Decimal("36.00")
        or maximum_temperature >= Decimal("38.00")
    ):
        advisories.append(
            {
                "code": "HEAT_STRESS",
                "priority": "high",
                "title": "Heat stress risk",
                "message": (
                    "High temperatures may increase "
                    "moisture stress in coconut trees."
                ),
                "recommended_action": (
                    "Check soil moisture and schedule "
                    "irrigation during cooler hours."
                ),
                "metric": {
                    "current_temperature": str(
                        current_temperature
                    ),
                    "maximum_temperature": str(
                        maximum_temperature
                    ),
                },
            }
        )

    if (
        maximum_rain_probability
        >= Decimal("70.00")
        or forecast_rain >= Decimal("20.00")
    ):
        advisories.append(
            {
                "code": "RAIN_EXPECTED",
                "priority": "medium",
                "title": "Rain is likely",
                "message": (
                    "Significant rainfall is possible "
                    "during the forecast period."
                ),
                "recommended_action": (
                    "Review irrigation plans and avoid "
                    "unnecessary watering or spraying."
                ),
                "metric": {
                    "rain_probability": str(
                        maximum_rain_probability
                    ),
                    "forecast_rain_mm": str(
                        forecast_rain
                    ),
                },
            }
        )

    if (
        current_wind >= Decimal("35.00")
        or current_gust >= Decimal("45.00")
        or maximum_gust >= Decimal("50.00")
    ):
        advisories.append(
            {
                "code": "STRONG_WIND",
                "priority": "high",
                "title": "Strong wind risk",
                "message": (
                    "Strong winds or gusts may affect "
                    "harvest and climbing safety."
                ),
                "recommended_action": (
                    "Avoid tree climbing during unsafe "
                    "wind conditions and secure loose "
                    "farm materials."
                ),
                "metric": {
                    "current_wind_kmh": str(
                        current_wind
                    ),
                    "current_gust_kmh": str(
                        current_gust
                    ),
                    "maximum_gust_kmh": str(
                        maximum_gust
                    ),
                },
            }
        )

    if (
        forecast_rain < Decimal("5.00")
        and total_et0 >= Decimal("20.00")
    ):
        advisories.append(
            {
                "code": "IRRIGATION_ATTENTION",
                "priority": "medium",
                "title": "Irrigation may be required",
                "message": (
                    "Forecast rainfall is low while "
                    "evapotranspiration demand is high."
                ),
                "recommended_action": (
                    "Inspect soil moisture and plan "
                    "irrigation based on actual field "
                    "conditions."
                ),
                "metric": {
                    "forecast_rain_mm": str(
                        forecast_rain
                    ),
                    "forecast_et0_mm": str(
                        total_et0
                    ),
                },
            }
        )

    if not advisories:
        advisories.append(
            {
                "code": "NO_WEATHER_ALERT",
                "priority": "info",
                "title": "No major weather alert",
                "message": (
                    "The current forecast does not "
                    "show a major heat, rain, or wind "
                    "warning."
                ),
                "recommended_action": (
                    "Continue checking local field "
                    "conditions before farm activities."
                ),
                "metric": None,
            }
        )

    return advisories


def normalize_weather_forecast(
    payload: dict[str, object],
) -> dict[str, object]:
    current = dict(
        payload.get("current") or {}
    )

    daily = dict(
        payload.get("daily") or {}
    )

    dates = list(daily.get("time") or [])

    def daily_value(
        name: str,
        index: int,
    ) -> object:
        values = list(
            daily.get(name) or []
        )

        if index >= len(values):
            return None

        return values[index]

    daily_rows = []

    for index, forecast_date in enumerate(dates):
        code = daily_value(
            "weather_code",
            index,
        )

        daily_rows.append(
            {
                "date": forecast_date,
                "weather_code": code,
                "condition": (
                    weather_code_description(code)
                ),
                "temperature_max": daily_value(
                    "temperature_2m_max",
                    index,
                ),
                "temperature_min": daily_value(
                    "temperature_2m_min",
                    index,
                ),
                "apparent_temperature_max": (
                    daily_value(
                        "apparent_temperature_max",
                        index,
                    )
                ),
                "apparent_temperature_min": (
                    daily_value(
                        "apparent_temperature_min",
                        index,
                    )
                ),
                "precipitation_sum": daily_value(
                    "precipitation_sum",
                    index,
                ),
                "rain_sum": daily_value(
                    "rain_sum",
                    index,
                ),
                "precipitation_probability": (
                    daily_value(
                        (
                            "precipitation_"
                            "probability_max"
                        ),
                        index,
                    )
                ),
                "wind_speed_max": daily_value(
                    "wind_speed_10m_max",
                    index,
                ),
                "wind_gust_max": daily_value(
                    "wind_gusts_10m_max",
                    index,
                ),
                "sunrise": daily_value(
                    "sunrise",
                    index,
                ),
                "sunset": daily_value(
                    "sunset",
                    index,
                ),
                "evapotranspiration": (
                    daily_value(
                        (
                            "et0_fao_"
                            "evapotranspiration"
                        ),
                        index,
                    )
                ),
            }
        )

    current_code = current.get(
        "weather_code"
    )

    current_summary = {
        "time": current.get("time"),
        "temperature": current.get(
            "temperature_2m"
        ),
        "relative_humidity": current.get(
            "relative_humidity_2m"
        ),
        "apparent_temperature": current.get(
            "apparent_temperature"
        ),
        "precipitation": current.get(
            "precipitation"
        ),
        "rain": current.get("rain"),
        "weather_code": current_code,
        "condition": weather_code_description(
            current_code
        ),
        "cloud_cover": current.get(
            "cloud_cover"
        ),
        "wind_speed": current.get(
            "wind_speed_10m"
        ),
        "wind_direction": current.get(
            "wind_direction_10m"
        ),
        "wind_gust": current.get(
            "wind_gusts_10m"
        ),
    }

    return {
        "provider": MESSIS_WEATHER_PROVIDER,
        "provider_attribution": (
            "Weather data by Open-Meteo.com"
        ),
        "latitude": payload.get("latitude"),
        "longitude": payload.get("longitude"),
        "elevation": payload.get("elevation"),
        "timezone": payload.get("timezone"),
        "timezone_abbreviation": payload.get(
            "timezone_abbreviation"
        ),
        "current": current_summary,
        "daily": daily_rows,
        "advisories": build_weather_advisories(
            current=current_summary,
            daily_rows=daily_rows,
        ),
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
    }


@app.get(
    "/weather/forecast",
    response_class=JSONResponse,
)
def weather_forecast(
    latitude: float,
    longitude: float,
    forecast_days: int = 7,
    user: User = Depends(current_user),
):
    payload = fetch_weather_forecast(
        latitude=latitude,
        longitude=longitude,
        forecast_days=forecast_days,
    )

    normalized = normalize_weather_forecast(
        payload
    )

    return {
        "requested_by_user_id": user.id,
        **normalized,
    }


@app.get(
    "/weather/provider",
    response_class=JSONResponse,
)
def weather_provider_information(
    user: User = Depends(current_user),
):
    return {
        "provider": MESSIS_WEATHER_PROVIDER,
        "forecast_endpoint": (
            "/weather/forecast"
        ),
        "requires_api_key": False,
        "maximum_forecast_days": 16,
        "coordinates_required": True,
        "units": {
            "temperature": "Celsius",
            "wind_speed": "km/h",
            "precipitation": "mm",
            "evapotranspiration": "mm",
        },
        "attribution": (
            "Weather data by Open-Meteo.com"
        ),
        "user_id": user.id,
    }



# PATCH-WEATHER-001B: FARM LOCATION AND WEATHER UI


def get_farm_weather_location(
    db: Session,
    owner_id: int,
    farm_id: int,
) -> dict[str, object] | None:
    row = db.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                farm_id,
                location_name,
                latitude,
                longitude,
                created_at,
                updated_at
            FROM farm_weather_locations
            WHERE owner_id = :owner_id
              AND farm_id = :farm_id
            """
        ),
        {
            "owner_id": owner_id,
            "farm_id": farm_id,
        },
    ).mappings().first()

    if row is None:
        return None

    return dict(row)


@app.get(
    "/weather/manage",
    response_class=HTMLResponse,
)
def weather_management_page(
    request: Request,
    farm_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    selected_farm = None
    location = None

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

        location = get_farm_weather_location(
            db=db,
            owner_id=user.id,
            farm_id=selected_farm.id,
        )

    return templates.TemplateResponse(
        request=request,
        name="weather/index.html",
        context={
            "current_user": user,
            "farms": farms,
            "selected_farm": selected_farm,
            "location": location,
        },
    )


@app.post(
    "/weather/location",
)
def save_farm_weather_location(
    request: Request,
    farm_id: int = Form(...),
    latitude: float = Form(...),
    longitude: float = Form(...),
    location_name: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    validate_weather_coordinates(
        latitude=latitude,
        longitude=longitude,
    )

    normalized_name = (
        location_name.strip()
    )

    if len(normalized_name) > 180:
        raise HTTPException(
            status_code=422,
            detail=(
                "Location name cannot exceed "
                "180 characters."
            ),
        )

    try:
        db.execute(
            text(
                """
                INSERT INTO farm_weather_locations (
                    owner_id,
                    farm_id,
                    location_name,
                    latitude,
                    longitude,
                    created_at,
                    updated_at
                )
                VALUES (
                    :owner_id,
                    :farm_id,
                    :location_name,
                    :latitude,
                    :longitude,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (owner_id, farm_id)
                DO UPDATE SET
                    location_name =
                        EXCLUDED.location_name,
                    latitude =
                        EXCLUDED.latitude,
                    longitude =
                        EXCLUDED.longitude,
                    updated_at = NOW()
                """
            ),
            {
                "owner_id": user.id,
                "farm_id": farm.id,
                "location_name": (
                    normalized_name or None
                ),
                "latitude": latitude,
                "longitude": longitude,
            },
        )

        audit(
            db,
            request,
            "farm_weather_location_saved",
            user.id,
            (
                f"Farm ID: {farm.id}; "
                f"Latitude: {latitude}; "
                f"Longitude: {longitude}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to save farm "
                "weather location."
            ),
        )

    return RedirectResponse(
        url=(
            "/weather/manage"
            f"?farm_id={farm.id}"
        ),
        status_code=303,
    )


@app.get(
    "/weather/farms/{farm_id}/location",
    response_class=JSONResponse,
)
def farm_weather_location_api(
    farm_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db=db,
        farm_id=farm_id,
        owner_id=user.id,
    )

    location = get_farm_weather_location(
        db=db,
        owner_id=user.id,
        farm_id=farm.id,
    )

    if location is None:
        raise HTTPException(
            status_code=404,
            detail=(
                "Weather location is not configured "
                "for this farm."
            ),
        )

    return {
        "farm": {
            "id": farm.id,
            "name": farm.name,
        },
        "location": {
            "location_name": (
                location["location_name"]
            ),
            "latitude": str(
                location["latitude"]
            ),
            "longitude": str(
                location["longitude"]
            ),
            "updated_at": (
                location["updated_at"]
            ),
        },
    }



# PATCH-WEATHER-001C: DASHBOARD WEATHER SUMMARY


@app.get(
    "/weather/dashboard-summary",
    response_class=JSONResponse,
)
def dashboard_weather_summary(
    farm_id: int | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    selected_farm = None
    location = None

    if farm_id is not None:
        selected_farm = require_owned_farm(
            db=db,
            farm_id=farm_id,
            owner_id=user.id,
        )

        location = get_farm_weather_location(
            db=db,
            owner_id=user.id,
            farm_id=selected_farm.id,
        )
    else:
        row = db.execute(
            text(
                """
                SELECT
                    f.id AS farm_id,
                    f.name AS farm_name,
                    w.location_name,
                    w.latitude,
                    w.longitude
                FROM farms AS f
                INNER JOIN farm_weather_locations AS w
                    ON w.farm_id = f.id
                   AND w.owner_id = f.owner_id
                WHERE f.owner_id = :owner_id
                ORDER BY
                    LOWER(f.name),
                    f.id
                LIMIT 1
                """
            ),
            {
                "owner_id": user.id,
            },
        ).mappings().first()

        if row is not None:
            selected_farm = require_owned_farm(
                db=db,
                farm_id=int(row["farm_id"]),
                owner_id=user.id,
            )

            location = {
                "farm_id": row["farm_id"],
                "location_name": (
                    row["location_name"]
                ),
                "latitude": row["latitude"],
                "longitude": row["longitude"],
            }

    if selected_farm is None:
        return {
            "configured": False,
            "reason": "NO_FARM",
            "message": (
                "Create a farm and configure its "
                "weather location."
            ),
            "weather_url": "/weather/manage",
        }

    if location is None:
        return {
            "configured": False,
            "reason": "LOCATION_NOT_CONFIGURED",
            "farm": {
                "id": selected_farm.id,
                "name": selected_farm.name,
            },
            "message": (
                "Weather location is not configured "
                "for this farm."
            ),
            "weather_url": (
                "/weather/manage"
                f"?farm_id={selected_farm.id}"
            ),
        }

    latitude = float(location["latitude"])
    longitude = float(location["longitude"])

    payload = fetch_weather_forecast(
        latitude=latitude,
        longitude=longitude,
        forecast_days=3,
    )

    weather = normalize_weather_forecast(
        payload
    )

    advisories = list(
        weather.get("advisories") or []
    )

    priority_order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
    }

    advisories.sort(
        key=lambda item: priority_order.get(
            str(item.get("priority") or "info"),
            0,
        ),
        reverse=True,
    )

    return {
        "configured": True,
        "farm": {
            "id": selected_farm.id,
            "name": selected_farm.name,
        },
        "location": {
            "name": (
                location.get("location_name")
                if isinstance(location, dict)
                else None
            ),
            "latitude": str(
                location["latitude"]
            ),
            "longitude": str(
                location["longitude"]
            ),
        },
        "current": weather["current"],
        "forecast": weather["daily"][:3],
        "top_advisory": (
            advisories[0]
            if advisories
            else None
        ),
        "weather_url": (
            "/weather/manage"
            f"?farm_id={selected_farm.id}"
        ),
        "provider": weather["provider"],
        "provider_attribution": weather[
            "provider_attribution"
        ],
        "generated_at": weather[
            "generated_at"
        ],
    }



# PATCH-NOTIFY-001A: ALERT AND NOTIFICATION FOUNDATION


MESSIS_NOTIFICATION_PRIORITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


def notification_json_metadata(
    value: object,
) -> str:
    try:
        return json.dumps(
            value or {},
            ensure_ascii=False,
            default=str,
        )
    except (TypeError, ValueError):
        return "{}"


def notification_row_to_dict(
    row: object,
) -> dict[str, object]:
    item = dict(row)

    metadata = item.get("metadata")

    if isinstance(metadata, str):
        try:
            metadata = json.loads(metadata)
        except json.JSONDecodeError:
            metadata = {}

    item["metadata"] = metadata or {}

    for field in (
        "created_at",
        "updated_at",
        "read_at",
        "dismissed_at",
        "expires_at",
    ):
        value = item.get(field)

        if value is not None:
            item[field] = value.isoformat()

    return item


def upsert_notification(
    db: Session,
    owner_id: int,
    farm_id: int | None,
    notification_type: str,
    source_code: str,
    deduplication_key: str,
    priority: str,
    category: str,
    title: str,
    message: str,
    recommended_action: str | None,
    action_url: str | None,
    metadata: dict[str, object] | None = None,
    expires_at: datetime | None = None,
) -> None:
    normalized_priority = (
        priority
        if priority
        in MESSIS_NOTIFICATION_PRIORITY_ORDER
        else "info"
    )

    db.execute(
        text(
            """
            INSERT INTO notifications (
                owner_id,
                farm_id,
                notification_type,
                source_code,
                deduplication_key,
                priority,
                category,
                title,
                message,
                recommended_action,
                action_url,
                metadata,
                is_read,
                is_dismissed,
                created_at,
                updated_at,
                expires_at
            )
            VALUES (
                :owner_id,
                :farm_id,
                :notification_type,
                :source_code,
                :deduplication_key,
                :priority,
                :category,
                :title,
                :message,
                :recommended_action,
                :action_url,
                CAST(:metadata AS JSONB),
                FALSE,
                FALSE,
                NOW(),
                NOW(),
                :expires_at
            )
            ON CONFLICT (
                owner_id,
                deduplication_key
            )
            DO UPDATE SET
                farm_id = EXCLUDED.farm_id,
                notification_type =
                    EXCLUDED.notification_type,
                source_code =
                    EXCLUDED.source_code,
                priority = EXCLUDED.priority,
                category = EXCLUDED.category,
                title = EXCLUDED.title,
                message = EXCLUDED.message,
                recommended_action =
                    EXCLUDED.recommended_action,
                action_url =
                    EXCLUDED.action_url,
                metadata =
                    EXCLUDED.metadata,
                is_dismissed = FALSE,
                dismissed_at = NULL,
                updated_at = NOW(),
                expires_at =
                    EXCLUDED.expires_at
            """
        ),
        {
            "owner_id": owner_id,
            "farm_id": farm_id,
            "notification_type": (
                notification_type
            ),
            "source_code": source_code,
            "deduplication_key": (
                deduplication_key
            ),
            "priority": normalized_priority,
            "category": category,
            "title": title,
            "message": message,
            "recommended_action": (
                recommended_action
            ),
            "action_url": action_url,
            "metadata": (
                notification_json_metadata(
                    metadata
                )
            ),
            "expires_at": expires_at,
        },
    )


def generate_owner_notifications(
    user: User,
    db: Session,
) -> dict[str, int]:
    today = date.today()

    period_from, period_to = (
        analytics_default_period()
    )

    generated = 0
    ai_generated = 0
    harvest_generated = 0
    weather_generated = 0
    payment_generated = 0

    farms = db.scalars(
        select(Farm)
        .where(Farm.owner_id == user.id)
        .order_by(func.lower(Farm.name))
    ).all()

    for farm in farms:
        recommendation_result = (
            farm_recommendation_engine(
                farm=farm,
                user=user,
                db=db,
                date_from=period_from,
                date_to=period_to,
            )
        )

        for item in recommendation_result[
            "recommendations"
        ]:
            priority = str(
                item.get("priority") or "info"
            )

            if priority not in {
                "critical",
                "high",
            }:
                continue

            source_code = str(
                item.get("code")
                or "AI_RECOMMENDATION"
            )

            deduplication_key = (
                f"ai:{farm.id}:{source_code}"
            )

            upsert_notification(
                db=db,
                owner_id=user.id,
                farm_id=farm.id,
                notification_type=(
                    "ai_recommendation"
                ),
                source_code=source_code,
                deduplication_key=(
                    deduplication_key
                ),
                priority=priority,
                category=str(
                    item.get("category")
                    or "General"
                ),
                title=str(
                    item.get("title")
                    or "Farm recommendation"
                ),
                message=str(
                    item.get("message")
                    or ""
                ),
                recommended_action=str(
                    item.get(
                        "recommended_action"
                    )
                    or ""
                ),
                action_url=(
                    item.get("action_url")
                ),
                metadata={
                    "farm_name": farm.name,
                    "metric": (
                        item.get("metric")
                    ),
                    "period_from": (
                        period_from.isoformat()
                    ),
                    "period_to": (
                        period_to.isoformat()
                    ),
                },
            )

            generated += 1
            ai_generated += 1

        cycles = db.scalars(
            select(HarvestCycle)
            .where(
                HarvestCycle.owner_id
                == user.id,
                HarvestCycle.farm_id
                == farm.id,
            )
            .order_by(
                HarvestCycle
                .planned_harvest_date
                .asc()
            )
        ).all()

        for cycle in cycles:
            if cycle.status in {
                "Completed",
                "Cancelled",
            }:
                continue

            current_status = (
                harvest_cycle_status(
                    cycle
                    .planned_harvest_date,
                    cycle.minimum_due_date,
                    cycle.maximum_due_date,
                    today,
                )
            )

            if current_status not in {
                "Due Soon",
                "Due",
                "Overdue",
            }:
                continue

            priority = (
                "critical"
                if current_status
                == "Overdue"
                else "high"
            )

            source_code = (
                "HARVEST_OVERDUE"
                if current_status
                == "Overdue"
                else "HARVEST_DUE"
            )

            upsert_notification(
                db=db,
                owner_id=user.id,
                farm_id=farm.id,
                notification_type=(
                    "harvest"
                ),
                source_code=source_code,
                deduplication_key=(
                    f"harvest:{cycle.id}:"
                    f"{current_status}"
                ),
                priority=priority,
                category="Harvest",
                title=(
                    f"{farm.name}: "
                    f"{current_status}"
                ),
                message=(
                    "Planned harvest date: "
                    f"{cycle.planned_harvest_date}"
                ),
                recommended_action=(
                    "Review the harvest cycle and "
                    "record or reschedule the "
                    "harvest."
                ),
                action_url="/harvests/manage",
                metadata={
                    "farm_name": farm.name,
                    "harvest_cycle_id": (
                        cycle.id
                    ),
                    "status": current_status,
                    "planned_date": (
                        cycle
                        .planned_harvest_date
                        .isoformat()
                    ),
                },
            )

            generated += 1
            harvest_generated += 1

        sales = db.scalars(
            select(Sale).where(
                Sale.owner_id == user.id,
                Sale.farm_id == farm.id,
                Sale.balance_amount > 0,
            )
        ).all()

        outstanding = sum(
            (
                Decimal(
                    str(
                        sale.balance_amount
                        or 0
                    )
                )
                for sale in sales
            ),
            Decimal("0.00"),
        )

        if outstanding > 0:
            priority = (
                "high"
                if outstanding
                >= Decimal("10000.00")
                else "medium"
            )

            upsert_notification(
                db=db,
                owner_id=user.id,
                farm_id=farm.id,
                notification_type="payment",
                source_code=(
                    "OUTSTANDING_PAYMENT"
                ),
                deduplication_key=(
                    f"payment:{farm.id}:"
                    "outstanding"
                ),
                priority=priority,
                category="Sales",
                title=(
                    f"{farm.name}: "
                    "Payment collection pending"
                ),
                message=(
                    f"₹{outstanding.quantize(Decimal('0.01'))} "
                    "remains outstanding."
                ),
                recommended_action=(
                    "Follow up with buyers and "
                    "record received payments."
                ),
                action_url="/sales/manage",
                metadata={
                    "farm_name": farm.name,
                    "outstanding": str(
                        outstanding.quantize(
                            Decimal("0.01")
                        )
                    ),
                    "sale_count": len(sales),
                },
            )

            generated += 1
            payment_generated += 1

        location = get_farm_weather_location(
            db=db,
            owner_id=user.id,
            farm_id=farm.id,
        )

        if location is None:
            continue

        try:
            payload = fetch_weather_forecast(
                latitude=float(
                    location["latitude"]
                ),
                longitude=float(
                    location["longitude"]
                ),
                forecast_days=3,
            )

            weather = (
                normalize_weather_forecast(
                    payload
                )
            )

            for advisory in weather.get(
                "advisories",
                [],
            ):
                priority = str(
                    advisory.get(
                        "priority"
                    )
                    or "info"
                )

                if priority not in {
                    "critical",
                    "high",
                    "medium",
                }:
                    continue

                source_code = str(
                    advisory.get("code")
                    or "WEATHER_ALERT"
                )

                upsert_notification(
                    db=db,
                    owner_id=user.id,
                    farm_id=farm.id,
                    notification_type=(
                        "weather"
                    ),
                    source_code=source_code,
                    deduplication_key=(
                        f"weather:{farm.id}:"
                        f"{source_code}:"
                        f"{today.isoformat()}"
                    ),
                    priority=priority,
                    category="Weather",
                    title=(
                        f"{farm.name}: "
                        f"{advisory.get('title')}"
                    ),
                    message=str(
                        advisory.get(
                            "message"
                        )
                        or ""
                    ),
                    recommended_action=str(
                        advisory.get(
                            "recommended_action"
                        )
                        or ""
                    ),
                    action_url=(
                        "/weather/manage"
                        f"?farm_id={farm.id}"
                    ),
                    metadata={
                        "farm_name": (
                            farm.name
                        ),
                        "metric": advisory.get(
                            "metric"
                        ),
                        "forecast_date": (
                            today.isoformat()
                        ),
                    },
                    expires_at=(
                        datetime.now(
                            timezone.utc
                        )
                        + timedelta(days=2)
                    ),
                )

                generated += 1
                weather_generated += 1
        except HTTPException:
            pass

    db.execute(
        text(
            """
            DELETE FROM notifications
            WHERE owner_id = :owner_id
              AND is_dismissed = TRUE
              AND dismissed_at
                  < NOW() - INTERVAL '90 days'
            """
        ),
        {
            "owner_id": user.id,
        },
    )

    db.execute(
        text(
            """
            UPDATE notifications
            SET
                is_dismissed = TRUE,
                dismissed_at =
                    COALESCE(
                        dismissed_at,
                        NOW()
                    ),
                updated_at = NOW()
            WHERE owner_id = :owner_id
              AND is_dismissed = FALSE
              AND expires_at IS NOT NULL
              AND expires_at < NOW()
            """
        ),
        {
            "owner_id": user.id,
        },
    )

    db.commit()

    return {
        "generated": generated,
        "ai": ai_generated,
        "harvest": harvest_generated,
        "weather": weather_generated,
        "payment": payment_generated,
    }


@app.post(
    "/notifications/refresh",
    response_class=JSONResponse,
)
def refresh_notifications(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    result = generate_owner_notifications(
        user=user,
        db=db,
    )

    return {
        "status": "ok",
        **result,
    }


@app.get(
    "/notifications",
    response_class=JSONResponse,
)
def list_notifications(
    unread_only: bool = False,
    include_dismissed: bool = False,
    limit: int = 50,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    safe_limit = max(
        1,
        min(limit, 200),
    )

    conditions = [
        "owner_id = :owner_id",
    ]

    if unread_only:
        conditions.append(
            "is_read = FALSE"
        )

    if not include_dismissed:
        conditions.append(
            "is_dismissed = FALSE"
        )

    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                owner_id,
                farm_id,
                notification_type,
                source_code,
                priority,
                category,
                title,
                message,
                recommended_action,
                action_url,
                metadata,
                is_read,
                is_dismissed,
                read_at,
                dismissed_at,
                created_at,
                updated_at,
                expires_at
            FROM notifications
            WHERE {' AND '.join(conditions)}
            ORDER BY
                CASE priority
                    WHEN 'critical' THEN 5
                    WHEN 'high' THEN 4
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 2
                    ELSE 1
                END DESC,
                created_at DESC
            LIMIT :limit
            """
        ),
        {
            "owner_id": user.id,
            "limit": safe_limit,
        },
    ).mappings().all()

    return {
        "count": len(rows),
        "items": [
            notification_row_to_dict(row)
            for row in rows
        ],
    }


@app.get(
    "/notifications/summary",
    response_class=JSONResponse,
)
def notification_summary(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            """
            SELECT
                COUNT(*) FILTER (
                    WHERE is_dismissed = FALSE
                ) AS active_count,
                COUNT(*) FILTER (
                    WHERE is_dismissed = FALSE
                      AND is_read = FALSE
                ) AS unread_count,
                COUNT(*) FILTER (
                    WHERE is_dismissed = FALSE
                      AND is_read = FALSE
                      AND priority = 'critical'
                ) AS critical_unread,
                COUNT(*) FILTER (
                    WHERE is_dismissed = FALSE
                      AND is_read = FALSE
                      AND priority = 'high'
                ) AS high_unread,
                COUNT(*) FILTER (
                    WHERE is_dismissed = FALSE
                      AND is_read = FALSE
                      AND priority = 'medium'
                ) AS medium_unread
            FROM notifications
            WHERE owner_id = :owner_id
            """
        ),
        {
            "owner_id": user.id,
        },
    ).mappings().one()

    return {
        key: int(value or 0)
        for key, value in row.items()
    }


@app.post(
    "/notifications/{notification_id}/read",
    response_class=JSONResponse,
)
def mark_notification_read(
    notification_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    result = db.execute(
        text(
            """
            UPDATE notifications
            SET
                is_read = TRUE,
                read_at = COALESCE(
                    read_at,
                    NOW()
                ),
                updated_at = NOW()
            WHERE id = :notification_id
              AND owner_id = :owner_id
            """
        ),
        {
            "notification_id": (
                notification_id
            ),
            "owner_id": user.id,
        },
    )

    if result.rowcount == 0:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail="Notification not found.",
        )

    db.commit()

    return {
        "status": "ok",
        "notification_id": notification_id,
        "is_read": True,
    }


@app.post(
    "/notifications/read-all",
    response_class=JSONResponse,
)
def mark_all_notifications_read(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    result = db.execute(
        text(
            """
            UPDATE notifications
            SET
                is_read = TRUE,
                read_at = COALESCE(
                    read_at,
                    NOW()
                ),
                updated_at = NOW()
            WHERE owner_id = :owner_id
              AND is_dismissed = FALSE
              AND is_read = FALSE
            """
        ),
        {
            "owner_id": user.id,
        },
    )

    db.commit()

    return {
        "status": "ok",
        "updated_count": (
            result.rowcount or 0
        ),
    }


@app.post(
    "/notifications/{notification_id}/dismiss",
    response_class=JSONResponse,
)
def dismiss_notification(
    notification_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    result = db.execute(
        text(
            """
            UPDATE notifications
            SET
                is_dismissed = TRUE,
                dismissed_at = NOW(),
                updated_at = NOW()
            WHERE id = :notification_id
              AND owner_id = :owner_id
            """
        ),
        {
            "notification_id": (
                notification_id
            ),
            "owner_id": user.id,
        },
    )

    if result.rowcount == 0:
        db.rollback()

        raise HTTPException(
            status_code=404,
            detail="Notification not found.",
        )

    db.commit()

    return {
        "status": "ok",
        "notification_id": notification_id,
        "is_dismissed": True,
    }



# PATCH-NOTIFY-001B: NOTIFICATION CENTER UI


@app.get(
    "/notifications/manage",
    response_class=HTMLResponse,
)
def notification_management_page(
    request: Request,
    user: User = Depends(current_user),
):
    return templates.TemplateResponse(
        request=request,
        name="notifications/index.html",
        context={
            "current_user": user,
        },
    )



# PATCH-PWA-001A: MOBILE INSTALLABLE APP FOUNDATION


@app.get(
    "/service-worker.js",
    include_in_schema=False,
)
def messis_service_worker():
    service_worker_path = (
        Path(__file__).resolve().parent
        / "static"
        / "pwa"
        / "service-worker.js"
    )

    if not service_worker_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Service worker is missing.",
        )

    return HTMLResponse(
        content=service_worker_path.read_text(
            encoding="utf-8"
        ),
        media_type=(
            "application/javascript"
        ),
        headers={
            "Service-Worker-Allowed": "/",
            "Cache-Control": (
                "no-cache, no-store, "
                "must-revalidate"
            ),
        },
    )



# PATCH-PWA-001C: MOBILE QUICK ENTRY AND CAMERA CAPTURE


MESSIS_MOBILE_CAPTURE_ROOT = (
    Path(__file__).resolve().parent
    / "uploads"
    / "mobile-captures"
)

MESSIS_MOBILE_CAPTURE_TYPES = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}

MESSIS_MOBILE_CAPTURE_MAX_BYTES = (
    5 * 1024 * 1024
)


def mobile_capture_owned_expense(
    db: Session,
    owner_id: int,
    expense_id: int,
) -> dict[str, object] | None:
    row = db.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                expense_date,
                amount,
                description
            FROM expenses
            WHERE id = :expense_id
              AND owner_id = :owner_id
            """
        ),
        {
            "expense_id": expense_id,
            "owner_id": owner_id,
        },
    ).mappings().first()

    return dict(row) if row else None


def mobile_capture_recent_expenses(
    db: Session,
    owner_id: int,
) -> list[dict[str, object]]:
    rows = db.execute(
        text(
            """
            SELECT
                id,
                expense_date,
                amount,
                description
            FROM expenses
            WHERE owner_id = :owner_id
            ORDER BY
                expense_date DESC,
                id DESC
            LIMIT 25
            """
        ),
        {
            "owner_id": owner_id,
        },
    ).mappings().all()

    return [
        dict(row)
        for row in rows
    ]


def mobile_capture_recent_items(
    db: Session,
    owner_id: int,
) -> list[dict[str, object]]:
    rows = db.execute(
        text(
            """
            SELECT
                id,
                expense_id,
                original_filename,
                stored_filename,
                content_type,
                file_size,
                note,
                created_at
            FROM mobile_captures
            WHERE owner_id = :owner_id
            ORDER BY
                created_at DESC,
                id DESC
            LIMIT 15
            """
        ),
        {
            "owner_id": owner_id,
        },
    ).mappings().all()

    return [
        dict(row)
        for row in rows
    ]


@app.get(
    "/mobile/quick-entry",
    response_class=HTMLResponse,
)
def mobile_quick_entry_page(
    request: Request,
    saved: bool = False,
    error: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    return templates.TemplateResponse(
        request=request,
        name="mobile/quick-entry.html",
        context={
            "current_user": user,
            "expenses": (
                mobile_capture_recent_expenses(
                    db=db,
                    owner_id=user.id,
                )
            ),
            "captures": (
                mobile_capture_recent_items(
                    db=db,
                    owner_id=user.id,
                )
            ),
            "success_message": (
                "Receipt image saved successfully."
                if saved
                else None
            ),
            "error_message": error,
        },
    )


@app.post(
    "/mobile/captures",
)
async def create_mobile_capture(
    request: Request,
    capture_file: UploadFile = File(...),
    expense_id: str = Form(""),
    note: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    content_type = (
        capture_file.content_type or ""
    ).lower()

    extension = (
        MESSIS_MOBILE_CAPTURE_TYPES.get(
            content_type
        )
    )

    if extension is None:
        await capture_file.close()

        return RedirectResponse(
            url=(
                "/mobile/quick-entry"
                "?error=Unsupported+image+format"
            ),
            status_code=303,
        )

    normalized_note = note.strip()

    if len(normalized_note) > 500:
        await capture_file.close()

        return RedirectResponse(
            url=(
                "/mobile/quick-entry"
                "?error=Note+is+too+long"
            ),
            status_code=303,
        )

    selected_expense_id = None

    if expense_id.strip():
        try:
            selected_expense_id = int(
                expense_id
            )
        except ValueError:
            await capture_file.close()

            return RedirectResponse(
                url=(
                    "/mobile/quick-entry"
                    "?error=Invalid+expense"
                ),
                status_code=303,
            )

        expense = mobile_capture_owned_expense(
            db=db,
            owner_id=user.id,
            expense_id=selected_expense_id,
        )

        if expense is None:
            await capture_file.close()

            raise HTTPException(
                status_code=404,
                detail="Expense not found.",
            )

    owner_directory = (
        MESSIS_MOBILE_CAPTURE_ROOT
        / str(user.id)
    )

    owner_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    owner_directory.chmod(0o750)

    stored_filename = (
        secrets.token_hex(20)
        + extension
    )

    destination = (
        owner_directory
        / stored_filename
    )

    total_size = 0

    try:
        with destination.open("wb") as output:
            while True:
                chunk = await capture_file.read(
                    1024 * 1024
                )

                if not chunk:
                    break

                total_size += len(chunk)

                if (
                    total_size
                    > MESSIS_MOBILE_CAPTURE_MAX_BYTES
                ):
                    raise ValueError(
                        "File exceeds 5 MB."
                    )

                output.write(chunk)
    except ValueError:
        destination.unlink(
            missing_ok=True
        )

        await capture_file.close()

        return RedirectResponse(
            url=(
                "/mobile/quick-entry"
                "?error=Image+exceeds+5+MB"
            ),
            status_code=303,
        )
    except OSError:
        destination.unlink(
            missing_ok=True
        )

        await capture_file.close()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to store receipt image."
            ),
        )
    finally:
        await capture_file.close()

    if total_size <= 0:
        destination.unlink(
            missing_ok=True
        )

        return RedirectResponse(
            url=(
                "/mobile/quick-entry"
                "?error=Empty+image+file"
            ),
            status_code=303,
        )

    relative_path = str(
        destination.relative_to(
            Path(__file__).resolve().parent
        )
    )

    try:
        result = db.execute(
            text(
                """
                INSERT INTO mobile_captures (
                    owner_id,
                    expense_id,
                    capture_type,
                    original_filename,
                    stored_filename,
                    relative_path,
                    content_type,
                    file_size,
                    note,
                    created_at
                )
                VALUES (
                    :owner_id,
                    :expense_id,
                    'expense_receipt',
                    :original_filename,
                    :stored_filename,
                    :relative_path,
                    :content_type,
                    :file_size,
                    :note,
                    NOW()
                )
                RETURNING id
                """
            ),
            {
                "owner_id": user.id,
                "expense_id": (
                    selected_expense_id
                ),
                "original_filename": (
                    capture_file.filename
                ),
                "stored_filename": (
                    stored_filename
                ),
                "relative_path": (
                    relative_path
                ),
                "content_type": (
                    content_type
                ),
                "file_size": total_size,
                "note": (
                    normalized_note or None
                ),
            },
        ).scalar_one()

        audit(
            db,
            request,
            "mobile_capture_created",
            user.id,
            (
                f"Capture ID: {result}; "
                f"Expense ID: "
                f"{selected_expense_id}; "
                f"Size: {total_size}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        destination.unlink(
            missing_ok=True
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to save receipt record."
            ),
        )

    return RedirectResponse(
        url="/mobile/quick-entry?saved=true",
        status_code=303,
    )


@app.get(
    "/mobile/captures/{capture_id}/view",
    include_in_schema=False,
)
def view_mobile_capture(
    capture_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    row = db.execute(
        text(
            """
            SELECT
                id,
                original_filename,
                relative_path,
                content_type
            FROM mobile_captures
            WHERE id = :capture_id
              AND owner_id = :owner_id
            """
        ),
        {
            "capture_id": capture_id,
            "owner_id": user.id,
        },
    ).mappings().first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Receipt image not found.",
        )

    app_root = (
        Path(__file__).resolve().parent
    )

    file_path = (
        app_root
        / str(row["relative_path"])
    ).resolve()

    permitted_root = (
        MESSIS_MOBILE_CAPTURE_ROOT
        / str(user.id)
    ).resolve()

    if (
        permitted_root
        not in file_path.parents
    ):
        raise HTTPException(
            status_code=403,
            detail="Invalid receipt path.",
        )

    if not file_path.is_file():
        raise HTTPException(
            status_code=404,
            detail="Receipt file is missing.",
        )

    return FileResponse(
        path=file_path,
        media_type=str(
            row["content_type"]
        ),
        filename=str(
            row["original_filename"]
            or file_path.name
        ),
        headers={
            "Cache-Control": (
                "private, no-store, "
                "max-age=0"
            ),
            "X-Content-Type-Options": (
                "nosniff"
            ),
        },
    )







# PATCH-FINANCE-001E: BUSINESS SETTINGS


MESSIS_CURRENCY_OPTIONS = (
    {
        "code": "INR",
        "symbol": "₹",
    },
    {
        "code": "USD",
        "symbol": "$",
    },
    {
        "code": "EUR",
        "symbol": "€",
    },
    {
        "code": "GBP",
        "symbol": "£",
    },
)

MESSIS_DATE_FORMATS = (
    "DD-MM-YYYY",
    "DD/MM/YYYY",
    "YYYY-MM-DD",
    "MM/DD/YYYY",
)

MESSIS_TIMEZONE_OPTIONS = (
    "Asia/Kolkata",
    "Asia/Dubai",
    "Asia/Singapore",
    "Europe/London",
    "America/New_York",
    "UTC",
)

MESSIS_MONTH_OPTIONS = (
    {"number": 1, "name": "January"},
    {"number": 2, "name": "February"},
    {"number": 3, "name": "March"},
    {"number": 4, "name": "April"},
    {"number": 5, "name": "May"},
    {"number": 6, "name": "June"},
    {"number": 7, "name": "July"},
    {"number": 8, "name": "August"},
    {"number": 9, "name": "September"},
    {"number": 10, "name": "October"},
    {"number": 11, "name": "November"},
    {"number": 12, "name": "December"},
)


def finance_business_settings_row(
    db: Session,
    owner_id: int,
) -> dict[str, object]:
    db.execute(
        text(
            """
            INSERT INTO business_settings (
                owner_id,
                business_name,
                currency_code,
                currency_symbol,
                date_format,
                financial_year_start_month,
                timezone_name,
                default_payment_method_id,
                created_at,
                updated_at
            )
            VALUES (
                :owner_id,
                'Messis AI Farm',
                'INR',
                '₹',
                'DD-MM-YYYY',
                4,
                'Asia/Kolkata',
                (
                    SELECT id
                    FROM payment_methods
                    WHERE owner_id = :owner_id
                      AND is_default = TRUE
                    ORDER BY id
                    LIMIT 1
                ),
                NOW(),
                NOW()
            )
            ON CONFLICT (owner_id)
            DO NOTHING
            """
        ),
        {
            "owner_id": owner_id,
        },
    )

    row = db.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                business_name,
                owner_name,
                phone,
                email,
                address,
                gstin,
                currency_code,
                currency_symbol,
                date_format,
                financial_year_start_month,
                timezone_name,
                default_payment_method_id,
                report_header,
                report_footer,
                created_at,
                updated_at
            FROM business_settings
            WHERE owner_id = :owner_id
            """
        ),
        {
            "owner_id": owner_id,
        },
    ).mappings().one()

    return dict(row)


def finance_business_settings_values(
    settings: dict[str, object],
) -> dict[str, object]:
    return {
        "business_name": str(
            settings.get("business_name")
            or "Messis AI Farm"
        ),
        "owner_name": str(
            settings.get("owner_name")
            or ""
        ),
        "phone": str(
            settings.get("phone")
            or ""
        ),
        "email": str(
            settings.get("email")
            or ""
        ),
        "address": str(
            settings.get("address")
            or ""
        ),
        "gstin": str(
            settings.get("gstin")
            or ""
        ),
        "currency_code": str(
            settings.get("currency_code")
            or "INR"
        ),
        "date_format": str(
            settings.get("date_format")
            or "DD-MM-YYYY"
        ),
        "financial_year_start_month": int(
            settings.get(
                "financial_year_start_month"
            )
            or 4
        ),
        "timezone_name": str(
            settings.get("timezone_name")
            or "Asia/Kolkata"
        ),
        "default_payment_method_id": (
            int(
                settings[
                    "default_payment_method_id"
                ]
            )
            if settings.get(
                "default_payment_method_id"
            )
            is not None
            else None
        ),
        "report_header": str(
            settings.get("report_header")
            or ""
        ),
        "report_footer": str(
            settings.get("report_footer")
            or ""
        ),
    }


def finance_business_settings_methods(
    db: Session,
    owner_id: int,
) -> list[dict[str, object]]:
    rows = db.execute(
        text(
            """
            SELECT
                id,
                name,
                icon,
                is_default
            FROM payment_methods
            WHERE owner_id = :owner_id
              AND is_active = TRUE
            ORDER BY
                is_default DESC,
                display_order,
                LOWER(name),
                id
            """
        ),
        {
            "owner_id": owner_id,
        },
    ).mappings().all()

    return [
        dict(row)
        for row in rows
    ]


def validate_finance_business_settings(
    *,
    business_name: str,
    owner_name: str,
    phone: str,
    email: str,
    address: str,
    gstin: str,
    currency_code: str,
    date_format: str,
    financial_year_start_month: str,
    timezone_name: str,
    default_payment_method_id: str,
    report_header: str,
    report_footer: str,
) -> tuple[
    dict[str, str],
    int | None,
    int | None,
]:
    errors: dict[str, str] = {}

    normalized_business_name = (
        business_name.strip()
    )

    if not normalized_business_name:
        errors["business_name"] = (
            "Business name is required."
        )
    elif len(normalized_business_name) > 180:
        errors["business_name"] = (
            "Business name cannot exceed "
            "180 characters."
        )

    if len(owner_name.strip()) > 180:
        errors["owner_name"] = (
            "Owner name cannot exceed "
            "180 characters."
        )

    normalized_phone = phone.strip()

    if len(normalized_phone) > 30:
        errors["phone"] = (
            "Phone number cannot exceed "
            "30 characters."
        )
    elif normalized_phone:
        compact_phone = "".join(
            character
            for character in normalized_phone
            if character not in {
                " ",
                "-",
                "(",
                ")",
            }
        )

        if compact_phone.startswith("+"):
            compact_phone = compact_phone[1:]

        if not compact_phone.isdigit():
            errors["phone"] = (
                "Enter a valid phone number."
            )

    normalized_email = email.strip()

    if len(normalized_email) > 180:
        errors["email"] = (
            "Email cannot exceed 180 characters."
        )
    elif normalized_email and (
        "@" not in normalized_email
        or "." not in normalized_email.split("@")[-1]
    ):
        errors["email"] = (
            "Enter a valid email address."
        )

    if len(address.strip()) > 1500:
        errors["address"] = (
            "Address cannot exceed "
            "1500 characters."
        )

    normalized_gstin = gstin.strip().upper()

    if normalized_gstin and (
        len(normalized_gstin) != 15
        or not normalized_gstin.isalnum()
    ):
        errors["gstin"] = (
            "GSTIN must contain exactly "
            "15 letters and numbers."
        )

    valid_currency_codes = {
        item["code"]
        for item in MESSIS_CURRENCY_OPTIONS
    }

    if currency_code not in valid_currency_codes:
        errors["currency_code"] = (
            "Select a valid currency."
        )

    if date_format not in MESSIS_DATE_FORMATS:
        errors["date_format"] = (
            "Select a valid date format."
        )

    parsed_month = None

    try:
        parsed_month = int(
            financial_year_start_month
        )
    except (TypeError, ValueError):
        errors[
            "financial_year_start_month"
        ] = (
            "Select a valid financial "
            "year month."
        )
    else:
        if not 1 <= parsed_month <= 12:
            errors[
                "financial_year_start_month"
            ] = (
                "Select a valid financial "
                "year month."
            )

    if timezone_name not in MESSIS_TIMEZONE_OPTIONS:
        errors["timezone_name"] = (
            "Select a valid timezone."
        )

    parsed_payment_method = None

    if default_payment_method_id.strip():
        try:
            parsed_payment_method = int(
                default_payment_method_id
            )
        except ValueError:
            errors[
                "default_payment_method_id"
            ] = (
                "Select a valid payment method."
            )

    if len(report_header.strip()) > 500:
        errors["report_header"] = (
            "Report header cannot exceed "
            "500 characters."
        )

    if len(report_footer.strip()) > 1000:
        errors["report_footer"] = (
            "Report footer cannot exceed "
            "1000 characters."
        )

    return (
        errors,
        parsed_month,
        parsed_payment_method,
    )


def render_finance_business_settings(
    request: Request,
    user: User,
    db: Session,
    settings: dict[str, object],
    errors: dict[str, str],
    *,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name=(
            "finance/"
            "business-settings.html"
        ),
        context={
            "current_user": user,
            "settings": settings,
            "errors": errors,
            "payment_methods": (
                finance_business_settings_methods(
                    db=db,
                    owner_id=user.id,
                )
            ),
            "currency_options": (
                MESSIS_CURRENCY_OPTIONS
            ),
            "date_formats": (
                MESSIS_DATE_FORMATS
            ),
            "timezone_options": (
                MESSIS_TIMEZONE_OPTIONS
            ),
            "month_options": (
                MESSIS_MONTH_OPTIONS
            ),
            "success_message": (
                request.query_params.get(
                    "success"
                )
            ),
            "error_message": (
                request.query_params.get(
                    "error"
                )
            ),
        },
        status_code=status_code,
    )


@app.get(
    "/business-settings",
    response_class=JSONResponse,
)
def finance_business_settings_api(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    settings = finance_business_settings_row(
        db=db,
        owner_id=user.id,
    )

    db.commit()

    return {
        "item": settings,
    }


@app.get(
    "/business-settings/manage",
    response_class=HTMLResponse,
)
def finance_business_settings_page(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    settings = finance_business_settings_row(
        db=db,
        owner_id=user.id,
    )

    db.commit()

    return render_finance_business_settings(
        request=request,
        user=user,
        db=db,
        settings=(
            finance_business_settings_values(
                settings
            )
        ),
        errors={},
    )


@app.post(
    "/business-settings/manage",
    response_class=HTMLResponse,
)
def finance_business_settings_submit(
    request: Request,
    business_name: str = Form(...),
    owner_name: str = Form(""),
    phone: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    gstin: str = Form(""),
    currency_code: str = Form("INR"),
    date_format: str = Form("DD-MM-YYYY"),
    financial_year_start_month: str = Form("4"),
    timezone_name: str = Form("Asia/Kolkata"),
    default_payment_method_id: str = Form(""),
    report_header: str = Form(""),
    report_footer: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    (
        errors,
        parsed_month,
        parsed_payment_method,
    ) = validate_finance_business_settings(
        business_name=business_name,
        owner_name=owner_name,
        phone=phone,
        email=email,
        address=address,
        gstin=gstin,
        currency_code=currency_code,
        date_format=date_format,
        financial_year_start_month=(
            financial_year_start_month
        ),
        timezone_name=timezone_name,
        default_payment_method_id=(
            default_payment_method_id
        ),
        report_header=report_header,
        report_footer=report_footer,
    )

    currency_map = {
        item["code"]: item["symbol"]
        for item in MESSIS_CURRENCY_OPTIONS
    }

    settings = {
        "business_name": (
            business_name.strip()
        ),
        "owner_name": owner_name.strip(),
        "phone": phone.strip(),
        "email": email.strip(),
        "address": address.strip(),
        "gstin": gstin.strip().upper(),
        "currency_code": currency_code,
        "date_format": date_format,
        "financial_year_start_month": (
            parsed_month
            if parsed_month is not None
            else 4
        ),
        "timezone_name": timezone_name,
        "default_payment_method_id": (
            parsed_payment_method
        ),
        "report_header": (
            report_header.strip()
        ),
        "report_footer": (
            report_footer.strip()
        ),
    }

    if (
        not errors
        and parsed_payment_method is not None
    ):
        payment_method_exists = db.execute(
            text(
                """
                SELECT id
                FROM payment_methods
                WHERE id = :method_id
                  AND owner_id = :owner_id
                  AND is_active = TRUE
                """
            ),
            {
                "method_id": (
                    parsed_payment_method
                ),
                "owner_id": user.id,
            },
        ).scalar_one_or_none()

        if payment_method_exists is None:
            errors[
                "default_payment_method_id"
            ] = (
                "Selected payment method "
                "is unavailable."
            )

    if errors:
        return render_finance_business_settings(
            request=request,
            user=user,
            db=db,
            settings=settings,
            errors=errors,
            status_code=422,
        )

    try:
        db.execute(
            text(
                """
                INSERT INTO business_settings (
                    owner_id,
                    business_name,
                    owner_name,
                    phone,
                    email,
                    address,
                    gstin,
                    currency_code,
                    currency_symbol,
                    date_format,
                    financial_year_start_month,
                    timezone_name,
                    default_payment_method_id,
                    report_header,
                    report_footer,
                    created_at,
                    updated_at
                )
                VALUES (
                    :owner_id,
                    :business_name,
                    :owner_name,
                    :phone,
                    :email,
                    :address,
                    :gstin,
                    :currency_code,
                    :currency_symbol,
                    :date_format,
                    :financial_year_start_month,
                    :timezone_name,
                    :default_payment_method_id,
                    :report_header,
                    :report_footer,
                    NOW(),
                    NOW()
                )
                ON CONFLICT (owner_id)
                DO UPDATE SET
                    business_name =
                        EXCLUDED.business_name,
                    owner_name =
                        EXCLUDED.owner_name,
                    phone =
                        EXCLUDED.phone,
                    email =
                        EXCLUDED.email,
                    address =
                        EXCLUDED.address,
                    gstin =
                        EXCLUDED.gstin,
                    currency_code =
                        EXCLUDED.currency_code,
                    currency_symbol =
                        EXCLUDED.currency_symbol,
                    date_format =
                        EXCLUDED.date_format,
                    financial_year_start_month =
                        EXCLUDED.financial_year_start_month,
                    timezone_name =
                        EXCLUDED.timezone_name,
                    default_payment_method_id =
                        EXCLUDED.default_payment_method_id,
                    report_header =
                        EXCLUDED.report_header,
                    report_footer =
                        EXCLUDED.report_footer,
                    updated_at = NOW()
                """
            ),
            {
                "owner_id": user.id,
                "business_name": (
                    settings["business_name"]
                ),
                "owner_name": (
                    normalize_optional_text(
                        settings["owner_name"]
                    )
                ),
                "phone": (
                    normalize_optional_text(
                        settings["phone"]
                    )
                ),
                "email": (
                    normalize_optional_text(
                        settings["email"]
                    )
                ),
                "address": (
                    normalize_optional_text(
                        settings["address"]
                    )
                ),
                "gstin": (
                    normalize_optional_text(
                        settings["gstin"]
                    )
                ),
                "currency_code": currency_code,
                "currency_symbol": (
                    currency_map[currency_code]
                ),
                "date_format": date_format,
                "financial_year_start_month": (
                    parsed_month
                ),
                "timezone_name": timezone_name,
                "default_payment_method_id": (
                    parsed_payment_method
                ),
                "report_header": (
                    normalize_optional_text(
                        settings["report_header"]
                    )
                ),
                "report_footer": (
                    normalize_optional_text(
                        settings["report_footer"]
                    )
                ),
            },
        )

        if parsed_payment_method is not None:
            finance_set_default_payment_method(
                db=db,
                owner_id=user.id,
                method_id=(
                    parsed_payment_method
                ),
            )

        audit(
            db,
            request,
            "business_settings_updated",
            user.id,
            (
                "Business settings updated; "
                f"Business: "
                f"{settings['business_name']}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return render_finance_business_settings(
            request=request,
            user=user,
            db=db,
            settings=settings,
            errors={
                "form": (
                    "Unable to save business "
                    "settings. Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/business-settings/manage"
            "?success="
            + quote(
                "Business settings were "
                "saved successfully."
            )
        ),
        status_code=303,
    )


# PATCH-FINANCE-001D: PAYMENT METHODS MANAGEMENT


MESSIS_PAYMENT_METHOD_ICONS = (
    "💳",
    "💵",
    "📱",
    "🏦",
    "🧾",
    "✍️",
    "💰",
    "🌐",
    "📦",
)


def finance_payment_method_row(
    db: Session,
    owner_id: int,
    method_id: int,
) -> dict[str, object]:
    row = db.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                name,
                method_code,
                icon,
                is_system,
                is_default,
                is_active,
                display_order,
                notes,
                created_at,
                updated_at
            FROM payment_methods
            WHERE id = :method_id
              AND owner_id = :owner_id
            """
        ),
        {
            "method_id": method_id,
            "owner_id": owner_id,
        },
    ).mappings().first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Payment method not found.",
        )

    return dict(row)


def finance_payment_method_code(
    name: str,
) -> str:
    normalized = re.sub(
        r"[^a-z0-9]+",
        "_",
        name.strip().lower(),
    ).strip("_")

    if not normalized:
        normalized = "payment_method"

    return normalized[:80]


def finance_payment_method_values(
    method: dict[str, object] | None = None,
    *,
    name: str = "",
    icon: str = "💳",
    display_order: str = "100",
    notes: str = "",
    is_default: bool = False,
) -> dict[str, object]:
    if method is not None:
        return {
            "name": str(
                method.get("name") or ""
            ),
            "icon": str(
                method.get("icon") or "💳"
            ),
            "display_order": str(
                method.get("display_order")
                or 100
            ),
            "notes": str(
                method.get("notes") or ""
            ),
            "is_default": bool(
                method.get("is_default")
            ),
        }

    return {
        "name": name,
        "icon": icon,
        "display_order": display_order,
        "notes": notes,
        "is_default": is_default,
    }


def validate_finance_payment_method(
    name: str,
    icon: str,
    display_order: str,
    notes: str,
) -> tuple[
    dict[str, str],
    int | None,
]:
    errors: dict[str, str] = {}

    normalized_name = name.strip()
    normalized_icon = icon.strip()

    if not normalized_name:
        errors["name"] = (
            "Payment method name is required."
        )
    elif len(normalized_name) > 120:
        errors["name"] = (
            "Payment method name cannot exceed "
            "120 characters."
        )

    if (
        normalized_icon
        not in MESSIS_PAYMENT_METHOD_ICONS
    ):
        errors["icon"] = (
            "Select a valid payment method icon."
        )

    parsed_order = None

    try:
        parsed_order = int(display_order)
    except (TypeError, ValueError):
        errors["display_order"] = (
            "Display order must be a number."
        )
    else:
        if not 1 <= parsed_order <= 9999:
            errors["display_order"] = (
                "Display order must be between "
                "1 and 9999."
            )

    if len(notes.strip()) > 1000:
        errors["notes"] = (
            "Notes cannot exceed 1000 characters."
        )

    return errors, parsed_order


def render_finance_payment_method_form(
    request: Request,
    user: User,
    *,
    page_title: str,
    form_action: str,
    submit_label: str,
    form_data: dict[str, object],
    errors: dict[str, str],
    is_system: bool = False,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name=(
            "finance/"
            "payment-method-form.html"
        ),
        context={
            "current_user": user,
            "page_title": page_title,
            "form_action": form_action,
            "submit_label": submit_label,
            "form_data": form_data,
            "errors": errors,
            "is_system": is_system,
            "icon_options": (
                MESSIS_PAYMENT_METHOD_ICONS
            ),
        },
        status_code=status_code,
    )


def finance_set_default_payment_method(
    db: Session,
    owner_id: int,
    method_id: int,
) -> None:
    db.execute(
        text(
            """
            UPDATE payment_methods
            SET
                is_default = FALSE,
                updated_at = NOW()
            WHERE owner_id = :owner_id
            """
        ),
        {
            "owner_id": owner_id,
        },
    )

    result = db.execute(
        text(
            """
            UPDATE payment_methods
            SET
                is_default = TRUE,
                is_active = TRUE,
                updated_at = NOW()
            WHERE id = :method_id
              AND owner_id = :owner_id
            """
        ),
        {
            "method_id": method_id,
            "owner_id": owner_id,
        },
    )

    if result.rowcount == 0:
        raise HTTPException(
            status_code=404,
            detail="Payment method not found.",
        )


@app.get(
    "/payment-methods",
    response_class=JSONResponse,
)
def list_payment_methods_api(
    active_only: bool = True,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    conditions = [
        "owner_id = :owner_id",
    ]

    if active_only:
        conditions.append(
            "is_active = TRUE"
        )

    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                name,
                method_code,
                icon,
                is_system,
                is_default,
                is_active,
                display_order,
                notes
            FROM payment_methods
            WHERE {' AND '.join(conditions)}
            ORDER BY
                is_default DESC,
                display_order,
                LOWER(name),
                id
            """
        ),
        {
            "owner_id": user.id,
        },
    ).mappings().all()

    return {
        "count": len(rows),
        "items": [
            dict(row)
            for row in rows
        ],
    }


@app.get(
    "/payment-methods/manage",
    response_class=HTMLResponse,
)
def finance_payment_method_management(
    request: Request,
    search: str = "",
    status: str = "active",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_search = search.strip()
    normalized_status = status.strip().lower()

    if normalized_status not in {
        "active",
        "inactive",
        "all",
    }:
        normalized_status = "active"

    conditions = [
        "owner_id = :owner_id",
    ]

    parameters: dict[str, object] = {
        "owner_id": user.id,
    }

    if normalized_status == "active":
        conditions.append(
            "is_active = TRUE"
        )
    elif normalized_status == "inactive":
        conditions.append(
            "is_active = FALSE"
        )

    if normalized_search:
        conditions.append(
            "LOWER(name) LIKE :search_value"
        )

        parameters["search_value"] = (
            "%"
            + normalized_search.lower()
            + "%"
        )

    rows = db.execute(
        text(
            f"""
            SELECT
                id,
                name,
                method_code,
                icon,
                is_system,
                is_default,
                is_active,
                display_order,
                notes,
                updated_at
            FROM payment_methods
            WHERE {' AND '.join(conditions)}
            ORDER BY
                is_default DESC,
                is_active DESC,
                display_order,
                LOWER(name),
                id
            """
        ),
        parameters,
    ).mappings().all()

    methods = [
        dict(row)
        for row in rows
    ]

    summary = db.execute(
        text(
            """
            SELECT
                COUNT(*) AS total_methods,
                COUNT(*) FILTER (
                    WHERE is_active = TRUE
                ) AS active_methods,
                COUNT(*) FILTER (
                    WHERE is_system = FALSE
                ) AS custom_methods,
                MAX(name) FILTER (
                    WHERE is_default = TRUE
                ) AS default_method
            FROM payment_methods
            WHERE owner_id = :owner_id
            """
        ),
        {
            "owner_id": user.id,
        },
    ).mappings().one()

    return templates.TemplateResponse(
        request=request,
        name=(
            "finance/"
            "payment-methods.html"
        ),
        context={
            "current_user": user,
            "methods": methods,
            "filters": {
                "search": normalized_search,
                "status": normalized_status,
            },
            "summary": {
                "total_methods": int(
                    summary["total_methods"]
                    or 0
                ),
                "active_methods": int(
                    summary["active_methods"]
                    or 0
                ),
                "custom_methods": int(
                    summary["custom_methods"]
                    or 0
                ),
                "default_method": (
                    summary["default_method"]
                    or "Not set"
                ),
            },
            "success_message": (
                request.query_params.get(
                    "success"
                )
            ),
            "error_message": (
                request.query_params.get(
                    "error"
                )
            ),
        },
    )


@app.get(
    "/payment-methods/new",
    response_class=HTMLResponse,
)
def finance_payment_method_create_page(
    request: Request,
    user: User = Depends(current_user),
):
    return render_finance_payment_method_form(
        request=request,
        user=user,
        page_title="Add Payment Method",
        form_action="/payment-methods/new",
        submit_label="Create Payment Method",
        form_data=(
            finance_payment_method_values()
        ),
        errors={},
    )


@app.post(
    "/payment-methods/new",
    response_class=HTMLResponse,
)
def finance_payment_method_create_submit(
    request: Request,
    name: str = Form(...),
    icon: str = Form("💳"),
    display_order: str = Form("100"),
    notes: str = Form(""),
    is_default: str | None = Form(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    selected_default = (
        is_default == "true"
    )

    form_data = finance_payment_method_values(
        name=name,
        icon=icon,
        display_order=display_order,
        notes=notes,
        is_default=selected_default,
    )

    errors, parsed_order = (
        validate_finance_payment_method(
            name=name,
            icon=icon,
            display_order=display_order,
            notes=notes,
        )
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.execute(
            text(
                """
                SELECT id
                FROM payment_methods
                WHERE owner_id = :owner_id
                  AND LOWER(name)
                      = LOWER(:name)
                LIMIT 1
                """
            ),
            {
                "owner_id": user.id,
                "name": normalized_name,
            },
        ).scalar_one_or_none()

        if duplicate is not None:
            errors["name"] = (
                "A payment method with this "
                "name already exists."
            )

    if errors:
        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Add Payment Method",
            form_action="/payment-methods/new",
            submit_label="Create Payment Method",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    base_code = finance_payment_method_code(
        normalized_name
    )

    method_code = base_code
    suffix = 1

    while db.execute(
        text(
            """
            SELECT id
            FROM payment_methods
            WHERE owner_id = :owner_id
              AND method_code = :method_code
            LIMIT 1
            """
        ),
        {
            "owner_id": user.id,
            "method_code": method_code,
        },
    ).scalar_one_or_none() is not None:
        suffix += 1
        method_code = (
            f"{base_code}_{suffix}"
        )[:80]

    try:
        method_id = db.execute(
            text(
                """
                INSERT INTO payment_methods (
                    owner_id,
                    name,
                    method_code,
                    icon,
                    is_system,
                    is_default,
                    is_active,
                    display_order,
                    notes,
                    created_at,
                    updated_at
                )
                VALUES (
                    :owner_id,
                    :name,
                    :method_code,
                    :icon,
                    FALSE,
                    FALSE,
                    TRUE,
                    :display_order,
                    :notes,
                    NOW(),
                    NOW()
                )
                RETURNING id
                """
            ),
            {
                "owner_id": user.id,
                "name": normalized_name,
                "method_code": method_code,
                "icon": icon,
                "display_order": (
                    parsed_order
                ),
                "notes": (
                    normalize_optional_text(
                        notes
                    )
                ),
            },
        ).scalar_one()

        if selected_default:
            finance_set_default_payment_method(
                db=db,
                owner_id=user.id,
                method_id=method_id,
            )

        audit(
            db,
            request,
            "payment_method_created",
            user.id,
            (
                f"Payment method ID: "
                f"{method_id}; "
                f"Name: {normalized_name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Add Payment Method",
            form_action="/payment-methods/new",
            submit_label="Create Payment Method",
            form_data=form_data,
            errors={
                "name": (
                    "A payment method with this "
                    "name already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Add Payment Method",
            form_action="/payment-methods/new",
            submit_label="Create Payment Method",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to create payment "
                    "method. Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/payment-methods/manage"
            "?success="
            + quote(
                f"{normalized_name} was created."
            )
        ),
        status_code=303,
    )


@app.get(
    "/payment-methods/{method_id}/edit",
    response_class=HTMLResponse,
)
def finance_payment_method_edit_page(
    method_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    method = finance_payment_method_row(
        db=db,
        owner_id=user.id,
        method_id=method_id,
    )

    return render_finance_payment_method_form(
        request=request,
        user=user,
        page_title="Edit Payment Method",
        form_action=(
            f"/payment-methods/{method_id}/edit"
        ),
        submit_label="Update Payment Method",
        form_data=(
            finance_payment_method_values(
                method
            )
        ),
        errors={},
        is_system=bool(
            method["is_system"]
        ),
    )


@app.post(
    "/payment-methods/{method_id}/edit",
    response_class=HTMLResponse,
)
def finance_payment_method_edit_submit(
    method_id: int,
    request: Request,
    name: str = Form(...),
    icon: str = Form("💳"),
    display_order: str = Form("100"),
    notes: str = Form(""),
    is_default: str | None = Form(None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    method = finance_payment_method_row(
        db=db,
        owner_id=user.id,
        method_id=method_id,
    )

    selected_default = (
        is_default == "true"
    )

    form_data = finance_payment_method_values(
        name=name,
        icon=icon,
        display_order=display_order,
        notes=notes,
        is_default=selected_default,
    )

    errors, parsed_order = (
        validate_finance_payment_method(
            name=name,
            icon=icon,
            display_order=display_order,
            notes=notes,
        )
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.execute(
            text(
                """
                SELECT id
                FROM payment_methods
                WHERE owner_id = :owner_id
                  AND id <> :method_id
                  AND LOWER(name)
                      = LOWER(:name)
                LIMIT 1
                """
            ),
            {
                "owner_id": user.id,
                "method_id": method_id,
                "name": normalized_name,
            },
        ).scalar_one_or_none()

        if duplicate is not None:
            errors["name"] = (
                "A payment method with this "
                "name already exists."
            )

    if errors:
        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Edit Payment Method",
            form_action=(
                f"/payment-methods/{method_id}/edit"
            ),
            submit_label="Update Payment Method",
            form_data=form_data,
            errors=errors,
            is_system=bool(
                method["is_system"]
            ),
            status_code=422,
        )

    try:
        db.execute(
            text(
                """
                UPDATE payment_methods
                SET
                    name = :name,
                    icon = :icon,
                    display_order =
                        :display_order,
                    notes = :notes,
                    updated_at = NOW()
                WHERE id = :method_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "method_id": method_id,
                "owner_id": user.id,
                "name": normalized_name,
                "icon": icon,
                "display_order": (
                    parsed_order
                ),
                "notes": (
                    normalize_optional_text(
                        notes
                    )
                ),
            },
        )

        if selected_default:
            finance_set_default_payment_method(
                db=db,
                owner_id=user.id,
                method_id=method_id,
            )
        elif bool(method["is_default"]):
            db.execute(
                text(
                    """
                    UPDATE payment_methods
                    SET
                        is_default = FALSE,
                        updated_at = NOW()
                    WHERE id = :method_id
                      AND owner_id = :owner_id
                    """
                ),
                {
                    "method_id": method_id,
                    "owner_id": user.id,
                },
            )

        audit(
            db,
            request,
            "payment_method_updated",
            user.id,
            (
                f"Payment method ID: "
                f"{method_id}; "
                f"Name: {normalized_name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Edit Payment Method",
            form_action=(
                f"/payment-methods/{method_id}/edit"
            ),
            submit_label="Update Payment Method",
            form_data=form_data,
            errors={
                "name": (
                    "A payment method with this "
                    "name already exists."
                )
            },
            is_system=bool(
                method["is_system"]
            ),
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_payment_method_form(
            request=request,
            user=user,
            page_title="Edit Payment Method",
            form_action=(
                f"/payment-methods/{method_id}/edit"
            ),
            submit_label="Update Payment Method",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to update payment "
                    "method. Please try again."
                )
            },
            is_system=bool(
                method["is_system"]
            ),
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/payment-methods/manage"
            "?success="
            + quote(
                f"{normalized_name} was updated."
            )
        ),
        status_code=303,
    )


@app.post(
    "/payment-methods/{method_id}/default",
)
def finance_payment_method_make_default(
    method_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    method = finance_payment_method_row(
        db=db,
        owner_id=user.id,
        method_id=method_id,
    )

    try:
        finance_set_default_payment_method(
            db=db,
            owner_id=user.id,
            method_id=method_id,
        )

        audit(
            db,
            request,
            "payment_method_default_changed",
            user.id,
            (
                f"Payment method ID: "
                f"{method_id}; "
                f"Name: {method['name']}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                "/payment-methods/manage"
                "?error="
                + quote(
                    "Unable to set default "
                    "payment method."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/payment-methods/manage"
            "?success="
            + quote(
                f"{method['name']} is now "
                "the default payment method."
            )
        ),
        status_code=303,
    )


@app.post(
    "/payment-methods/{method_id}/toggle",
)
def finance_payment_method_toggle(
    method_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    method = finance_payment_method_row(
        db=db,
        owner_id=user.id,
        method_id=method_id,
    )

    new_status = not bool(
        method["is_active"]
    )

    if (
        bool(method["is_default"])
        and not new_status
    ):
        return RedirectResponse(
            url=(
                "/payment-methods/manage"
                "?error="
                + quote(
                    "The default payment method "
                    "cannot be disabled. Set another "
                    "method as default first."
                )
            ),
            status_code=303,
        )

    state = (
        "enabled"
        if new_status
        else "disabled"
    )

    try:
        db.execute(
            text(
                """
                UPDATE payment_methods
                SET
                    is_active = :is_active,
                    updated_at = NOW()
                WHERE id = :method_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "method_id": method_id,
                "owner_id": user.id,
                "is_active": new_status,
            },
        )

        audit(
            db,
            request,
            "payment_method_status_changed",
            user.id,
            (
                f"Payment method ID: "
                f"{method_id}; "
                f"Status: {state}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                "/payment-methods/manage"
                "?error="
                + quote(
                    "Unable to change payment "
                    "method status."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/payment-methods/manage"
            "?success="
            + quote(
                f"{method['name']} was {state}."
            )
        ),
        status_code=303,
    )


# PATCH-FINANCE-001C: EXPENSE CATEGORIES MANAGEMENT UI


MESSIS_CATEGORY_ICONS = (
    "📂",
    "👷",
    "🌱",
    "🚚",
    "⚡",
    "⛽",
    "🛠️",
    "🥥",
    "💧",
    "🧪",
    "🚜",
    "🏪",
    "🧾",
    "📦",
    "➕",
)


def finance_category_row(
    db: Session,
    owner_id: int,
    category_id: int,
) -> dict[str, object]:
    row = db.execute(
        text(
            """
            SELECT
                id,
                owner_id,
                name,
                is_system,
                icon,
                color,
                display_order,
                is_active,
                created_at,
                updated_at
            FROM expense_categories
            WHERE id = :category_id
              AND owner_id = :owner_id
            """
        ),
        {
            "category_id": category_id,
            "owner_id": owner_id,
        },
    ).mappings().first()

    if row is None:
        raise HTTPException(
            status_code=404,
            detail="Expense category not found.",
        )

    return dict(row)


def finance_category_form_values(
    category: dict[str, object] | None = None,
    *,
    name: str = "",
    icon: str = "📂",
    color: str = "#059669",
    display_order: str = "100",
) -> dict[str, str]:
    if category is not None:
        return {
            "name": str(
                category.get("name") or ""
            ),
            "icon": str(
                category.get("icon") or "📂"
            ),
            "color": str(
                category.get("color")
                or "#059669"
            ),
            "display_order": str(
                category.get("display_order")
                or 100
            ),
        }

    return {
        "name": name,
        "icon": icon,
        "color": color,
        "display_order": display_order,
    }


def validate_finance_category_form(
    name: str,
    icon: str,
    color: str,
    display_order: str,
) -> tuple[
    dict[str, str],
    int | None,
]:
    errors: dict[str, str] = {}

    normalized_name = name.strip()
    normalized_icon = icon.strip()
    normalized_color = color.strip()

    if not normalized_name:
        errors["name"] = (
            "Category name is required."
        )
    elif len(normalized_name) > 120:
        errors["name"] = (
            "Category name cannot exceed "
            "120 characters."
        )

    if normalized_icon not in MESSIS_CATEGORY_ICONS:
        errors["icon"] = (
            "Select a valid category icon."
        )

    if (
        len(normalized_color) != 7
        or not normalized_color.startswith("#")
    ):
        errors["color"] = (
            "Select a valid category colour."
        )
    else:
        try:
            int(normalized_color[1:], 16)
        except ValueError:
            errors["color"] = (
                "Select a valid category colour."
            )

    parsed_order = None

    try:
        parsed_order = int(display_order)
    except (TypeError, ValueError):
        errors["display_order"] = (
            "Display order must be a number."
        )
    else:
        if not 1 <= parsed_order <= 9999:
            errors["display_order"] = (
                "Display order must be between "
                "1 and 9999."
            )

    return errors, parsed_order


def render_finance_category_form(
    request: Request,
    user: User,
    *,
    page_title: str,
    form_action: str,
    submit_label: str,
    form_data: dict[str, str],
    errors: dict[str, str],
    is_system: bool = False,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name=(
            "finance/"
            "expense-category-form.html"
        ),
        context={
            "current_user": user,
            "page_title": page_title,
            "form_action": form_action,
            "submit_label": submit_label,
            "form_data": form_data,
            "errors": errors,
            "is_system": is_system,
            "icon_options": (
                MESSIS_CATEGORY_ICONS
            ),
        },
        status_code=status_code,
    )


@app.get(
    "/expense-categories/manage",
    response_class=HTMLResponse,
)
def finance_category_management_page(
    request: Request,
    search: str = "",
    category_type: str = "",
    status: str = "active",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_search = search.strip()
    normalized_type = (
        category_type.strip().lower()
    )
    normalized_status = (
        status.strip().lower()
    )

    if normalized_type not in {
        "",
        "system",
        "custom",
    }:
        normalized_type = ""

    if normalized_status not in {
        "active",
        "inactive",
        "all",
    }:
        normalized_status = "active"

    conditions = [
        "c.owner_id = :owner_id",
    ]

    parameters: dict[str, object] = {
        "owner_id": user.id,
    }

    if normalized_status == "active":
        conditions.append(
            "c.is_active = TRUE"
        )
    elif normalized_status == "inactive":
        conditions.append(
            "c.is_active = FALSE"
        )

    if normalized_type == "system":
        conditions.append(
            "c.is_system = TRUE"
        )
    elif normalized_type == "custom":
        conditions.append(
            "c.is_system = FALSE"
        )

    if normalized_search:
        conditions.append(
            "LOWER(c.name) LIKE :search_value"
        )

        parameters["search_value"] = (
            "%"
            + normalized_search.lower()
            + "%"
        )

    rows = db.execute(
        text(
            f"""
            SELECT
                c.id,
                c.name,
                c.is_system,
                c.icon,
                c.color,
                c.display_order,
                c.is_active,
                c.updated_at,
                COUNT(e.id) AS expense_count,
                COALESCE(
                    SUM(e.amount),
                    0
                ) AS total_expense
            FROM expense_categories AS c
            LEFT JOIN expenses AS e
                ON e.category_id = c.id
               AND e.owner_id = c.owner_id
            WHERE {' AND '.join(conditions)}
            GROUP BY
                c.id,
                c.name,
                c.is_system,
                c.icon,
                c.color,
                c.display_order,
                c.is_active,
                c.updated_at
            ORDER BY
                c.is_active DESC,
                c.display_order,
                LOWER(c.name),
                c.id
            """
        ),
        parameters,
    ).mappings().all()

    categories = []

    for row in rows:
        item = dict(row)

        item["expense_count"] = int(
            item.get("expense_count") or 0
        )

        item["total_expense"] = Decimal(
            str(
                item.get("total_expense")
                or 0
            )
        ).quantize(Decimal("0.01"))

        categories.append(item)

    summary = db.execute(
        text(
            """
            SELECT
                COUNT(DISTINCT c.id)
                    AS total_categories,
                COUNT(DISTINCT c.id)
                    FILTER (
                        WHERE c.is_active = TRUE
                    )
                    AS active_categories,
                COUNT(e.id)
                    AS expense_count,
                COALESCE(
                    SUM(e.amount),
                    0
                )
                    AS total_expense
            FROM expense_categories AS c
            LEFT JOIN expenses AS e
                ON e.category_id = c.id
               AND e.owner_id = c.owner_id
            WHERE c.owner_id = :owner_id
            """
        ),
        {
            "owner_id": user.id,
        },
    ).mappings().one()

    return templates.TemplateResponse(
        request=request,
        name=(
            "finance/"
            "expense-categories.html"
        ),
        context={
            "current_user": user,
            "categories": categories,
            "filters": {
                "search": normalized_search,
                "category_type": normalized_type,
                "status": normalized_status,
            },
            "summary": {
                "total_categories": int(
                    summary[
                        "total_categories"
                    ]
                    or 0
                ),
                "active_categories": int(
                    summary[
                        "active_categories"
                    ]
                    or 0
                ),
                "expense_count": int(
                    summary["expense_count"]
                    or 0
                ),
                "total_expense": Decimal(
                    str(
                        summary["total_expense"]
                        or 0
                    )
                ).quantize(
                    Decimal("0.01")
                ),
            },
            "success_message": (
                request.query_params.get(
                    "success"
                )
            ),
            "error_message": (
                request.query_params.get(
                    "error"
                )
            ),
        },
    )


@app.get(
    "/expense-categories/new",
    response_class=HTMLResponse,
)
def finance_category_create_page(
    request: Request,
    user: User = Depends(current_user),
):
    return render_finance_category_form(
        request=request,
        user=user,
        page_title="Add Expense Category",
        form_action=(
            "/expense-categories/new"
        ),
        submit_label="Create Category",
        form_data=(
            finance_category_form_values()
        ),
        errors={},
    )


@app.post(
    "/expense-categories/new",
    response_class=HTMLResponse,
)
def finance_category_create_submit(
    request: Request,
    name: str = Form(...),
    icon: str = Form("📂"),
    color: str = Form("#059669"),
    display_order: str = Form("100"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form_data = (
        finance_category_form_values(
            name=name,
            icon=icon,
            color=color,
            display_order=display_order,
        )
    )

    errors, parsed_order = (
        validate_finance_category_form(
            name=name,
            icon=icon,
            color=color,
            display_order=display_order,
        )
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.execute(
            text(
                """
                SELECT id
                FROM expense_categories
                WHERE owner_id = :owner_id
                  AND LOWER(name)
                      = LOWER(:name)
                LIMIT 1
                """
            ),
            {
                "owner_id": user.id,
                "name": normalized_name,
            },
        ).scalar_one_or_none()

        if duplicate is not None:
            errors["name"] = (
                "A category with this name "
                "already exists."
            )

    if errors:
        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Add Expense Category"
            ),
            form_action=(
                "/expense-categories/new"
            ),
            submit_label="Create Category",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    try:
        category_id = db.execute(
            text(
                """
                INSERT INTO expense_categories (
                    owner_id,
                    name,
                    is_system,
                    icon,
                    color,
                    display_order,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (
                    :owner_id,
                    :name,
                    FALSE,
                    :icon,
                    :color,
                    :display_order,
                    TRUE,
                    NOW(),
                    NOW()
                )
                RETURNING id
                """
            ),
            {
                "owner_id": user.id,
                "name": normalized_name,
                "icon": icon,
                "color": color,
                "display_order": (
                    parsed_order
                ),
            },
        ).scalar_one()

        audit(
            db,
            request,
            "expense_category_created",
            user.id,
            (
                f"Category ID: {category_id}; "
                f"Name: {normalized_name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Add Expense Category"
            ),
            form_action=(
                "/expense-categories/new"
            ),
            submit_label="Create Category",
            form_data=form_data,
            errors={
                "name": (
                    "A category with this name "
                    "already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Add Expense Category"
            ),
            form_action=(
                "/expense-categories/new"
            ),
            submit_label="Create Category",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to create category. "
                    "Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/expense-categories/manage"
            "?success="
            + quote(
                f"{normalized_name} was created."
            )
        ),
        status_code=303,
    )


@app.get(
    "/expense-categories/{category_id}/edit",
    response_class=HTMLResponse,
)
def finance_category_edit_page(
    category_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    category = finance_category_row(
        db=db,
        owner_id=user.id,
        category_id=category_id,
    )

    return render_finance_category_form(
        request=request,
        user=user,
        page_title="Edit Expense Category",
        form_action=(
            "/expense-categories/"
            f"{category_id}/edit"
        ),
        submit_label="Update Category",
        form_data=(
            finance_category_form_values(
                category
            )
        ),
        errors={},
        is_system=bool(
            category["is_system"]
        ),
    )


@app.post(
    "/expense-categories/{category_id}/edit",
    response_class=HTMLResponse,
)
def finance_category_edit_submit(
    category_id: int,
    request: Request,
    name: str = Form(...),
    icon: str = Form("📂"),
    color: str = Form("#059669"),
    display_order: str = Form("100"),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    category = finance_category_row(
        db=db,
        owner_id=user.id,
        category_id=category_id,
    )

    form_data = (
        finance_category_form_values(
            name=name,
            icon=icon,
            color=color,
            display_order=display_order,
        )
    )

    errors, parsed_order = (
        validate_finance_category_form(
            name=name,
            icon=icon,
            color=color,
            display_order=display_order,
        )
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.execute(
            text(
                """
                SELECT id
                FROM expense_categories
                WHERE owner_id = :owner_id
                  AND id <> :category_id
                  AND LOWER(name)
                      = LOWER(:name)
                LIMIT 1
                """
            ),
            {
                "owner_id": user.id,
                "category_id": category_id,
                "name": normalized_name,
            },
        ).scalar_one_or_none()

        if duplicate is not None:
            errors["name"] = (
                "A category with this name "
                "already exists."
            )

    if errors:
        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Edit Expense Category"
            ),
            form_action=(
                "/expense-categories/"
                f"{category_id}/edit"
            ),
            submit_label="Update Category",
            form_data=form_data,
            errors=errors,
            is_system=bool(
                category["is_system"]
            ),
            status_code=422,
        )

    try:
        db.execute(
            text(
                """
                UPDATE expense_categories
                SET
                    name = :name,
                    icon = :icon,
                    color = :color,
                    display_order =
                        :display_order,
                    updated_at = NOW()
                WHERE id = :category_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "category_id": category_id,
                "owner_id": user.id,
                "name": normalized_name,
                "icon": icon,
                "color": color,
                "display_order": (
                    parsed_order
                ),
            },
        )

        audit(
            db,
            request,
            "expense_category_updated",
            user.id,
            (
                f"Category ID: {category_id}; "
                f"Name: {normalized_name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Edit Expense Category"
            ),
            form_action=(
                "/expense-categories/"
                f"{category_id}/edit"
            ),
            submit_label="Update Category",
            form_data=form_data,
            errors={
                "name": (
                    "A category with this name "
                    "already exists."
                )
            },
            is_system=bool(
                category["is_system"]
            ),
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_category_form(
            request=request,
            user=user,
            page_title=(
                "Edit Expense Category"
            ),
            form_action=(
                "/expense-categories/"
                f"{category_id}/edit"
            ),
            submit_label="Update Category",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to update category. "
                    "Please try again."
                )
            },
            is_system=bool(
                category["is_system"]
            ),
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/expense-categories/manage"
            "?success="
            + quote(
                f"{normalized_name} was updated."
            )
        ),
        status_code=303,
    )


@app.post(
    "/expense-categories/{category_id}/toggle",
)
def finance_category_toggle_status(
    category_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    category = finance_category_row(
        db=db,
        owner_id=user.id,
        category_id=category_id,
    )

    new_status = not bool(
        category["is_active"]
    )

    state = (
        "enabled"
        if new_status
        else "disabled"
    )

    try:
        db.execute(
            text(
                """
                UPDATE expense_categories
                SET
                    is_active = :is_active,
                    updated_at = NOW()
                WHERE id = :category_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "category_id": category_id,
                "owner_id": user.id,
                "is_active": new_status,
            },
        )

        audit(
            db,
            request,
            "expense_category_status_changed",
            user.id,
            (
                f"Category ID: {category_id}; "
                f"Status: {state}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                "/expense-categories/manage"
                "?error="
                + quote(
                    "Unable to change "
                    "category status."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/expense-categories/manage"
            "?success="
            + quote(
                f"{category['name']} "
                f"was {state}."
            )
        ),
        status_code=303,
    )


# PATCH-FINANCE-001B: VENDORS MANAGEMENT UI


MESSIS_VENDOR_TYPES = (
    "Fertilizer",
    "Equipment",
    "Labour",
    "Transport",
    "Irrigation",
    "Pesticide",
    "Electricity",
    "Maintenance",
    "General",
)


def require_finance_vendor(
    vendor_id: int,
    user: User,
    db: Session,
) -> Vendor:
    vendor = db.scalar(
        select(Vendor).where(
            Vendor.id == vendor_id,
            Vendor.owner_id == user.id,
        )
    )

    if vendor is None:
        raise HTTPException(
            status_code=404,
            detail="Vendor not found.",
        )

    return vendor


def finance_vendor_form_values(
    vendor: Vendor | None = None,
    *,
    name: str = "",
    vendor_type: str = "General",
    mobile_number: str = "",
    email: str = "",
    address: str = "",
    notes: str = "",
) -> dict[str, str]:
    if vendor is not None:
        return {
            "name": vendor.name or "",
            "vendor_type": (
                getattr(
                    vendor,
                    "vendor_type",
                    None,
                )
                or "General"
            ),
            "mobile_number": (
                vendor.mobile_number or ""
            ),
            "email": vendor.email or "",
            "address": vendor.address or "",
            "notes": vendor.notes or "",
        }

    return {
        "name": name,
        "vendor_type": vendor_type,
        "mobile_number": mobile_number,
        "email": email,
        "address": address,
        "notes": notes,
    }


def validate_finance_vendor_form(
    name: str,
    vendor_type: str,
    mobile_number: str,
    email: str,
    address: str,
    notes: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}

    normalized_name = name.strip()
    normalized_type = vendor_type.strip()
    normalized_mobile = mobile_number.strip()
    normalized_email = email.strip()

    if not normalized_name:
        errors["name"] = "Vendor name is required."
    elif len(normalized_name) > 160:
        errors["name"] = (
            "Vendor name cannot exceed 160 characters."
        )

    if normalized_type not in MESSIS_VENDOR_TYPES:
        errors["vendor_type"] = (
            "Select a valid vendor type."
        )

    if len(normalized_mobile) > 20:
        errors["mobile_number"] = (
            "Mobile number cannot exceed 20 characters."
        )
    elif normalized_mobile:
        compact_mobile = "".join(
            character
            for character in normalized_mobile
            if character not in {
                " ",
                "-",
                "(",
                ")",
            }
        )

        if compact_mobile.startswith("+"):
            compact_mobile = compact_mobile[1:]

        if not compact_mobile.isdigit():
            errors["mobile_number"] = (
                "Enter a valid mobile number."
            )

    if len(normalized_email) > 180:
        errors["email"] = (
            "Email cannot exceed 180 characters."
        )
    elif normalized_email and (
        "@" not in normalized_email
        or "." not in normalized_email.split("@")[-1]
    ):
        errors["email"] = (
            "Enter a valid email address."
        )

    if len(address.strip()) > 1000:
        errors["address"] = (
            "Address cannot exceed 1000 characters."
        )

    if len(notes.strip()) > 2000:
        errors["notes"] = (
            "Notes cannot exceed 2000 characters."
        )

    return errors


def render_finance_vendor_form(
    request: Request,
    user: User,
    *,
    page_title: str,
    form_action: str,
    submit_label: str,
    form_data: dict[str, str],
    errors: dict[str, str],
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name="finance/vendor-form.html",
        context={
            "page_title": page_title,
            "current_user": user,
            "form_action": form_action,
            "submit_label": submit_label,
            "form_data": form_data,
            "errors": errors,
            "vendor_types": MESSIS_VENDOR_TYPES,
        },
        status_code=status_code,
    )


@app.get(
    "/vendors/manage",
    response_class=HTMLResponse,
)
def finance_vendor_management_page(
    request: Request,
    search: str = "",
    vendor_type: str = "",
    status: str = "active",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_search = search.strip()
    normalized_type = vendor_type.strip()
    normalized_status = status.strip().lower()

    if normalized_status not in {
        "active",
        "inactive",
        "all",
    }:
        normalized_status = "active"

    where_parts = [
        "v.owner_id = :owner_id",
    ]

    parameters = {
        "owner_id": user.id,
    }

    if normalized_status == "active":
        where_parts.append(
            "v.is_active = TRUE"
        )
    elif normalized_status == "inactive":
        where_parts.append(
            "v.is_active = FALSE"
        )

    if normalized_type:
        if normalized_type not in MESSIS_VENDOR_TYPES:
            normalized_type = ""
        else:
            where_parts.append(
                "v.vendor_type = :vendor_type"
            )

            parameters["vendor_type"] = (
                normalized_type
            )

    if normalized_search:
        where_parts.append(
            """
            (
                LOWER(v.name)
                    LIKE :search_value
                OR LOWER(
                    COALESCE(
                        v.mobile_number,
                        ''
                    )
                ) LIKE :search_value
                OR LOWER(
                    COALESCE(
                        v.email,
                        ''
                    )
                ) LIKE :search_value
            )
            """
        )

        parameters["search_value"] = (
            "%"
            + normalized_search.lower()
            + "%"
        )

    vendor_rows = db.execute(
        text(
            f"""
            SELECT
                v.id,
                v.name,
                v.vendor_type,
                v.mobile_number,
                v.email,
                v.address,
                v.notes,
                v.is_active,
                COUNT(e.id) AS expense_count,
                COALESCE(
                    SUM(e.amount),
                    0
                ) AS total_purchase,
                MAX(e.expense_date)
                    AS last_purchase
            FROM vendors AS v
            LEFT JOIN expenses AS e
                ON e.vendor_id = v.id
               AND e.owner_id = v.owner_id
            WHERE {' AND '.join(where_parts)}
            GROUP BY
                v.id,
                v.name,
                v.vendor_type,
                v.mobile_number,
                v.email,
                v.address,
                v.notes,
                v.is_active
            ORDER BY
                v.is_active DESC,
                LOWER(v.name),
                v.id DESC
            """
        ),
        parameters,
    ).mappings().all()

    vendors = []

    for row in vendor_rows:
        item = dict(row)

        item["expense_count"] = int(
            item.get("expense_count") or 0
        )

        item["total_purchase"] = Decimal(
            str(
                item.get("total_purchase")
                or 0
            )
        ).quantize(Decimal("0.01"))

        vendors.append(item)

    summary = db.execute(
        text(
            """
            SELECT
                COUNT(DISTINCT v.id)
                    AS total_vendors,
                COUNT(DISTINCT v.id)
                    FILTER (
                        WHERE v.is_active = TRUE
                    )
                    AS active_vendors,
                COUNT(e.id)
                    AS expense_count,
                COALESCE(
                    SUM(e.amount),
                    0
                )
                    AS total_purchase
            FROM vendors AS v
            LEFT JOIN expenses AS e
                ON e.vendor_id = v.id
               AND e.owner_id = v.owner_id
            WHERE v.owner_id = :owner_id
            """
        ),
        {
            "owner_id": user.id,
        },
    ).mappings().one()

    return templates.TemplateResponse(
        request=request,
        name="finance/vendors.html",
        context={
            "current_user": user,
            "vendors": vendors,
            "vendor_types": MESSIS_VENDOR_TYPES,
            "filters": {
                "search": normalized_search,
                "vendor_type": normalized_type,
                "status": normalized_status,
            },
            "summary": {
                "total_vendors": int(
                    summary["total_vendors"]
                    or 0
                ),
                "active_vendors": int(
                    summary["active_vendors"]
                    or 0
                ),
                "expense_count": int(
                    summary["expense_count"]
                    or 0
                ),
                "total_purchase": Decimal(
                    str(
                        summary["total_purchase"]
                        or 0
                    )
                ).quantize(
                    Decimal("0.01")
                ),
            },
            "success_message": (
                request.query_params.get(
                    "success"
                )
            ),
            "error_message": (
                request.query_params.get(
                    "error"
                )
            ),
        },
    )


@app.get(
    "/vendors/new",
    response_class=HTMLResponse,
)
def finance_vendor_create_page(
    request: Request,
    user: User = Depends(current_user),
):
    return render_finance_vendor_form(
        request=request,
        user=user,
        page_title="Add Vendor",
        form_action="/vendors/new",
        submit_label="Create Vendor",
        form_data=finance_vendor_form_values(),
        errors={},
    )


@app.post(
    "/vendors/new",
    response_class=HTMLResponse,
)
def finance_vendor_create_submit(
    request: Request,
    name: str = Form(...),
    vendor_type: str = Form("General"),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form_data = finance_vendor_form_values(
        name=name,
        vendor_type=vendor_type,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    errors = validate_finance_vendor_form(
        name=name,
        vendor_type=vendor_type,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.scalar(
            select(Vendor.id).where(
                Vendor.owner_id == user.id,
                func.lower(Vendor.name)
                == normalized_name.lower(),
            )
        )

        if duplicate is not None:
            errors["name"] = (
                "A vendor with this name "
                "already exists."
            )

    if errors:
        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Add Vendor",
            form_action="/vendors/new",
            submit_label="Create Vendor",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    try:
        result = db.execute(
            text(
                """
                INSERT INTO vendors (
                    owner_id,
                    name,
                    vendor_type,
                    mobile_number,
                    email,
                    address,
                    notes,
                    is_active,
                    created_at,
                    updated_at
                )
                VALUES (
                    :owner_id,
                    :name,
                    :vendor_type,
                    :mobile_number,
                    :email,
                    :address,
                    :notes,
                    TRUE,
                    NOW(),
                    NOW()
                )
                RETURNING id
                """
            ),
            {
                "owner_id": user.id,
                "name": normalized_name,
                "vendor_type": vendor_type,
                "mobile_number": (
                    normalize_optional_text(
                        mobile_number
                    )
                ),
                "email": (
                    normalize_optional_text(
                        email
                    )
                ),
                "address": (
                    normalize_optional_text(
                        address
                    )
                ),
                "notes": (
                    normalize_optional_text(
                        notes
                    )
                ),
            },
        ).scalar_one()

        audit(
            db,
            request,
            "vendor_created",
            user.id,
            (
                f"Vendor ID: {result}; "
                f"Name: {normalized_name}; "
                f"Type: {vendor_type}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Add Vendor",
            form_action="/vendors/new",
            submit_label="Create Vendor",
            form_data=form_data,
            errors={
                "name": (
                    "A vendor with this name "
                    "already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Add Vendor",
            form_action="/vendors/new",
            submit_label="Create Vendor",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to create vendor. "
                    "Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/vendors/manage?success="
            + quote(
                f"{normalized_name} was created."
            )
        ),
        status_code=303,
    )


@app.get(
    "/vendors/{vendor_id}/edit",
    response_class=HTMLResponse,
)
def finance_vendor_edit_page(
    vendor_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vendor = require_finance_vendor(
        vendor_id=vendor_id,
        user=user,
        db=db,
    )

    vendor_type = db.execute(
        text(
            """
            SELECT vendor_type
            FROM vendors
            WHERE id = :vendor_id
              AND owner_id = :owner_id
            """
        ),
        {
            "vendor_id": vendor.id,
            "owner_id": user.id,
        },
    ).scalar_one()

    form_data = finance_vendor_form_values(
        vendor
    )

    form_data["vendor_type"] = (
        vendor_type or "General"
    )

    return render_finance_vendor_form(
        request=request,
        user=user,
        page_title="Edit Vendor",
        form_action=(
            f"/vendors/{vendor.id}/edit"
        ),
        submit_label="Update Vendor",
        form_data=form_data,
        errors={},
    )


@app.post(
    "/vendors/{vendor_id}/edit",
    response_class=HTMLResponse,
)
def finance_vendor_edit_submit(
    vendor_id: int,
    request: Request,
    name: str = Form(...),
    vendor_type: str = Form("General"),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vendor = require_finance_vendor(
        vendor_id=vendor_id,
        user=user,
        db=db,
    )

    form_data = finance_vendor_form_values(
        name=name,
        vendor_type=vendor_type,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    errors = validate_finance_vendor_form(
        name=name,
        vendor_type=vendor_type,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.scalar(
            select(Vendor.id).where(
                Vendor.owner_id == user.id,
                Vendor.id != vendor.id,
                func.lower(Vendor.name)
                == normalized_name.lower(),
            )
        )

        if duplicate is not None:
            errors["name"] = (
                "A vendor with this name "
                "already exists."
            )

    if errors:
        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Edit Vendor",
            form_action=(
                f"/vendors/{vendor.id}/edit"
            ),
            submit_label="Update Vendor",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    try:
        db.execute(
            text(
                """
                UPDATE vendors
                SET
                    name = :name,
                    vendor_type = :vendor_type,
                    mobile_number = :mobile_number,
                    email = :email,
                    address = :address,
                    notes = :notes,
                    updated_at = NOW()
                WHERE id = :vendor_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "vendor_id": vendor.id,
                "owner_id": user.id,
                "name": normalized_name,
                "vendor_type": vendor_type,
                "mobile_number": (
                    normalize_optional_text(
                        mobile_number
                    )
                ),
                "email": (
                    normalize_optional_text(
                        email
                    )
                ),
                "address": (
                    normalize_optional_text(
                        address
                    )
                ),
                "notes": (
                    normalize_optional_text(
                        notes
                    )
                ),
            },
        )

        audit(
            db,
            request,
            "vendor_updated",
            user.id,
            (
                f"Vendor ID: {vendor.id}; "
                f"Name: {normalized_name}; "
                f"Type: {vendor_type}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Edit Vendor",
            form_action=(
                f"/vendors/{vendor.id}/edit"
            ),
            submit_label="Update Vendor",
            form_data=form_data,
            errors={
                "name": (
                    "A vendor with this name "
                    "already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_finance_vendor_form(
            request=request,
            user=user,
            page_title="Edit Vendor",
            form_action=(
                f"/vendors/{vendor.id}/edit"
            ),
            submit_label="Update Vendor",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to update vendor. "
                    "Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/vendors/manage?success="
            + quote(
                f"{normalized_name} was updated."
            )
        ),
        status_code=303,
    )


@app.post(
    "/vendors/{vendor_id}/toggle",
)
def finance_vendor_toggle_status(
    vendor_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    vendor = require_finance_vendor(
        vendor_id=vendor_id,
        user=user,
        db=db,
    )

    new_status = not bool(
        vendor.is_active
    )

    state = (
        "enabled"
        if new_status
        else "disabled"
    )

    try:
        db.execute(
            text(
                """
                UPDATE vendors
                SET
                    is_active = :is_active,
                    updated_at = NOW()
                WHERE id = :vendor_id
                  AND owner_id = :owner_id
                """
            ),
            {
                "vendor_id": vendor.id,
                "owner_id": user.id,
                "is_active": new_status,
            },
        )

        audit(
            db,
            request,
            "vendor_status_changed",
            user.id,
            (
                f"Vendor ID: {vendor.id}; "
                f"Status: {state}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                "/vendors/manage?error="
                + quote(
                    "Unable to change vendor status."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/vendors/manage?success="
            + quote(
                f"{vendor.name} was {state}."
            )
        ),
        status_code=303,
    )


# PATCH-FINANCE-001A: BUYERS MANAGEMENT UI


def require_owned_buyer(
    buyer_id: int,
    user: User,
    db: Session,
) -> Buyer:
    buyer = db.scalar(
        select(Buyer).where(
            Buyer.id == buyer_id,
            Buyer.owner_id == user.id,
        )
    )

    if buyer is None:
        raise HTTPException(
            status_code=404,
            detail="Buyer not found.",
        )

    return buyer


def buyer_form_values(
    buyer: Buyer | None = None,
    *,
    name: str = "",
    mobile_number: str = "",
    email: str = "",
    address: str = "",
    notes: str = "",
) -> dict[str, str]:
    if buyer is not None:
        return {
            "name": buyer.name or "",
            "mobile_number": (
                buyer.mobile_number or ""
            ),
            "email": buyer.email or "",
            "address": buyer.address or "",
            "notes": buyer.notes or "",
        }

    return {
        "name": name,
        "mobile_number": mobile_number,
        "email": email,
        "address": address,
        "notes": notes,
    }


def validate_buyer_form(
    name: str,
    mobile_number: str,
    email: str,
    address: str,
    notes: str,
) -> dict[str, str]:
    errors: dict[str, str] = {}

    normalized_name = name.strip()
    normalized_mobile = mobile_number.strip()
    normalized_email = email.strip()
    normalized_address = address.strip()
    normalized_notes = notes.strip()

    if not normalized_name:
        errors["name"] = "Buyer name is required."
    elif len(normalized_name) > 160:
        errors["name"] = (
            "Buyer name cannot exceed 160 characters."
        )

    if len(normalized_mobile) > 20:
        errors["mobile_number"] = (
            "Mobile number cannot exceed 20 characters."
        )
    elif normalized_mobile:
        compact_mobile = "".join(
            character
            for character in normalized_mobile
            if character not in {" ", "-", "(", ")"}
        )

        if (
            compact_mobile.startswith("+")
        ):
            compact_mobile = compact_mobile[1:]

        if not compact_mobile.isdigit():
            errors["mobile_number"] = (
                "Enter a valid mobile number."
            )

    if len(normalized_email) > 180:
        errors["email"] = (
            "Email cannot exceed 180 characters."
        )
    elif normalized_email and (
        "@" not in normalized_email
        or "." not in normalized_email.split("@")[-1]
    ):
        errors["email"] = (
            "Enter a valid email address."
        )

    if len(normalized_address) > 1000:
        errors["address"] = (
            "Address cannot exceed 1000 characters."
        )

    if len(normalized_notes) > 2000:
        errors["notes"] = (
            "Notes cannot exceed 2000 characters."
        )

    return errors


def render_buyer_form(
    request: Request,
    user: User,
    *,
    page_title: str,
    form_action: str,
    submit_label: str,
    form_data: dict[str, str],
    errors: dict[str, str],
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name="finance/buyer-form.html",
        context={
            "page_title": page_title,
            "current_user": user,
            "form_action": form_action,
            "submit_label": submit_label,
            "form_data": form_data,
            "errors": errors,
        },
        status_code=status_code,
    )


@app.get(
    "/buyers/manage",
    response_class=HTMLResponse,
)
def buyer_management_page(
    request: Request,
    search: str = "",
    status: str = "active",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    normalized_search = search.strip()
    normalized_status = status.lower().strip()

    if normalized_status not in {
        "active",
        "inactive",
        "all",
    }:
        normalized_status = "active"

    query = select(Buyer).where(
        Buyer.owner_id == user.id
    )

    if normalized_status == "active":
        query = query.where(
            Buyer.is_active.is_(True)
        )
    elif normalized_status == "inactive":
        query = query.where(
            Buyer.is_active.is_(False)
        )

    if normalized_search:
        like_value = (
            "%"
            + normalized_search.lower()
            + "%"
        )

        query = query.where(
            or_(
                func.lower(Buyer.name).like(
                    like_value
                ),
                func.lower(
                    func.coalesce(
                        Buyer.mobile_number,
                        "",
                    )
                ).like(like_value),
                func.lower(
                    func.coalesce(
                        Buyer.email,
                        "",
                    )
                ).like(like_value),
            )
        )

    buyers = db.scalars(
        query.order_by(
            Buyer.is_active.desc(),
            func.lower(Buyer.name),
            Buyer.id.desc(),
        )
    ).all()

    sale_statistics = {
        int(row.buyer_id): {
            "sale_count": int(
                row.sale_count or 0
            ),
            "total_sales": Decimal(
                str(row.total_sales or 0)
            ).quantize(Decimal("0.01")),
        }
        for row in db.execute(
            select(
                Sale.buyer_id.label("buyer_id"),
                func.count(Sale.id).label(
                    "sale_count"
                ),
                func.coalesce(
                    func.sum(Sale.net_amount),
                    0,
                ).label("total_sales"),
            )
            .where(
                Sale.owner_id == user.id,
                Sale.buyer_id.is_not(None),
            )
            .group_by(Sale.buyer_id)
        ).all()
    }

    buyer_rows = []

    for buyer in buyers:
        statistics = sale_statistics.get(
            buyer.id,
            {
                "sale_count": 0,
                "total_sales": Decimal("0.00"),
            },
        )

        buyer_rows.append(
            {
                "buyer": buyer,
                "sale_count": (
                    statistics["sale_count"]
                ),
                "total_sales": (
                    statistics["total_sales"]
                ),
            }
        )

    total_buyers = db.scalar(
        select(func.count(Buyer.id)).where(
            Buyer.owner_id == user.id
        )
    ) or 0

    active_buyers = db.scalar(
        select(func.count(Buyer.id)).where(
            Buyer.owner_id == user.id,
            Buyer.is_active.is_(True),
        )
    ) or 0

    total_sale_count = db.scalar(
        select(func.count(Sale.id)).where(
            Sale.owner_id == user.id,
            Sale.buyer_id.is_not(None),
        )
    ) or 0

    total_sales = db.scalar(
        select(
            func.coalesce(
                func.sum(Sale.net_amount),
                0,
            )
        ).where(
            Sale.owner_id == user.id,
            Sale.buyer_id.is_not(None),
        )
    ) or Decimal("0.00")

    return templates.TemplateResponse(
        request=request,
        name="finance/buyers.html",
        context={
            "current_user": user,
            "buyers": buyer_rows,
            "filters": {
                "search": normalized_search,
                "status": normalized_status,
            },
            "summary": {
                "total_buyers": int(
                    total_buyers
                ),
                "active_buyers": int(
                    active_buyers
                ),
                "sale_count": int(
                    total_sale_count
                ),
                "total_sales": Decimal(
                    str(total_sales)
                ).quantize(
                    Decimal("0.01")
                ),
            },
            "success_message": (
                request.query_params.get(
                    "success"
                )
            ),
            "error_message": (
                request.query_params.get(
                    "error"
                )
            ),
        },
    )


@app.get(
    "/buyers/new",
    response_class=HTMLResponse,
)
def buyer_create_page(
    request: Request,
    user: User = Depends(current_user),
):
    return render_buyer_form(
        request=request,
        user=user,
        page_title="Add Buyer",
        form_action="/buyers/new",
        submit_label="Create Buyer",
        form_data=buyer_form_values(),
        errors={},
    )


@app.post(
    "/buyers/new",
    response_class=HTMLResponse,
)
def buyer_create_page_submit(
    request: Request,
    name: str = Form(...),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    form_data = buyer_form_values(
        name=name,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    errors = validate_buyer_form(
        name=name,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.scalar(
            select(Buyer.id).where(
                Buyer.owner_id == user.id,
                func.lower(Buyer.name)
                == normalized_name.lower(),
            )
        )

        if duplicate is not None:
            errors["name"] = (
                "A buyer with this name "
                "already exists."
            )

    if errors:
        return render_buyer_form(
            request=request,
            user=user,
            page_title="Add Buyer",
            form_action="/buyers/new",
            submit_label="Create Buyer",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    buyer = Buyer(
        owner_id=user.id,
        name=normalized_name,
        mobile_number=normalize_optional_text(
            mobile_number
        ),
        email=normalize_optional_text(email),
        address=normalize_optional_text(address),
        notes=normalize_optional_text(notes),
        is_active=True,
    )

    try:
        db.add(buyer)
        db.flush()

        audit(
            db,
            request,
            "buyer_created",
            user.id,
            (
                f"Buyer ID: {buyer.id}; "
                f"Name: {buyer.name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_buyer_form(
            request=request,
            user=user,
            page_title="Add Buyer",
            form_action="/buyers/new",
            submit_label="Create Buyer",
            form_data=form_data,
            errors={
                "name": (
                    "A buyer with this name "
                    "already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_buyer_form(
            request=request,
            user=user,
            page_title="Add Buyer",
            form_action="/buyers/new",
            submit_label="Create Buyer",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to create buyer. "
                    "Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/buyers/manage?success="
            + quote(
                f"{buyer.name} was created."
            )
        ),
        status_code=303,
    )


@app.get(
    "/buyers/{buyer_id}/edit",
    response_class=HTMLResponse,
)
def buyer_edit_page(
    buyer_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    buyer = require_owned_buyer(
        buyer_id=buyer_id,
        user=user,
        db=db,
    )

    return render_buyer_form(
        request=request,
        user=user,
        page_title="Edit Buyer",
        form_action=(
            f"/buyers/{buyer.id}/edit"
        ),
        submit_label="Update Buyer",
        form_data=buyer_form_values(buyer),
        errors={},
    )


@app.post(
    "/buyers/{buyer_id}/edit",
    response_class=HTMLResponse,
)
def buyer_edit_page_submit(
    buyer_id: int,
    request: Request,
    name: str = Form(...),
    mobile_number: str = Form(""),
    email: str = Form(""),
    address: str = Form(""),
    notes: str = Form(""),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    buyer = require_owned_buyer(
        buyer_id=buyer_id,
        user=user,
        db=db,
    )

    form_data = buyer_form_values(
        name=name,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    errors = validate_buyer_form(
        name=name,
        mobile_number=mobile_number,
        email=email,
        address=address,
        notes=notes,
    )

    normalized_name = name.strip()

    if not errors:
        duplicate = db.scalar(
            select(Buyer.id).where(
                Buyer.owner_id == user.id,
                Buyer.id != buyer.id,
                func.lower(Buyer.name)
                == normalized_name.lower(),
            )
        )

        if duplicate is not None:
            errors["name"] = (
                "A buyer with this name "
                "already exists."
            )

    if errors:
        return render_buyer_form(
            request=request,
            user=user,
            page_title="Edit Buyer",
            form_action=(
                f"/buyers/{buyer.id}/edit"
            ),
            submit_label="Update Buyer",
            form_data=form_data,
            errors=errors,
            status_code=422,
        )

    buyer.name = normalized_name
    buyer.mobile_number = normalize_optional_text(
        mobile_number
    )
    buyer.email = normalize_optional_text(email)
    buyer.address = normalize_optional_text(address)
    buyer.notes = normalize_optional_text(notes)
    buyer.updated_at = datetime.now(
        timezone.utc
    )

    try:
        audit(
            db,
            request,
            "buyer_updated",
            user.id,
            (
                f"Buyer ID: {buyer.id}; "
                f"Name: {buyer.name}"
            ),
        )

        db.commit()
    except IntegrityError:
        db.rollback()

        return render_buyer_form(
            request=request,
            user=user,
            page_title="Edit Buyer",
            form_action=(
                f"/buyers/{buyer.id}/edit"
            ),
            submit_label="Update Buyer",
            form_data=form_data,
            errors={
                "name": (
                    "A buyer with this name "
                    "already exists."
                )
            },
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_buyer_form(
            request=request,
            user=user,
            page_title="Edit Buyer",
            form_action=(
                f"/buyers/{buyer.id}/edit"
            ),
            submit_label="Update Buyer",
            form_data=form_data,
            errors={
                "form": (
                    "Unable to update buyer. "
                    "Please try again."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            "/buyers/manage?success="
            + quote(
                f"{buyer.name} was updated."
            )
        ),
        status_code=303,
    )


@app.post(
    "/buyers/{buyer_id}/toggle",
)
def buyer_toggle_status(
    buyer_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    buyer = require_owned_buyer(
        buyer_id=buyer_id,
        user=user,
        db=db,
    )

    buyer.is_active = not buyer.is_active
    buyer.updated_at = datetime.now(
        timezone.utc
    )

    state = (
        "enabled"
        if buyer.is_active
        else "disabled"
    )

    try:
        audit(
            db,
            request,
            "buyer_status_changed",
            user.id,
            (
                f"Buyer ID: {buyer.id}; "
                f"Status: {state}"
            ),
        )

        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                "/buyers/manage?error="
                + quote(
                    "Unable to change buyer status."
                )
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            "/buyers/manage?success="
            + quote(
                f"{buyer.name} was {state}."
            )
        ),
        status_code=303,
    )


# PATCH-005A.2: COCONUT TREE CRUD BACKEND

TREE_VARIETIES = {
    "Tall",
    "Dwarf",
    "Hybrid",
}

TREE_HEALTH_STATUSES = {
    "Healthy",
    "Needs Attention",
    "Diseased",
    "Removed",
}


def coconut_tree_to_dict(tree: CoconutTree) -> dict[str, object]:
    return {
        "id": tree.id,
        "farm_id": tree.farm_id,
        "tree_code": tree.tree_code,
        "tree_name": tree.tree_name,
        "qr_code_id": tree.qr_code_id,
        "variety": tree.variety,
        "planting_date": (
            tree.planting_date.isoformat()
            if tree.planting_date
            else None
        ),
        "block_name": tree.block_name,
        "row_number": tree.row_number,
        "position_number": tree.position_number,
        "health_status": tree.health_status,
        "height_m": (
            str(tree.height_m)
            if tree.height_m is not None
            else None
        ),
        "canopy_diameter_m": (
            str(tree.canopy_diameter_m)
            if tree.canopy_diameter_m is not None
            else None
        ),
        "trunk_girth_cm": (
            str(tree.trunk_girth_cm)
            if tree.trunk_girth_cm is not None
            else None
        ),
        "remarks": tree.remarks,
        "is_active": tree.is_active,
        "created_at": (
            tree.created_at.isoformat()
            if tree.created_at
            else None
        ),
        "updated_at": (
            tree.updated_at.isoformat()
            if tree.updated_at
            else None
        ),
    }


def require_owned_farm(
    db: Session,
    farm_id: int,
    owner_id: int,
) -> Farm:
    farm = db.scalar(
        select(Farm).where(
            Farm.id == farm_id,
            Farm.owner_id == owner_id,
        )
    )

    if farm is None:
        raise HTTPException(
            status_code=404,
            detail="Farm not found.",
        )

    return farm


def require_owned_coconut_tree(
    db: Session,
    tree_id: int,
    owner_id: int,
) -> CoconutTree:
    tree = db.scalar(
        select(CoconutTree)
        .join(Farm, Farm.id == CoconutTree.farm_id)
        .where(
            CoconutTree.id == tree_id,
            Farm.owner_id == owner_id,
        )
    )

    if tree is None:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    return tree


def normalize_tree_text(
    value: object,
    field_name: str,
    maximum_length: int,
    errors: dict[str, str],
    *,
    required: bool = False,
) -> str | None:
    if value is None:
        if required:
            errors[field_name] = (
                f"{field_name.replace('_', ' ').title()} is required."
            )
        return None

    if not isinstance(value, str):
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} must be text."
        )
        return None

    normalized = value.strip()

    if required and not normalized:
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} is required."
        )
        return None

    if not normalized:
        return None

    if len(normalized) > maximum_length:
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} cannot exceed "
            f"{maximum_length} characters."
        )
        return None

    return normalized


def parse_tree_decimal(
    value: object,
    field_name: str,
    maximum: Decimal,
    errors: dict[str, str],
) -> Decimal | None:
    if value is None or value == "":
        return None

    if isinstance(value, bool):
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} must be a number."
        )
        return None

    try:
        parsed = Decimal(str(value).strip())
    except (InvalidOperation, ValueError):
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} must be a number."
        )
        return None

    if not parsed.is_finite():
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} must be a number."
        )
        return None

    if parsed < 0:
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} cannot be negative."
        )
        return None

    if parsed > maximum:
        errors[field_name] = (
            f"{field_name.replace('_', ' ').title()} exceeds the "
            "supported limit."
        )
        return None

    return parsed.quantize(Decimal("0.01"))


def validate_coconut_tree_payload(
    payload: object,
    *,
    partial: bool = False,
) -> tuple[dict[str, object], dict[str, str]]:
    if not isinstance(payload, dict):
        return {}, {
            "payload": "Request body must be a JSON object.",
        }

    values: dict[str, object] = {}
    errors: dict[str, str] = {}

    allowed_fields = {
        "tree_code",
        "tree_name",
        "qr_code_id",
        "variety",
        "planting_date",
        "block_name",
        "row_number",
        "position_number",
        "health_status",
        "height_m",
        "canopy_diameter_m",
        "trunk_girth_cm",
        "remarks",
        "is_active",
    }

    unknown_fields = sorted(set(payload) - allowed_fields)

    if unknown_fields:
        errors["unknown_fields"] = (
            "Unsupported fields: " + ", ".join(unknown_fields)
        )

    if not partial or "tree_code" in payload:
        tree_code = normalize_tree_text(
            payload.get("tree_code"),
            "tree_code",
            50,
            errors,
            required=True,
        )

        if tree_code is not None:
            values["tree_code"] = tree_code.upper()

    text_fields = {
        "tree_name": 120,
        "qr_code_id": 100,
        "block_name": 80,
        "row_number": 40,
        "position_number": 40,
        "remarks": 5000,
    }

    for field_name, maximum_length in text_fields.items():
        if partial and field_name not in payload:
            continue

        values[field_name] = normalize_tree_text(
            payload.get(field_name),
            field_name,
            maximum_length,
            errors,
        )

    if not partial or "variety" in payload:
        variety = payload.get("variety", "Tall")

        if not isinstance(variety, str):
            errors["variety"] = "Variety must be text."
        else:
            variety = variety.strip().title()

            if variety not in TREE_VARIETIES:
                errors["variety"] = (
                    "Variety must be Tall, Dwarf, or Hybrid."
                )
            else:
                values["variety"] = variety

    if not partial or "health_status" in payload:
        health_status = payload.get(
            "health_status",
            "Healthy",
        )

        if not isinstance(health_status, str):
            errors["health_status"] = (
                "Health status must be text."
            )
        else:
            health_status = health_status.strip().title()

            if health_status not in TREE_HEALTH_STATUSES:
                errors["health_status"] = (
                    "Health status must be Healthy, "
                    "Needs Attention, Diseased, or Removed."
                )
            else:
                values["health_status"] = health_status

    if not partial or "planting_date" in payload:
        planting_date_value = payload.get("planting_date")

        if planting_date_value in (None, ""):
            values["planting_date"] = None
        elif not isinstance(planting_date_value, str):
            errors["planting_date"] = (
                "Planting date must use YYYY-MM-DD format."
            )
        else:
            try:
                planting_date = date.fromisoformat(
                    planting_date_value.strip()
                )
            except ValueError:
                errors["planting_date"] = (
                    "Planting date must use YYYY-MM-DD format."
                )
            else:
                if planting_date > date.today():
                    errors["planting_date"] = (
                        "Planting date cannot be in the future."
                    )
                elif planting_date < date(1900, 1, 1):
                    errors["planting_date"] = (
                        "Planting date cannot be earlier than 1900-01-01."
                    )
                else:
                    values["planting_date"] = planting_date

    decimal_fields = {
        "height_m": Decimal("100.00"),
        "canopy_diameter_m": Decimal("100.00"),
        "trunk_girth_cm": Decimal("5000.00"),
    }

    for field_name, maximum in decimal_fields.items():
        if partial and field_name not in payload:
            continue

        values[field_name] = parse_tree_decimal(
            payload.get(field_name),
            field_name,
            maximum,
            errors,
        )

    if not partial or "is_active" in payload:
        is_active = payload.get("is_active", True)

        if not isinstance(is_active, bool):
            errors["is_active"] = (
                "Active status must be true or false."
            )
        else:
            values["is_active"] = is_active

    return values, errors


async def read_json_payload(request: Request) -> object:
    content_type = request.headers.get(
        "content-type",
        "",
    ).lower()

    if "application/json" not in content_type:
        raise HTTPException(
            status_code=415,
            detail="Content-Type must be application/json.",
        )

    try:
        return await request.json()
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid JSON request body.",
        ) from exc


@app.get(
    "/api/farms/{farm_id}/trees",
    response_class=JSONResponse,
)
def list_coconut_trees(
    farm_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    trees = db.scalars(
        select(CoconutTree)
        .where(CoconutTree.farm_id == farm_id)
        .order_by(
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
    ).all()

    return {
        "farm_id": farm_id,
        "count": len(trees),
        "items": [
            coconut_tree_to_dict(tree)
            for tree in trees
        ],
    }


@app.post(
    "/api/farms/{farm_id}/trees",
    status_code=201,
    response_class=JSONResponse,
)
async def create_coconut_tree(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    payload = await read_json_payload(request)
    values, errors = validate_coconut_tree_payload(payload)

    if errors:
        raise HTTPException(
            status_code=422,
            detail=errors,
        )

    tree = CoconutTree(
        farm_id=farm.id,
        **values,
    )

    db.add(tree)

    audit(
        db,
        request,
        "coconut_tree.created",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_code={values['tree_code']}"
        ),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        error_text = str(exc.orig).lower()

        if (
            "uq_coconut_trees_farm_tree_code" in error_text
            or "tree_code" in error_text
        ):
            detail = {
                "tree_code": (
                    "Tree code already exists in this farm."
                )
            }
        elif "qr_code_id" in error_text:
            detail = {
                "qr_code_id": (
                    "QR code ID already exists."
                )
            }
        else:
            detail = {
                "database": (
                    "Unable to create the coconut tree."
                )
            }

        raise HTTPException(
            status_code=409,
            detail=detail,
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to create the coconut tree.",
        ) from exc

    db.refresh(tree)

    return {
        "message": "Coconut tree created successfully.",
        "item": coconut_tree_to_dict(tree),
    }


@app.get(
    "/api/trees/{tree_id}",
    response_class=JSONResponse,
)
def get_coconut_tree(
    tree_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    return {
        "item": coconut_tree_to_dict(tree),
    }


@app.put(
    "/api/trees/{tree_id}",
    response_class=JSONResponse,
)
async def update_coconut_tree(
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    payload = await read_json_payload(request)
    values, errors = validate_coconut_tree_payload(
        payload,
        partial=True,
    )

    if errors:
        raise HTTPException(
            status_code=422,
            detail=errors,
        )

    if not values:
        raise HTTPException(
            status_code=422,
            detail={
                "payload": (
                    "At least one supported field is required."
                )
            },
        )

    for field_name, value in values.items():
        setattr(tree, field_name, value)

    tree.updated_at = datetime.now(timezone.utc)

    audit(
        db,
        request,
        "coconut_tree.updated",
        owner_id=user.id,
        detail=(
            f"tree_id={tree.id};"
            f"farm_id={tree.farm_id};"
            f"fields={','.join(sorted(values))}"
        ),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        error_text = str(exc.orig).lower()

        if (
            "uq_coconut_trees_farm_tree_code" in error_text
            or "tree_code" in error_text
        ):
            detail = {
                "tree_code": (
                    "Tree code already exists in this farm."
                )
            }
        elif "qr_code_id" in error_text:
            detail = {
                "qr_code_id": (
                    "QR code ID already exists."
                )
            }
        else:
            detail = {
                "database": (
                    "Unable to update the coconut tree."
                )
            }

        raise HTTPException(
            status_code=409,
            detail=detail,
        ) from exc
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to update the coconut tree.",
        ) from exc

    db.refresh(tree)

    return {
        "message": "Coconut tree updated successfully.",
        "item": coconut_tree_to_dict(tree),
    }


@app.delete(
    "/api/trees/{tree_id}",
    response_class=JSONResponse,
)
def delete_coconut_tree(
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    deleted_tree_id = tree.id
    deleted_tree_code = tree.tree_code
    farm_id = tree.farm_id

    audit(
        db,
        request,
        "coconut_tree.deleted",
        owner_id=user.id,
        detail=(
            f"tree_id={deleted_tree_id};"
            f"farm_id={farm_id};"
            f"tree_code={deleted_tree_code}"
        ),
    )

    db.delete(tree)

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Unable to delete the coconut tree.",
        ) from exc

    return {
        "message": "Coconut tree deleted successfully.",
        "deleted_id": deleted_tree_id,
        "farm_id": farm_id,
        "tree_code": deleted_tree_code,
    }


# PATCH-005A.3: COCONUT TREE LIST UI


@app.get(
    "/farms/{farm_id}/trees",
    response_class=HTMLResponse,
)
def coconut_tree_list_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    query_text = request.query_params.get(
        "q",
        "",
    ).strip()

    variety_filter = request.query_params.get(
        "variety",
        "",
    ).strip().title()

    health_filter = request.query_params.get(
        "health_status",
        "",
    ).strip().title()

    activity_filter = request.query_params.get(
        "activity",
        "",
    ).strip().lower()

    try:
        page = int(
            request.query_params.get(
                "page",
                "1",
            )
        )
    except ValueError:
        page = 1

    try:
        page_size = int(
            request.query_params.get(
                "page_size",
                "20",
            )
        )
    except ValueError:
        page_size = 20

    page = max(page, 1)

    if page_size not in {10, 20, 50, 100}:
        page_size = 20

    conditions = [
        CoconutTree.farm_id == farm.id,
    ]

    if query_text:
        search_pattern = f"%{query_text}%"

        conditions.append(
            or_(
                CoconutTree.tree_code.ilike(
                    search_pattern
                ),
                CoconutTree.tree_name.ilike(
                    search_pattern
                ),
                CoconutTree.qr_code_id.ilike(
                    search_pattern
                ),
                CoconutTree.block_name.ilike(
                    search_pattern
                ),
                CoconutTree.row_number.ilike(
                    search_pattern
                ),
                CoconutTree.position_number.ilike(
                    search_pattern
                ),
            )
        )

    if variety_filter in TREE_VARIETIES:
        conditions.append(
            CoconutTree.variety == variety_filter
        )
    else:
        variety_filter = ""

    if health_filter in TREE_HEALTH_STATUSES:
        conditions.append(
            CoconutTree.health_status == health_filter
        )
    else:
        health_filter = ""

    if activity_filter == "active":
        conditions.append(
            CoconutTree.is_active.is_(True)
        )
    elif activity_filter == "inactive":
        conditions.append(
            CoconutTree.is_active.is_(False)
        )
    else:
        activity_filter = ""

    all_farm_trees = db.scalars(
        select(CoconutTree)
        .where(CoconutTree.farm_id == farm.id)
        .order_by(CoconutTree.id.asc())
    ).all()

    status_counts = {
        "Healthy": 0,
        "Needs Attention": 0,
        "Diseased": 0,
        "Removed": 0,
    }

    active_count = 0

    for tree in all_farm_trees:
        if tree.health_status in status_counts:
            status_counts[tree.health_status] += 1

        if tree.is_active:
            active_count += 1

    filtered_count = db.scalar(
        select(func.count(CoconutTree.id))
        .where(*conditions)
    ) or 0

    total_pages = max(
        1,
        (
            filtered_count + page_size - 1
        ) // page_size,
    )

    if page > total_pages:
        page = total_pages

    offset = (page - 1) * page_size

    trees = db.scalars(
        select(CoconutTree)
        .where(*conditions)
        .order_by(
            CoconutTree.is_active.desc(),
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
        .offset(offset)
        .limit(page_size)
    ).all()

    pagination_start = (
        offset + 1
        if filtered_count > 0
        else 0
    )

    pagination_end = min(
        offset + len(trees),
        filtered_count,
    )

    return templates.TemplateResponse(
        request=request,
        name="trees/list.html",
        context={
            "user": user,
            "farm": farm,
            "trees": trees,
            "tree_count": len(all_farm_trees),
            "filtered_count": filtered_count,
            "active_count": active_count,
            "inactive_count": (
                len(all_farm_trees) - active_count
            ),
            "status_counts": status_counts,
            "query_text": query_text,
            "variety_filter": variety_filter,
            "health_filter": health_filter,
            "activity_filter": activity_filter,
            "tree_varieties": sorted(
                TREE_VARIETIES
            ),
            "tree_health_statuses": [
                "Healthy",
                "Needs Attention",
                "Diseased",
                "Removed",
            ],
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "pagination_start": pagination_start,
            "pagination_end": pagination_end,
        },
    )


# PATCH-005A.4: COCONUT TREE ADD AND EDIT FORMS


def coconut_tree_form_values(
    tree: CoconutTree | None = None,
) -> dict[str, object]:
    if tree is None:
        return {
            "tree_code": "",
            "tree_name": "",
            "qr_code_id": "",
            "variety": "Tall",
            "planting_date": "",
            "block_name": "",
            "row_number": "",
            "position_number": "",
            "health_status": "Healthy",
            "height_m": "",
            "canopy_diameter_m": "",
            "trunk_girth_cm": "",
            "remarks": "",
            "is_active": True,
        }

    return {
        "tree_code": tree.tree_code,
        "tree_name": tree.tree_name or "",
        "qr_code_id": tree.qr_code_id or "",
        "variety": tree.variety,
        "planting_date": (
            tree.planting_date.isoformat()
            if tree.planting_date
            else ""
        ),
        "block_name": tree.block_name or "",
        "row_number": tree.row_number or "",
        "position_number": tree.position_number or "",
        "health_status": tree.health_status,
        "height_m": (
            str(tree.height_m)
            if tree.height_m is not None
            else ""
        ),
        "canopy_diameter_m": (
            str(tree.canopy_diameter_m)
            if tree.canopy_diameter_m is not None
            else ""
        ),
        "trunk_girth_cm": (
            str(tree.trunk_girth_cm)
            if tree.trunk_girth_cm is not None
            else ""
        ),
        "remarks": tree.remarks or "",
        "is_active": tree.is_active,
    }


async def coconut_tree_form_payload(
    request: Request,
) -> dict[str, object]:
    form = await request.form()

    return {
        "tree_code": str(form.get("tree_code", "")),
        "tree_name": str(form.get("tree_name", "")),
        "qr_code_id": str(form.get("qr_code_id", "")),
        "variety": str(form.get("variety", "Tall")),
        "planting_date": str(form.get("planting_date", "")),
        "block_name": str(form.get("block_name", "")),
        "row_number": str(form.get("row_number", "")),
        "position_number": str(
            form.get("position_number", "")
        ),
        "health_status": str(
            form.get("health_status", "Healthy")
        ),
        "height_m": str(form.get("height_m", "")),
        "canopy_diameter_m": str(
            form.get("canopy_diameter_m", "")
        ),
        "trunk_girth_cm": str(
            form.get("trunk_girth_cm", "")
        ),
        "remarks": str(form.get("remarks", "")),
        "is_active": form.get("is_active") == "on",
    }


def render_coconut_tree_form(
    request: Request,
    user: User,
    farm: Farm,
    *,
    mode: str,
    values: dict[str, object],
    errors: dict[str, str] | None = None,
    tree: CoconutTree | None = None,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name="trees/form.html",
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "mode": mode,
            "values": values,
            "errors": errors or {},
            "tree_varieties": sorted(TREE_VARIETIES),
            "tree_health_statuses": [
                "Healthy",
                "Needs Attention",
                "Diseased",
                "Removed",
            ],
        },
        status_code=status_code,
    )


@app.get(
    "/farms/{farm_id}/trees/new",
    response_class=HTMLResponse,
)
def new_coconut_tree_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    return render_coconut_tree_form(
        request,
        user,
        farm,
        mode="create",
        values=coconut_tree_form_values(),
    )


@app.post(
    "/farms/{farm_id}/trees/new",
    response_class=HTMLResponse,
)
async def create_coconut_tree_from_form(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    payload = await coconut_tree_form_payload(request)
    values, errors = validate_coconut_tree_payload(payload)

    if errors:
        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="create",
            values=payload,
            errors=errors,
            status_code=422,
        )

    tree = CoconutTree(
        farm_id=farm.id,
        **values,
    )

    db.add(tree)

    audit(
        db,
        request,
        "coconut_tree.created",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_code={values['tree_code']};"
            "source=form"
        ),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        error_text = str(exc.orig).lower()

        if (
            "uq_coconut_trees_farm_tree_code" in error_text
            or "tree_code" in error_text
        ):
            errors = {
                "tree_code": (
                    "Tree code already exists in this farm."
                )
            }
        elif "qr_code_id" in error_text:
            errors = {
                "qr_code_id": (
                    "QR code ID already exists."
                )
            }
        else:
            errors = {
                "database": (
                    "Unable to create the coconut tree."
                )
            }

        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="create",
            values=payload,
            errors=errors,
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="create",
            values=payload,
            errors={
                "database": (
                    "Unable to create the coconut tree."
                )
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees"
            "?success=Tree%20created%20successfully"
        ),
        status_code=303,
    )


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/edit",
    response_class=HTMLResponse,
)
def edit_coconut_tree_page(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    if tree.farm_id != farm.id:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    return render_coconut_tree_form(
        request,
        user,
        farm,
        mode="edit",
        values=coconut_tree_form_values(tree),
        tree=tree,
    )


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/edit",
    response_class=HTMLResponse,
)
async def update_coconut_tree_from_form(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    if tree.farm_id != farm.id:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    payload = await coconut_tree_form_payload(request)
    values, errors = validate_coconut_tree_payload(payload)

    if errors:
        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="edit",
            values=payload,
            errors=errors,
            tree=tree,
            status_code=422,
        )

    for field_name, value in values.items():
        setattr(tree, field_name, value)

    tree.updated_at = datetime.now(timezone.utc)

    audit(
        db,
        request,
        "coconut_tree.updated",
        owner_id=user.id,
        detail=(
            f"tree_id={tree.id};"
            f"farm_id={farm.id};"
            "source=form"
        ),
    )

    try:
        db.commit()
    except IntegrityError as exc:
        db.rollback()

        error_text = str(exc.orig).lower()

        if (
            "uq_coconut_trees_farm_tree_code" in error_text
            or "tree_code" in error_text
        ):
            errors = {
                "tree_code": (
                    "Tree code already exists in this farm."
                )
            }
        elif "qr_code_id" in error_text:
            errors = {
                "qr_code_id": (
                    "QR code ID already exists."
                )
            }
        else:
            errors = {
                "database": (
                    "Unable to update the coconut tree."
                )
            }

        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="edit",
            values=payload,
            errors=errors,
            tree=tree,
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_coconut_tree_form(
            request,
            user,
            farm,
            mode="edit",
            values=payload,
            errors={
                "database": (
                    "Unable to update the coconut tree."
                )
            },
            tree=tree,
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees"
            "?success=Tree%20updated%20successfully"
        ),
        status_code=303,
    )


# PATCH-005A.5: COCONUT TREE DETAIL PAGE


def calculate_tree_age(
    planting_date: date | None,
) -> dict[str, int] | None:
    if planting_date is None:
        return None

    today = date.today()

    if planting_date > today:
        return None

    completed_months = (
        (today.year - planting_date.year) * 12
        + today.month
        - planting_date.month
    )

    if today.day < planting_date.day:
        completed_months -= 1

    completed_months = max(completed_months, 0)

    return {
        "years": completed_months // 12,
        "months": completed_months % 12,
        "total_months": completed_months,
    }


@app.get(
    "/farms/{farm_id}/trees/{tree_id}",
    response_class=HTMLResponse,
)
def coconut_tree_detail_page(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    if tree.farm_id != farm.id:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    return templates.TemplateResponse(
        request=request,
        name="trees/detail.html",
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "tree_age": calculate_tree_age(
                tree.planting_date
            ),
        },
    )


# PATCH-005A.6: COCONUT TREE DELETE UI


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/delete",
    response_class=HTMLResponse,
)
async def delete_coconut_tree_from_form(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = require_owned_coconut_tree(
        db,
        tree_id,
        user.id,
    )

    if tree.farm_id != farm.id:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    form = await request.form()
    confirmation = str(
        form.get("confirmation", "")
    ).strip()

    if confirmation != tree.tree_code:
        return RedirectResponse(
            url=(
                f"/farms/{farm.id}/trees/{tree.id}"
                "?delete_error=Enter%20the%20exact%20tree%20code"
            ),
            status_code=303,
        )

    deleted_tree_id = tree.id
    deleted_tree_code = tree.tree_code

    audit(
        db,
        request,
        "coconut_tree.deleted",
        owner_id=user.id,
        detail=(
            f"tree_id={deleted_tree_id};"
            f"farm_id={farm.id};"
            f"tree_code={deleted_tree_code};"
            "source=form"
        ),
    )

    db.delete(tree)

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return RedirectResponse(
            url=(
                f"/farms/{farm.id}/trees/{tree.id}"
                "?delete_error=Unable%20to%20delete%20the%20tree"
            ),
            status_code=303,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees"
            "?success=Tree%20deleted%20successfully"
        ),
        status_code=303,
    )


# PATCH-005A.7: COCONUT TREE SEARCH FILTER AND PAGINATION


# PATCH-005A.8: COCONUT TREE CSV EXPORT


def coconut_tree_export_conditions(
    farm_id: int,
    *,
    query_text: str = "",
    variety_filter: str = "",
    health_filter: str = "",
    activity_filter: str = "",
):
    conditions = [
        CoconutTree.farm_id == farm_id,
    ]

    query_text = query_text.strip()

    if query_text:
        search_pattern = f"%{query_text}%"

        conditions.append(
            or_(
                CoconutTree.tree_code.ilike(
                    search_pattern
                ),
                CoconutTree.tree_name.ilike(
                    search_pattern
                ),
                CoconutTree.qr_code_id.ilike(
                    search_pattern
                ),
                CoconutTree.block_name.ilike(
                    search_pattern
                ),
                CoconutTree.row_number.ilike(
                    search_pattern
                ),
                CoconutTree.position_number.ilike(
                    search_pattern
                ),
            )
        )

    variety_filter = variety_filter.strip().title()

    if variety_filter in TREE_VARIETIES:
        conditions.append(
            CoconutTree.variety == variety_filter
        )

    health_filter = health_filter.strip().title()

    if health_filter in TREE_HEALTH_STATUSES:
        conditions.append(
            CoconutTree.health_status == health_filter
        )

    activity_filter = activity_filter.strip().lower()

    if activity_filter == "active":
        conditions.append(
            CoconutTree.is_active.is_(True)
        )
    elif activity_filter == "inactive":
        conditions.append(
            CoconutTree.is_active.is_(False)
        )

    return conditions


@app.get(
    "/farms/{farm_id}/trees/export.csv",
)
def export_coconut_trees_csv(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    query_text = request.query_params.get(
        "q",
        "",
    )

    variety_filter = request.query_params.get(
        "variety",
        "",
    )

    health_filter = request.query_params.get(
        "health_status",
        "",
    )

    activity_filter = request.query_params.get(
        "activity",
        "",
    )

    conditions = coconut_tree_export_conditions(
        farm.id,
        query_text=query_text,
        variety_filter=variety_filter,
        health_filter=health_filter,
        activity_filter=activity_filter,
    )

    trees = db.scalars(
        select(CoconutTree)
        .where(*conditions)
        .order_by(
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
    ).all()

    output = io.StringIO(newline="")

    writer = csv.writer(output)

    writer.writerow(
        [
            "Tree ID",
            "Farm ID",
            "Farm Name",
            "Tree Code",
            "Tree Name",
            "QR Code ID",
            "Variety",
            "Planting Date",
            "Block",
            "Row",
            "Position",
            "Health Status",
            "Height (m)",
            "Canopy Diameter (m)",
            "Trunk Girth (cm)",
            "Remarks",
            "Active",
            "Created At",
            "Updated At",
        ]
    )

    for tree in trees:
        writer.writerow(
            [
                tree.id,
                tree.farm_id,
                farm.name,
                tree.tree_code,
                tree.tree_name or "",
                tree.qr_code_id or "",
                tree.variety,
                (
                    tree.planting_date.isoformat()
                    if tree.planting_date
                    else ""
                ),
                tree.block_name or "",
                tree.row_number or "",
                tree.position_number or "",
                tree.health_status,
                (
                    str(tree.height_m)
                    if tree.height_m is not None
                    else ""
                ),
                (
                    str(tree.canopy_diameter_m)
                    if tree.canopy_diameter_m is not None
                    else ""
                ),
                (
                    str(tree.trunk_girth_cm)
                    if tree.trunk_girth_cm is not None
                    else ""
                ),
                tree.remarks or "",
                "Yes" if tree.is_active else "No",
                (
                    tree.created_at.isoformat()
                    if tree.created_at
                    else ""
                ),
                (
                    tree.updated_at.isoformat()
                    if tree.updated_at
                    else ""
                ),
            ]
        )

    csv_content = "\ufeff" + output.getvalue()

    safe_farm_name = "".join(
        character
        if character.isalnum()
        else "-"
        for character in farm.name.lower()
    ).strip("-")

    safe_farm_name = safe_farm_name or f"farm-{farm.id}"

    filename = (
        f"{safe_farm_name}-coconut-trees-"
        f"{date.today().isoformat()}.csv"
    )

    audit(
        db,
        request,
        "coconut_tree.exported",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"record_count={len(trees)};"
            "format=csv"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                f'attachment; filename="{filename}"'
            ),
            "Cache-Control": "no-store",
        },
    )


# PATCH-005A.9: COCONUT TREE CSV IMPORT


COCONUT_TREE_IMPORT_REQUIRED_HEADERS = {
    "tree_code",
    "variety",
    "health_status",
}

COCONUT_TREE_IMPORT_OPTIONAL_HEADERS = {
    "tree_name",
    "qr_code_id",
    "planting_date",
    "block_name",
    "row_number",
    "position_number",
    "height_m",
    "canopy_diameter_m",
    "trunk_girth_cm",
    "remarks",
    "is_active",
}

COCONUT_TREE_IMPORT_MAX_ROWS = 1000


def normalize_coconut_tree_import_header(
    value: str,
) -> str:
    return (
        value.strip()
        .lower()
        .replace(" ", "_")
        .replace("-", "_")
    )


def parse_import_boolean(
    value: object,
    *,
    default: bool = True,
) -> bool:
    text = str(value or "").strip().lower()

    if not text:
        return default

    if text in {
        "1",
        "true",
        "yes",
        "y",
        "active",
        "on",
    }:
        return True

    if text in {
        "0",
        "false",
        "no",
        "n",
        "inactive",
        "off",
    }:
        return False

    raise ValueError(
        "Use Yes/No, True/False, Active/Inactive, or 1/0."
    )


def coconut_tree_import_payload(
    row: dict[str, object],
) -> dict[str, object]:
    return {
        "tree_code": str(
            row.get("tree_code", "")
        ).strip(),
        "tree_name": str(
            row.get("tree_name", "")
        ).strip(),
        "qr_code_id": str(
            row.get("qr_code_id", "")
        ).strip(),
        "variety": str(
            row.get("variety", "")
        ).strip(),
        "planting_date": str(
            row.get("planting_date", "")
        ).strip(),
        "block_name": str(
            row.get("block_name", "")
        ).strip(),
        "row_number": str(
            row.get("row_number", "")
        ).strip(),
        "position_number": str(
            row.get("position_number", "")
        ).strip(),
        "health_status": str(
            row.get("health_status", "")
        ).strip(),
        "height_m": str(
            row.get("height_m", "")
        ).strip(),
        "canopy_diameter_m": str(
            row.get("canopy_diameter_m", "")
        ).strip(),
        "trunk_girth_cm": str(
            row.get("trunk_girth_cm", "")
        ).strip(),
        "remarks": str(
            row.get("remarks", "")
        ).strip(),
        "is_active": parse_import_boolean(
            row.get("is_active", ""),
            default=True,
        ),
    }


def render_coconut_tree_import_page(
    request: Request,
    user: User,
    farm: Farm,
    *,
    errors: list[str] | None = None,
    imported_count: int = 0,
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name="trees/import.html",
        context={
            "user": user,
            "farm": farm,
            "errors": errors or [],
            "imported_count": imported_count,
            "max_rows": COCONUT_TREE_IMPORT_MAX_ROWS,
            "required_headers": sorted(
                COCONUT_TREE_IMPORT_REQUIRED_HEADERS
            ),
            "optional_headers": sorted(
                COCONUT_TREE_IMPORT_OPTIONAL_HEADERS
            ),
        },
        status_code=status_code,
    )


@app.get(
    "/farms/{farm_id}/trees/import",
    response_class=HTMLResponse,
)
def coconut_tree_import_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    return render_coconut_tree_import_page(
        request,
        user,
        farm,
    )


@app.post(
    "/farms/{farm_id}/trees/import",
    response_class=HTMLResponse,
)
async def import_coconut_trees_csv(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    form = await request.form()
    uploaded_file = form.get("csv_file")

    if uploaded_file is None:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=["Select a CSV file to import."],
            status_code=422,
        )

    filename = str(
        getattr(uploaded_file, "filename", "")
        or ""
    ).strip()

    if not filename.lower().endswith(".csv"):
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=["Only .csv files are supported."],
            status_code=422,
        )

    raw_content = await uploaded_file.read()

    if not raw_content:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=["The selected CSV file is empty."],
            status_code=422,
        )

    if len(raw_content) > 5 * 1024 * 1024:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "CSV file size must not exceed 5 MB."
            ],
            status_code=413,
        )

    try:
        decoded_content = raw_content.decode(
            "utf-8-sig"
        )
    except UnicodeDecodeError:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "CSV file must use UTF-8 encoding."
            ],
            status_code=422,
        )

    csv_stream = io.StringIO(decoded_content)

    try:
        reader = csv.DictReader(csv_stream)
    except csv.Error:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=["Unable to read the CSV file."],
            status_code=422,
        )

    if not reader.fieldnames:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=["CSV header row is missing."],
            status_code=422,
        )

    normalized_headers = [
        normalize_coconut_tree_import_header(
            header or ""
        )
        for header in reader.fieldnames
    ]

    if len(normalized_headers) != len(
        set(normalized_headers)
    ):
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "CSV contains duplicate column headers."
            ],
            status_code=422,
        )

    missing_headers = (
        COCONUT_TREE_IMPORT_REQUIRED_HEADERS
        - set(normalized_headers)
    )

    if missing_headers:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                (
                    "Missing required columns: "
                    + ", ".join(
                        sorted(missing_headers)
                    )
                )
            ],
            status_code=422,
        )

    allowed_headers = (
        COCONUT_TREE_IMPORT_REQUIRED_HEADERS
        | COCONUT_TREE_IMPORT_OPTIONAL_HEADERS
    )

    unsupported_headers = (
        set(normalized_headers)
        - allowed_headers
    )

    if unsupported_headers:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                (
                    "Unsupported columns: "
                    + ", ".join(
                        sorted(unsupported_headers)
                    )
                )
            ],
            status_code=422,
        )

    header_mapping = dict(
        zip(
            reader.fieldnames,
            normalized_headers,
            strict=True,
        )
    )

    existing_tree_codes = {
        value.lower()
        for value in db.scalars(
            select(CoconutTree.tree_code)
            .where(
                CoconutTree.farm_id == farm.id
            )
        ).all()
        if value
    }

    existing_qr_codes = {
        value.lower()
        for value in db.scalars(
            select(CoconutTree.qr_code_id)
            .where(
                CoconutTree.qr_code_id.is_not(None)
            )
        ).all()
        if value
    }

    import_tree_codes: set[str] = set()
    import_qr_codes: set[str] = set()
    import_errors: list[str] = []
    valid_values: list[dict[str, object]] = []

    try:
        rows = list(reader)
    except csv.Error as exc:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                f"CSV parsing error: {exc}"
            ],
            status_code=422,
        )

    if not rows:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "CSV does not contain any data rows."
            ],
            status_code=422,
        )

    if len(rows) > COCONUT_TREE_IMPORT_MAX_ROWS:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                (
                    "CSV contains more than "
                    f"{COCONUT_TREE_IMPORT_MAX_ROWS} rows."
                )
            ],
            status_code=422,
        )

    for row_number, raw_row in enumerate(
        rows,
        start=2,
    ):
        normalized_row = {
            header_mapping[key]: value
            for key, value in raw_row.items()
            if key in header_mapping
        }

        if not any(
            str(value or "").strip()
            for value in normalized_row.values()
        ):
            continue

        try:
            payload = coconut_tree_import_payload(
                normalized_row
            )
        except ValueError as exc:
            import_errors.append(
                f"Row {row_number}: is_active: {exc}"
            )
            continue

        values, validation_errors = (
            validate_coconut_tree_payload(
                payload
            )
        )

        if validation_errors:
            for field_name, message in sorted(
                validation_errors.items()
            ):
                import_errors.append(
                    (
                        f"Row {row_number}: "
                        f"{field_name}: {message}"
                    )
                )

            continue

        tree_code = str(
            values["tree_code"]
        ).lower()

        if tree_code in existing_tree_codes:
            import_errors.append(
                (
                    f"Row {row_number}: tree_code "
                    f"'{values['tree_code']}' already "
                    "exists in this farm."
                )
            )
            continue

        if tree_code in import_tree_codes:
            import_errors.append(
                (
                    f"Row {row_number}: duplicate "
                    f"tree_code '{values['tree_code']}' "
                    "inside the CSV file."
                )
            )
            continue

        qr_code_id = values.get("qr_code_id")
        normalized_qr_code = (
            str(qr_code_id).lower()
            if qr_code_id
            else ""
        )

        if (
            normalized_qr_code
            and normalized_qr_code
            in existing_qr_codes
        ):
            import_errors.append(
                (
                    f"Row {row_number}: qr_code_id "
                    f"'{qr_code_id}' already exists."
                )
            )
            continue

        if (
            normalized_qr_code
            and normalized_qr_code
            in import_qr_codes
        ):
            import_errors.append(
                (
                    f"Row {row_number}: duplicate "
                    f"qr_code_id '{qr_code_id}' "
                    "inside the CSV file."
                )
            )
            continue

        import_tree_codes.add(tree_code)

        if normalized_qr_code:
            import_qr_codes.add(
                normalized_qr_code
            )

        valid_values.append(values)

    if import_errors:
        visible_errors = import_errors[:100]

        if len(import_errors) > 100:
            visible_errors.append(
                (
                    f"{len(import_errors) - 100} "
                    "additional errors were omitted."
                )
            )

        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=visible_errors,
            status_code=422,
        )

    if not valid_values:
        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "CSV does not contain importable rows."
            ],
            status_code=422,
        )

    trees = [
        CoconutTree(
            farm_id=farm.id,
            **values,
        )
        for values in valid_values
    ]

    db.add_all(trees)

    audit(
        db,
        request,
        "coconut_tree.imported",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"record_count={len(trees)};"
            f"filename={filename};"
            "format=csv"
        ),
    )

    try:
        db.commit()
    except IntegrityError:
        db.rollback()

        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                (
                    "Import failed because one or more "
                    "tree codes or QR code IDs already exist."
                )
            ],
            status_code=409,
        )
    except SQLAlchemyError:
        db.rollback()

        return render_coconut_tree_import_page(
            request,
            user,
            farm,
            errors=[
                "Unable to import coconut trees."
            ],
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees"
            f"?success={len(trees)}%20trees%20"
            "imported%20successfully"
        ),
        status_code=303,
    )


# PATCH-005A.10: COCONUT TREE CSV TEMPLATE DOWNLOAD


COCONUT_TREE_IMPORT_TEMPLATE_HEADERS = [
    "tree_code",
    "tree_name",
    "variety",
    "health_status",
    "planting_date",
    "block_name",
    "row_number",
    "position_number",
    "qr_code_id",
    "height_m",
    "canopy_diameter_m",
    "trunk_girth_cm",
    "remarks",
    "is_active",
]


COCONUT_TREE_IMPORT_TEMPLATE_ROWS = [
    [
        "CTN-001",
        "North Tree",
        "Tall",
        "Healthy",
        "2020-06-15",
        "Block A",
        "R1",
        "P1",
        "QR-CTN-001",
        "8.50",
        "5.25",
        "75.40",
        "Healthy producing tree",
        "Yes",
    ],
    [
        "CTN-002",
        "Canal Tree",
        "Dwarf",
        "Needs Attention",
        "2021-01-10",
        "Block A",
        "R1",
        "P2",
        "QR-CTN-002",
        "6.20",
        "4.80",
        "62.30",
        "Inspect leaf colour",
        "Yes",
    ],
]


def generate_coconut_tree_import_template_csv() -> str:
    import csv as csv_module
    import io as io_module

    output = io_module.StringIO(newline="")

    writer = csv_module.writer(
        output,
        quoting=csv_module.QUOTE_MINIMAL,
    )

    writer.writerow(
        COCONUT_TREE_IMPORT_TEMPLATE_HEADERS
    )

    writer.writerows(
        COCONUT_TREE_IMPORT_TEMPLATE_ROWS
    )

    return "\ufeff" + output.getvalue()


@app.get(
    "/farms/{farm_id}/trees/import-template.csv",
)
def download_coconut_tree_import_template(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    csv_content = (
        generate_coconut_tree_import_template_csv()
    )

    audit(
        db,
        request,
        "coconut_tree.import_template_downloaded",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            "format=csv"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv; charset=utf-8",
        headers={
            "Content-Disposition": (
                'attachment; filename="'
                'coconut-tree-import-template.csv"'
            ),
            "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff",
        },
    )

# PATCH-005A.10-FIX1: ENSURE CSV IO IMPORTS

# PATCH-005A.10-FIX2: LOCAL CSV MODULE IMPORTS


# PATCH-005A.11: COCONUT TREE BULK UPDATE


COCONUT_TREE_BULK_ACTIONS = {
    "set_health_status",
    "activate",
    "deactivate",
}


def normalize_coconut_tree_ids(
    values: list[object],
) -> list[int]:
    tree_ids: list[int] = []

    for value in values:
        try:
            tree_id = int(
                str(value).strip()
            )
        except (TypeError, ValueError):
            continue

        if tree_id <= 0:
            continue

        if tree_id not in tree_ids:
            tree_ids.append(tree_id)

    return tree_ids


def render_coconut_tree_bulk_update_page(
    request: Request,
    user: User,
    farm: Farm,
    trees: list[CoconutTree],
    *,
    errors: list[str] | None = None,
    selected_tree_ids: list[int] | None = None,
    selected_action: str = "",
    selected_health_status: str = "",
    status_code: int = 200,
):
    return templates.TemplateResponse(
        request=request,
        name="trees/bulk_update.html",
        context={
            "user": user,
            "farm": farm,
            "trees": trees,
            "errors": errors or [],
            "selected_tree_ids": (
                selected_tree_ids or []
            ),
            "selected_action": selected_action,
            "selected_health_status": (
                selected_health_status
            ),
            "tree_health_statuses": [
                "Healthy",
                "Needs Attention",
                "Diseased",
                "Removed",
            ],
        },
        status_code=status_code,
    )


@app.get(
    "/farms/{farm_id}/trees/bulk-update",
    response_class=HTMLResponse,
)
def coconut_tree_bulk_update_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    trees = db.scalars(
        select(CoconutTree)
        .where(
            CoconutTree.farm_id == farm.id
        )
        .order_by(
            CoconutTree.is_active.desc(),
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
    ).all()

    return render_coconut_tree_bulk_update_page(
        request,
        user,
        farm,
        trees,
    )


@app.post(
    "/farms/{farm_id}/trees/bulk-update",
    response_class=HTMLResponse,
)
async def bulk_update_coconut_trees(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    farm_trees = db.scalars(
        select(CoconutTree)
        .where(
            CoconutTree.farm_id == farm.id
        )
        .order_by(
            CoconutTree.is_active.desc(),
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
    ).all()

    form = await request.form()

    selected_tree_ids = (
        normalize_coconut_tree_ids(
            form.getlist("tree_ids")
        )
    )

    selected_action = str(
        form.get("bulk_action", "")
        or ""
    ).strip()

    selected_health_status = str(
        form.get("health_status", "")
        or ""
    ).strip().title()

    errors: list[str] = []

    if not selected_tree_ids:
        errors.append(
            "Select at least one coconut tree."
        )

    if (
        selected_action
        not in COCONUT_TREE_BULK_ACTIONS
    ):
        errors.append(
            "Select a valid bulk action."
        )

    if (
        selected_action
        == "set_health_status"
        and selected_health_status
        not in TREE_HEALTH_STATUSES
    ):
        errors.append(
            "Select a valid health status."
        )

    farm_tree_ids = {
        tree.id
        for tree in farm_trees
    }

    unauthorized_tree_ids = [
        tree_id
        for tree_id in selected_tree_ids
        if tree_id not in farm_tree_ids
    ]

    if unauthorized_tree_ids:
        errors.append(
            (
                "One or more selected coconut trees "
                "do not belong to this farm."
            )
        )

    if errors:
        return render_coconut_tree_bulk_update_page(
            request,
            user,
            farm,
            farm_trees,
            errors=errors,
            selected_tree_ids=selected_tree_ids,
            selected_action=selected_action,
            selected_health_status=(
                selected_health_status
            ),
            status_code=422,
        )

    trees_to_update = [
        tree
        for tree in farm_trees
        if tree.id in selected_tree_ids
    ]

    for tree in trees_to_update:
        if selected_action == "set_health_status":
            tree.health_status = (
                selected_health_status
            )

            if selected_health_status == "Removed":
                tree.is_active = False

        elif selected_action == "activate":
            tree.is_active = True

            if tree.health_status == "Removed":
                tree.health_status = "Needs Attention"

        elif selected_action == "deactivate":
            tree.is_active = False

    action_detail = selected_action

    if selected_action == "set_health_status":
        action_detail = (
            f"{selected_action}:"
            f"{selected_health_status}"
        )

    audit(
        db,
        request,
        "coconut_tree.bulk_updated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"record_count={len(trees_to_update)};"
            f"action={action_detail};"
            "tree_ids="
            + ",".join(
                str(tree.id)
                for tree in trees_to_update
            )
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return render_coconut_tree_bulk_update_page(
            request,
            user,
            farm,
            farm_trees,
            errors=[
                (
                    "Unable to update the selected "
                    "coconut trees."
                )
            ],
            selected_tree_ids=selected_tree_ids,
            selected_action=selected_action,
            selected_health_status=(
                selected_health_status
            ),
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees"
            f"?success={len(trees_to_update)}%20"
            "trees%20updated%20successfully"
        ),
        status_code=303,
    )


# PATCH-005A.12: COCONUT TREE PRINTABLE LABELS


COCONUT_TREE_LABEL_PAGE_SIZES = {
    12,
    24,
    48,
    96,
}


def coconut_tree_label_conditions(
    farm_id: int,
    *,
    query_text: str = "",
    variety_filter: str = "",
    health_filter: str = "",
    activity_filter: str = "",
):
    conditions = [
        CoconutTree.farm_id == farm_id,
    ]

    query_text = query_text.strip()

    if query_text:
        search_pattern = f"%{query_text}%"

        conditions.append(
            or_(
                CoconutTree.tree_code.ilike(
                    search_pattern
                ),
                CoconutTree.tree_name.ilike(
                    search_pattern
                ),
                CoconutTree.qr_code_id.ilike(
                    search_pattern
                ),
                CoconutTree.block_name.ilike(
                    search_pattern
                ),
                CoconutTree.row_number.ilike(
                    search_pattern
                ),
                CoconutTree.position_number.ilike(
                    search_pattern
                ),
            )
        )

    variety_filter = (
        variety_filter.strip().title()
    )

    if variety_filter in TREE_VARIETIES:
        conditions.append(
            CoconutTree.variety == variety_filter
        )

    health_filter = (
        health_filter.strip().title()
    )

    if health_filter in TREE_HEALTH_STATUSES:
        conditions.append(
            CoconutTree.health_status == health_filter
        )

    activity_filter = (
        activity_filter.strip().lower()
    )

    if activity_filter == "active":
        conditions.append(
            CoconutTree.is_active.is_(True)
        )
    elif activity_filter == "inactive":
        conditions.append(
            CoconutTree.is_active.is_(False)
        )

    return conditions


def coconut_tree_label_location(
    tree: CoconutTree,
) -> str:
    parts = [
        tree.block_name,
        tree.row_number,
        tree.position_number,
    ]

    return " · ".join(
        str(part).strip()
        for part in parts
        if part is not None
        and str(part).strip()
    )


@app.get(
    "/farms/{farm_id}/trees/labels",
    response_class=HTMLResponse,
)
def coconut_tree_labels_page(
    farm_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    query_text = request.query_params.get(
        "q",
        "",
    ).strip()

    variety_filter = request.query_params.get(
        "variety",
        "",
    ).strip().title()

    health_filter = request.query_params.get(
        "health_status",
        "",
    ).strip().title()

    activity_filter = request.query_params.get(
        "activity",
        "",
    ).strip().lower()

    try:
        page = int(
            request.query_params.get(
                "page",
                "1",
            )
        )
    except ValueError:
        page = 1

    try:
        page_size = int(
            request.query_params.get(
                "page_size",
                "24",
            )
        )
    except ValueError:
        page_size = 24

    page = max(page, 1)

    if (
        page_size
        not in COCONUT_TREE_LABEL_PAGE_SIZES
    ):
        page_size = 24

    conditions = coconut_tree_label_conditions(
        farm.id,
        query_text=query_text,
        variety_filter=variety_filter,
        health_filter=health_filter,
        activity_filter=activity_filter,
    )

    filtered_count = db.scalar(
        select(func.count(CoconutTree.id))
        .where(*conditions)
    ) or 0

    total_pages = max(
        1,
        (
            filtered_count
            + page_size
            - 1
        )
        // page_size,
    )

    if page > total_pages:
        page = total_pages

    offset = (
        page - 1
    ) * page_size

    trees = db.scalars(
        select(CoconutTree)
        .where(*conditions)
        .order_by(
            CoconutTree.tree_code.asc(),
            CoconutTree.id.asc(),
        )
        .offset(offset)
        .limit(page_size)
    ).all()

    audit(
        db,
        request,
        "coconut_tree.labels_viewed",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"record_count={len(trees)};"
            f"page={page};"
            f"page_size={page_size}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return templates.TemplateResponse(
        request=request,
        name="trees/labels.html",
        context={
            "user": user,
            "farm": farm,
            "trees": trees,
            "query_text": query_text,
            "variety_filter": variety_filter,
            "health_filter": health_filter,
            "activity_filter": activity_filter,
            "tree_varieties": sorted(
                TREE_VARIETIES
            ),
            "tree_health_statuses": [
                "Healthy",
                "Needs Attention",
                "Diseased",
                "Removed",
            ],
            "page": page,
            "page_size": page_size,
            "page_sizes": sorted(
                COCONUT_TREE_LABEL_PAGE_SIZES
            ),
            "filtered_count": filtered_count,
            "total_pages": total_pages,
            "pagination_start": (
                offset + 1
                if filtered_count
                else 0
            ),
            "pagination_end": min(
                offset + len(trees),
                filtered_count,
            ),
            "coconut_tree_label_location": (
                coconut_tree_label_location
            ),
            "coconut_tree_timeline": (
                coconut_tree_timeline
            ),
        },
    )


# PATCH-005A.13: COCONUT TREE QR CODE GENERATION


COCONUT_TREE_QR_BOX_SIZES = {
    4,
    6,
    8,
    10,
    12,
}


def coconut_tree_qr_target_url(
    request: Request,
    farm_id: int,
    tree_id: int,
) -> str:
    base_url = str(
        request.base_url
    ).rstrip("/")

    return (
        f"{base_url}/farms/{farm_id}"
        f"/trees/{tree_id}"
    )


def generate_coconut_tree_qr_png(
    value: str,
    *,
    box_size: int = 8,
    border: int = 2,
) -> bytes:
    import io as io_module

    import qrcode
    from qrcode.constants import (
        ERROR_CORRECT_M,
    )

    normalized_value = str(
        value or ""
    ).strip()

    if not normalized_value:
        raise ValueError(
            "QR code value is required."
        )

    if box_size not in COCONUT_TREE_QR_BOX_SIZES:
        box_size = 8

    border = max(
        1,
        min(
            int(border),
            8,
        ),
    )

    qr = qrcode.QRCode(
        version=None,
        error_correction=ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )

    qr.add_data(
        normalized_value
    )

    qr.make(
        fit=True
    )

    image = qr.make_image(
        fill_color="black",
        back_color="white",
    )

    output = io_module.BytesIO()

    image.save(
        output,
        format="PNG",
        optimize=True,
    )

    return output.getvalue()


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/qr.png",
)
def coconut_tree_qr_png(
    farm_id: int,
    tree_id: int,
    request: Request,
    download: bool = False,
    box_size: int = 8,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = db.scalar(
        select(CoconutTree)
        .where(
            CoconutTree.id == tree_id,
            CoconutTree.farm_id == farm.id,
        )
    )

    if tree is None:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    target_url = coconut_tree_qr_target_url(
        request,
        farm.id,
        tree.id,
    )

    png_content = generate_coconut_tree_qr_png(
        target_url,
        box_size=box_size,
        border=2,
    )

    disposition = "inline"

    if download:
        disposition = "attachment"

    safe_tree_code = "".join(
        character
        for character in tree.tree_code
        if (
            character.isalnum()
            or character in {"-", "_"}
        )
    ) or f"tree-{tree.id}"

    audit(
        db,
        request,
        "coconut_tree.qr_generated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"tree_code={tree.tree_code};"
            f"download={str(download).lower()};"
            f"box_size={box_size}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return StreamingResponse(
        iter([png_content]),
        media_type="image/png",
        headers={
            "Content-Disposition": (
                f'{disposition}; filename="'
                f'{safe_tree_code}-qr.png"'
            ),
            "Cache-Control": (
                "private, max-age=300"
            ),
            "X-Content-Type-Options": "nosniff",
        },
    )


# PATCH-005A.14: TREE TIMELINE


def coconut_tree_timeline(tree: CoconutTree):
    events = []

    if tree.planting_date:
        events.append({
            "date": tree.planting_date,
            "title": "Tree Planted",
            "description": (
                f"Variety: {tree.variety}"
            ),
        })

    if getattr(tree, "created_at", None):
        events.append({
            "date": tree.created_at.date(),
            "title": "Registered",
            "description": (
                "Tree registered in Messis AI."
            ),
        })

    if getattr(tree, "updated_at", None):
        events.append({
            "date": tree.updated_at.date(),
            "title": "Last Updated",
            "description": (
                "Latest modification."
            ),
        })

    events.sort(
        key=lambda item: item["date"] or "",
        reverse=True,
    )

    return events


# PATCH-005A.15: TREE AGE AND TEMPLATE HELPERS


def normalize_coconut_tree_date(
    value,
):
    from datetime import date, datetime

    if value is None:
        return None

    if isinstance(value, datetime):
        return value.date()

    if isinstance(value, date):
        return value

    date_method = getattr(
        value,
        "date",
        None,
    )

    if callable(date_method):
        try:
            date_value = date_method()
        except (
            TypeError,
            ValueError,
            AttributeError,
        ):
            date_value = None

        if date_value is not None:
            if isinstance(
                date_value,
                datetime,
            ):
                return date_value.date()

            if isinstance(
                date_value,
                date,
            ):
                return date_value

            normalized_date_value = str(
                date_value
            ).strip()

            if normalized_date_value:
                try:
                    return date.fromisoformat(
                        normalized_date_value[:10]
                    )
                except ValueError:
                    pass

    normalized_value = str(
        value
    ).strip()

    if not normalized_value:
        return None

    try:
        return date.fromisoformat(
            normalized_value[:10]
        )
    except ValueError:
        return None


def coconut_tree_age_details(
    tree: CoconutTree,
    *,
    today=None,
):
    from datetime import date

    planting_date = normalize_coconut_tree_date(
        getattr(
            tree,
            "planting_date",
            None,
        )
    )

    if planting_date is None:
        return {
            "years": None,
            "months": None,
            "days": None,
            "total_months": None,
            "label": "Planting date not recorded",
            "planting_date": None,
        }

    current_date = (
        normalize_coconut_tree_date(today)
        if today is not None
        else date.today()
    )

    if current_date is None:
        current_date = date.today()

    if planting_date > current_date:
        return {
            "years": 0,
            "months": 0,
            "days": 0,
            "total_months": 0,
            "label": "Planting date is in the future",
            "planting_date": planting_date,
        }

    years = (
        current_date.year
        - planting_date.year
    )

    months = (
        current_date.month
        - planting_date.month
    )

    days = (
        current_date.day
        - planting_date.day
    )

    if days < 0:
        months -= 1

        previous_month = (
            current_date.month - 1
        )

        previous_month_year = (
            current_date.year
        )

        if previous_month == 0:
            previous_month = 12
            previous_month_year -= 1

        import calendar

        days_in_previous_month = (
            calendar.monthrange(
                previous_month_year,
                previous_month,
            )[1]
        )

        days += days_in_previous_month

    if months < 0:
        years -= 1
        months += 12

    total_months = (
        years * 12
        + months
    )

    label_parts = []

    if years:
        label_parts.append(
            (
                f"{years} year"
                if years == 1
                else f"{years} years"
            )
        )

    if months:
        label_parts.append(
            (
                f"{months} month"
                if months == 1
                else f"{months} months"
            )
        )

    if not label_parts:
        if days == 0:
            label = "Planted today"
        else:
            label = (
                f"{days} day"
                if days == 1
                else f"{days} days"
            )
    else:
        label = " ".join(
            label_parts
        )

    return {
        "years": years,
        "months": months,
        "days": days,
        "total_months": total_months,
        "label": label,
        "planting_date": planting_date,
    }


def coconut_tree_age_label(
    tree: CoconutTree,
) -> str:
    return coconut_tree_age_details(
        tree
    )["label"]


def coconut_tree_maturity_status(
    tree: CoconutTree,
) -> str:
    age_details = coconut_tree_age_details(
        tree
    )

    total_months = age_details[
        "total_months"
    ]

    if total_months is None:
        return "Unknown"

    if total_months < 12:
        return "Seedling"

    if total_months < 36:
        return "Juvenile"

    if total_months < 72:
        return "Early Bearing"

    return "Mature"


def coconut_tree_timeline(
    tree: CoconutTree,
):
    events = []

    planting_date = normalize_coconut_tree_date(
        getattr(
            tree,
            "planting_date",
            None,
        )
    )

    created_date = normalize_coconut_tree_date(
        getattr(
            tree,
            "created_at",
            None,
        )
    )

    updated_date = normalize_coconut_tree_date(
        getattr(
            tree,
            "updated_at",
            None,
        )
    )

    if planting_date:
        events.append({
            "date": planting_date,
            "title": "Tree Planted",
            "description": (
                f"Variety: {tree.variety}"
            ),
        })

    if created_date:
        events.append({
            "date": created_date,
            "title": "Registered",
            "description": (
                "Tree registered in Messis AI."
            ),
        })

    if (
        updated_date
        and updated_date != created_date
    ):
        events.append({
            "date": updated_date,
            "title": "Last Updated",
            "description": (
                "Latest tree record modification."
            ),
        })

    events.sort(
        key=lambda item: item["date"],
        reverse=True,
    )

    return events


templates.env.globals.update({
    "coconut_tree_label_location": (
        coconut_tree_label_location
    ),
    "coconut_tree_timeline": (
        coconut_tree_timeline
    ),
    "coconut_tree_age_details": (
        coconut_tree_age_details
    ),
    "coconut_tree_age_label": (
        coconut_tree_age_label
    ),
    "coconut_tree_maturity_status": (
        coconut_tree_maturity_status
    ),
})


# PATCH-005A.16: TREE HEALTH SCORE


COCONUT_TREE_HEALTH_SCORES = {
    "excellent": 100,
    "healthy": 90,
    "good": 80,
    "fair": 60,
    "poor": 40,
    "critical": 20,
    "dead": 0,
}


def coconut_tree_health_score(
    tree: CoconutTree,
):
    health = str(
        getattr(
            tree,
            "health_status",
            "",
        )
    ).strip().lower()

    score = (
        COCONUT_TREE_HEALTH_SCORES.get(
            health,
            75,
        )
    )

    if score >= 90:
        color = "emerald"
        label = "Excellent"

    elif score >= 75:
        color = "green"
        label = "Healthy"

    elif score >= 50:
        color = "amber"
        label = "Needs Attention"

    elif score >= 25:
        color = "orange"
        label = "Poor"

    else:
        color = "red"
        label = "Critical"

    return {
        "score": score,
        "color": color,
        "label": label,
    }


templates.env.globals.update({
    "coconut_tree_health_score":
        coconut_tree_health_score,
})


# PATCH-005A.17: TREE CARE RECOMMENDATIONS


def coconut_tree_care_recommendations(
    tree: CoconutTree,
):
    health = coconut_tree_health_score(
        tree
    )

    score = health["score"]

    recommendations = []

    if score >= 90:
        recommendations.extend([
            {
                "priority": "Routine",
                "title": "Continue regular monitoring",
                "description": (
                    "Inspect the tree periodically and "
                    "record any visible changes."
                ),
            },
            {
                "priority": "Routine",
                "title": "Maintain irrigation schedule",
                "description": (
                    "Continue the current watering plan "
                    "based on soil moisture and weather."
                ),
            },
            {
                "priority": "Routine",
                "title": "Review nutrition programme",
                "description": (
                    "Apply fertiliser and organic manure "
                    "according to the farm schedule."
                ),
            },
        ])

    elif score >= 75:
        recommendations.extend([
            {
                "priority": "Monitor",
                "title": "Inspect leaves and crown",
                "description": (
                    "Check for discolouration, damaged "
                    "leaves, insects, and crown symptoms."
                ),
            },
            {
                "priority": "Monitor",
                "title": "Check soil moisture",
                "description": (
                    "Confirm that the root zone is neither "
                    "too dry nor waterlogged."
                ),
            },
            {
                "priority": "Routine",
                "title": "Verify nutrient application",
                "description": (
                    "Review the most recent fertiliser and "
                    "manure application records."
                ),
            },
        ])

    elif score >= 50:
        recommendations.extend([
            {
                "priority": "Attention",
                "title": "Perform detailed inspection",
                "description": (
                    "Inspect the trunk, crown, leaves, and "
                    "root zone for disease or pest signs."
                ),
            },
            {
                "priority": "Attention",
                "title": "Review irrigation immediately",
                "description": (
                    "Check irrigation quantity, drainage, "
                    "and soil moisture around the tree."
                ),
            },
            {
                "priority": "Attention",
                "title": "Assess nutrient deficiency",
                "description": (
                    "Review leaf colour and growth before "
                    "planning corrective nutrition."
                ),
            },
        ])

    elif score >= 25:
        recommendations.extend([
            {
                "priority": "Urgent",
                "title": "Schedule field assessment",
                "description": (
                    "Arrange an immediate inspection by "
                    "the farm supervisor or agronomist."
                ),
            },
            {
                "priority": "Urgent",
                "title": "Isolate suspected problems",
                "description": (
                    "Prevent the spread of pests or disease "
                    "to nearby coconut trees."
                ),
            },
            {
                "priority": "Urgent",
                "title": "Document visible symptoms",
                "description": (
                    "Capture photographs and record all "
                    "observed symptoms before treatment."
                ),
            },
        ])

    else:
        recommendations.extend([
            {
                "priority": "Critical",
                "title": "Immediate expert inspection",
                "description": (
                    "Request urgent evaluation by a "
                    "qualified agriculture professional."
                ),
            },
            {
                "priority": "Critical",
                "title": "Protect surrounding trees",
                "description": (
                    "Inspect nearby trees and implement "
                    "appropriate isolation measures."
                ),
            },
            {
                "priority": "Critical",
                "title": "Evaluate recovery potential",
                "description": (
                    "Determine whether treatment, removal, "
                    "or replacement is appropriate."
                ),
            },
        ])

    return {
        "health_score": score,
        "health_label": health["label"],
        "recommendations": recommendations,
        "count": len(recommendations),
    }


def coconut_tree_priority_style(
    priority: str,
):
    normalized_priority = str(
        priority or ""
    ).strip().lower()

    styles = {
        "routine": {
            "badge": (
                "bg-emerald-100 text-emerald-700"
            ),
            "border": "border-emerald-200",
            "icon": "text-emerald-600",
        },
        "monitor": {
            "badge": (
                "bg-sky-100 text-sky-700"
            ),
            "border": "border-sky-200",
            "icon": "text-sky-600",
        },
        "attention": {
            "badge": (
                "bg-amber-100 text-amber-700"
            ),
            "border": "border-amber-200",
            "icon": "text-amber-600",
        },
        "urgent": {
            "badge": (
                "bg-orange-100 text-orange-700"
            ),
            "border": "border-orange-200",
            "icon": "text-orange-600",
        },
        "critical": {
            "badge": (
                "bg-red-100 text-red-700"
            ),
            "border": "border-red-200",
            "icon": "text-red-600",
        },
    }

    return styles.get(
        normalized_priority,
        {
            "badge": (
                "bg-slate-100 text-slate-700"
            ),
            "border": "border-slate-200",
            "icon": "text-slate-600",
        },
    )


templates.env.globals.update({
    "coconut_tree_care_recommendations": (
        coconut_tree_care_recommendations
    ),
    "coconut_tree_priority_style": (
        coconut_tree_priority_style
    ),
})


# PATCH-005A.18: PRINTABLE TREE HEALTH REPORT


def coconut_tree_report_summary(
    tree: CoconutTree,
):
    age = coconut_tree_age_details(
        tree
    )

    health = coconut_tree_health_score(
        tree
    )

    care_plan = (
        coconut_tree_care_recommendations(
            tree
        )
    )

    location = coconut_tree_label_location(
        tree
    )

    return {
        "tree_code": getattr(
            tree,
            "tree_code",
            "",
        ),
        "variety": getattr(
            tree,
            "variety",
            "",
        ),
        "health_status": getattr(
            tree,
            "health_status",
            "",
        ),
        "is_active": bool(
            getattr(
                tree,
                "is_active",
                False,
            )
        ),
        "location": location or "Not recorded",
        "planting_date": age[
            "planting_date"
        ],
        "age_label": age["label"],
        "maturity_status": (
            coconut_tree_maturity_status(
                tree
            )
        ),
        "health_score": health["score"],
        "health_label": health["label"],
        "recommendations": care_plan[
            "recommendations"
        ],
        "recommendation_count": care_plan[
            "count"
        ],
    }


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/health-report",
    response_class=HTMLResponse,
)
def coconut_tree_health_report_page(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm = require_owned_farm(
        db,
        farm_id,
        user.id,
    )

    tree = db.scalar(
        select(CoconutTree)
        .where(
            CoconutTree.id == tree_id,
            CoconutTree.farm_id == farm.id,
        )
    )

    if tree is None:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    report = coconut_tree_report_summary(
        tree
    )

    audit(
        db,
        request,
        "coconut_tree.health_report_viewed",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"tree_code={tree.tree_code};"
            f"health_score={report['health_score']}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

    return templates.TemplateResponse(
        request=request,
        name="trees/health_report.html",
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "report": report,
        },
    )


templates.env.globals.update({
    "coconut_tree_report_summary": (
        coconut_tree_report_summary
    ),
})


# PATCH-005B.2: TREE ACTIVITY CRUD BACKEND

from datetime import date as tree_activity_date_type
from decimal import Decimal as TreeActivityAmount

from pydantic import (
    BaseModel as TreeActivitySchema,
    ConfigDict as TreeActivityConfig,
    Field as TreeActivityField,
    field_validator as tree_activity_field_validator,
)

from app.models import TreeActivity


TREE_ACTIVITY_TYPES = (
    "irrigation",
    "fertiliser",
    "manure",
    "pesticide",
    "disease_treatment",
    "pruning",
    "cleaning",
    "soil_testing",
    "inspection",
    "harvesting",
    "replacement",
    "other",
)

TREE_ACTIVITY_STATUSES = (
    "planned",
    "in_progress",
    "completed",
    "cancelled",
)


class TreeActivityCreatePayload(
    TreeActivitySchema
):
    activity_type: str = TreeActivityField(
        min_length=2,
        max_length=50,
    )

    activity_date: tree_activity_date_type

    status: str = TreeActivityField(
        default="completed",
        min_length=2,
        max_length=30,
    )

    title: str = TreeActivityField(
        min_length=2,
        max_length=150,
    )

    description: str | None = (
        TreeActivityField(
            default=None,
            max_length=5000,
        )
    )

    quantity: TreeActivityAmount | None = (
        TreeActivityField(
            default=None,
            ge=0,
            max_digits=12,
            decimal_places=3,
        )
    )

    unit: str | None = TreeActivityField(
        default=None,
        max_length=30,
    )

    cost: TreeActivityAmount | None = (
        TreeActivityField(
            default=None,
            ge=0,
            max_digits=12,
            decimal_places=2,
        )
    )

    performed_by: str | None = (
        TreeActivityField(
            default=None,
            max_length=120,
        )
    )

    next_due_date: (
        tree_activity_date_type | None
    ) = None

    notes: str | None = TreeActivityField(
        default=None,
        max_length=5000,
    )

    @tree_activity_field_validator(
        "activity_type"
    )
    @classmethod
    def validate_activity_type(
        cls,
        value: str,
    ) -> str:
        normalized = str(
            value or ""
        ).strip().lower()

        if normalized not in TREE_ACTIVITY_TYPES:
            raise ValueError(
                "Unsupported activity type."
            )

        return normalized

    @tree_activity_field_validator(
        "status"
    )
    @classmethod
    def validate_status(
        cls,
        value: str,
    ) -> str:
        normalized = str(
            value or ""
        ).strip().lower()

        if normalized not in TREE_ACTIVITY_STATUSES:
            raise ValueError(
                "Unsupported activity status."
            )

        return normalized

    @tree_activity_field_validator(
        "title",
        "description",
        "unit",
        "performed_by",
        "notes",
        mode="before",
    )
    @classmethod
    def normalize_text(
        cls,
        value,
    ):
        if value is None:
            return None

        normalized = str(
            value
        ).strip()

        return normalized or None

    @tree_activity_field_validator(
        "next_due_date"
    )
    @classmethod
    def validate_next_due_date(
        cls,
        value,
        info,
    ):
        if value is None:
            return None

        activity_date = info.data.get(
            "activity_date"
        )

        if (
            activity_date is not None
            and value < activity_date
        ):
            raise ValueError(
                "Next due date cannot be before "
                "the activity date."
            )

        return value


class TreeActivityUpdatePayload(
    TreeActivityCreatePayload
):
    pass


class TreeActivityResponse(
    TreeActivitySchema
):
    model_config = TreeActivityConfig(
        from_attributes=True
    )

    id: int
    farm_id: int
    tree_id: int
    activity_type: str
    activity_date: tree_activity_date_type
    status: str
    title: str
    description: str | None
    quantity: TreeActivityAmount | None
    unit: str | None
    cost: TreeActivityAmount | None
    performed_by: str | None
    next_due_date: (
        tree_activity_date_type | None
    )
    notes: str | None


def require_owned_coconut_tree(
    db: Session,
    farm_id: int,
    tree_id: int,
    owner_id: int,
):
    farm = require_owned_farm(
        db,
        farm_id,
        owner_id,
    )

    tree = db.scalar(
        select(CoconutTree)
        .where(
            CoconutTree.id == tree_id,
            CoconutTree.farm_id == farm.id,
        )
    )

    if tree is None:
        raise HTTPException(
            status_code=404,
            detail="Coconut tree not found.",
        )

    return farm, tree


def require_tree_activity(
    db: Session,
    farm_id: int,
    tree_id: int,
    activity_id: int,
):
    activity = db.scalar(
        select(TreeActivity)
        .where(
            TreeActivity.id == activity_id,
            TreeActivity.farm_id == farm_id,
            TreeActivity.tree_id == tree_id,
        )
    )

    if activity is None:
        raise HTTPException(
            status_code=404,
            detail="Tree activity not found.",
        )

    return activity


def tree_activity_to_response(
    activity: TreeActivity,
):
    return TreeActivityResponse.model_validate(
        activity
    )


@app.get(
    "/api/farms/{farm_id}/trees/{tree_id}/activities",
    response_model=list[TreeActivityResponse],
)
def list_tree_activities_api(
    farm_id: int,
    tree_id: int,
    activity_type: str | None = None,
    status: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    statement = (
        select(TreeActivity)
        .where(
            TreeActivity.farm_id == farm.id,
            TreeActivity.tree_id == tree.id,
        )
        .order_by(
            TreeActivity.activity_date.desc(),
            TreeActivity.id.desc(),
        )
    )

    if activity_type:
        normalized_type = (
            str(activity_type)
            .strip()
            .lower()
        )

        if normalized_type not in TREE_ACTIVITY_TYPES:
            raise HTTPException(
                status_code=422,
                detail="Unsupported activity type.",
            )

        statement = statement.where(
            TreeActivity.activity_type
            == normalized_type
        )

    if status:
        normalized_status = (
            str(status)
            .strip()
            .lower()
        )

        if (
            normalized_status
            not in TREE_ACTIVITY_STATUSES
        ):
            raise HTTPException(
                status_code=422,
                detail="Unsupported activity status.",
            )

        statement = statement.where(
            TreeActivity.status
            == normalized_status
        )

    activities = list(
        db.scalars(
            statement
        ).all()
    )

    return [
        tree_activity_to_response(
            activity
        )
        for activity in activities
    ]


@app.get(
    "/api/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}",
    response_model=TreeActivityResponse,
)
def get_tree_activity_api(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    return tree_activity_to_response(
        activity
    )


@app.post(
    "/api/farms/{farm_id}/trees/{tree_id}/activities",
    response_model=TreeActivityResponse,
    status_code=201,
)
def create_tree_activity_api(
    farm_id: int,
    tree_id: int,
    payload: TreeActivityCreatePayload,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = TreeActivity(
        farm_id=farm.id,
        tree_id=tree.id,
        **payload.model_dump(),
    )

    db.add(
        activity
    )

    audit(
        db,
        request,
        "tree_activity.created",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_type={activity.activity_type};"
            f"activity_date={activity.activity_date}"
        ),
    )

    try:
        db.commit()
        db.refresh(
            activity
        )
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to create tree activity."
            ),
        ) from exc

    return tree_activity_to_response(
        activity
    )


@app.put(
    "/api/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}",
    response_model=TreeActivityResponse,
)
def update_tree_activity_api(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    payload: TreeActivityUpdatePayload,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    changes = payload.model_dump()

    for field_name, value in changes.items():
        setattr(
            activity,
            field_name,
            value,
        )

    audit(
        db,
        request,
        "tree_activity.updated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_id={activity.id};"
            f"activity_type={activity.activity_type}"
        ),
    )

    try:
        db.commit()
        db.refresh(
            activity
        )
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to update tree activity."
            ),
        ) from exc

    return tree_activity_to_response(
        activity
    )


@app.delete(
    "/api/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}",
    status_code=204,
)
def delete_tree_activity_api(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    detail = (
        f"farm_id={farm.id};"
        f"tree_id={tree.id};"
        f"activity_id={activity.id};"
        f"activity_type={activity.activity_type}"
    )

    db.delete(
        activity
    )

    audit(
        db,
        request,
        "tree_activity.deleted",
        owner_id=user.id,
        detail=detail,
    )

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to delete tree activity."
            ),
        ) from exc

    return Response(
        status_code=204
    )


# PATCH-005B.3: TREE ACTIVITY WEB UI


TREE_ACTIVITY_TYPE_LABELS = {
    "irrigation": "Irrigation",
    "fertiliser": "Fertiliser",
    "manure": "Organic Manure",
    "pesticide": "Pesticide Treatment",
    "disease_treatment": "Disease Treatment",
    "pruning": "Pruning",
    "cleaning": "Tree Cleaning",
    "soil_testing": "Soil Testing",
    "inspection": "Tree Inspection",
    "harvesting": "Harvesting",
    "replacement": "Tree Replacement",
    "other": "Other Activity",
}

TREE_ACTIVITY_STATUS_LABELS = {
    "planned": "Planned",
    "in_progress": "In Progress",
    "completed": "Completed",
    "cancelled": "Cancelled",
}


def tree_activity_type_label(
    activity_type: str,
) -> str:
    normalized = str(
        activity_type or ""
    ).strip().lower()

    return TREE_ACTIVITY_TYPE_LABELS.get(
        normalized,
        normalized.replace(
            "_",
            " ",
        ).title() or "Activity",
    )


def tree_activity_status_label(
    status: str,
) -> str:
    normalized = str(
        status or ""
    ).strip().lower()

    return TREE_ACTIVITY_STATUS_LABELS.get(
        normalized,
        normalized.replace(
            "_",
            " ",
        ).title() or "Unknown",
    )


def tree_activity_status_style(
    status: str,
) -> str:
    normalized = str(
        status or ""
    ).strip().lower()

    styles = {
        "planned": (
            "bg-sky-100 text-sky-700 "
            "border-sky-200"
        ),
        "in_progress": (
            "bg-amber-100 text-amber-700 "
            "border-amber-200"
        ),
        "completed": (
            "bg-emerald-100 text-emerald-700 "
            "border-emerald-200"
        ),
        "cancelled": (
            "bg-slate-100 text-slate-600 "
            "border-slate-200"
        ),
    }

    return styles.get(
        normalized,
        (
            "bg-slate-100 text-slate-600 "
            "border-slate-200"
        ),
    )


def tree_activity_type_style(
    activity_type: str,
) -> str:
    normalized = str(
        activity_type or ""
    ).strip().lower()

    styles = {
        "irrigation": (
            "bg-blue-100 text-blue-700"
        ),
        "fertiliser": (
            "bg-lime-100 text-lime-700"
        ),
        "manure": (
            "bg-green-100 text-green-700"
        ),
        "pesticide": (
            "bg-orange-100 text-orange-700"
        ),
        "disease_treatment": (
            "bg-red-100 text-red-700"
        ),
        "pruning": (
            "bg-purple-100 text-purple-700"
        ),
        "cleaning": (
            "bg-cyan-100 text-cyan-700"
        ),
        "soil_testing": (
            "bg-amber-100 text-amber-700"
        ),
        "inspection": (
            "bg-indigo-100 text-indigo-700"
        ),
        "harvesting": (
            "bg-emerald-100 text-emerald-700"
        ),
        "replacement": (
            "bg-rose-100 text-rose-700"
        ),
        "other": (
            "bg-slate-100 text-slate-700"
        ),
    }

    return styles.get(
        normalized,
        "bg-slate-100 text-slate-700",
    )


def tree_activity_decimal_from_form(
    value,
    field_name: str,
    decimal_places: int,
):
    normalized = str(
        value or ""
    ).strip()

    if not normalized:
        return None

    try:
        amount = TreeActivityAmount(
            normalized
        )
    except Exception as exc:
        raise ValueError(
            f"{field_name} must be a valid number."
        ) from exc

    if amount < 0:
        raise ValueError(
            f"{field_name} cannot be negative."
        )

    quantizer = (
        TreeActivityAmount("1")
        if decimal_places == 0
        else TreeActivityAmount(
            "0." + (
                "0" * (
                    decimal_places - 1
                )
            ) + "1"
        )
    )

    return amount.quantize(
        quantizer
    )


def tree_activity_date_from_form(
    value,
    field_name: str,
    required: bool = False,
):
    normalized = str(
        value or ""
    ).strip()

    if not normalized:
        if required:
            raise ValueError(
                f"{field_name} is required."
            )

        return None

    try:
        return tree_activity_date_type.fromisoformat(
            normalized
        )
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be a valid date."
        ) from exc


def tree_activity_form_payload(
    form,
):
    activity_date = (
        tree_activity_date_from_form(
            form.get(
                "activity_date"
            ),
            "Activity date",
            required=True,
        )
    )

    next_due_date = (
        tree_activity_date_from_form(
            form.get(
                "next_due_date"
            ),
            "Next due date",
        )
    )

    raw_payload = {
        "activity_type": form.get(
            "activity_type"
        ),
        "activity_date": activity_date,
        "status": form.get(
            "status"
        ) or "completed",
        "title": form.get(
            "title"
        ),
        "description": form.get(
            "description"
        ),
        "quantity": (
            tree_activity_decimal_from_form(
                form.get(
                    "quantity"
                ),
                "Quantity",
                3,
            )
        ),
        "unit": form.get(
            "unit"
        ),
        "cost": (
            tree_activity_decimal_from_form(
                form.get(
                    "cost"
                ),
                "Cost",
                2,
            )
        ),
        "performed_by": form.get(
            "performed_by"
        ),
        "next_due_date": next_due_date,
        "notes": form.get(
            "notes"
        ),
    }

    return TreeActivityCreatePayload(
        **raw_payload
    )


def tree_activity_form_values(
    form=None,
    activity=None,
):
    fields = (
        "activity_type",
        "activity_date",
        "status",
        "title",
        "description",
        "quantity",
        "unit",
        "cost",
        "performed_by",
        "next_due_date",
        "notes",
    )

    values = {}

    for field_name in fields:
        if form is not None:
            value = form.get(
                field_name,
                "",
            )
        elif activity is not None:
            value = getattr(
                activity,
                field_name,
                "",
            )
        else:
            value = ""

        if value is None:
            value = ""

        if isinstance(
            value,
            tree_activity_date_type,
        ):
            value = value.isoformat()

        values[field_name] = str(
            value
        )

    if not values["activity_date"]:
        values["activity_date"] = (
            tree_activity_date_type
            .today()
            .isoformat()
        )

    if not values["status"]:
        values["status"] = "completed"

    return values


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/activities",
    response_class=HTMLResponse,
)
def tree_activity_list_page(
    farm_id: int,
    tree_id: int,
    request: Request,
    activity_type: str | None = None,
    status: str | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    statement = (
        select(TreeActivity)
        .where(
            TreeActivity.farm_id == farm.id,
            TreeActivity.tree_id == tree.id,
        )
        .order_by(
            TreeActivity.activity_date.desc(),
            TreeActivity.id.desc(),
        )
    )

    selected_type = str(
        activity_type or ""
    ).strip().lower()

    selected_status = str(
        status or ""
    ).strip().lower()

    if (
        selected_type
        and selected_type
        in TREE_ACTIVITY_TYPES
    ):
        statement = statement.where(
            TreeActivity.activity_type
            == selected_type
        )

    if (
        selected_status
        and selected_status
        in TREE_ACTIVITY_STATUSES
    ):
        statement = statement.where(
            TreeActivity.status
            == selected_status
        )

    activities = list(
        db.scalars(
            statement
        ).all()
    )

    total_cost = sum(
        (
            activity.cost
            or TreeActivityAmount("0")
        )
        for activity in activities
    )

    completed_count = sum(
        1
        for activity in activities
        if activity.status == "completed"
    )

    planned_count = sum(
        1
        for activity in activities
        if activity.status == "planned"
    )

    return templates.TemplateResponse(
        request=request,
        name=(
            "tree_activities/list.html"
        ),
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "activities": activities,
            "activity_types": (
                TREE_ACTIVITY_TYPES
            ),
            "activity_statuses": (
                TREE_ACTIVITY_STATUSES
            ),
            "selected_type": selected_type,
            "selected_status": (
                selected_status
            ),
            "total_cost": total_cost,
            "completed_count": (
                completed_count
            ),
            "planned_count": (
                planned_count
            ),
        },
    )


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/activities/new",
    response_class=HTMLResponse,
)
def tree_activity_create_page(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    return templates.TemplateResponse(
        request=request,
        name=(
            "tree_activities/form.html"
        ),
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "activity": None,
            "form_mode": "create",
            "form_action": (
                f"/farms/{farm.id}/trees/"
                f"{tree.id}/activities/new"
            ),
            "form_values": (
                tree_activity_form_values()
            ),
            "form_error": None,
            "activity_types": (
                TREE_ACTIVITY_TYPES
            ),
            "activity_statuses": (
                TREE_ACTIVITY_STATUSES
            ),
        },
    )


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/activities/new",
    response_class=HTMLResponse,
)
async def tree_activity_create_submit(
    farm_id: int,
    tree_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    form = await request.form()

    try:
        payload = tree_activity_form_payload(
            form
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request=request,
            name=(
                "tree_activities/form.html"
            ),
            context={
                "user": user,
                "farm": farm,
                "tree": tree,
                "activity": None,
                "form_mode": "create",
                "form_action": (
                    f"/farms/{farm.id}/trees/"
                    f"{tree.id}/activities/new"
                ),
                "form_values": (
                    tree_activity_form_values(
                        form=form
                    )
                ),
                "form_error": str(
                    exc
                ),
                "activity_types": (
                    TREE_ACTIVITY_TYPES
                ),
                "activity_statuses": (
                    TREE_ACTIVITY_STATUSES
                ),
            },
            status_code=422,
        )

    activity = TreeActivity(
        farm_id=farm.id,
        tree_id=tree.id,
        **payload.model_dump(),
    )

    db.add(
        activity
    )

    audit(
        db,
        request,
        "tree_activity.created",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_type="
            f"{activity.activity_type};"
            f"activity_date="
            f"{activity.activity_date}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name=(
                "tree_activities/form.html"
            ),
            context={
                "user": user,
                "farm": farm,
                "tree": tree,
                "activity": None,
                "form_mode": "create",
                "form_action": (
                    f"/farms/{farm.id}/trees/"
                    f"{tree.id}/activities/new"
                ),
                "form_values": (
                    tree_activity_form_values(
                        form=form
                    )
                ),
                "form_error": (
                    "Unable to save the tree "
                    "activity."
                ),
                "activity_types": (
                    TREE_ACTIVITY_TYPES
                ),
                "activity_statuses": (
                    TREE_ACTIVITY_STATUSES
                ),
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities"
        ),
        status_code=303,
    )


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}/edit",
    response_class=HTMLResponse,
)
def tree_activity_edit_page(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    return templates.TemplateResponse(
        request=request,
        name=(
            "tree_activities/form.html"
        ),
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "activity": activity,
            "form_mode": "edit",
            "form_action": (
                f"/farms/{farm.id}/trees/"
                f"{tree.id}/activities/"
                f"{activity.id}/edit"
            ),
            "form_values": (
                tree_activity_form_values(
                    activity=activity
                )
            ),
            "form_error": None,
            "activity_types": (
                TREE_ACTIVITY_TYPES
            ),
            "activity_statuses": (
                TREE_ACTIVITY_STATUSES
            ),
        },
    )


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}/edit",
    response_class=HTMLResponse,
)
async def tree_activity_edit_submit(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    form = await request.form()

    try:
        payload = tree_activity_form_payload(
            form
        )
    except Exception as exc:
        return templates.TemplateResponse(
            request=request,
            name=(
                "tree_activities/form.html"
            ),
            context={
                "user": user,
                "farm": farm,
                "tree": tree,
                "activity": activity,
                "form_mode": "edit",
                "form_action": (
                    f"/farms/{farm.id}/trees/"
                    f"{tree.id}/activities/"
                    f"{activity.id}/edit"
                ),
                "form_values": (
                    tree_activity_form_values(
                        form=form
                    )
                ),
                "form_error": str(
                    exc
                ),
                "activity_types": (
                    TREE_ACTIVITY_TYPES
                ),
                "activity_statuses": (
                    TREE_ACTIVITY_STATUSES
                ),
            },
            status_code=422,
        )

    for field_name, value in (
        payload.model_dump().items()
    ):
        setattr(
            activity,
            field_name,
            value,
        )

    audit(
        db,
        request,
        "tree_activity.updated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_id={activity.id};"
            f"activity_type="
            f"{activity.activity_type}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError:
        db.rollback()

        return templates.TemplateResponse(
            request=request,
            name=(
                "tree_activities/form.html"
            ),
            context={
                "user": user,
                "farm": farm,
                "tree": tree,
                "activity": activity,
                "form_mode": "edit",
                "form_action": (
                    f"/farms/{farm.id}/trees/"
                    f"{tree.id}/activities/"
                    f"{activity.id}/edit"
                ),
                "form_values": (
                    tree_activity_form_values(
                        form=form
                    )
                ),
                "form_error": (
                    "Unable to update the tree "
                    "activity."
                ),
                "activity_types": (
                    TREE_ACTIVITY_TYPES
                ),
                "activity_statuses": (
                    TREE_ACTIVITY_STATUSES
                ),
            },
            status_code=500,
        )

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities"
        ),
        status_code=303,
    )


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}/delete",
    response_class=HTMLResponse,
)
def tree_activity_delete_submit(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    detail = (
        f"farm_id={farm.id};"
        f"tree_id={tree.id};"
        f"activity_id={activity.id};"
        f"activity_type="
        f"{activity.activity_type}"
    )

    db.delete(
        activity
    )

    audit(
        db,
        request,
        "tree_activity.deleted",
        owner_id=user.id,
        detail=detail,
    )

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to delete tree activity."
            ),
        ) from exc

    return RedirectResponse(
        url=(
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities"
        ),
        status_code=303,
    )


templates.env.globals.update({
    "tree_activity_type_label": (
        tree_activity_type_label
    ),
    "tree_activity_status_label": (
        tree_activity_status_label
    ),
    "tree_activity_status_style": (
        tree_activity_status_style
    ),
    "tree_activity_type_style": (
        tree_activity_type_style
    ),
})


# PATCH-005B.4: ACTIVITY DETAIL AND TREE SUMMARY


def tree_activity_summary(
    db: Session,
    farm_id: int,
    tree_id: int,
):
    activities = list(
        db.scalars(
            select(TreeActivity)
            .where(
                TreeActivity.farm_id == farm_id,
                TreeActivity.tree_id == tree_id,
            )
            .order_by(
                TreeActivity.activity_date.desc(),
                TreeActivity.id.desc(),
            )
        ).all()
    )

    today = tree_activity_date_type.today()

    completed_count = sum(
        1
        for activity in activities
        if activity.status == "completed"
    )

    planned_count = sum(
        1
        for activity in activities
        if activity.status == "planned"
    )

    in_progress_count = sum(
        1
        for activity in activities
        if activity.status == "in_progress"
    )

    overdue_count = sum(
        1
        for activity in activities
        if (
            activity.next_due_date is not None
            and activity.next_due_date < today
            and activity.status != "cancelled"
        )
    )

    total_cost = sum(
        (
            activity.cost
            or TreeActivityAmount("0")
        )
        for activity in activities
    )

    next_due_activities = sorted(
        [
            activity
            for activity in activities
            if (
                activity.next_due_date is not None
                and activity.next_due_date >= today
                and activity.status != "cancelled"
            )
        ],
        key=lambda item: (
            item.next_due_date,
            item.id or 0,
        ),
    )

    recent_activities = activities[:5]

    return {
        "total_count": len(activities),
        "completed_count": completed_count,
        "planned_count": planned_count,
        "in_progress_count": in_progress_count,
        "overdue_count": overdue_count,
        "total_cost": total_cost,
        "recent_activities": recent_activities,
        "next_due_activity": (
            next_due_activities[0]
            if next_due_activities
            else None
        ),
    }


def tree_activity_is_overdue(
    activity: TreeActivity,
) -> bool:
    next_due_date = getattr(
        activity,
        "next_due_date",
        None,
    )

    status = str(
        getattr(
            activity,
            "status",
            "",
        )
        or ""
    ).strip().lower()

    return bool(
        next_due_date is not None
        and next_due_date
        < tree_activity_date_type.today()
        and status != "cancelled"
    )


@app.get(
    "/farms/{farm_id}/trees/{tree_id}/activities/{activity_id}",
    response_class=HTMLResponse,
)
def tree_activity_detail_page(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    return templates.TemplateResponse(
        request=request,
        name="tree_activities/detail.html",
        context={
            "user": user,
            "farm": farm,
            "tree": tree,
            "activity": activity,
            "is_overdue": (
                tree_activity_is_overdue(
                    activity
                )
            ),
        },
    )


@app.get(
    "/api/farms/{farm_id}/trees/{tree_id}/activities-summary",
)
def tree_activity_summary_api(
    farm_id: int,
    tree_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    summary = tree_activity_summary(
        db,
        farm.id,
        tree.id,
    )

    next_due_activity = summary[
        "next_due_activity"
    ]

    return {
        "farm_id": farm.id,
        "tree_id": tree.id,
        "total_count": summary[
            "total_count"
        ],
        "completed_count": summary[
            "completed_count"
        ],
        "planned_count": summary[
            "planned_count"
        ],
        "in_progress_count": summary[
            "in_progress_count"
        ],
        "overdue_count": summary[
            "overdue_count"
        ],
        "total_cost": str(
            summary["total_cost"]
        ),
        "next_due_activity": (
            {
                "id": next_due_activity.id,
                "title": next_due_activity.title,
                "activity_type": (
                    next_due_activity.activity_type
                ),
                "next_due_date": (
                    next_due_activity
                    .next_due_date
                    .isoformat()
                ),
            }
            if next_due_activity is not None
            else None
        ),
    }


templates.env.globals.update({
    "tree_activity_is_overdue": (
        tree_activity_is_overdue
    ),
    "tree_activity_summary": (
        tree_activity_summary
    ),
})


# PATCH-005B.5: ACTIVITY STATUS WORKFLOW


TREE_ACTIVITY_STATUS_TRANSITIONS = {
    "planned": {
        "in_progress",
        "completed",
        "cancelled",
    },
    "in_progress": {
        "completed",
        "cancelled",
    },
    "completed": {
        "planned",
    },
    "cancelled": {
        "planned",
    },
}


def normalize_tree_activity_status(
    value,
) -> str:
    normalized = str(
        value or ""
    ).strip().lower()

    if normalized not in TREE_ACTIVITY_STATUSES:
        raise ValueError(
            "Unsupported activity status."
        )

    return normalized


def tree_activity_status_transition_allowed(
    current_status,
    target_status,
) -> bool:
    current = normalize_tree_activity_status(
        current_status
    )

    target = normalize_tree_activity_status(
        target_status
    )

    if current == target:
        return True

    return target in (
        TREE_ACTIVITY_STATUS_TRANSITIONS.get(
            current,
            set(),
        )
    )


def tree_activity_status_actions(
    activity: TreeActivity,
):
    current_status = normalize_tree_activity_status(
        activity.status
    )

    actions = []

    definitions = (
        (
            "in_progress",
            "Start Activity",
            "bg-amber-500 hover:bg-amber-600",
        ),
        (
            "completed",
            "Mark Completed",
            "bg-emerald-600 hover:bg-emerald-700",
        ),
        (
            "planned",
            "Move to Planned",
            "bg-sky-600 hover:bg-sky-700",
        ),
        (
            "cancelled",
            "Cancel Activity",
            "bg-red-600 hover:bg-red-700",
        ),
    )

    for (
        target_status,
        label,
        css_class,
    ) in definitions:
        if target_status == current_status:
            continue

        if not tree_activity_status_transition_allowed(
            current_status,
            target_status,
        ):
            continue

        actions.append({
            "status": target_status,
            "label": label,
            "css_class": css_class,
        })

    return actions


def update_tree_activity_status(
    db: Session,
    activity: TreeActivity,
    target_status,
):
    normalized_target = (
        normalize_tree_activity_status(
            target_status
        )
    )

    current_status = (
        normalize_tree_activity_status(
            activity.status
        )
    )

    if not tree_activity_status_transition_allowed(
        current_status,
        normalized_target,
    ):
        raise ValueError(
            "Status transition from "
            f"{current_status} to "
            f"{normalized_target} is not allowed."
        )

    activity.status = normalized_target

    return activity


@app.post(
    "/farms/{farm_id}/trees/{tree_id}/activities/"
    "{activity_id}/status",
    response_class=HTMLResponse,
)
async def tree_activity_status_submit(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    form = await request.form()

    target_status = form.get(
        "status"
    )

    try:
        previous_status = (
            normalize_tree_activity_status(
                activity.status
            )
        )

        update_tree_activity_status(
            db,
            activity,
            target_status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    audit(
        db,
        request,
        "tree_activity.status_updated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_id={activity.id};"
            f"previous_status={previous_status};"
            f"new_status={activity.status}"
        ),
    )

    try:
        db.commit()
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to update activity status."
            ),
        ) from exc

    redirect_to = str(
        form.get(
            "redirect_to",
            "",
        )
        or ""
    ).strip()

    allowed_redirects = {
        (
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities"
        ),
        (
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities/"
            f"{activity.id}"
        ),
    }

    if redirect_to not in allowed_redirects:
        redirect_to = (
            f"/farms/{farm.id}/trees/"
            f"{tree.id}/activities/"
            f"{activity.id}"
        )

    return RedirectResponse(
        url=redirect_to,
        status_code=303,
    )


@app.patch(
    "/api/farms/{farm_id}/trees/{tree_id}/activities/"
    "{activity_id}/status",
    response_model=TreeActivityResponse,
)
def tree_activity_status_api(
    farm_id: int,
    tree_id: int,
    activity_id: int,
    status: str,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
):
    farm, tree = require_owned_coconut_tree(
        db,
        farm_id,
        tree_id,
        user.id,
    )

    activity = require_tree_activity(
        db,
        farm.id,
        tree.id,
        activity_id,
    )

    previous_status = (
        normalize_tree_activity_status(
            activity.status
        )
    )

    try:
        update_tree_activity_status(
            db,
            activity,
            status,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    audit(
        db,
        request,
        "tree_activity.status_updated",
        owner_id=user.id,
        detail=(
            f"farm_id={farm.id};"
            f"tree_id={tree.id};"
            f"activity_id={activity.id};"
            f"previous_status={previous_status};"
            f"new_status={activity.status}"
        ),
    )

    try:
        db.commit()
        db.refresh(
            activity
        )
    except SQLAlchemyError as exc:
        db.rollback()

        raise HTTPException(
            status_code=500,
            detail=(
                "Unable to update activity status."
            ),
        ) from exc

    return tree_activity_to_response(
        activity
    )


templates.env.globals.update({
    "tree_activity_status_actions": (
        tree_activity_status_actions
    ),
    "tree_activity_status_transition_allowed": (
        tree_activity_status_transition_allowed
    ),
})

# PATCH-ROUTE-ORDER-001A: STATIC ROUTE PRIORITY


def _messis_promote_static_route(
    static_path: str,
    dynamic_path: str,
) -> None:
    """
    Ensure a literal route such as /harvests/manage is checked
    before a dynamic route such as /harvests/{cycle_id}.
    """

    routes = app.router.routes

    static_route = next(
        (
            route
            for route in routes
            if getattr(route, "path", None) == static_path
        ),
        None,
    )

    dynamic_route = next(
        (
            route
            for route in routes
            if getattr(route, "path", None) == dynamic_path
        ),
        None,
    )

    if static_route is None or dynamic_route is None:
        return

    static_index = routes.index(static_route)
    dynamic_index = routes.index(dynamic_route)

    if static_index < dynamic_index:
        return

    routes.remove(static_route)

    dynamic_index = routes.index(dynamic_route)
    routes.insert(dynamic_index, static_route)


_MESSIS_STATIC_ROUTE_PRIORITIES = (
    (
        "/harvests/manage",
        "/harvests/{cycle_id}",
    ),
    (
        "/harvest-records/manage",
        "/harvest-records/{record_id}",
    ),
    (
        "/expenses/manage",
        "/expenses/{expense_id}",
    ),
    (
        "/expenses/new",
        "/expenses/{expense_id}",
    ),
    (
        "/sales/manage",
        "/sales/{sale_id}",
    ),
    (
        "/sales/new",
        "/sales/{sale_id}",
    ),
    (
        "/farms/new",
        "/farms/{farm_id}",
    ),
)

for (
    _messis_static_path,
    _messis_dynamic_path,
) in _MESSIS_STATIC_ROUTE_PRIORITIES:
    _messis_promote_static_route(
        static_path=_messis_static_path,
        dynamic_path=_messis_dynamic_path,
    )
