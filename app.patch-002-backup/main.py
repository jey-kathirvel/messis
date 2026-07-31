from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.middleware.sessions import SessionMiddleware

from app.config import get_settings
from app.database import Base, engine, get_db
from app.models import AuditLog, Farm, User
from app.security import valid_passcode, verify_passcode

BASE_DIR = Path(__file__).resolve().parent
settings = get_settings()

app = FastAPI(title="Messis AI", version="0.2.0")
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie=settings.session_cookie_name,
    max_age=settings.session_max_age_seconds,
    same_site="lax",
    https_only=settings.app_env == "production",
)
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")
templates = Jinja2Templates(directory=BASE_DIR / "templates")

@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)

def audit(db: Session, request: Request, event: str, owner_id=None, detail=None):
    ip = request.headers.get("x-forwarded-for")
    if ip:
        ip = ip.split(",")[0].strip()
    elif request.client:
        ip = request.client.host
    db.add(AuditLog(owner_id=owner_id, event_type=event, ip_address=ip, detail=detail))

def current_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    if not isinstance(user_id, int):
        raise HTTPException(status_code=401, detail="Authentication required")
    user = db.get(User, user_id)
    if not user or not user.is_active:
        request.session.clear()
        raise HTTPException(status_code=401, detail="Authentication required")
    return user

@app.get("/health", response_class=JSONResponse)
def health():
    return {
        "status": "ok",
        "application": "Messis AI",
        "subtitle": "Smart Agriculture Management System",
        "version": "0.2.0",
        "database": "connected",
        "authentication": "enabled",
    }

@app.get("/", response_class=HTMLResponse)
def login_page(request: Request):
    if request.session.get("user_id"):
        return RedirectResponse("/dashboard", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="auth/login.html",
        context={"page_title": "Secure Login", "error_message": request.query_params.get("error")},
    )

@app.post("/auth/login")
def login(request: Request, user_id: str = Form(...), passcode: str = Form(...), db: Session = Depends(get_db)):
    if not valid_passcode(passcode):
        return RedirectResponse("/?error=" + quote("Passcode must contain exactly six digits."), status_code=303)

    user = db.scalar(select(User).where(or_(User.user_id == user_id.strip(), User.mobile_number == user_id.strip())))
    now = datetime.now(timezone.utc)

    if not user or not user.is_active:
        audit(db, request, "login_failed", detail="Unknown or inactive account")
        db.commit()
        return RedirectResponse("/?error=" + quote("Invalid User ID or passcode."), status_code=303)

    if user.locked_until:
        locked_until = user.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        if locked_until > now:
            return RedirectResponse("/?error=" + quote("Account temporarily locked. Try again later."), status_code=303)
        user.failed_attempts = 0
        user.locked_until = None

    if not verify_passcode(user.passcode_hash, passcode):
        user.failed_attempts += 1
        if user.failed_attempts >= settings.login_max_attempts:
            user.locked_until = now + timedelta(minutes=settings.login_lock_minutes)
        audit(db, request, "login_failed", user.id, f"Attempt {user.failed_attempts}")
        db.commit()
        message = (
            f"Too many attempts. Account locked for {settings.login_lock_minutes} minutes."
            if user.locked_until else "Invalid User ID or passcode."
        )
        return RedirectResponse("/?error=" + quote(message), status_code=303)

    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    audit(db, request, "login_success", user.id)
    db.commit()
    request.session.clear()
    request.session.update({"user_id": user.id, "owner_id": user.id, "role": user.role})
    return RedirectResponse("/dashboard", status_code=303)

@app.post("/auth/logout")
def logout(request: Request, db: Session = Depends(get_db)):
    owner_id = request.session.get("owner_id")
    if isinstance(owner_id, int):
        audit(db, request, "logout", owner_id)
        db.commit()
    request.session.clear()
    return RedirectResponse("/", status_code=303)

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user: User = Depends(current_user), db: Session = Depends(get_db)):
    farm_count = db.scalar(select(func.count(Farm.id)).where(Farm.owner_id == user.id)) or 0
    total_trees = db.scalar(select(func.coalesce(func.sum(Farm.total_trees), 0)).where(Farm.owner_id == user.id)) or 0
    farms = db.scalars(select(Farm).where(Farm.owner_id == user.id).order_by(Farm.id.desc()).limit(5)).all()
    return templates.TemplateResponse(
        request=request,
        name="dashboard/index.html",
        context={
            "page_title": "Dashboard",
            "current_user": user,
            "farm_count": farm_count,
            "total_trees": total_trees,
            "farms": farms,
        },
    )
