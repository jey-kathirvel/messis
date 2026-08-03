"""Farm task management workflow."""
from datetime import date, datetime, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Farm, FarmTask, User

router = APIRouter(prefix="/tasks", tags=["tasks"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
VALID_STATUSES = {"NEW", "PENDING", "CLOSED"}
VALID_PRIORITIES = {"LOW", "MEDIUM", "HIGH", "URGENT"}


def signed_in_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active:
        raise HTTPException(401, "Authentication required")
    return user


def owner_farm(db: Session, owner_id: int, farm_id: int) -> Farm:
    farm = db.scalar(select(Farm).where(Farm.id == farm_id, Farm.owner_id == owner_id))
    if not farm:
        raise HTTPException(404, "Farm not found")
    return farm


def owner_task(db: Session, owner_id: int, task_id: int) -> FarmTask:
    task = db.scalar(select(FarmTask).where(FarmTask.id == task_id, FarmTask.owner_id == owner_id))
    if not task:
        raise HTTPException(404, "Task not found")
    return task


@router.get("", response_class=HTMLResponse)
def task_dashboard(request: Request, farm_id: str = "", status: str = "ALL",
                   user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    farms = db.scalars(select(Farm).where(Farm.owner_id == user.id).order_by(Farm.name)).all()
    query = select(FarmTask, Farm).join(Farm, Farm.id == FarmTask.farm_id).where(FarmTask.owner_id == user.id)
    selected_farm_id = None
    if farm_id.strip():
        try:
            selected_farm_id = int(farm_id)
        except ValueError:
            raise HTTPException(422, "Invalid farm filter")
        owner_farm(db, user.id, selected_farm_id)
        query = query.where(FarmTask.farm_id == selected_farm_id)
    normalized_status = status.upper()
    if normalized_status in VALID_STATUSES:
        query = query.where(FarmTask.status == normalized_status)
    rows = db.execute(query.order_by(FarmTask.due_date.is_(None), FarmTask.due_date, FarmTask.created_at.desc())).all()
    counts = dict(db.execute(select(FarmTask.status, func.count(FarmTask.id)).where(
        FarmTask.owner_id == user.id).group_by(FarmTask.status)).all())
    today = date.today()
    overdue = db.scalar(select(func.count(FarmTask.id)).where(
        FarmTask.owner_id == user.id, FarmTask.status != "CLOSED", FarmTask.due_date < today)) or 0
    return templates.TemplateResponse(request=request, name="tasks/index.html", context={
        "page_title": "Farm Tasks", "current_user": user, "rows": rows, "farms": farms,
        "selected_farm_id": selected_farm_id, "selected_status": normalized_status, "counts": counts,
        "overdue_count": overdue, "today": today, "success_message": request.query_params.get("success"),
    })


@router.get("/new", response_class=HTMLResponse)
def new_task_page(request: Request, farm_id: int | None = None,
                  user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    farms = db.scalars(select(Farm).where(Farm.owner_id == user.id).order_by(Farm.name)).all()
    if farm_id is not None:
        owner_farm(db, user.id, farm_id)
    return templates.TemplateResponse(request=request, name="tasks/form.html", context={
        "page_title": "Create Farm Task", "current_user": user, "farms": farms,
        "selected_farm_id": farm_id, "task": None, "error_message": None,
    })


@router.post("/new")
def create_task(request: Request, farm_id: int = Form(...), title: str = Form(...),
                description: str = Form(""), priority: str = Form("MEDIUM"), due_date: str = Form(""),
                user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    owner_farm(db, user.id, farm_id)
    clean_title = title.strip()
    if not clean_title:
        raise HTTPException(422, "Task title is required")
    normalized_priority = priority.upper() if priority.upper() in VALID_PRIORITIES else "MEDIUM"
    parsed_due = date.fromisoformat(due_date) if due_date else None
    task = FarmTask(owner_id=user.id, farm_id=farm_id, title=clean_title,
                    description=description.strip() or None, priority=normalized_priority,
                    due_date=parsed_due, status="NEW")
    db.add(task); db.commit(); db.refresh(task)
    return RedirectResponse(f"/tasks/{task.id}?success={quote('Task created with New status.')}", 303)


@router.get("/{task_id}", response_class=HTMLResponse)
def task_detail(request: Request, task_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    task = owner_task(db, user.id, task_id)
    farm = owner_farm(db, user.id, task.farm_id)
    return templates.TemplateResponse(request=request, name="tasks/detail.html", context={
        "page_title": task.title, "current_user": user, "task": task, "farm": farm,
        "today": date.today(), "success_message": request.query_params.get("success"),
    })


@router.post("/{task_id}/assign")
def assign_task(task_id: int, worker_name: str = Form(...), worker_phone: str = Form(...),
                assignment_notes: str = Form(...), user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    task = owner_task(db, user.id, task_id)
    if task.status == "CLOSED":
        raise HTTPException(409, "Closed tasks cannot be assigned")
    if not worker_name.strip() or not worker_phone.strip() or not assignment_notes.strip():
        raise HTTPException(422, "Worker name, phone number and assignment notes are required")
    task.worker_name = worker_name.strip(); task.worker_phone = worker_phone.strip()
    task.assignment_notes = assignment_notes.strip(); task.status = "PENDING"
    task.assigned_at = datetime.now(timezone.utc); task.closed_at = None
    db.commit()
    return RedirectResponse(f"/tasks/{task.id}?success={quote('Worker assigned. Task moved to Pending.')}", 303)


@router.post("/{task_id}/close")
def close_task(task_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    task = owner_task(db, user.id, task_id)
    if task.status != "PENDING":
        raise HTTPException(409, "Only Pending tasks can be closed")
    task.status = "CLOSED"; task.closed_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(f"/tasks/{task.id}?success={quote('Task completed and closed.')}", 303)


@router.post("/{task_id}/reopen")
def reopen_task(task_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    task = owner_task(db, user.id, task_id)
    if task.status != "CLOSED":
        raise HTTPException(409, "Only Closed tasks can be reopened")
    task.status = "PENDING" if task.worker_name else "NEW"; task.closed_at = None
    db.commit()
    return RedirectResponse(f"/tasks/{task.id}?success={quote('Task reopened.')}", 303)
