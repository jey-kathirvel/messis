"""Lightweight daily reminder popup for farm tasks and harvest cycles."""
from datetime import date, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Farm, FarmTask, HarvestCycle, HarvestPhase, User

router = APIRouter(prefix="/reminders", tags=["reminders"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


def signed_in_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active:
        raise HTTPException(401, "Authentication required")
    return user


@router.get("/popup", response_class=HTMLResponse)
def reminder_popup(request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    today = date.today()
    task_rows = db.execute(
        select(FarmTask, Farm)
        .join(Farm, Farm.id == FarmTask.farm_id)
        .where(FarmTask.owner_id == user.id, FarmTask.status == "PENDING")
        .order_by(FarmTask.due_date.is_(None), FarmTask.due_date, FarmTask.created_at)
        .limit(12)
    ).all()

    harvest_rows = db.execute(
        select(HarvestCycle, Farm)
        .join(Farm, Farm.id == HarvestCycle.farm_id)
        .where(
            HarvestCycle.owner_id == user.id,
            HarvestCycle.status.notin_(["Completed", "Cancelled"]),
            HarvestCycle.planned_harvest_date <= today + timedelta(days=7),
        )
        .order_by(HarvestCycle.planned_harvest_date)
        .limit(12)
    ).all()

    phase_rows = db.execute(
        select(HarvestPhase, HarvestCycle, Farm)
        .join(HarvestCycle, HarvestCycle.id == HarvestPhase.harvest_cycle_id)
        .join(Farm, Farm.id == HarvestCycle.farm_id)
        .where(
            HarvestPhase.owner_id == user.id,
            HarvestPhase.status.notin_(["COMPLETED", "SKIPPED"]),
            HarvestPhase.start_date <= today,
            HarvestPhase.due_date <= today + timedelta(days=1),
        )
        .order_by(HarvestPhase.due_date, HarvestPhase.phase_order)
        .limit(12)
    ).all()

    task_items = []
    for task, farm in task_rows:
        if task.due_date is None:
            timing, tone = "Due date not set", "normal"
        elif task.due_date < today:
            timing, tone = f"Overdue by {(today - task.due_date).days} day(s)", "urgent"
        elif task.due_date == today:
            timing, tone = "Due today", "urgent"
        else:
            timing, tone = f"Due in {(task.due_date - today).days} day(s)", "soon"
        task_items.append({"id": task.id, "title": task.title, "farm": farm.name, "timing": timing, "tone": tone})

    harvest_items = []
    for cycle, farm in harvest_rows:
        delta = (cycle.planned_harvest_date - today).days
        if delta < 0:
            timing, tone = f"Overdue by {abs(delta)} day(s)", "urgent"
        elif delta == 0:
            timing, tone = "Harvest due today", "urgent"
        else:
            timing, tone = f"Harvest due in {delta} day(s)", "soon"
        harvest_items.append({"id": cycle.id, "farm": farm.name, "date": cycle.planned_harvest_date, "timing": timing, "tone": tone})

    phase_items = []
    for phase, cycle, farm in phase_rows:
        delta = (phase.due_date - today).days
        if delta < 0:
            timing, tone = f"Phase overdue by {abs(delta)} day(s)", "urgent"
        elif delta == 0:
            timing, tone = "Phase due today", "urgent"
        else:
            timing, tone = "Phase due tomorrow", "soon"
        phase_items.append({"cycle_id": cycle.id, "name": phase.name, "farm": farm.name,
                            "timing": timing, "tone": tone})

    return templates.TemplateResponse(request=request, name="reminders/popup.html", context={
        "task_items": task_items, "harvest_items": harvest_items, "phase_items": phase_items,
        "reminder_count": len(task_items) + len(harvest_items) + len(phase_items), "today": today,
    })
