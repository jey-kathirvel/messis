"""Editable recommended phases for harvest lifecycles."""
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Farm, HarvestCycle, HarvestPhase, User

router = APIRouter(tags=["harvest-phases"])
templates = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")
VALID_PHASE_STATUSES = {"UPCOMING", "IN_PROGRESS", "OVERDUE", "COMPLETED", "SKIPPED"}

RECOMMENDED_PHASES = (
    ("Post-harvest review & cleanup", "Review the previous harvest, remove waste and record field observations."),
    ("Irrigation recovery", "Check soil moisture and restore the planned irrigation schedule."),
    ("Nutrition & soil care", "Review nutrient needs, apply the approved inputs and record quantities."),
    ("Pest & disease monitoring", "Inspect palms/field blocks and record symptoms or treatment needs."),
    ("Water & field maintenance", "Maintain irrigation lines, access paths and drainage before harvest activity."),
    ("Maturity and yield observation", "Observe crop maturity and update the expected harvest readiness."),
    ("Labour, tools & buyer preparation", "Confirm workers, tools, transport, storage and buyer readiness."),
    ("Final harvest readiness", "Complete safety checks and confirm the final harvest date and work plan."),
)


def signed_in_user(request: Request, db: Session = Depends(get_db)) -> User:
    user_id = request.session.get("user_id")
    user = db.get(User, user_id) if isinstance(user_id, int) else None
    if not user or not user.is_active:
        raise HTTPException(401, "Authentication required")
    return user


def owned_cycle(db: Session, owner_id: int, cycle_id: int) -> tuple[HarvestCycle, Farm]:
    row = db.execute(
        select(HarvestCycle, Farm).join(Farm, Farm.id == HarvestCycle.farm_id).where(
            HarvestCycle.id == cycle_id, HarvestCycle.owner_id == owner_id, Farm.owner_id == owner_id
        )
    ).first()
    if not row:
        raise HTTPException(404, "Harvest cycle not found")
    return row[0], row[1]


def phase_status_for_dates(start_date: date, due_date: date, completed: bool = False) -> str:
    if completed:
        return "COMPLETED"
    today = date.today()
    if today < start_date:
        return "UPCOMING"
    if today <= due_date:
        return "IN_PROGRESS"
    return "OVERDUE"


def recommended_phase_ranges(total_days: int) -> list[tuple[int, int]]:
    """Split the complete cycle into eight contiguous, non-empty ranges."""
    total = max(8, total_days)
    base, remainder = divmod(total, len(RECOMMENDED_PHASES))
    ranges, cursor = [], 1
    for index in range(len(RECOMMENDED_PHASES)):
        length = base + (1 if index < remainder else 0)
        end = cursor + length - 1
        ranges.append((cursor, end))
        cursor = end + 1
    return ranges


def ensure_recommended_phases(db: Session, cycle: HarvestCycle) -> list[HarvestPhase]:
    phases = db.scalars(select(HarvestPhase).where(
        HarvestPhase.harvest_cycle_id == cycle.id, HarvestPhase.owner_id == cycle.owner_id
    ).order_by(HarvestPhase.phase_order)).all()
    if phases:
        return list(phases)
    origin = cycle.previous_harvest_date or (cycle.planned_harvest_date - timedelta(days=cycle.harvest_interval_days))
    for order, ((name, description), (start_day, end_day)) in enumerate(
        zip(RECOMMENDED_PHASES, recommended_phase_ranges(cycle.harvest_interval_days)), 1
    ):
        start_date = origin + timedelta(days=start_day)
        due_date = origin + timedelta(days=end_day)
        db.add(HarvestPhase(
            harvest_cycle_id=cycle.id, owner_id=cycle.owner_id, phase_order=order,
            name=name, description=description, start_day=start_day, end_day=end_day,
            start_date=start_date, due_date=due_date,
            status=phase_status_for_dates(start_date, due_date), is_ai_recommended=True,
        ))
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
    return list(db.scalars(select(HarvestPhase).where(
        HarvestPhase.harvest_cycle_id == cycle.id, HarvestPhase.owner_id == cycle.owner_id
    ).order_by(HarvestPhase.phase_order)).all())


def lifecycle_context(db: Session, cycle: HarvestCycle) -> dict:
    phases = ensure_recommended_phases(db, cycle)
    changed = False
    for phase in phases:
        if phase.status not in {"COMPLETED", "SKIPPED"}:
            calculated = phase_status_for_dates(phase.start_date, phase.due_date)
            if phase.status != calculated:
                phase.status = calculated; changed = True
    if changed:
        db.commit()
    completed = sum(p.status == "COMPLETED" for p in phases)
    return {"phases": phases, "completed": completed, "total": len(phases),
            "progress": round((completed / len(phases)) * 100) if phases else 0}


def owned_phase(db: Session, owner_id: int, cycle_id: int, phase_id: int) -> HarvestPhase:
    phase = db.scalar(select(HarvestPhase).where(
        HarvestPhase.id == phase_id, HarvestPhase.harvest_cycle_id == cycle_id,
        HarvestPhase.owner_id == owner_id,
    ))
    if not phase:
        raise HTTPException(404, "Harvest phase not found")
    return phase


@router.get("/harvests/{cycle_id}/phases", response_class=HTMLResponse)
def phase_page(cycle_id: int, request: Request, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    cycle, farm = owned_cycle(db, user.id, cycle_id)
    context = lifecycle_context(db, cycle)
    return templates.TemplateResponse(request=request, name="harvests/phases.html", context={
        "page_title": "Harvest Lifecycle Phases", "current_user": user, "cycle": cycle, "farm": farm,
        **context, "success_message": request.query_params.get("success"),
    })


@router.post("/harvests/{cycle_id}/phases/add")
def add_phase(cycle_id: int, name: str = Form(...), description: str = Form(""),
              start_day: int = Form(...), end_day: int = Form(...),
              user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    cycle, _ = owned_cycle(db, user.id, cycle_id)
    if not name.strip() or start_day < 1 or end_day < start_day or end_day > cycle.harvest_interval_days:
        raise HTTPException(422, "Phase days must be within the harvest cycle")
    order = (db.scalar(select(func.coalesce(func.max(HarvestPhase.phase_order), 0)).where(
        HarvestPhase.harvest_cycle_id == cycle.id)) or 0) + 1
    origin = cycle.previous_harvest_date or (cycle.planned_harvest_date - timedelta(days=cycle.harvest_interval_days))
    start_date, due_date = origin + timedelta(days=start_day), origin + timedelta(days=end_day)
    db.add(HarvestPhase(harvest_cycle_id=cycle.id, owner_id=user.id, phase_order=order,
        name=name.strip(), description=description.strip() or None, start_day=start_day, end_day=end_day,
        start_date=start_date, due_date=due_date, status=phase_status_for_dates(start_date, due_date),
        is_ai_recommended=False))
    db.commit()
    return RedirectResponse(f"/harvests/{cycle.id}/phases?success={quote('Phase added successfully.')}", 303)


@router.post("/harvests/{cycle_id}/phases/{phase_id}/update")
def update_phase(cycle_id: int, phase_id: int, name: str = Form(...), description: str = Form(""),
                 start_day: int = Form(...), end_day: int = Form(...), phase_order: int = Form(...),
                 status: str = Form("UPCOMING"), user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    cycle, _ = owned_cycle(db, user.id, cycle_id)
    phase = owned_phase(db, user.id, cycle_id, phase_id)
    normalized_status = status.upper()
    if (not name.strip() or start_day < 1 or end_day < start_day or end_day > cycle.harvest_interval_days
            or normalized_status not in VALID_PHASE_STATUSES or phase_order < 1):
        raise HTTPException(422, "Invalid phase details")
    duplicate = db.scalar(select(HarvestPhase).where(HarvestPhase.harvest_cycle_id == cycle.id,
        HarvestPhase.phase_order == phase_order, HarvestPhase.id != phase.id))
    if duplicate:
        previous_order = phase.phase_order
        duplicate.phase_order = 1000000 + duplicate.id
        db.flush()
        phase.phase_order = phase_order
        db.flush()
        duplicate.phase_order = previous_order
    origin = cycle.previous_harvest_date or (cycle.planned_harvest_date - timedelta(days=cycle.harvest_interval_days))
    phase.name = name.strip(); phase.description = description.strip() or None
    phase.start_day = start_day; phase.end_day = end_day; phase.phase_order = phase_order
    phase.start_date = origin + timedelta(days=start_day); phase.due_date = origin + timedelta(days=end_day)
    phase.status = normalized_status
    phase.completed_at = datetime.now(timezone.utc) if normalized_status == "COMPLETED" else None
    db.commit()
    return RedirectResponse(f"/harvests/{cycle.id}/phases?success={quote('Phase updated successfully.')}", 303)


@router.post("/harvests/{cycle_id}/phases/{phase_id}/complete")
def complete_phase(cycle_id: int, phase_id: int, user: User = Depends(signed_in_user), db: Session = Depends(get_db)):
    owned_cycle(db, user.id, cycle_id)
    phase = owned_phase(db, user.id, cycle_id, phase_id)
    phase.status = "COMPLETED"; phase.completed_at = datetime.now(timezone.utc)
    db.commit()
    return RedirectResponse(f"/harvests/{cycle_id}/phases?success={quote('Phase marked complete.')}", 303)
