"""Farm capability resolution and HTTP boundary enforcement."""
from __future__ import annotations

import re

from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select

from app.agro_framework import capabilities_for_type
from app.database import SessionLocal
from app.models import Farm, FarmTemplate, FarmTemplateAssignment, FarmTemplateVersion, FarmType


FARM_ROUTE = re.compile(r"^/farms/(?P<farm_id>\d+)(?P<suffix>/.*)?$")
RESTRICTED_SUFFIXES = (
    (re.compile(r"^/(?:harvests|harvest-records)(?:/|$)"), "legacy_coconut_harvest"),
    (re.compile(r"^/trees(?:/|$)"), "perennial_assets"),
)
GLOBAL_ROUTE_CAPABILITIES = (
    (re.compile(r"^/(?:harvests|harvest-records)(?:/|$)"), "legacy_coconut_harvest"),
    (re.compile(r"^/irrigation(?:/|$)"), "irrigation"),
)


def farm_type_code(db, farm_id: int, owner_id: int) -> str | None:
    """Resolve a farm type while preserving Coconut compatibility for legacy farms."""
    farm = db.scalar(select(Farm).where(Farm.id == farm_id, Farm.owner_id == owner_id))
    if not farm:
        return None
    code = db.scalar(
        select(FarmType.code)
        .join(FarmTemplate, FarmTemplate.farm_type_id == FarmType.id)
        .join(FarmTemplateVersion, FarmTemplateVersion.template_id == FarmTemplate.id)
        .join(
            FarmTemplateAssignment,
            FarmTemplateAssignment.template_version_id == FarmTemplateVersion.id,
        )
        .where(
            FarmTemplateAssignment.farm_id == farm_id,
            FarmTemplateAssignment.owner_id == owner_id,
        )
    )
    return code or "coconut"


class FarmCapabilityMiddleware:
    """Block incompatible farm-scoped routes even when users enter URLs directly."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        match = FARM_ROUTE.match(scope.get("path", ""))
        path = scope.get("path", "")
        required = None
        if match:
            suffix = match.group("suffix") or ""
            required = next(
                (capability for pattern, capability in RESTRICTED_SUFFIXES if pattern.match(suffix)),
                None,
            )
        else:
            required = next(
                (capability for pattern, capability in GLOBAL_ROUTE_CAPABILITIES if pattern.match(path)),
                None,
            )

        if not match and not required:
            await self.app(scope, receive, send)
            return

        session = scope.get("session") or {}
        owner_id = session.get("user_id")
        if not isinstance(owner_id, int):
            await self.app(scope, receive, send)
            return

        farm_id = int(match.group("farm_id")) if match else session.get("active_farm_id")
        if not isinstance(farm_id, int):
            # Portfolio-wide pages remain available until a farm is selected.
            await self.app(scope, receive, send)
            return
        with SessionLocal() as db:
            code = farm_type_code(db, farm_id, owner_id)
        if code is None:
            await self.app(scope, receive, send)
            return
        if match:
            session["active_farm_id"] = farm_id
        if not required:
            await self.app(scope, receive, send)
            return
        if required in capabilities_for_type(code):
            await self.app(scope, receive, send)
            return

        if scope.get("path", "").startswith("/api/"):
            response = JSONResponse(
                {"detail": f"This farm does not support the {required} capability."},
                status_code=403,
            )
        else:
            response = RedirectResponse(
                f"/farms/{farm_id}?error=That+module+is+not+available+for+this+farm+type",
                status_code=303,
            )
        await response(scope, receive, send)
