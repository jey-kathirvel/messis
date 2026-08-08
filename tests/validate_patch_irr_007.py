"""PATCH-IRR-007 routes, templates, safety, approval and stock lifecycle."""
from datetime import date
from decimal import Decimal
from pathlib import Path

from jinja2 import Environment
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from starlette.requests import Request

from app.database import Base
from app.irrigation_management import (fertigation_complete, fertigation_decision, fertigation_item_add,
    fertigation_plan_create, fertigation_submit, fertilizer_create)
from app.main import app
from app.models import (AuditLog, Farm, FertigationPlan, FertigationPlanItem, FertilizerProduct,
    FertilizerStockMovement, IrrigationZone, User)


root=Path(__file__).resolve().parents[1]
for relative in ("fertigation_dashboard.html","fertilizer_list.html","fertilizer_form.html","fertigation_plan_form.html","fertigation_plan_detail.html","fertigation_report.html"):
    path=root/"app/templates/irrigation"/relative; assert path.is_file(),relative; Environment().parse(path.read_text(encoding="utf-8"))
paths={getattr(route,"path",None) for route in app.routes}
required={"/irrigation/fertigation","/irrigation/fertilizers","/irrigation/fertilizers/new","/irrigation/fertigation/plans/new",
    "/irrigation/fertigation/plans/{plan_id}","/irrigation/fertigation/plans/{plan_id}/items",
    "/irrigation/fertigation/plans/{plan_id}/submit","/irrigation/fertigation/plans/{plan_id}/decision",
    "/irrigation/fertigation/plans/{plan_id}/complete","/irrigation/fertigation/report"}
assert not(required-paths),sorted(required-paths)
assert "fertilizer_stock_movements" in Base.metadata.tables
for name in ("status","approval_notes","completed_at","worker_remarks","stock_deducted"):
    assert name in Base.metadata.tables["fertigation_plans"].columns

engine=create_engine("sqlite+pysqlite:///:memory:"); Base.metadata.create_all(engine)
with Session(engine) as db:
    user=User(user_id="irr007",display_name="Owner",passcode_hash="x"); db.add(user); db.flush()
    farm=Farm(owner_id=user.id,name="Farm"); db.add(farm); db.flush()
    zone=IrrigationZone(owner_id=user.id,farm_id=farm.id,name="Zone",irrigation_method="drip"); db.add(zone); db.commit()
    request=Request({"type":"http","method":"POST","path":"/test","headers":[],"client":("127.0.0.1",1)})
    fertilizer_create(request,"NPK 19-19-19","npk","Maker","kg","10","2",(date.today()).isoformat(),"Compatible","Use PPE","on",user,db)
    product=db.query(FertilizerProduct).one(); assert product.stock_quantity==Decimal("10")
    fertigation_plan_create(request,farm.id,zone.id,"","August NPK",date.today().isoformat(),"fruiting","2000","1000","10","30","10","AGR-1","Kumar","Wear PPE",user,db)
    plan=db.query(FertigationPlan).one(); assert plan.number_of_batches==2
    fertigation_item_add(plan.id,request,product.id,"4","1","Dissolve fully",user,db)
    item=db.query(FertigationPlanItem).one(); assert item.quantity_per_batch==Decimal("2")
    fertigation_submit(plan.id,request,user,db); assert plan.approval_status=="pending"
    fertigation_decision(plan.id,request,"approved","Recipe checked",user,db); assert plan.approval_status=="approved"
    fertigation_complete(plan.id,request,"Applied successfully",user,db)
    assert plan.status=="completed" and plan.stock_deducted and product.stock_quantity==Decimal("6")
    movement=db.query(FertilizerStockMovement).filter_by(movement_type="fertigation_consumption").one()
    assert movement.quantity_change==Decimal("-4") and movement.balance_after==Decimal("6")
    assert db.query(AuditLog).filter_by(owner_id=user.id).count()==6

print("PATCH-IRR-007 FERTIGATION MANAGEMENT: PASSED")
