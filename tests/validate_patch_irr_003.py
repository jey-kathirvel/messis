from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import Farm, User, IrrigationPump, IrrigationEquipment, PumpMaintenanceRecord, PumpRuntimeLog

engine=create_engine("sqlite+pysqlite:///:memory:")
Base.metadata.create_all(engine)
required={"irrigation_pumps","irrigation_equipment","pump_maintenance_records","pump_runtime_logs"}
assert required.issubset(Base.metadata.tables)
with Session(engine) as db:
 u=User(user_id="irr003",display_name="Owner",passcode_hash="x"); db.add(u); db.flush()
 f=Farm(owner_id=u.id,name="Farm"); db.add(f); db.flush()
 p=IrrigationPump(owner_id=u.id,farm_id=f.id,name="Main Pump",status="available"); db.add(p); db.flush()
 e=IrrigationEquipment(owner_id=u.id,farm_id=f.id,pump_id=p.id,name="Filter",equipment_type="filter"); db.add(e)
 db.commit()
 assert db.query(IrrigationPump).count()==1 and db.query(IrrigationEquipment).count()==1
print("PATCH-IRR-003 PUMPS AND IRRIGATION EQUIPMENT MANAGEMENT: PASSED")
