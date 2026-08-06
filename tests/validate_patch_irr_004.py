from decimal import Decimal
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from app.database import Base
from app.models import User,Farm,IrrigationZone,IrrigationPump,WaterRequirementCalculation
from app.services.water_calculator import calculate_water
engine=create_engine("sqlite+pysqlite:///:memory:"); Base.metadata.create_all(engine)
assert "water_requirement_calculations" in Base.metadata.tables
r=calculate_water(plant_count=100,litres_per_plant=Decimal("50"),soil_type="loamy",irrigation_method="drip",pump_flow_lpm=Decimal("100"),pump_cost_per_hour=Decimal("60"),temperature_c=Decimal("38"),humidity_percent=Decimal("60"),rain_probability_percent=Decimal("10"),expected_rain_mm=Decimal("0"),area_value=Decimal("1"))
assert r.final_water_litres>0 and r.estimated_runtime_minutes>0 and r.recommendation=="increase_water"
with Session(engine) as db:
 u=User(user_id="irr004",display_name="Owner",passcode_hash="x"); db.add(u); db.flush(); f=Farm(owner_id=u.id,name="Farm"); db.add(f); db.flush(); z=IrrigationZone(owner_id=u.id,farm_id=f.id,name="Zone",plant_count=100,irrigation_method="drip"); db.add(z); db.flush(); row=WaterRequirementCalculation(owner_id=u.id,farm_id=f.id,zone_id=z.id,plant_count=100,base_litres_per_plant=Decimal("50"),base_water_litres=r.base_water_litres,soil_factor=r.soil_factor,irrigation_efficiency=r.irrigation_efficiency,weather_adjustment_percent=r.weather_adjustment_percent,effective_rain_litres=r.effective_rain_litres,final_water_litres=r.final_water_litres,water_saved_litres=r.water_saved_litres,recommendation=r.recommendation); db.add(row); db.commit(); assert db.query(WaterRequirementCalculation).count()==1
print("PATCH-IRR-004 SMART WATER REQUIREMENT CALCULATOR: PASSED")
