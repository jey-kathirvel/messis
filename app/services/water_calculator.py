from dataclasses import dataclass
from decimal import Decimal, ROUND_HALF_UP

SOIL_FACTORS={"sandy":Decimal("1.15"),"clay":Decimal("0.90"),"loamy":Decimal("1.00"),"red":Decimal("1.05"),"black":Decimal("0.95"),"other":Decimal("1.00")}
METHOD_EFFICIENCY={"drip":Decimal("0.90"),"micro_sprinkler":Decimal("0.85"),"sprinkler":Decimal("0.75"),"furrow":Decimal("0.65"),"flood":Decimal("0.55"),"manual_hose":Decimal("0.70"),"rain_fed":Decimal("1.00"),"other":Decimal("0.70")}

def q(v): return Decimal(v).quantize(Decimal("0.01"),rounding=ROUND_HALF_UP)
@dataclass(frozen=True)
class WaterResult:
 base_water_litres:Decimal; soil_factor:Decimal; irrigation_efficiency:Decimal; weather_adjustment_percent:Decimal; effective_rain_litres:Decimal; final_water_litres:Decimal; water_saved_litres:Decimal; estimated_runtime_minutes:int|None; estimated_operating_cost:Decimal|None; recommendation:str; reason:str

def calculate_water(*,plant_count:int,litres_per_plant:Decimal,soil_type:str|None,irrigation_method:str,pump_flow_lpm:Decimal|None,pump_cost_per_hour:Decimal|None,temperature_c:Decimal|None=None,humidity_percent:Decimal|None=None,rain_probability_percent:Decimal|None=None,expected_rain_mm:Decimal|None=None,area_value:Decimal|None=None):
 if plant_count<=0: raise ValueError("Plant count must be greater than zero.")
 if litres_per_plant<=0: raise ValueError("Litres per plant must be greater than zero.")
 base=q(Decimal(plant_count)*litres_per_plant)
 soil=SOIL_FACTORS.get((soil_type or "other").lower(),Decimal("1.00")); efficiency=METHOD_EFFICIENCY.get(irrigation_method,Decimal("0.70"))
 adjusted=base*soil/efficiency; weather=Decimal("0"); reasons=[]
 if temperature_c is not None and temperature_c>=Decimal("36"): weather+=Decimal("10"); reasons.append("high temperature")
 elif temperature_c is not None and temperature_c<=Decimal("24"): weather-=Decimal("5"); reasons.append("cool temperature")
 if humidity_percent is not None and humidity_percent>=Decimal("80"): weather-=Decimal("10"); reasons.append("high humidity")
 if rain_probability_percent is not None and rain_probability_percent>=Decimal("70"): weather-=Decimal("30"); reasons.append("high rain probability")
 elif rain_probability_percent is not None and rain_probability_percent>=Decimal("40"): weather-=Decimal("15"); reasons.append("possible rain")
 rain_litres=Decimal("0")
 if expected_rain_mm and expected_rain_mm>0 and area_value and area_value>0:
  rain_litres=expected_rain_mm*area_value*Decimal("4046.8564224")*Decimal("0.70")
 weathered=adjusted*(Decimal("1")+weather/Decimal("100")); final=max(Decimal("0"),weathered-rain_litres); saved=max(Decimal("0"),adjusted-final)
 if rain_probability_percent is not None and rain_probability_percent>=Decimal("70"): rec="delay_irrigation"
 elif weather<=Decimal("-15"): rec="reduce_water"
 elif weather>=Decimal("10"): rec="increase_water"
 else: rec="proceed"
 runtime=None; cost=None
 if pump_flow_lpm and pump_flow_lpm>0:
  runtime=max(1,int((final/pump_flow_lpm).to_integral_value(rounding=ROUND_HALF_UP))) if final>0 else 0
  if pump_cost_per_hour is not None: cost=q(Decimal(runtime)/Decimal("60")*pump_cost_per_hour)
 reason=(", ".join(reasons).capitalize()+".") if reasons else "Standard crop, soil and irrigation efficiency calculation."
 return WaterResult(q(base),soil,efficiency,q(weather),q(rain_litres),q(final),q(saved),runtime,cost,rec,reason)
