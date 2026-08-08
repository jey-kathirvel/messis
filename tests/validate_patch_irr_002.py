from pathlib import Path
from app.database import Base
from app.main import app

required_tables={"irrigation_zones","water_sources"}
missing_tables=required_tables-set(Base.metadata.tables)
assert not missing_tables, f"Missing tables: {sorted(missing_tables)}"
paths={getattr(route,"path",None) for route in app.routes}
required_paths={"/irrigation","/irrigation/zones","/irrigation/zones/new","/irrigation/zones/{zone_id}/edit","/irrigation/zones/{zone_id}/delete","/irrigation/water-sources","/irrigation/water-sources/new","/irrigation/water-sources/{source_id}/edit","/irrigation/water-sources/{source_id}/delete"}
missing_paths=required_paths-paths
assert not missing_paths, f"Missing routes: {sorted(missing_paths)}"
base=Path(__file__).resolve().parents[1]
for relative in ["app/irrigation_management.py","app/static/css/irrigation.css","app/templates/irrigation/dashboard.html","app/templates/irrigation/zones_list.html","app/templates/irrigation/zone_form.html","app/templates/irrigation/sources_list.html","app/templates/irrigation/source_form.html"]:
    assert (base/relative).is_file(), f"Missing file: {relative}"
print("PATCH-IRR-002 IRRIGATION ZONES AND WATER SOURCES CRUD: PASSED")
