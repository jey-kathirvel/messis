"""Create a PostgreSQL safety backup for the application-wide UX rollout."""
from pathlib import Path
import shutil
import subprocess
import sys
from app.config import get_settings


def main() -> None:
    if len(sys.argv) != 2: raise SystemExit("usage: backup_messis_ux_glass_001.py OUTPUT.dump")
    pg_dump = shutil.which("pg_dump")
    if not pg_dump: raise SystemExit("pg_dump is required before UX deployment")
    output = Path(sys.argv[1]).resolve(); output.parent.mkdir(parents=True, exist_ok=True)
    database_url = get_settings().database_url.replace("postgresql+psycopg2://", "postgresql://", 1).replace("postgresql+psycopg://", "postgresql://", 1)
    subprocess.run([pg_dump, "--format=custom", "--file", str(output), database_url], check=True, stdout=subprocess.DEVNULL)
    if not output.is_file() or output.stat().st_size == 0: raise SystemExit("database backup was not created")
    print(f"database backup created: {output} ({output.stat().st_size} bytes)")


if __name__ == "__main__": main()
