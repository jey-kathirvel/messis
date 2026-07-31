from __future__ import annotations

import importlib
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path


REQUIRED_PACKAGES = {
    "fastapi": "0.116.1",
    "uvicorn": "0.35.0",
    "Jinja2": "3.1.6",
    "httpx": "0.28.1",
    "SQLAlchemy": "2.0.43",
    "psycopg": "3.2.9",
    "pydantic": "2.13.4",
    "pydantic-settings": "2.10.1",
    "argon2-cffi": "25.1.0",
    "python-multipart": "0.0.20",
    "qrcode": "8.2",
    "pillow": "12.3.0",
    "itsdangerous": "2.2.0",
    "python-dotenv": "1.1.1",
}

REQUIRED_IMPORTS = (
    "fastapi",
    "uvicorn",
    "jinja2",
    "httpx",
    "sqlalchemy",
    "psycopg",
    "pydantic",
    "pydantic_settings",
    "argon2",
    "multipart",
    "qrcode",
    "PIL",
    "itsdangerous",
    "dotenv",
)


def requirement_lines() -> set[str]:
    lines = set()
    for raw_line in Path("requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            lines.add(line.lower())
    return lines


def main() -> None:
    declared = requirement_lines()
    failures = []

    for package, expected_version in REQUIRED_PACKAGES.items():
        normalized = package.lower()
        if package == "psycopg":
            declaration_present = f"psycopg[binary]=={expected_version}" in declared
        elif package == "uvicorn":
            declaration_present = f"uvicorn[standard]=={expected_version}" in declared
        else:
            declaration_present = f"{normalized}=={expected_version}" in declared

        if not declaration_present:
            failures.append(f"missing requirement pin: {package}=={expected_version}")

        try:
            installed_version = version(package)
        except PackageNotFoundError:
            failures.append(f"package not installed: {package}")
        else:
            if installed_version != expected_version:
                failures.append(
                    f"version mismatch: {package} expected={expected_version} "
                    f"actual={installed_version}"
                )

    for module in REQUIRED_IMPORTS:
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures.append(f"import failed: {module}: {exc}")

    if failures:
        raise SystemExit("DEPENDENCY VALIDATION FAILED\n" + "\n".join(failures))

    print(f"DEPENDENCY PINS VALIDATED={len(REQUIRED_PACKAGES)}")
    print(f"DEPENDENCY IMPORTS VALIDATED={len(REQUIRED_IMPORTS)}")
    print("PATCH-UAT-FIX-002 DEPENDENCIES: PASSED")


if __name__ == "__main__":
    main()
