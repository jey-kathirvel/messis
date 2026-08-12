"""Focused regression tests for the universal farm capability foundation."""
from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path


_DB_FILE = Path(tempfile.gettempdir()) / "messis_capability_foundation_test.db"
os.environ.setdefault("APP_ENV", "test")
os.environ.setdefault("SECRET_KEY", "test-secret-key-with-sufficient-length")
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_DB_FILE.as_posix()}")

from app.agro_framework import (  # noqa: E402
    assign_legacy_farms,
    capabilities_for_type,
    farm_template_context,
    seed_agro_framework,
)
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.farm_capabilities import farm_type_code  # noqa: E402
from app.models import (  # noqa: E402
    Farm,
    FarmOperationalProfile,
    FarmTemplate,
    FarmTemplateAssignment,
    FarmTemplateVersion,
    FarmType,
    User,
)
from app.security import hash_passcode  # noqa: E402


class FarmCapabilityFoundationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)

    def setUp(self):
        self.db = SessionLocal()
        seed_agro_framework(self.db)
        self.user = User(
            user_id="capability-owner",
            display_name="Capability Owner",
            email="capability@example.test",
            passcode_hash=hash_passcode("123456"),
        )
        self.db.add(self.user)
        self.db.commit()
        self.db.refresh(self.user)

    def tearDown(self):
        self.db.rollback()
        for table in reversed(Base.metadata.sorted_tables):
            self.db.execute(table.delete())
        self.db.commit()
        self.db.close()

    def test_capabilities_are_domain_specific(self):
        self.assertIn("legacy_coconut_harvest", capabilities_for_type("coconut"))
        self.assertNotIn("legacy_coconut_harvest", capabilities_for_type("paddy"))
        self.assertIn("herd", capabilities_for_type("dairy"))
        self.assertNotIn("irrigation", capabilities_for_type("dairy"))

    def test_legacy_farm_gets_explicit_coconut_assignment_once(self):
        farm = Farm(owner_id=self.user.id, name="Legacy Farm", acreage="2", total_trees=10)
        self.db.add(farm)
        self.db.commit()

        self.assertEqual(assign_legacy_farms(self.db), 1)
        self.assertEqual(assign_legacy_farms(self.db), 0)
        self.assertEqual(farm_type_code(self.db, farm.id, self.user.id), "coconut")
        self.assertEqual(
            self.db.query(FarmTemplateAssignment).filter_by(farm_id=farm.id).count(),
            1,
        )
        self.assertEqual(
            self.db.query(FarmOperationalProfile).filter_by(farm_id=farm.id).count(),
            1,
        )
        context = farm_template_context(self.db, farm, self.user.id)
        self.assertIn("legacy_coconut_harvest", context["capabilities"])

    def test_dairy_farm_cannot_open_legacy_harvest_route(self):
        from fastapi.testclient import TestClient
        from app.main import app

        dairy_version = self.db.query(FarmTemplateVersion).join(FarmTemplate).join(FarmType).filter(
            FarmType.code == "dairy"
        ).one()
        farm = Farm(owner_id=self.user.id, name="Dairy Farm", acreage="2", total_trees=0)
        self.db.add(farm)
        self.db.flush()
        self.db.add(FarmTemplateAssignment(
            farm_id=farm.id,
            owner_id=self.user.id,
            template_version_id=dairy_version.id,
        ))
        self.db.commit()

        with TestClient(app) as client:
            login = client.post(
                "/auth/login",
                data={"user_id": self.user.user_id, "passcode": "123456"},
                follow_redirects=False,
            )
            self.assertEqual(login.status_code, 303)
            response = client.get(
                f"/farms/{farm.id}/harvests/new",
                follow_redirects=False,
            )
            client.get(f"/farms/{farm.id}", follow_redirects=False)
            global_response = client.get("/harvests/manage", follow_redirects=False)
        self.assertEqual(response.status_code, 303)
        self.assertIn(f"/farms/{farm.id}?error=", response.headers["location"])
        self.assertEqual(global_response.status_code, 303)
        self.assertIn(f"/farms/{farm.id}?error=", global_response.headers["location"])


if __name__ == "__main__":
    unittest.main()
