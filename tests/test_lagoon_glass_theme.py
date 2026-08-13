"""Static regression checks for the Lagoon Glass theme rollout."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]
THEME = ROOT / "app" / "static" / "css" / "lagoon-glass.css"
TEMPLATES = (
    "app/templates/base.html",
    "app/templates/dashboard/business.html",
    "app/templates/farms/detail.html",
    "app/templates/farms/list.html",
    "app/templates/setup/wizard.html",
    "app/templates/auth/login.html",
    "app/templates/auth/forgot_passcode.html",
    "app/templates/auth/reset_passcode.html",
    "app/templates/auth/set_passcode.html",
)


class LagoonGlassThemeTests(unittest.TestCase):
    def test_lagoon_theme_defines_core_system(self):
        css = THEME.read_text(encoding="utf-8")
        for token in (
            "--lagoon-canvas",
            "--lagoon-glass",
            "--lagoon-mint",
            "--lagoon-blue",
            "--lagoon-gold",
            "backdrop-filter",
            "prefers-reduced-transparency",
        ):
            self.assertIn(token, css)

    def test_lagoon_theme_loads_after_agricultural_theme(self):
        for relative_path in TEMPLATES:
            with self.subTest(template=relative_path):
                source = (ROOT / relative_path).read_text(encoding="utf-8")
                agricultural = source.index("agri-theme.css")
                lagoon = source.index("lagoon-glass.css")
                self.assertGreater(lagoon, agricultural)


if __name__ == "__main__":
    unittest.main()
