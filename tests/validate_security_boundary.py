import ast
from pathlib import Path


def main() -> None:
    source = Path("app/main.py").read_text(encoding="utf-8")
    config = Path("app/config.py").read_text(encoding="utf-8")
    login = Path("app/templates/auth/login.html").read_text(encoding="utf-8")
    signup = Path("app/templates/auth/set_passcode.html").read_text(encoding="utf-8")

    ast.parse(source)
    ast.parse(config)
    assert "async def enforce_csrf(" in source
    assert 'fetch_site == "cross-site"' in source
    assert 'headers.get("x-messis-csrf") == "1"' in source
    assert "signup_access_code" in config
    assert "signup_max_attempts" in config
    assert "compare_digest(" in source and "settings.signup_access_code" in source
    assert 'name="registration_code"' in signup
    assert 'name="email"' in signup and 'type="email"' in signup
    assert 'href="/auth/forgot-passcode"' in login
    assert 'value="OWNER001"' not in login
    print("PATCH-UAT-FIX-001 SECURITY BOUNDARY SOURCE: PASSED")


if __name__ == "__main__":
    main()
