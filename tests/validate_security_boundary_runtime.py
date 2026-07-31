from app.main import csrf_request_allowed, settings


def main() -> None:
    original_environment = settings.app_env
    try:
        settings.app_env = "production"
        assert csrf_request_allowed("GET", "https", "messis.test", {})
        assert csrf_request_allowed(
            "POST",
            "https",
            "messis.test",
            {"origin": "https://messis.test"},
        )
        assert not csrf_request_allowed(
            "POST",
            "https",
            "messis.test",
            {"origin": "https://attacker.test"},
        )
        assert not csrf_request_allowed(
            "POST",
            "https",
            "messis.test",
            {"sec-fetch-site": "cross-site", "x-messis-csrf": "1"},
        )
        assert not csrf_request_allowed("POST", "https", "messis.test", {})
        assert csrf_request_allowed(
            "POST",
            "https",
            "messis.test",
            {"x-messis-csrf": "1"},
        )
    finally:
        settings.app_env = original_environment

    print("PATCH-UAT-FIX-001 CSRF RUNTIME: PASSED")


if __name__ == "__main__":
    main()
