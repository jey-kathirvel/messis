import ast
from pathlib import Path


def main() -> None:
    main_source = Path("app/main.py").read_text(encoding="utf-8")
    models = Path("app/models.py").read_text(encoding="utf-8")
    config = Path("app/config.py").read_text(encoding="utf-8")
    mailer = Path("app/email_service.py").read_text(encoding="utf-8")
    signup = Path("app/templates/auth/set_passcode.html").read_text(encoding="utf-8")
    login = Path("app/templates/auth/login.html").read_text(encoding="utf-8")
    forgot = Path("app/templates/auth/forgot_passcode.html").read_text(encoding="utf-8")
    reset = Path("app/templates/auth/reset_passcode.html").read_text(encoding="utf-8")
    recovery_email = Path("app/templates/auth/recovery_email.html").read_text(encoding="utf-8")

    for source in (main_source, models, config, mailer):
        ast.parse(source)

    assert "email: Mapped[str | None]" in models
    assert "class PasscodeResetToken" in models
    assert "token_hash" in models and "expires_at" in models and "used_at" in models
    assert 'name="email" type="email"' in signup
    assert 'href="/auth/forgot-passcode"' in login
    assert '@app.post("/auth/forgot-passcode"' in main_source
    assert '@app.post("/auth/reset-passcode"' in main_source
    assert "hashlib.sha256" in main_source
    assert "secrets.token_urlsafe(32)" in main_source
    assert "PasscodeResetToken.used_at.is_(None)" in main_source
    assert "user.passcode_hash = hash_passcode(new_passcode)" in main_source
    assert "user.failed_attempts = 0" in main_source
    assert "user.locked_until = None" in main_source
    assert "db.delete(user)" not in main_source
    assert "secure link" in forgot.lower()
    assert "remain unchanged" in reset.lower()
    assert "smtplib.SMTP" in mailer and "starttls" in mailer
    assert "public_base_url" in config and "passcode_reset_minutes" in config
    assert '@app.post("/account/recovery-email"' in main_source
    assert "if not user.email:" in main_source
    assert "recovery-email?next=" in main_source
    assert "Save and continue" in recovery_email
    assert "all existing records remain unchanged" in recovery_email
    print("PASSCODE RECOVERY SOURCE VALIDATION: PASSED")


if __name__ == "__main__":
    main()
