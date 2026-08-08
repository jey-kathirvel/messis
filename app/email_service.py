import smtplib
import ssl
from email.message import EmailMessage

from app.config import Settings


def send_passcode_reset_email(
    settings: Settings,
    recipient: str,
    reset_url: str,
) -> None:
    if not settings.smtp_host or not settings.smtp_from_email:
        raise RuntimeError("Email delivery is not configured")

    message = EmailMessage()
    message["Subject"] = "Reset your Messis AI passcode"
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message.set_content(
        "A request was received to reset your Messis AI passcode.\n\n"
        f"Set a new passcode: {reset_url}\n\n"
        f"This secure link expires in {settings.passcode_reset_minutes} minutes "
        "and can be used only once. If you did not request this change, you can "
        "ignore this email; your current passcode remains unchanged."
    )

    smtp_class = smtplib.SMTP_SSL if settings.smtp_use_ssl else smtplib.SMTP
    smtp_kwargs = {"timeout": 20}
    if settings.smtp_use_ssl:
        smtp_kwargs["context"] = ssl.create_default_context()
    with smtp_class(settings.smtp_host, settings.smtp_port, **smtp_kwargs) as client:
        if settings.smtp_use_tls and not settings.smtp_use_ssl:
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password)
        client.send_message(message)
