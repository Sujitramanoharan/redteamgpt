"""Transactional email over SMTP.

Works with any provider that offers SMTP (Resend, Brevo, SendGrid, Postmark,
SES). Without SMTP_HOST - development and tests - the message is logged
instead, so sign-up and password reset can be exercised locally by copying the
link from the console.
"""
import logging
import smtplib
import ssl
from email.message import EmailMessage

from config import settings

logger = logging.getLogger("redteamgpt.email")

# Tests read what would have been sent from here.
outbox: list[dict] = []


def send(to: str, subject: str, body: str) -> None:
    outbox.append({"to": to, "subject": subject, "body": body})
    del outbox[:-50]

    if not settings.email_configured:
        logger.warning("Email not configured - would send to %s: %s\n%s", to, subject, body)
        return

    msg = EmailMessage()
    msg["From"] = settings.smtp_from
    msg["To"] = to
    msg["Subject"] = subject
    msg.set_content(body)

    try:
        if settings.smtp_port == 465:
            server = smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port,
                                      context=ssl.create_default_context(), timeout=15)
        else:
            server = smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15)
            if settings.smtp_starttls:
                server.starttls(context=ssl.create_default_context())
        with server:
            if settings.smtp_username:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
        logger.info("Sent '%s' email", subject)
    except (smtplib.SMTPException, OSError):
        # Runs as a background task after the response; the user sees a
        # generic "check your email" either way, so log loudly for the operator.
        logger.exception("Failed to send '%s' email", subject)


def _link(path: str, token: str) -> str:
    return f"{settings.app_base_url.rstrip('/')}{path}?token={token}"


def verification(to: str, token: str) -> None:
    send(to, "Confirm your RedTeamGPT account",
         "Welcome to RedTeamGPT.\n\n"
         f"Confirm your email address to finish creating your account:\n{_link('/verify-email', token)}\n\n"
         "This link expires in 24 hours. If you did not sign up, ignore this email.")


def password_reset(to: str, token: str) -> None:
    send(to, "Reset your RedTeamGPT password",
         "Someone asked to reset the password for this email address.\n\n"
         f"Choose a new password here:\n{_link('/reset-password', token)}\n\n"
         "This link expires in 1 hour. If it wasn't you, ignore this email; "
         "your password has not changed.")


def invitation(to: str, token: str, org_name: str, inviter: str) -> None:
    send(to, f"You've been invited to {org_name} on RedTeamGPT",
         f"{inviter} invited you to join {org_name} on RedTeamGPT, an AI "
         "prompt-injection firewall.\n\n"
         f"Accept the invitation and set your password:\n{_link('/invite', token)}\n\n"
         "This link expires in 7 days.")
