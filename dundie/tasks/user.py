import smtplib
from datetime import timedelta
from time import sleep

from sqlmodel import Session, select

from dundie.auth import create_access_token
from dundie.config import settings
from dundie.db import engine
from dundie.models.user import User


def send_email(email: str, message: str):
    if settings.email.debug_mode is True:
        _send_email_debug(email, message)
    else:
        _send_email_smtp(email, message)



def _send_email_debug(email: str, message: str):
    """Mock email sendig by printing to a file"""
    with open("email.log", "a") as f:
        sleep(3) # pretend it takes 3 seconds
        f.write(f"--- START EMAIL {email} ---\n" f"{message}\n" "--- END OF EMAIL ---")


def _send_email_smtp(email: str, message: str):
    """Connect to SMTP server and send email"""
    with smtplib.SMTP_SSL(
        settings.email.smtp_server, settings.email.smpt_port
    ) as server:
        server.login(settings.email.smtp_user, settings.email.smtp_password)
        server.sendmail(
            settings.email.smtp_sender,
            email,
            message.encode("utf-8"),
        )

MESSAGE = """\
From: Dundie <{sender}>
To: {to}
Subject: Password reset for Dundie

Please use the following link to reset your password:
{url}?pwd_reset_token={pwd_reset_token}

This link will expire in {expire} minutes.
"""
def try_to_send_pwd_reset_email(email):
    """Given an email address sends email if user is found"""
    with Session(engine) as session:
        user = session.exec(select(User).where(User.email == email)).first()
        if not user:
            return

        sender = settings.email.smtp_sender
        url = settings.security.PWD_RESET_URL
        expire = settings.security.RESET_TOKEN_EXPIRE_MINUTES

        pwd_reset_token = create_access_token(
            data={"sub": user.username},
            expires_delta=timedelta(minutes=expire),
            scope="pwd_reset",
        )

        send_email(
            email=user.email,
            message=MESSAGE.format(
                sender=sender,
                to=user.email,
                url=url,
                pwd_reset_token=pwd_reset_token,
                expire=expire,
            ),
        )
