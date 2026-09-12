import os
import time
import secrets
import logging
import smtplib
from typing import Dict, Any, Tuple, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from src.db.repository import OTPRepository

logger = logging.getLogger("sre_copilot.otp")

class OTPService:
    """
    Manages generation, delivery, rate limiting, and verification of 
    6-digit One-Time Passwords (OTPs) for members and platform administrators.
    Backed by persistent database storage to guarantee consistency across multi-worker deployments.
    """

    @classmethod
    def generate_otp(cls, email: str, purpose: str = "member_login") -> Tuple[str, bool, str]:
        """
        Generates a secure 6-digit code for the specified email.
        Returns: (otp_code, email_sent_via_smtp, message)
        """
        email = email.strip().lower()
        now = time.time()

        # Rate limiting: minimum 10 seconds between OTP requests for the same email
        existing = OTPRepository.get_otp(email)
        if existing:
            last_sent = existing.get("created_at", 0)
            if now - last_sent < 10:
                remaining = int(10 - (now - last_sent))
                return "", False, f"Please wait {remaining} seconds before requesting a new code."

        # Generate cryptographically secure 6-digit code (100000 - 999999)
        code = str(secrets.randbelow(900000) + 100000)

        # 10 minutes lifetime, persisted across all workers in database
        OTPRepository.save_otp(
            email=email,
            code=code,
            purpose=purpose,
            expires_at=now + 600
        )

        logger.info(f"[AUTH OTP] Generated verification code for {email} (purpose: {purpose})")

        # Attempt to send via SMTP if configured
        sent_via_smtp = cls._send_smtp_email(email, code, purpose)

        if sent_via_smtp:
            msg = "Verification code has been dispatched to your email address."
        else:
            expose_dev = os.getenv("EXPOSE_DEV_OTP", "false").lower() in ["true", "1", "yes"]
            if expose_dev:
                msg = f"Verification code generated (Code: {code}). Configure SMTP in .env for inbox delivery."
            else:
                msg = "Verification code generated. If email delivery is not configured, please check server logs."

        return code, sent_via_smtp, msg

    @classmethod
    def verify_otp(cls, email: str, code: str, purpose: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validates the submitted OTP against database storage.
        Returns: (success, error_or_success_message)
        """
        email = email.strip().lower()
        code = (code or "").strip()

        if not email or not code:
            return False, "Email and 6-digit verification code are required."

        record = OTPRepository.get_otp(email)
        if not record:
            return False, "No active verification code found for this email. Please request a new code."

        now = time.time()
        if now > record["expires_at"]:
            OTPRepository.delete_otp(email)
            return False, "Verification code has expired. Please request a new code."

        if purpose and record.get("purpose") != purpose:
            return False, "Code was generated for a different authentication context."

        attempts = OTPRepository.increment_attempts(email)
        if attempts > 5:
            OTPRepository.delete_otp(email)
            return False, "Too many failed attempts. This verification code has been revoked."

        if not secrets.compare_digest(record["code"], code):
            remaining = max(0, 5 - attempts)
            return False, f"Invalid verification code. {remaining} attempt(s) remaining."

        # Code matched! Consume and delete
        OTPRepository.delete_otp(email)
        return True, "Verification successful."

    @classmethod
    def _send_smtp_email(cls, recipient: str, code: str, purpose: str) -> bool:
        """
        Sends an HTML email with the 6-digit OTP code using SMTP credentials if available.
        """
        smtp_user = os.getenv("SMTP_USER", "").strip()
        smtp_pass = os.getenv("SMTP_PASSWORD", "").strip()

        # Fallback: scan /etc/secrets directory if on Render and not yet in environment
        if not smtp_user or not smtp_pass:
            if os.path.isdir("/etc/secrets"):
                from dotenv import load_dotenv
                try:
                    for fname in os.listdir("/etc/secrets"):
                        fpath = os.path.join("/etc/secrets", fname)
                        if os.path.isfile(fpath):
                            load_dotenv(fpath, override=True)
                except Exception as e:
                    logger.warning(f"Error reading /etc/secrets: {e}")
                smtp_user = os.getenv("SMTP_USER", "").strip().strip("'\"")
        smtp_pass = os.getenv("SMTP_PASSWORD", "").strip().strip("'\"").replace(" ", "")
        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com").strip().strip("'\"")
        try:
            smtp_port = int(str(os.getenv("SMTP_PORT", "587")).strip().strip("'\""))
        except Exception:
            smtp_port = 587

        if not smtp_user or not smtp_pass:
            logger.info(f"[AUTH OTP] SMTP not configured (SMTP_USER: {'set' if smtp_user else 'missing'}, SMTP_PASSWORD: {'set' if smtp_pass else 'missing'}). Generated verification code for {recipient}: {code}")
            return False

        try:
            subject_title = "Admin Console Access" if purpose == "admin_login" else "Account Verification"
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{subject_title}] Your Verification Code: {code}"
            msg["From"] = f"SRE Incident Copilot <{smtp_user}>"
            msg["To"] = recipient

            text_body = f"Your verification code for SRE Incident Copilot is: {code}\nThis code will expire in 10 minutes.\nIf you did not request this, please ignore."
            html_body = f"""
            <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 480px; margin: 0 auto; padding: 24px; border: 1px solid #e2e8f0; border-radius: 8px; background: #ffffff;">
                <h2 style="color: #000000; font-size: 20px; font-weight: 800; margin-top: 0;">SRE Incident Copilot</h2>
                <p style="color: #4a5568; font-size: 14px;">Use the following verification code to access your account:</p>
                <div style="background: #000000; color: #ffffff; font-family: monospace; font-size: 28px; font-weight: 700; letter-spacing: 6px; text-align: center; padding: 16px; border-radius: 6px; margin: 20px 0;">
                    {code}
                </div>
                <p style="color: #718096; font-size: 12px; margin-bottom: 0;">This code will expire in 10 minutes. If you did not request this, no action is needed.</p>
            </div>
            """

            msg.attach(MIMEText(text_body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            # 1. Primary Cloud Dispatch: Resend HTTPS API (Port 443 - never blocked by Render)
            resend_key = os.getenv("RESEND_API_KEY", "").strip()
            if resend_key:
                try:
                    import httpx
                    from_email = os.getenv("RESEND_FROM_EMAIL", "SRE Copilot <onboarding@resend.dev>").strip()
                    res = httpx.post(
                        "https://api.resend.com/emails",
                        headers={
                            "Authorization": f"Bearer {resend_key}",
                            "Content-Type": "application/json"
                        },
                        json={
                            "from": from_email,
                            "to": [recipient],
                            "subject": f"[{subject_title}] Your Verification Code: {code}",
                            "html": html_body,
                            "text": text_body
                        },
                        timeout=10.0
                    )
                    if res.status_code in [200, 201]:
                        logger.info(f"[AUTH OTP] Email dispatched successfully to {recipient} via Resend HTTPS API")
                        return True
                    else:
                        logger.error(f"[AUTH OTP] Resend API returned {res.status_code}: {res.text}")
                except Exception as resend_err:
                    logger.error(f"[AUTH OTP] Resend HTTP dispatch failed: {resend_err}")

            # 2. Secondary Cloud Dispatch: Brevo HTTPS API (Port 443 - never blocked by Render)
            brevo_key = os.getenv("BREVO_API_KEY", "").strip()
            if brevo_key:
                try:
                    import httpx
                    sender_email = smtp_user or os.getenv("BREVO_SENDER_EMAIL", "notifications@sre-copilot.internal")
                    res = httpx.post(
                        "https://api.brevo.com/v3/smtp/email",
                        headers={
                            "api-key": brevo_key,
                            "Content-Type": "application/json"
                        },
                        json={
                            "sender": {"name": "SRE Incident Copilot", "email": sender_email},
                            "to": [{"email": recipient}],
                            "subject": f"[{subject_title}] Your Verification Code: {code}",
                            "htmlContent": html_body,
                            "textContent": text_body
                        },
                        timeout=10.0
                    )
                    if res.status_code in [200, 201]:
                        logger.info(f"[AUTH OTP] Email dispatched successfully to {recipient} via Brevo HTTPS API")
                        return True
                    else:
                        logger.error(f"[AUTH OTP] Brevo API returned {res.status_code}: {res.text}")
                except Exception as brevo_err:
                    logger.error(f"[AUTH OTP] Brevo HTTP dispatch failed: {brevo_err}")

            # 3. Direct SMTP (Fallback for hosts that do not block ports 587/465)
            if smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=12) as server:
                    server.login(smtp_user, smtp_pass)
                    server.sendmail(smtp_user, [recipient], msg.as_string())
            else:
                try:
                    with smtplib.SMTP(smtp_host, smtp_port, timeout=12) as server:
                        server.ehlo()
                        server.starttls()
                        server.ehlo()
                        server.login(smtp_user, smtp_pass)
                        server.sendmail(smtp_user, [recipient], msg.as_string())
                except Exception as tls_err:
                    logger.warning(f"[AUTH OTP] STARTTLS failed ({tls_err}), attempting SSL on port 465 fallback...")
                    with smtplib.SMTP_SSL(smtp_host, 465, timeout=12) as server:
                        server.login(smtp_user, smtp_pass)
                        server.sendmail(smtp_user, [recipient], msg.as_string())

            logger.info(f"[AUTH OTP] Real email dispatched successfully to {recipient} via {smtp_host}")
            return True
        except Exception as e:
            logger.error(f"[AUTH OTP] Failed to send email via SMTP: {e}", exc_info=True)
            return False
