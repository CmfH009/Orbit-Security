import email
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
from typing import Optional
from dotenv import load_dotenv

load_dotenv()



class EmailDispatcher:
    def __init__(
        self,
        smtp_host: Optional[str] = None,
        smtp_port: Optional[int] = None,
        smtp_user: Optional[str] = None,
        smtp_password: Optional[str] = None,
        sender_name: Optional[str] = None,
    ):
        self.smtp_host = smtp_host or os.getenv("SMTP_HOST")
        self.smtp_port = smtp_port or int(os.getenv("SMTP_PORT", "587"))
        self.smtp_user = smtp_user or os.getenv("SMTP_USER")
        self.smtp_password = smtp_password or os.getenv("SMTP_PASSWORD")
        self.sender_name = sender_name or os.getenv("SENDER_NAME", "Carson @ Orbit Security")

    def is_configured(self) -> bool:
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    def build_message(
        self,
        recipient_email: str,
        subject: str,
        body_text: str,
        pdf_attachment_path: Optional[str] = None,
    ) -> MIMEMultipart:
        msg = MIMEMultipart()
        sender_header = f"{self.sender_name} <{self.smtp_user}>" if self.smtp_user else self.sender_name
        msg["From"] = sender_header
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg["Reply-To"] = self.smtp_user or recipient_email

        # Attach text body
        msg.attach(MIMEText(body_text, "plain", "utf-8"))

        # Attach PDF if present
        if pdf_attachment_path and os.path.exists(pdf_attachment_path):
            with open(pdf_attachment_path, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(pdf_attachment_path))
            part["Content-Disposition"] = f'attachment; filename="{os.path.basename(pdf_attachment_path)}"'
            msg.attach(part)

        return msg

    def export_eml(
        self,
        recipient_email: str,
        subject: str,
        body_text: str,
        pdf_attachment_path: Optional[str],
        output_eml_path: str,
    ) -> str:
        """Exports a standard .eml draft file that opens natively in any desktop mail client (Outlook, Mail, etc.)."""
        msg = self.build_message(recipient_email, subject, body_text, pdf_attachment_path)
        os.makedirs(os.path.dirname(os.path.abspath(output_eml_path)), exist_ok=True)
        with open(output_eml_path, "wb") as f:
            f.write(msg.as_bytes())
        return output_eml_path

    def send_email(
        self,
        recipient_email: str,
        subject: str,
        body_text: str,
        pdf_attachment_path: Optional[str] = None,
    ) -> bool:
        if not self.is_configured():
            raise ValueError(
                "SMTP is not configured. Please set SMTP_HOST, SMTP_USER, and SMTP_PASSWORD in your environment or .env file."
            )

        msg = self.build_message(recipient_email, subject, body_text, pdf_attachment_path)

        with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
            server.starttls()
            server.login(self.smtp_user, self.smtp_password)
            server.send_message(msg)

        return True
