import os
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from orbit_security.mailer import EmailDispatcher


def test_build_message_with_attachment():
    dispatcher = EmailDispatcher(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="auditor@myagency.com",
        smtp_password="testpassword",
        sender_name="Security Operations"
    )

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
        tmp_pdf.write(b"%PDF-1.4 test dummy pdf content")
        pdf_path = tmp_pdf.name

    try:
        msg = dispatcher.build_message(
            recipient_email="founder@targetagency.com",
            subject="Security Findings for client.com",
            body_text="Here are your findings.",
            pdf_attachment_path=pdf_path
        )

        assert msg["To"] == "founder@targetagency.com"
        assert msg["Subject"] == "Security Findings for client.com"
        assert "auditor@myagency.com" in msg["From"]
        assert len(msg.get_payload()) == 2  # Text body + PDF attachment
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)


def test_export_eml():
    dispatcher = EmailDispatcher(
        smtp_user="auditor@myagency.com",
        sender_name="Alex"
    )

    with tempfile.TemporaryDirectory() as tmpdir:
        eml_path = os.path.join(tmpdir, "draft.eml")
        dispatcher.export_eml(
            recipient_email="prospect@agency.com",
            subject="Domain Audit",
            body_text="Audit details here",
            pdf_attachment_path=None,
            output_eml_path=eml_path
        )

        assert os.path.exists(eml_path)
        with open(eml_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            assert "To: prospect@agency.com" in content
            assert "Subject: Domain Audit" in content


def test_send_email_mocked():
    dispatcher = EmailDispatcher(
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_user="user@gmail.com",
        smtp_password="app-password",
        sender_name="Auditor"
    )

    mock_smtp = MagicMock()
    with patch("smtplib.SMTP", return_value=mock_smtp):
        mock_instance = mock_smtp.__enter__.return_value
        result = dispatcher.send_email(
            recipient_email="client@agency.com",
            subject="Audit",
            body_text="Details"
        )

        assert result is True
        mock_instance.starttls.assert_called_once()
        mock_instance.login.assert_called_once_with("user@gmail.com", "app-password")
        mock_instance.send_message.assert_called_once()
