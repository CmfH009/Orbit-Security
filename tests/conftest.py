"""Pytest global fixtures for Orbit Security."""

from __future__ import annotations

import smtplib

import pytest


@pytest.fixture(autouse=True)
def _block_live_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent any test from opening a real SMTP connection."""

    def _blocked_smtp(*args, **kwargs):
        raise AssertionError(
            "Blocked live SMTP connection in pytest; mock EmailDispatcher.send_email or smtplib.SMTP"
        )

    monkeypatch.setattr(smtplib, "SMTP", _blocked_smtp)
    monkeypatch.setattr(smtplib, "SMTP_SSL", _blocked_smtp)
