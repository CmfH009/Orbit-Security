import os
import tempfile
from pathlib import Path
import pytest
from orbit_security.radar_telemetry import (
    get_effective_data_dir,
    RadarTelemetryService,
    RadarTelemetryHandler,
)


def test_get_effective_data_dir_respects_env_var(monkeypatch, tmp_path):
    custom_dir = tmp_path / "custom_data"
    custom_dir.mkdir()
    monkeypatch.setenv("ORBIT_DATA_DIR", str(custom_dir))
    effective = get_effective_data_dir()
    assert effective == custom_dir
    assert effective.exists()


def test_get_effective_data_dir_fallback_on_readonly(monkeypatch, tmp_path):
    # Simulate read-only path by setting an unwriteable directory
    readonly_dir = tmp_path / "readonly_mock"
    readonly_dir.mkdir()
    # Remove write permissions
    os.chmod(readonly_dir, 0o444)
    monkeypatch.setattr("orbit_security.radar_telemetry.DATA_DIR", readonly_dir)
    monkeypatch.delenv("ORBIT_DATA_DIR", raising=False)

    if os.name == "nt":
        # Windows chmod does not prevent writing inside directories like POSIX; mock write failure
        orig_write_text = Path.write_text

        def mock_write_text(self, *args, **kwargs):
            if str(readonly_dir) in str(self):
                raise PermissionError("Access denied (read-only filesystem)")
            return orig_write_text(self, *args, **kwargs)

        monkeypatch.setattr(Path, "write_text", mock_write_text)

    try:
        effective = get_effective_data_dir()
        assert effective != readonly_dir
        assert effective.exists()
        test_file = effective / "write_test.tmp"
        test_file.write_text("ok", encoding="utf-8")
        test_file.unlink()
    finally:
        os.chmod(readonly_dir, 0o777)


def test_radar_config_endpoint_returns_json():
    handler = RadarTelemetryHandler.__new__(RadarTelemetryHandler)
    config = handler._build_server_config()
    assert config["service"] == "orbit-radar-telemetry"
    assert "version" in config
    assert "env" in config
