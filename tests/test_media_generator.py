"""Unit tests for Multimodal Media Generator (media_generator.py)."""

from pathlib import Path
import tempfile
import pytest
from PIL import Image

from orbit_security.media_generator import MediaGenerator


def test_generate_dns_attack_diagram():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = MediaGenerator(project_root=Path(tmpdir))
        path = gen.generate_dns_attack_diagram(
            domain="store.brand.com",
            target_cname="unbouncepages.com",
            is_vulnerable=True,
        )
        assert path.exists()
        assert path.suffix == ".png"
        assert path.stat().st_size > 5000

        with Image.open(path) as img:
            assert img.size == (1200, 675)
            assert img.mode == "RGB"


def test_generate_ai_security_flowchart():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = MediaGenerator(project_root=Path(tmpdir))
        path = gen.generate_ai_security_flowchart(
            topic="Prompt Injection via MCP Tools",
            attack_vector="Payload executes arbitrary shell commands",
            orbit_defense="AST validation and strict sandbox perimeter",
        )
        assert path.exists()
        assert path.stat().st_size > 5000

        with Image.open(path) as img:
            assert img.size == (1200, 675)


def test_generate_telemetry_radar_card():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = MediaGenerator(project_root=Path(tmpdir))
        path = gen.generate_telemetry_radar_card(
            domain="targetco.com",
            score=92,
            spf_status="PASS",
            dmarc_status="ENFORCED",
            dangling_count=0,
        )
        assert path.exists()
        assert path.stat().st_size > 5000

        with Image.open(path) as img:
            assert img.size == (1200, 675)
