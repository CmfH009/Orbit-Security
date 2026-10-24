"""Fast HTTP and TLS Reconnaissance Probe wrapping xh / xhs.

Provides high-throughput security reconnaissance, header auditing, and TLS/certificate
inspection using the ultra-fast Rust-based xh CLI. Includes deep security header scoring
and fallback mechanisms.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import re
import shutil
import socket
import ssl
import subprocess
import time
from typing import Any, Dict, List, Optional, Tuple, Union
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class XHProbeError(Exception):
    """Base exception for xh reconnaissance probe errors."""
    pass


class XHNotInstalledError(XHProbeError):
    """Raised when xh or xhs CLI binary is not found."""
    pass


@dataclass
class CertificateInfo:
    """Detailed TLS certificate metadata."""
    subject: Dict[str, str] = field(default_factory=dict)
    issuer: Dict[str, str] = field(default_factory=dict)
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    days_remaining: Optional[int] = None
    san_list: List[str] = field(default_factory=list)
    serial_number: Optional[str] = None
    version: Optional[int] = None
    is_expired: bool = False
    is_self_signed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "subject": self.subject,
            "issuer": self.issuer,
            "valid_from": self.valid_from.isoformat() if self.valid_from else None,
            "valid_until": self.valid_until.isoformat() if self.valid_until else None,
            "days_remaining": self.days_remaining,
            "san_list": self.san_list,
            "serial_number": self.serial_number,
            "version": self.version,
            "is_expired": self.is_expired,
            "is_self_signed": self.is_self_signed,
        }


@dataclass
class SecurityHeaderAudit:
    """Security header analysis report and security hygiene grade."""
    grade: str
    score: int
    present_headers: Dict[str, str]
    missing_headers: List[str]
    recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grade": self.grade,
            "score": self.score,
            "present_headers": self.present_headers,
            "missing_headers": self.missing_headers,
            "recommendations": self.recommendations,
        }


@dataclass
class ProbeResult:
    """HTTP/TLS reconnaissance probe output."""
    url: str
    status_code: int
    headers: Dict[str, str]
    body: str
    tls_version: Optional[str] = None
    elapsed_ms: float = 0.0
    security_audit: Optional[SecurityHeaderAudit] = None
    certificate: Optional[CertificateInfo] = None
    raw_output: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "status_code": self.status_code,
            "headers": self.headers,
            "body": self.body[:500] if len(self.body) > 500 else self.body,
            "tls_version": self.tls_version,
            "elapsed_ms": self.elapsed_ms,
            "security_audit": self.security_audit.to_dict() if self.security_audit else None,
            "certificate": self.certificate.to_dict() if self.certificate else None,
        }


class XHProbe:
    """High-throughput reconnaissance probe wrapping xh.exe / xhs.exe."""

    SECURITY_HEADER_WEIGHTS = {
        "strict-transport-security": 25,
        "content-security-policy": 25,
        "x-frame-options": 15,
        "x-content-type-options": 15,
        "referrer-policy": 10,
        "permissions-policy": 10,
    }

    def __init__(self, xh_path: Optional[str] = None, xhs_path: Optional[str] = None):
        self.xh_path = xh_path or self._locate_binary("xh.exe", "xh")
        self.xhs_path = xhs_path or self._locate_binary("xhs.exe", "xhs")

    @classmethod
    def _locate_binary(cls, win_name: str, unix_name: str) -> Optional[str]:
        for name in [win_name, unix_name]:
            path = shutil.which(name)
            if path:
                return path

        common_locations = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / win_name,
            Path(os.environ.get("USERPROFILE", "")) / ".cargo" / "bin" / win_name,
        ]
        for loc in common_locations:
            if loc.is_file():
                return str(loc)
        return None

    def is_installed(self) -> bool:
        """Return True if xh CLI is installed."""
        return bool(self.xh_path and os.path.isfile(self.xh_path))

    def audit_headers(self, headers: Dict[str, str]) -> SecurityHeaderAudit:
        """Score security headers and calculate hygiene grade."""
        normalized = {k.lower(): v for k, v in headers.items()}
        score = 0
        present = {}
        missing = []
        recommendations = []

        for header, weight in self.SECURITY_HEADER_WEIGHTS.items():
            if header in normalized:
                val = normalized[header]
                present[header] = val
                score += weight
                if header == "strict-transport-security" and "includeSubDomains" not in val:
                    recommendations.append("HSTS should include 'includeSubDomains' and max-age >= 31536000.")
            else:
                missing.append(header)
                recommendations.append(f"Missing security header: {header}")

        if score >= 90:
            grade = "A+" if score == 100 else "A"
        elif score >= 75:
            grade = "B"
        elif score >= 50:
            grade = "C"
        elif score >= 25:
            grade = "D"
        else:
            grade = "F"

        return SecurityHeaderAudit(
            grade=grade,
            score=score,
            present_headers=present,
            missing_headers=missing,
            recommendations=recommendations,
        )

    def probe(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        timeout_sec: float = 10.0,
        follow_redirects: bool = True,
        verify_ssl: bool = True,
        tls_version: Optional[str] = None,
        inspect_cert: bool = True,
        offline: bool = False,
    ) -> ProbeResult:
        """Execute a high-speed reconnaissance probe against target URL.

        Args:
            url: Target URL or hostname.
            method: HTTP verb (GET, HEAD, POST, OPTIONS, etc.).
            headers: Optional dictionary of HTTP request headers.
            timeout_sec: Connection and read timeout in seconds.
            follow_redirects: Whether to follow HTTP 3xx redirects.
            verify_ssl: Verify TLS certificate validity.
            tls_version: Force specific TLS version ('tls1.2', 'tls1.3').
            inspect_cert: Extract full X.509 certificate metadata if HTTPS.
            offline: If True, simulate/build request without sending network packets.

        Returns:
            ProbeResult with response codes, headers, body, audit, and cert info.
        """
        if not self.is_installed():
            return self._fallback_httpx_probe(
                url=url,
                method=method,
                headers=headers,
                timeout_sec=timeout_sec,
                follow_redirects=follow_redirects,
                verify_ssl=verify_ssl,
                inspect_cert=inspect_cert,
                offline=offline,
            )

        print_flag = "--print=HB" if offline else "--print=hb"
        cmd = [self.xh_path, "--pretty=none", "-I", "--no-check-status", print_flag]

        if offline:
            cmd.append("--offline")
        if follow_redirects:
            cmd.append("-F")
        if not verify_ssl:
            cmd.extend(["--verify", "no"])
        if tls_version:
            cmd.extend(["--ssl", tls_version])

        cmd.extend(["--timeout", str(timeout_sec)])
        cmd.append(method.upper())
        cmd.append(url)

        if headers:
            for k, v in headers.items():
                cmd.append(f"{k}:{v}")

        start_time = time.perf_counter()
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec + 2.0,
            )
        except subprocess.TimeoutExpired as e:
            raise XHProbeError(f"Probe to {url} timed out after {timeout_sec}s") from e

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        raw_output = proc.stdout

        status_code, resp_headers, body = self._parse_xh_output(raw_output)

        cert_info = None
        if inspect_cert and url.lower().startswith("https://") and not offline:
            try:
                cert_info = self.inspect_certificate(url, timeout_sec=min(timeout_sec, 5.0))
            except Exception as e:
                logger.debug(f"Certificate inspection skipped/failed for {url}: {e}")

        audit = self.audit_headers(resp_headers)

        return ProbeResult(
            url=url,
            status_code=status_code,
            headers=resp_headers,
            body=body,
            tls_version=tls_version,
            elapsed_ms=elapsed_ms,
            security_audit=audit,
            certificate=cert_info,
            raw_output=raw_output,
        )

    def inspect_certificate(self, host_or_url: str, port: int = 443, timeout_sec: float = 5.0) -> CertificateInfo:
        """Inspect X.509 TLS certificate for expiry, SANs, and issuer."""
        if "://" in host_or_url:
            parsed = urlparse(host_or_url)
            hostname = parsed.hostname or host_or_url
            port = parsed.port or 443
        else:
            hostname = host_or_url.split(":")[0]
            if ":" in host_or_url:
                try:
                    port = int(host_or_url.split(":")[1])
                except ValueError:
                    port = 443

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=timeout_sec) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert() or {}

        # 1. Primary parser: high-fidelity X.509 parsing via cryptography
        if cert_bin:
            try:
                import cryptography.x509
                from cryptography.x509.oid import ExtensionOID

                x509_cert = cryptography.x509.load_der_x509_certificate(cert_bin)

                subject = {}
                for attr in x509_cert.subject:
                    name = getattr(attr.oid, "_name", str(attr.oid))
                    subject[name] = str(attr.value)

                issuer = {}
                for attr in x509_cert.issuer:
                    name = getattr(attr.oid, "_name", str(attr.oid))
                    issuer[name] = str(attr.value)

                sans: List[str] = []
                try:
                    san_ext = x509_cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                    sans = list(san_ext.value.get_values_for_type(cryptography.x509.DNSName))
                except Exception:
                    pass

                valid_from = getattr(x509_cert, "not_valid_before_utc", None)
                valid_until = getattr(x509_cert, "not_valid_after_utc", None)
                if valid_from is None and hasattr(x509_cert, "not_valid_before"):
                    valid_from = x509_cert.not_valid_before.replace(tzinfo=timezone.utc)
                if valid_until is None and hasattr(x509_cert, "not_valid_after"):
                    valid_until = x509_cert.not_valid_after.replace(tzinfo=timezone.utc)

                now = datetime.now(timezone.utc)
                is_expired = False
                days_rem = None
                if valid_until:
                    is_expired = now > valid_until
                    days_rem = (valid_until - now).days

                is_self_signed = (x509_cert.subject == x509_cert.issuer and bool(subject))

                return CertificateInfo(
                    subject=subject,
                    issuer=issuer,
                    valid_from=valid_from,
                    valid_until=valid_until,
                    days_remaining=days_rem,
                    san_list=sans,
                    serial_number=hex(x509_cert.serial_number)[2:].upper() if x509_cert.serial_number else None,
                    version=getattr(x509_cert.version, "value", 3),
                    is_expired=is_expired,
                    is_self_signed=is_self_signed,
                )
            except Exception as e:
                logger.debug(f"Cryptography X.509 parser fallback: {e}")

        # 2. Fallback: Parse from python ssl dict representation if populated
        subject = {}
        for rdn in cert_dict.get("subject", ()):
            for key, val in rdn:
                subject[key] = val

        issuer = {}
        for rdn in cert_dict.get("issuer", ()):
            for key, val in rdn:
                issuer[key] = val

        sans = [val for key, val in cert_dict.get("subjectAltName", ()) if key == "DNS"]

        def parse_cert_date(date_str: Optional[str]) -> Optional[datetime]:
            if not date_str:
                return None
            try:
                return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            except ValueError:
                return None

        valid_from = parse_cert_date(cert_dict.get("notBefore"))
        valid_until = parse_cert_date(cert_dict.get("notAfter"))

        now = datetime.now(timezone.utc)
        is_expired = False
        days_rem = None
        if valid_until:
            is_expired = now > valid_until
            days_rem = (valid_until - now).days

        is_self_signed = (subject.get("commonName") == issuer.get("commonName") and bool(subject))

        return CertificateInfo(
            subject=subject,
            issuer=issuer,
            valid_from=valid_from,
            valid_until=valid_until,
            days_remaining=days_rem,
            san_list=sans,
            serial_number=cert_dict.get("serialNumber"),
            version=cert_dict.get("version"),
            is_expired=is_expired,
            is_self_signed=is_self_signed,
        )

    def _parse_xh_output(self, raw: str) -> Tuple[int, Dict[str, str], str]:
        """Parse status code, headers, and body from xh CLI output."""
        status_code = 0
        headers: Dict[str, str] = {}
        body = ""

        # Strip ANSI escape codes
        clean_raw = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", raw)

        # Detect multiple HTTP blocks (e.g., 100 Continue or redirects)
        blocks = re.split(r"\r?\n\r?\n", clean_raw)
        header_block = blocks[0] if blocks else ""
        body = "\n\n".join(blocks[1:]) if len(blocks) > 1 else ""

        if len(blocks) > 1:
            for i, b in enumerate(blocks):
                first_line = b.strip().splitlines()[0] if b.strip().splitlines() else ""
                status_match = re.search(r"HTTP/\S+\s+(\d{3})", first_line)
                if status_match and int(status_match.group(1)) != 100:
                    header_block = b
                    body = "\n\n".join(blocks[i + 1:])
                    break

        lines = header_block.splitlines()
        for i, line in enumerate(lines):
            line_str = line.strip()
            if i == 0 and "HTTP/" in line_str:
                status_match = re.search(r"HTTP/\S+\s+(\d{3})", line_str)
                if status_match:
                    status_code = int(status_match.group(1))
            elif ":" in line_str:
                k, v = line_str.split(":", 1)
                headers[k.strip()] = v.strip()

        return status_code, headers, body

    def _fallback_httpx_probe(
        self,
        url: str,
        method: str,
        headers: Optional[Dict[str, str]],
        timeout_sec: float,
        follow_redirects: bool,
        verify_ssl: bool,
        inspect_cert: bool,
        offline: bool = False,
    ) -> ProbeResult:
        """Fallback probe using python httpx library."""
        try:
            import httpx
        except ImportError:
            raise XHNotInstalledError("Neither xh CLI nor httpx library is available.")

        if offline:
            req = httpx.Request(method.upper(), url, headers=headers)
            req_headers = dict(req.headers)
            audit = self.audit_headers(req_headers)
            raw_req = f"{method.upper()} {req.url.raw_path.decode('ascii', errors='ignore')} HTTP/1.1\n" + "\n".join(f"{k}: {v}" for k, v in req_headers.items())
            return ProbeResult(
                url=url,
                status_code=0,
                headers=req_headers,
                body="",
                elapsed_ms=0.0,
                security_audit=audit,
                certificate=None,
                raw_output=raw_req,
            )

        start_time = time.perf_counter()
        with httpx.Client(verify=verify_ssl, follow_redirects=follow_redirects, timeout=timeout_sec) as client:
            resp = client.request(method, url, headers=headers)
        elapsed_ms = (time.perf_counter() - start_time) * 1000.0

        resp_headers = dict(resp.headers)
        audit = self.audit_headers(resp_headers)

        cert_info = None
        if inspect_cert and url.lower().startswith("https://"):
            try:
                cert_info = self.inspect_certificate(url, timeout_sec=min(timeout_sec, 5.0))
            except Exception:
                pass

        return ProbeResult(
            url=url,
            status_code=resp.status_code,
            headers=resp_headers,
            body=resp.text,
            elapsed_ms=elapsed_ms,
            security_audit=audit,
            certificate=cert_info,
            raw_output=f"HTTP/1.1 {resp.status_code}\n" + "\n".join(f"{k}: {v}" for k, v in resp_headers.items()),
        )

    async def async_probe(self, url: str, **kwargs: Any) -> ProbeResult:
        """Asynchronously execute reconnaissance probe."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.probe(url, **kwargs))


# Default instance
default_probe = XHProbe()


def probe_target(url: str, **kwargs: Any) -> ProbeResult:
    """Convenience probe function."""
    return default_probe.probe(url, **kwargs)
