"""orbit_security.gemini_cli_bridge: Zero-Dependency gemini-api Subprocess Bridge.
==================================================================================
Replaces heavy cloud SDKs (google-genai, Pydantic/Starlette HTTP trees) with lightweight,
zero-dependency subprocess invocations against the standalone `gemini-api` CLI binary.

Architectural Guarantees:
1. Zero Cloud SDK Imports: Pure standard library subprocess execution.
2. Typed Exit-Code Routing:
   - 0: OK -> Machine-parsable JSON stdout returned as structured Pydantic or dict.
   - 1: Runtime/Validation Error -> Parsed JSON stderr logged; halts blind retry.
   - 2: Usage Error -> Command syntax/flag validation error handled.
   - 3: Authentication/Authorization -> Whoami failure or quota alert -> instant failover
        to local Ollama Pydantic triage endpoint without crashing 60s Sentinel loop.
3. Offline Schema Validation: `--dry-run -o json` execution without network rounds.
4. Disk-Only Artifact Streams: Direct file artifact writes for media and TTS.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, TypeVar, Union, TYPE_CHECKING
from dataclasses import dataclass, field

if TYPE_CHECKING:
    from pydantic import BaseModel

logger = logging.getLogger("orbit_security.gemini_cli_bridge")

DEFAULT_BINARY_CANDIDATES = [
    "gemini-api",
    "gemini-api.exe",
    r"C:\Users\purav\AppData\Local\agy\bin\gemini-api.exe",
    r"A:\system\bin\gemini-api.exe",
]

T = TypeVar("T")


class GeminiCLIError(Exception):
    """Base exception for Gemini CLI errors."""
    def __init__(self, message: str, exit_code: int = 1, raw_error: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.exit_code = exit_code
        self.raw_error = raw_error or {}


class GeminiRuntimeError(GeminiCLIError):
    """Exit code 1: Runtime error or validation failure."""
    pass


class GeminiUsageError(GeminiCLIError):
    """Exit code 2: Usage or CLI syntax error."""
    pass


class GeminiAuthError(GeminiCLIError):
    """Exit code 3: Authentication or authorization failure."""
    pass


class GeminiRateLimitError(GeminiCLIError):
    """Rate limit or quota exhaustion (429/RESOURCE_EXHAUSTED)."""
    pass


@dataclass
class GeminiCLIResult:
    """Standardized result envelope for gemini-api subprocess invocations."""
    exit_code: int
    success: bool
    data: Optional[Any] = None
    stdout: str = ""
    stderr: str = ""
    error_type: Optional[str] = None
    error_message: Optional[str] = None
    failed_over: bool = False
    dry_run: bool = False


class GeminiCLIBridge:
    """Lightweight subprocess wrapper for the standalone gemini-api CLI binary."""

    def __init__(self, binary_path: Optional[str] = None):
        self.binary_path = self._resolve_binary(binary_path)

    @classmethod
    def _resolve_binary(cls, candidate: Optional[str] = None) -> str:
        """Finds gemini-api binary across candidate paths and system PATH."""
        if candidate and (shutil.which(candidate) or os.path.isfile(candidate)):
            return candidate

        for c in DEFAULT_BINARY_CANDIDATES:
            resolved = shutil.which(c)
            if resolved:
                return resolved
            if os.path.isfile(c):
                return os.path.abspath(c)

        # Fall back to command name on PATH
        return "gemini-api"

    def is_available(self) -> bool:
        """Checks if gemini-api binary is executable."""
        try:
            res = subprocess.run(
                [self.binary_path, "version"],
                capture_output=True,
                text=True,
                timeout=5.0,
            )
            return res.returncode == 0
        except Exception:
            return False

    def _parse_error_envelope(self, stderr: str, stdout: str) -> Tuple[Optional[str], Optional[str], Optional[Dict[str, Any]]]:
        """Extracts structured JSON error message and error_type from stderr or stdout."""
        for text in (stderr, stdout):
            if not text:
                continue
            text = text.strip()
            if text.startswith("{") and text.endswith("}"):
                try:
                    obj = json.loads(text)
                    err_type = obj.get("error_type") or obj.get("error_reason")
                    msg = obj.get("message") or (obj.get("error", {}) if isinstance(obj.get("error"), dict) else {}).get("message")
                    return err_type, msg or text, obj
                except Exception:
                    pass
        return None, stderr.strip() if stderr else stdout.strip(), None

    def execute_cli(
        self,
        args: List[str],
        timeout: float = 30.0,
        stdin_input: Optional[str] = None,
    ) -> GeminiCLIResult:
        """Executes a synchronous gemini-api subprocess and routes the exit code."""
        cmd = [self.binary_path] + args
        try:
            proc = subprocess.run(
                cmd,
                input=stdin_input,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return self._handle_process_result(proc.returncode, proc.stdout, proc.stderr)
        except subprocess.TimeoutExpired as tex:
            logger.error(f"gemini-api subprocess timed out after {timeout}s: {' '.join(cmd)}")
            return GeminiCLIResult(
                exit_code=1,
                success=False,
                stderr=str(tex),
                error_type="TIMEOUT",
                error_message=f"Command timed out after {timeout}s",
            )
        except FileNotFoundError as fnf:
            logger.critical(f"gemini-api binary not found at '{self.binary_path}': {fnf}")
            return GeminiCLIResult(
                exit_code=2,
                success=False,
                stderr=str(fnf),
                error_type="BINARY_NOT_FOUND",
                error_message=f"gemini-api binary not found at '{self.binary_path}'",
            )
        except Exception as ex:
            logger.exception(f"Unexpected error executing gemini-api: {ex}")
            return GeminiCLIResult(
                exit_code=1,
                success=False,
                stderr=str(ex),
                error_type="EXECUTION_FAILED",
                error_message=str(ex),
            )

    async def execute_cli_async(
        self,
        args: List[str],
        timeout: float = 30.0,
        stdin_input: Optional[str] = None,
    ) -> GeminiCLIResult:
        """Executes an asynchronous gemini-api subprocess and routes the exit code."""
        cmd = [self.binary_path] + args
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if stdin_input else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            input_bytes = stdin_input.encode("utf-8") if stdin_input else None
            stdout_b, stderr_b = await asyncio.wait_for(
                proc.communicate(input=input_bytes),
                timeout=timeout,
            )
            return self._handle_process_result(
                proc.returncode or 0,
                stdout_b.decode("utf-8", errors="replace"),
                stderr_b.decode("utf-8", errors="replace"),
            )
        except asyncio.TimeoutError:
            logger.error(f"Async gemini-api subprocess timed out after {timeout}s: {' '.join(cmd)}")
            return GeminiCLIResult(
                exit_code=1,
                success=False,
                error_type="TIMEOUT",
                error_message=f"Command timed out after {timeout}s",
            )
        except Exception as ex:
            logger.exception(f"Unexpected error in async gemini-api execution: {ex}")
            return GeminiCLIResult(
                exit_code=1,
                success=False,
                stderr=str(ex),
                error_type="ASYNC_EXECUTION_FAILED",
                error_message=str(ex),
            )

    def _handle_process_result(self, returncode: int, stdout: str, stderr: str) -> GeminiCLIResult:
        """Processes return code and constructs typed GeminiCLIResult."""
        err_type, err_msg, raw_err = self._parse_error_envelope(stderr, stdout)

        # Detect rate limit / quota signals from output
        is_rate_limit = False
        combined_err = f"{err_type or ''} {err_msg or ''} {stderr}".lower()
        if "429" in combined_err or "quota" in combined_err or "resource_exhausted" in combined_err or "rate_limit" in combined_err:
            is_rate_limit = True

        if returncode == 0:
            parsed_data = None
            if stdout.strip().startswith(("{", "[")):
                try:
                    parsed_data = json.loads(stdout)
                except Exception:
                    parsed_data = stdout.strip()
            else:
                parsed_data = stdout.strip()

            dry_run = False
            if isinstance(parsed_data, dict) and parsed_data.get("dry_run"):
                dry_run = True

            return GeminiCLIResult(
                exit_code=0,
                success=True,
                data=parsed_data,
                stdout=stdout,
                stderr=stderr,
                dry_run=dry_run,
            )

        elif is_rate_limit:
            logger.warning(f"gemini-api hit rate limit / quota exhaustion: {err_msg}")
            return GeminiCLIResult(
                exit_code=3,
                success=False,
                data=raw_err,
                stdout=stdout,
                stderr=stderr,
                error_type="RATE_LIMIT_EXCEEDED",
                error_message=err_msg or "Rate limit or quota exhausted",
            )

        elif returncode == 1:
            logger.warning(f"gemini-api runtime/validation error (code 1): {err_msg}")
            return GeminiCLIResult(
                exit_code=1,
                success=False,
                data=raw_err,
                stdout=stdout,
                stderr=stderr,
                error_type=err_type or "RUNTIME_ERROR",
                error_message=err_msg or "Runtime error encountered",
            )

        elif returncode == 2:
            logger.error(f"gemini-api usage error (code 2): {err_msg}")
            return GeminiCLIResult(
                exit_code=2,
                success=False,
                data=raw_err,
                stdout=stdout,
                stderr=stderr,
                error_type=err_type or "USAGE_ERROR",
                error_message=err_msg or "Usage/flag error",
            )

        elif returncode == 3:
            logger.critical(f"gemini-api authentication/authorization error (code 3): {err_msg}")
            return GeminiCLIResult(
                exit_code=3,
                success=False,
                data=raw_err,
                stdout=stdout,
                stderr=stderr,
                error_type=err_type or "AUTH_ERROR",
                error_message=err_msg or "Authentication/authorization failed",
            )

        else:
            return GeminiCLIResult(
                exit_code=returncode,
                success=False,
                data=raw_err,
                stdout=stdout,
                stderr=stderr,
                error_type="UNKNOWN_ERROR",
                error_message=err_msg or f"Subprocess exited with code {returncode}",
            )

    def generate(
        self,
        prompt: str,
        model: str = "gemini-3.8-flash",
        system: Optional[str] = None,
        dry_run: bool = False,
        timeout: float = 30.0,
        fallback_fn: Optional[Callable[[], Any]] = None,
    ) -> GeminiCLIResult:
        """Executes gemini-api generate with stream=false and -o json."""
        args = ["generate", prompt, "--model", model, "--stream=false", "-o", "json"]
        if system:
            args.extend(["--system", system])
        if dry_run:
            args.append("--dry-run")

        result = self.execute_cli(args, timeout=timeout)

        # Trigger automatic failover on quota / auth errors
        if not result.success and result.exit_code == 3 and fallback_fn:
            logger.info("Failing over from gemini-api to configured fallback handler...")
            try:
                fallback_data = fallback_fn()
                return GeminiCLIResult(
                    exit_code=0,
                    success=True,
                    data=fallback_data,
                    stdout="[FAILOVER_COMPLETED]",
                    stderr=result.stderr,
                    failed_over=True,
                )
            except Exception as fex:
                logger.error(f"Failover handler execution failed: {fex}")

        return result

    async def generate_async(
        self,
        prompt: str,
        model: str = "gemini-3.8-flash",
        system: Optional[str] = None,
        dry_run: bool = False,
        timeout: float = 30.0,
        fallback_fn: Optional[Callable[[], Any]] = None,
    ) -> GeminiCLIResult:
        """Async execution of gemini-api generate."""
        args = ["generate", prompt, "--model", model, "--stream=false", "-o", "json"]
        if system:
            args.extend(["--system", system])
        if dry_run:
            args.append("--dry-run")

        result = await self.execute_cli_async(args, timeout=timeout)
        if not result.success and result.exit_code == 3 and fallback_fn:
            logger.info("Async failing over from gemini-api to configured fallback handler...")
            try:
                if inspect.iscoroutinefunction(fallback_fn):
                    fallback_data = await fallback_fn()
                else:
                    fallback_data = fallback_fn()
                return GeminiCLIResult(
                    exit_code=0,
                    success=True,
                    data=fallback_data,
                    stdout="[FAILOVER_COMPLETED]",
                    stderr=result.stderr,
                    failed_over=True,
                )
            except Exception as fex:
                logger.error(f"Async failover execution failed: {fex}")

        return result

    def execute_json(
        self,
        prompt: str,
        schema: Optional[Type[BaseModel]] = None,
        timeout: float = 30.0,
    ) -> GeminiCLIResult:
        """Executes gemini-api CLI requesting JSON output, parsing stdout into dict or schema."""
        schema_instruction = ""
        if schema is not None:
            if hasattr(schema, "model_json_schema"):
                try:
                    schema_json = json.dumps(schema.model_json_schema())
                    schema_instruction = f"\nRespond strictly with JSON adhering to this schema:\n{schema_json}\nDo not include code markdown blocks or additional text."
                except Exception:
                    schema_instruction = "\nRespond strictly with valid JSON. Do not include markdown code blocks or additional text."
            else:
                schema_instruction = "\nRespond strictly with valid JSON. Do not include markdown code blocks or additional text."

        full_prompt = prompt + schema_instruction
        args = ["generate", full_prompt, "--stream=false", "-o", "json"]
        res = self.execute_cli(args, timeout=timeout)
        if not res.success:
            return res

        raw_obj = res.data
        if isinstance(raw_obj, str):
            clean_str = raw_obj.strip()
            if clean_str.startswith("```"):
                clean_str = re.sub(r"^```(?:json)?\s*", "", clean_str)
                clean_str = re.sub(r"\s*```$", "", clean_str)
            try:
                raw_obj = json.loads(clean_str)
            except Exception as e:
                logger.warning(f"execute_json failed to parse JSON string: {e}")
                return GeminiCLIResult(
                    exit_code=1,
                    success=False,
                    stdout=res.stdout,
                    stderr=f"JSON parsing error: {e}",
                    error_type="JSON_DECODE_ERROR",
                    error_message=str(e),
                )
        elif isinstance(raw_obj, dict):
            if "candidates" in raw_obj and isinstance(raw_obj["candidates"], list):
                for cand in raw_obj["candidates"]:
                    content = cand.get("content", {})
                    parts = content.get("parts", []) if isinstance(content, dict) else []
                    for part in parts:
                        text_val = part.get("text", "") if isinstance(part, dict) else ""
                        if text_val and text_val.strip().startswith(("{", "[")):
                            try:
                                raw_obj = json.loads(text_val.strip())
                                break
                            except Exception:
                                pass
            elif "response" in raw_obj and isinstance(raw_obj["response"], str):
                resp_text = raw_obj["response"].strip()
                if resp_text.startswith(("{", "[")):
                    try:
                        raw_obj = json.loads(resp_text)
                    except Exception:
                        pass

        if schema is not None and isinstance(raw_obj, dict):
            try:
                if hasattr(schema, "model_validate"):
                    validated = schema.model_validate(raw_obj)
                else:
                    validated = schema(**raw_obj)
                return GeminiCLIResult(
                    exit_code=0,
                    success=True,
                    data=validated,
                    stdout=res.stdout,
                    stderr=res.stderr,
                )
            except Exception as e:
                logger.warning(f"execute_json failed schema validation for {schema}: {e}")
                return GeminiCLIResult(
                    exit_code=1,
                    success=False,
                    stdout=res.stdout,
                    stderr=f"Schema validation error: {e}",
                    error_type="SCHEMA_VALIDATION_ERROR",
                    error_message=str(e),
                )

        return GeminiCLIResult(
            exit_code=0,
            success=True,
            data=raw_obj,
            stdout=res.stdout,
            stderr=res.stderr,
        )

    def tts(
        self,
        text: str,
        out_dir_or_file: str = "./tmp/tts/",
        voice: str = "Kore",
        dry_run: bool = False,
        timeout: float = 30.0,
    ) -> GeminiCLIResult:
        """Executes gemini-api tts writing directly to disk artifact without base64 bloat."""
        args = ["tts", text, "--voice", voice, "--out", out_dir_or_file]
        if dry_run:
            args.extend(["--dry-run", "-o", "json"])

        # Ensure target dir exists
        out_p = Path(out_dir_or_file)
        if out_dir_or_file.endswith(("/", "\\")) or not out_p.suffix:
            out_p.mkdir(parents=True, exist_ok=True)
        else:
            out_p.parent.mkdir(parents=True, exist_ok=True)

        return self.execute_cli(args, timeout=timeout)

    def whoami(self, timeout: float = 10.0) -> GeminiCLIResult:
        """Runs gemini-api whoami -o json to verify credentials and configuration."""
        return self.execute_cli(["whoami", "-o", "json"], timeout=timeout)

    def triage_vulnerability(
        self,
        event_type: str,
        payload: Dict[str, Any],
        fallback_agent: Optional[Any] = None,
        dry_run: bool = False,
        timeout: float = 30.0,
    ) -> Tuple[Optional[Any], GeminiCLIResult]:
        """Triages vulnerability events via gemini-api with automatic failover to Ollama."""
        target = payload.get("domain") or payload.get("target") or "target.system"
        cve_id = payload.get("cve_id") or payload.get("service") or "VULN-UNKNOWN"

        prompt = (
            f"Analyze this security discovery and return JSON conforming to TriageRemediationSpec:\n"
            f"Event: {event_type}\n"
            f"Target: {target}\n"
            f"Vulnerability: {cve_id}\n"
            f"Details: {json.dumps(payload)}\n"
            f"Format required: {{\"cve_id\": \"...\", \"threat_level\": \"CRITICAL|HIGH|MEDIUM|LOW\", "
            f"\"cvss_score\": 0.0-10.0, \"attack_vector\": \"NETWORK|ADJACENT|LOCAL|PHYSICAL\", "
            f"\"remediation_patch\": \"...\", \"executive_summary\": \"...\"}}"
        )

        system = (
            "You are Orbit Security's autonomous triage agent. Output strictly valid JSON matching "
            "the schema. Do not add markdown backticks or commentary."
        )

        def _do_fallback():
            if fallback_agent and hasattr(fallback_agent, "triage_vulnerability"):
                return fallback_agent.triage_vulnerability(event_type, payload)
            elif fallback_agent and hasattr(fallback_agent, "_deterministic_fallback"):
                return fallback_agent._deterministic_fallback(event_type, payload)
            return None

        cli_res = self.generate(
            prompt=prompt,
            system=system,
            dry_run=dry_run,
            timeout=timeout,
            fallback_fn=_do_fallback,
        )

        if cli_res.failed_over:
            return cli_res.data, cli_res

        if cli_res.success and not cli_res.dry_run and cli_res.data:
            from orbit_security.triage_agent import TriageRemediationSpec
            try:
                # If data is a dict
                if isinstance(cli_res.data, dict):
                    # In interactions response, output may be wrapped or in candidates/steps
                    raw_data = cli_res.data
                    if "candidates" in raw_data:
                        # Parse candidate text if needed
                        pass
                    spec = TriageRemediationSpec.model_validate(raw_data)
                    return spec, cli_res
                elif isinstance(cli_res.data, str):
                    parsed = json.loads(cli_res.data)
                    spec = TriageRemediationSpec.model_validate(parsed)
                    return spec, cli_res
            except Exception as parse_err:
                logger.warning(f"Failed to parse gemini-api triage JSON into TriageRemediationSpec: {parse_err}")
                if fallback_agent:
                    fb_spec = _do_fallback()
                    return fb_spec, cli_res

        return None, cli_res
