"""Everything CLI (es.exe) Search Adapter.

Provides high-performance, sub-5ms path lookups, regex searches, and file finding
across NTFS drives without manually scanning directory trees. Automatically detects
the Everything IPC status and offers an optional local filesystem fallback when IPC
is unavailable.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import fnmatch
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


class EverythingSearchError(Exception):
    """Base exception for Everything search errors."""
    pass


class EverythingNotInstalledError(EverythingSearchError):
    """Raised when es.exe CLI is not found on the system."""
    pass


class EverythingIPCError(EverythingSearchError):
    """Raised when es.exe cannot connect to Everything desktop IPC service."""
    pass


@dataclass
class SearchResult:
    """Represents a file or directory discovered via search."""
    path: Path
    filename: str
    size: Optional[int] = None
    date_modified: Optional[datetime] = None
    is_directory: bool = False
    attributes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize search result to dict."""
        return {
            "path": str(self.path),
            "filename": self.filename,
            "size": self.size,
            "date_modified": self.date_modified.isoformat() if self.date_modified else None,
            "is_directory": self.is_directory,
            "attributes": self.attributes,
        }


class EverythingSearcher:
    """High-speed NTFS searcher wrapping es.exe."""

    DEFAULT_ES_NAMES = ["es.exe", "es"]

    def __init__(self, es_path: Optional[str] = None):
        self.es_path = es_path or self._locate_es()

    @classmethod
    def _locate_es(cls) -> Optional[str]:
        """Locate es.exe in PATH or common Windows package locations."""
        for name in cls.DEFAULT_ES_NAMES:
            path = shutil.which(name)
            if path:
                return path

        common_locations = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "es.exe",
            Path(os.environ.get("ProgramFiles", "C:\\Program Files")) / "Everything" / "es.exe",
            Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Everything" / "es.exe",
        ]
        for loc in common_locations:
            if loc.is_file():
                return str(loc)
        return None

    def is_installed(self) -> bool:
        """Return True if es.exe is found and executable."""
        return bool(self.es_path and os.path.isfile(self.es_path))

    def is_ipc_available(self) -> bool:
        """Check if Everything IPC service is responding to CLI queries."""
        if not self.is_installed():
            return False
        try:
            res = subprocess.run(
                [self.es_path, "-get-everything-version"],
                capture_output=True,
                text=True,
                timeout=2,
            )
            return res.returncode == 0
        except Exception:
            return False

    def search(
        self,
        query: str,
        max_results: int = 100,
        case_sensitive: bool = False,
        whole_word: bool = False,
        regex: bool = False,
        match_path: bool = False,
        extension: Optional[str] = None,
        sort: Optional[str] = None,
        timeout_sec: float = 3.0,
        fallback_on_ipc_error: bool = False,
        fallback_root: Optional[Union[str, Path]] = None,
    ) -> List[SearchResult]:
        """Execute an Everything query using es.exe.

        Args:
            query: The search query string.
            max_results: Max items to return (-n).
            case_sensitive: If True, enforce case match (-i).
            whole_word: Match whole words only (-w).
            regex: Enable regex search (-r).
            match_path: Match full path instead of filename only (-p).
            extension: Optional extension filter (-ext <ext>).
            sort: Sort criteria (-sort name, size, date-modified, etc.).
            timeout_sec: Execution timeout.
            fallback_on_ipc_error: If True and IPC is offline, run fallback search.
            fallback_root: Root directory for fallback filesystem traversal.

        Returns:
            List of SearchResult objects.
        """
        if not self.is_installed():
            if fallback_on_ipc_error:
                return self._fallback_search(
                    query=query,
                    max_results=max_results,
                    regex=regex,
                    extension=extension,
                    root=fallback_root,
                )
            raise EverythingNotInstalledError("es.exe not found on system PATH or known locations.")

        cmd = [self.es_path, "-n", str(max_results)]

        if case_sensitive:
            cmd.append("-i")
        if whole_word:
            cmd.append("-w")
        if regex:
            cmd.append("-r")
        if match_path:
            cmd.append("-p")
        if extension:
            cmd.extend(["-ext", extension.lstrip(".")])
        if sort:
            cmd.extend(["-sort", sort])

        cmd.append(query)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired as e:
            raise EverythingSearchError(f"Query timed out after {timeout_sec}s: {query}") from e

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            if "IPC not found" in stderr or "IPC" in stderr or proc.returncode == 8:
                if fallback_on_ipc_error:
                    logger.warning("Everything IPC offline; falling back to filesystem scan.")
                    return self._fallback_search(
                        query=query,
                        max_results=max_results,
                        regex=regex,
                        extension=extension,
                        root=fallback_root,
                    )
                raise EverythingIPCError(f"Everything IPC service not running: {stderr or proc.stdout.strip()}")
            raise EverythingSearchError(f"es.exe failed with code {proc.returncode}: {stderr or proc.stdout.strip()}")

        results: List[SearchResult] = []
        for line in proc.stdout.splitlines():
            clean = line.strip()
            if not clean:
                continue
            path_obj = Path(clean)
            is_dir = False
            try:
                is_dir = path_obj.is_dir()
            except OSError:
                pass

            size = None
            date_mod = None
            try:
                stat = path_obj.stat()
                size = stat.st_size if not is_dir else None
                date_mod = datetime.fromtimestamp(stat.st_mtime)
            except OSError:
                pass

            results.append(
                SearchResult(
                    path=path_obj,
                    filename=path_obj.name,
                    size=size,
                    date_modified=date_mod,
                    is_directory=is_dir,
                )
            )

        return results

    async def async_search(
        self,
        query: str,
        max_results: int = 100,
        **kwargs: Any,
    ) -> List[SearchResult]:
        """Asynchronous wrapper for search."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.search(query, max_results=max_results, **kwargs))

    def count(
        self,
        query: str,
        timeout_sec: float = 3.0,
        fallback_on_ipc_error: bool = False,
        fallback_root: Optional[Union[str, Path]] = None,
    ) -> int:
        """Return the count of matching items without listing them."""
        if not self.is_installed():
            if fallback_on_ipc_error:
                return len(self._fallback_search(query, max_results=999999, regex=False, extension=None, root=fallback_root))
            raise EverythingNotInstalledError("es.exe not installed.")

        cmd = [self.es_path, "-get-result-count", query]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec)
        if proc.returncode != 0:
            combined = (proc.stderr + " " + proc.stdout).strip()
            if "IPC not found" in combined or "IPC" in combined or proc.returncode == 8:
                if fallback_on_ipc_error:
                    return len(self._fallback_search(query, max_results=999999, regex=False, extension=None, root=fallback_root))
                raise EverythingIPCError("Everything IPC service not running.")
            raise EverythingSearchError(f"es.exe get-result-count failed: {combined}")

        output = proc.stdout.strip()
        try:
            return int(output.replace(",", ""))
        except ValueError:
            return 0

    def find_certificates(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_results: int = 50,
        fallback_on_ipc_error: bool = True,
    ) -> List[SearchResult]:
        """Discover TLS/SSL certificates and private keys."""
        exts = "ext:crt;cer;key;pem;pfx;p12"
        query = f'"{target_dir}" {exts}' if target_dir else exts
        return self.search(
            query=query,
            max_results=max_results,
            fallback_on_ipc_error=fallback_on_ipc_error,
            fallback_root=target_dir,
        )

    def find_env_secrets(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_results: int = 50,
        fallback_on_ipc_error: bool = True,
    ) -> List[SearchResult]:
        """Discover .env files, credentials, and SSH keys."""
        patterns = '".env" | ".env.*" | "*credentials*.json" | "*secret*" | "id_rsa" | "id_ed25519"'
        query = f'"{target_dir}" ({patterns})' if target_dir else patterns
        return self.search(
            query=query,
            max_results=max_results,
            fallback_on_ipc_error=fallback_on_ipc_error,
            fallback_root=target_dir,
        )

    def find_logs(
        self,
        query: str = "*.log",
        target_dir: Optional[Union[str, Path]] = None,
        max_results: int = 50,
        fallback_on_ipc_error: bool = True,
    ) -> List[SearchResult]:
        """Find log files for OSINT or forensic analysis."""
        full_query = f'"{target_dir}" {query}' if target_dir else query
        return self.search(
            query=full_query,
            max_results=max_results,
            fallback_on_ipc_error=fallback_on_ipc_error,
            fallback_root=target_dir,
        )

    def find_git_repos(
        self,
        target_dir: Optional[Union[str, Path]] = None,
        max_results: int = 50,
        fallback_on_ipc_error: bool = True,
    ) -> List[SearchResult]:
        """Find local Git repositories by locating .git directories."""
        query = f'"{target_dir}" folder:.git' if target_dir else "folder:.git"
        return self.search(
            query=query,
            max_results=max_results,
            fallback_on_ipc_error=fallback_on_ipc_error,
            fallback_root=target_dir,
        )

    def _fallback_search(
        self,
        query: str,
        max_results: int,
        regex: bool,
        extension: Optional[str],
        root: Optional[Union[str, Path]] = None,
    ) -> List[SearchResult]:
        """Filesystem scan fallback when IPC is unavailable."""
        search_root = None
        if root:
            search_root = Path(root).resolve()
        else:
            path_match = re.match(r'^(?:"([^"]+)"|([A-Za-z]:\\[^\s*?"]+|[A-Za-z]:/[^\s*?"]+|/[^\s*?"]+))\s*(.*)$', query.strip())
            if path_match:
                extracted_path = Path(path_match.group(1) or path_match.group(2))
                if extracted_path.is_dir():
                    search_root = extracted_path.resolve()
                    query = path_match.group(3).strip()

        if not search_root:
            search_root = Path.cwd().resolve()

        results: List[SearchResult] = []

        pattern = None
        if regex:
            try:
                pattern = re.compile(query, re.IGNORECASE)
            except re.error:
                pattern = None

        allowed_exts: set[str] = set()
        if extension:
            allowed_exts.add(extension.lstrip(".").lower())

        ext_match = re.search(r"\bext:([a-zA-Z0-9_;]+)", query, re.IGNORECASE)
        if ext_match:
            for e in ext_match.group(1).split(";"):
                if e.strip():
                    allowed_exts.add(e.strip().lstrip(".").lower())

        folder_filter: Optional[str] = None
        folder_match = re.search(r"\bfolder:(\S+)", query, re.IGNORECASE)
        if folder_match:
            folder_filter = folder_match.group(1).strip('"')

        clean_query = re.sub(r"\bext:[a-zA-Z0-9_;]+", "", query, flags=re.IGNORECASE)
        clean_query = re.sub(r"\bfolder:\S+", "", clean_query, flags=re.IGNORECASE)
        clean_query = clean_query.strip()

        if search_root and clean_query:
            for candidate in [str(search_root), str(search_root).replace("\\", "/"), str(search_root).replace("/", "\\")]:
                if clean_query.startswith(f'"{candidate}"'):
                    clean_query = clean_query[len(candidate) + 2:].strip()
                    break
                elif clean_query.startswith(candidate):
                    clean_query = clean_query[len(candidate):].strip()
                    break

        clean_query = clean_query.strip("()").strip()
        sub_patterns = [p.strip().strip('"').strip() for p in clean_query.split("|") if p.strip().strip('"').strip()]

        try:
            for root_dir, dirs, files in os.walk(search_root):
                current_subdirs = list(dirs)
                if folder_filter and folder_filter.lower() == ".git":
                    dirs[:] = [d for d in dirs if d != ".git"]
                else:
                    dirs[:] = [d for d in dirs if d not in (".git", "node_modules", ".venv", "__pycache__")]

                items_to_check: List[Tuple[str, bool]] = []
                for d in current_subdirs:
                    items_to_check.append((d, True))
                if not folder_filter:
                    for f in files:
                        items_to_check.append((f, False))

                for item_name, is_dir in items_to_check:
                    full_p = Path(root_dir) / item_name

                    if folder_filter:
                        if not is_dir:
                            continue
                        if not (fnmatch.fnmatch(item_name.lower(), folder_filter.lower()) or folder_filter.lower() in item_name.lower()):
                            continue

                    if allowed_exts:
                        if is_dir or full_p.suffix.lstrip(".").lower() not in allowed_exts:
                            continue

                    matched = False
                    if pattern:
                        matched = bool(pattern.search(item_name) or pattern.search(str(full_p)))
                    elif (allowed_exts or folder_filter) and not sub_patterns:
                        matched = True
                    elif sub_patterns:
                        for sp in sub_patterns:
                            if fnmatch.fnmatch(item_name.lower(), sp.lower()):
                                matched = True
                                break
                            elif sp.lower() in item_name.lower():
                                matched = True
                                break
                    elif not query.strip():
                        matched = True

                    if matched:
                        size = None
                        date_mod = None
                        try:
                            st = full_p.stat()
                            size = st.st_size if not is_dir else None
                            date_mod = datetime.fromtimestamp(st.st_mtime)
                        except OSError:
                            pass

                        results.append(
                            SearchResult(
                                path=full_p,
                                filename=item_name,
                                size=size,
                                date_modified=date_mod,
                                is_directory=is_dir,
                            )
                        )
                        if len(results) >= max_results:
                            return results
        except Exception as e:
            logger.error(f"Fallback search error on {search_root}: {e}")

        return results


# Module-level convenience functions
default_searcher = EverythingSearcher()


def search_files(query: str, max_results: int = 100, **kwargs: Any) -> List[SearchResult]:
    """Search files using default Everything searcher."""
    return default_searcher.search(query, max_results=max_results, **kwargs)
