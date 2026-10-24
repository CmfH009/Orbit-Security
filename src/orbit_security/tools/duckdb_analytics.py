"""In-process and CLI analytical OLAP engine using DuckDB.

Provides fast SQL analytics over Parquet, CSV, and JSON DNS telemetry, CVE feeds,
and reconnaissance scan findings. Seamlessly leverages the DuckDB Python package if
installed, falling back to the high-performance duckdb.exe binary.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)


class DuckDBAnalyticsError(Exception):
    """Base exception for DuckDB analytics operations."""
    pass


class DuckDBNotInstalledError(DuckDBAnalyticsError):
    """Raised when neither python duckdb nor duckdb.exe is available."""
    pass


class DuckDBQueryError(DuckDBAnalyticsError):
    """Raised when SQL execution encounters a syntax or runtime error."""
    pass


class DuckDBEngine:
    """Analytical query engine wrapping duckdb.exe or python duckdb package."""

    def __init__(self, cli_path: Optional[str] = None, default_db: Optional[str] = None):
        self.default_db = default_db
        self.duckdb_mod = self._try_import_duckdb()
        self.cli_path = cli_path or self._locate_cli()

    @staticmethod
    def _try_import_duckdb() -> Optional[Any]:
        try:
            import duckdb
            return duckdb
        except ImportError:
            return None

    @classmethod
    def _locate_cli(cls) -> Optional[str]:
        for name in ["duckdb.exe", "duckdb"]:
            found = shutil.which(name)
            if found:
                return found

        common_locations = [
            Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "WinGet" / "Links" / "duckdb.exe",
            Path(os.environ.get("USERPROFILE", "")) / ".cargo" / "bin" / "duckdb.exe",
        ]
        for loc in common_locations:
            if loc.is_file():
                return str(loc)
        return None

    def is_available(self) -> bool:
        """Return True if either python duckdb or duckdb.exe CLI is available."""
        return bool(self.duckdb_mod is not None or (self.cli_path and os.path.isfile(self.cli_path)))

    @staticmethod
    def normalize_path(path: Union[str, Path]) -> str:
        """Convert a filesystem path to forward slashes for DuckDB SQL compatibility."""
        p = Path(path).resolve()
        return str(p).replace("\\", "/")

    def execute_query(
        self,
        sql: str,
        params: Optional[List[Any]] = None,
        database: Optional[str] = None,
        timeout_sec: float = 30.0,
    ) -> List[Dict[str, Any]]:
        """Execute SQL query and return results as a list of dicts.

        Args:
            sql: SQL statement to execute.
            params: Optional query parameters for python duckdb.
            database: Optional DuckDB database file path (defaults to in-memory).
            timeout_sec: Timeout for CLI execution.

        Returns:
            List of row records as dictionaries.
        """
        # If python module is installed, use native in-process engine
        if self.duckdb_mod is not None:
            try:
                db_target = database or self.default_db or ":memory:"
                con = self.duckdb_mod.connect(db_target)
                try:
                    cursor = con.execute(sql, params or [])
                    columns = [desc[0] for desc in cursor.description] if cursor.description else []
                    rows = cursor.fetchall()
                    return [dict(zip(columns, row)) for row in rows]
                finally:
                    con.close()
            except Exception as e:
                raise DuckDBQueryError(f"In-process DuckDB query failed: {e}") from e

        # Fallback to duckdb.exe CLI with -json output
        if not self.cli_path or not os.path.isfile(self.cli_path):
            raise DuckDBNotInstalledError("DuckDB is not available: python module missing and duckdb.exe not found.")

        target_db = database or self.default_db or ""
        cmd = [self.cli_path, "-json"]
        if target_db:
            cmd.append(target_db)
        cmd.extend(["-c", sql])

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired as e:
            raise DuckDBAnalyticsError(f"DuckDB CLI query timed out after {timeout_sec}s") from e

        if proc.returncode != 0:
            err = proc.stderr.strip() or proc.stdout.strip()
            raise DuckDBQueryError(f"DuckDB CLI query failed (code {proc.returncode}): {err}")

        out = proc.stdout.strip()
        if not out:
            return []

        try:
            parsed = json.loads(out)
            if isinstance(parsed, list):
                return parsed
            elif isinstance(parsed, dict):
                return [parsed]
            return []
        except json.JSONDecodeError as e:
            raise DuckDBAnalyticsError(f"Failed to parse DuckDB JSON output: {out[:200]}") from e

    async def async_execute_query(self, sql: str, **kwargs: Any) -> List[Dict[str, Any]]:
        """Asynchronously execute a DuckDB SQL query."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: self.execute_query(sql, **kwargs))

    def _get_table_source(self, file_path: Union[str, Path]) -> str:
        """Resolve appropriate DuckDB reader table function based on file extension."""
        norm_path = self.normalize_path(file_path)
        ext = Path(file_path).suffix.lower()

        if ext in (".parquet", ".pq"):
            return f"read_parquet('{norm_path}')"
        elif ext in (".csv", ".tsv"):
            return f"read_csv_auto('{norm_path}')"
        elif ext in (".json", ".jsonl", ".ndjson"):
            return f"read_json_auto('{norm_path}')"
        else:
            return f"'{norm_path}'"

    def query_file(
        self,
        file_path: Union[str, Path],
        sql_filter: Optional[str] = None,
        columns: str = "*",
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Query a Parquet, CSV, or JSON file directly using DuckDB file readers."""
        table_source = self._get_table_source(file_path)

        query = f"SELECT {columns} FROM {table_source}"
        if sql_filter:
            query += f" WHERE {sql_filter}"
        if limit:
            query += f" LIMIT {limit}"

        return self.execute_query(query)

    def analyze_dns_telemetry(
        self,
        file_path: Union[str, Path],
        top_n: int = 20,
    ) -> Dict[str, Any]:
        """Analyze DNS telemetry for NXDOMAIN spikes, status distribution, and subdomain counts."""
        table_source = self._get_table_source(file_path)

        # Count total queries & distinct domains
        overview_sql = f"""
            SELECT
                count(*) AS total_queries,
                count(DISTINCT domain) AS unique_domains,
                count(CASE WHEN status = 'NXDOMAIN' THEN 1 END) AS nxdomain_count,
                count(CASE WHEN status = 'NOERROR' THEN 1 END) AS noerror_count
            FROM {table_source}
        """
        overview = self.execute_query(overview_sql)
        stats = overview[0] if overview else {}

        # Top queried domains
        top_domains_sql = f"""
            SELECT domain, count(*) as query_count, min(status) as status
            FROM {table_source}
            GROUP BY domain
            ORDER BY query_count DESC
            LIMIT {top_n}
        """
        top_domains = self.execute_query(top_domains_sql)

        # Status distribution
        status_sql = f"""
            SELECT status, count(*) as count
            FROM {table_source}
            GROUP BY status
            ORDER BY count DESC
        """
        status_dist = self.execute_query(status_sql)

        return {
            "summary": stats,
            "top_domains": top_domains,
            "status_distribution": status_dist,
        }

    def analyze_cve_feed(
        self,
        file_path: Union[str, Path],
        min_cvss: float = 7.0,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query CVE JSON/Parquet feed for high-severity vulnerabilities."""
        table_source = self._get_table_source(file_path)
        sql = f"""
            SELECT *
            FROM {table_source}
            WHERE cvss_score >= {min_cvss}
            ORDER BY cvss_score DESC
            LIMIT {limit}
        """
        return self.execute_query(sql)

    def analyze_recon_findings(
        self,
        file_path: Union[str, Path],
    ) -> Dict[str, Any]:
        """Aggregate reconnaissance scan findings by severity and category."""
        table_source = self._get_table_source(file_path)

        by_severity_sql = f"""
            SELECT severity, count(*) as count
            FROM {table_source}
            GROUP BY severity
            ORDER BY count DESC
        """
        by_sev = self.execute_query(by_severity_sql)

        by_cat_sql = f"""
            SELECT category, count(*) as count
            FROM {table_source}
            GROUP BY category
            ORDER BY count DESC
            LIMIT 15
        """
        by_cat = self.execute_query(by_cat_sql)

        return {
            "by_severity": by_sev,
            "by_category": by_cat,
        }

    def export_to_parquet(
        self,
        query: str,
        output_parquet_path: Union[str, Path],
        database: Optional[str] = None,
    ) -> Path:
        """Export SQL query results directly into Parquet file format."""
        out_p = Path(output_parquet_path).resolve()
        out_p.parent.mkdir(parents=True, exist_ok=True)
        norm_out = self.normalize_path(out_p)

        clean_query = query.strip().rstrip(";")
        export_sql = f"COPY ({clean_query}) TO '{norm_out}' (FORMAT PARQUET);"
        self.execute_query(export_sql, database=database)
        return out_p


# Default engine instance
default_duckdb = DuckDBEngine()


def run_analytics_query(sql: str, **kwargs: Any) -> List[Dict[str, Any]]:
    """Execute analytical query using default DuckDB engine."""
    return default_duckdb.execute_query(sql, **kwargs)
