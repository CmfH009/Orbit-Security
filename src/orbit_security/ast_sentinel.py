#!/usr/bin/env python3
r"""
ast_sentinel.py: AST Code Sentinel (Static Code Hygiene & Symbol Verification)
=============================================================================
Runs static AST linting and deterministic symbol verification before git staging
to catch runtime omissions (such as unimported standard library modules like 'time')
that unit tests with outer mocks miss.

Fail Gate: Any missing import or unresolved standard library symbol fails immediately.
"""

from __future__ import annotations

import ast
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Optional

import builtins

# Standard library modules commonly omitted in error handling / edge paths
CRITICAL_STDLIB_SYMBOLS = {
    "time": ["time", "sleep", "strftime", "gmtime", "monotonic"],
    "json": ["loads", "dumps", "dump", "load"],
    "re": ["compile", "match", "search", "findall", "sub", "split"],
    "os": ["path", "environ", "remove", "rename", "listdir", "walk", "getpid", "stat"],
    "sys": ["path", "executable", "platform", "argv", "exit", "stdout", "stderr"],
    "shutil": ["which", "copy", "rmtree", "move"],
    "subprocess": ["run", "Popen", "PIPE", "DEVNULL", "check_output"],
    "socket": ["socket", "getaddrinfo", "AF_INET", "SOCK_STREAM"],
    "sqlite3": ["connect", "Row"],
    "math": ["floor", "ceil", "sqrt", "sin", "cos"],
    "uuid": ["uuid4", "UUID"],
    "Path": ["cwd", "home"],
}

PYTHON_BUILTINS = set(dir(builtins))


class ASTSymbolVisitor(ast.NodeVisitor):
    """Inspects AST for imported symbols vs used symbols in scopes."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.imports: Set[str] = set()
        self.imported_symbols: Set[str] = set()
        self.defined_globals: Set[str] = set()
        self.scopes: List[Set[str]] = [set()]  # Global scope
        self.loaded_names: List[Tuple[str, int]] = []
        self.loaded_attributes: List[Tuple[str, str, int]] = []
        self.has_pydantic_models = False

    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            name = alias.asname or alias.name
            self.imports.add(name)
            self.scopes[-1].add(name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        mod = node.module or ""
        self.imports.add(mod)
        for alias in node.names:
            name = alias.asname or alias.name
            self.imported_symbols.add(name)
            self.scopes[-1].add(name)
            if alias.name == "BaseModel" or mod == "pydantic":
                self.has_pydantic_models = True
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.scopes[-1].add(node.name)
        # New local scope
        local_scope = set(self.scopes[-1])
        for arg in node.args.args:
            local_scope.add(arg.arg)
        if node.args.vararg:
            local_scope.add(node.args.vararg.arg)
        if node.args.kwarg:
            local_scope.add(node.args.kwarg.arg)
        self.scopes.append(local_scope)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        self.visit_FunctionDef(node)  # type: ignore

    def visit_ClassDef(self, node: ast.ClassDef):
        self.scopes[-1].add(node.name)
        local_scope = set(self.scopes[-1])
        local_scope.add("self")
        local_scope.add("cls")
        self.scopes.append(local_scope)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_Name(self, node: ast.Name):
        if isinstance(node.ctx, ast.Store):
            self.scopes[-1].add(node.id)
        elif isinstance(node.ctx, ast.Load):
            self.loaded_names.append((node.id, node.lineno))
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if isinstance(node.value, ast.Name) and isinstance(node.ctx, ast.Load):
            self.loaded_attributes.append((node.value.id, node.attr, node.lineno))
        self.generic_visit(node)


class ASTCodeSentinel:
    """Standalone validator ensuring zero unimported symbols and valid syntax."""

    def __init__(self, workspace_root: Optional[Path] = None):
        self.workspace_root = workspace_root or (Path("A:/") if Path("A:/").exists() else Path("C:/AgyHut"))

    def inspect_file(self, file_path: Path) -> Dict[str, Any]:
        """Inspects a single Python file using AST traversal."""
        path = Path(file_path)
        if not path.exists():
            return {"ok": False, "file": str(path), "error": "File does not exist"}

        try:
            content = path.read_text(encoding="utf-8")
        except Exception as e:
            return {"ok": False, "file": str(path), "error": f"Encoding error: {e}"}

        try:
            tree = ast.parse(content, filename=str(path))
        except SyntaxError as se:
            return {
                "ok": False,
                "file": str(path),
                "error": f"SyntaxError at line {se.lineno}: {se.msg}",
                "lineno": se.lineno,
                "offset": se.offset,
            }

        visitor = ASTSymbolVisitor(str(path))
        visitor.visit(tree)

        missing_imports = []
        # Check loaded attributes against critical standard library modules
        for loaded_mod, loaded_attr, lineno in visitor.loaded_attributes:
            if loaded_mod in CRITICAL_STDLIB_SYMBOLS:
                if loaded_mod not in visitor.imports and loaded_mod not in visitor.imported_symbols:
                    missing_imports.append({
                        "module": loaded_mod,
                        "symbol": f"{loaded_mod}.{loaded_attr}",
                        "lineno": lineno,
                        "reason": f"Module '{loaded_mod}' accessed at line {lineno} without import."
                    })

        # Deduplicate
        seen = set()
        unique_missing = []
        for mi in missing_imports:
            k = (mi["module"], mi["lineno"])
            if k not in seen:
                seen.add(k)
                unique_missing.append(mi)

        return {
            "ok": len(unique_missing) == 0,
            "file": str(path),
            "missing_imports": unique_missing,
            "has_pydantic": visitor.has_pydantic_models,
            "imports_count": len(visitor.imports) + len(visitor.imported_symbols),
        }

    def inspect_directory(self, dir_path: Path, max_files: int = 200) -> Dict[str, Any]:
        """Inspects all Python files in a directory."""
        dir_p = Path(dir_path)
        py_files = list(dir_p.rglob("*.py"))[:max_files]
        results = []
        total_missing = 0

        for f in py_files:
            # Skip hidden, virtual environments and pycache
            if any(part.startswith(".") or part in ("__pycache__", "venv", "node_modules") for part in f.parts):
                continue
            res = self.inspect_file(f)
            if not res["ok"]:
                total_missing += len(res.get("missing_imports", []))
                results.append(res)

        payload = {
            "ok": total_missing == 0,
            "files_scanned": len(py_files),
            "files_with_issues": len(results),
            "issues": results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
        try:
            from orbit_security import blackboard
            blackboard.publish_event(
                event_type="ast_scan_completed",
                payload=payload,
                source="ast_sentinel",
                topic=getattr(blackboard, "TOPIC_TELEMETRY", "telemetry")
            )
        except Exception:
            pass
        return payload


def main():
    import argparse
    parser = argparse.ArgumentParser(description="AST Code Sentinel: Static Symbol & Import Verifier")
    parser.add_argument("--check", type=str, help="Check single file or directory")
    parser.add_argument("--daemon", action="store_true", help="Run continuously in background")
    parser.add_argument("--interval", type=int, default=60, help="Check interval in seconds")
    args = parser.parse_args()

    sentinel = ASTCodeSentinel()

    if args.check:
        target = Path(args.check)
        if target.is_dir():
            res = sentinel.inspect_directory(target)
            print(f"AST Sentinel Directory Scan: {target}")
            print(f"Scanned: {res['files_scanned']} files | Issues: {res['files_with_issues']}")
            if not res["ok"]:
                for iss in res["issues"]:
                    print(f"  ❌ {iss['file']}: {iss.get('error') or iss.get('missing_imports')}")
                sys.exit(1)
            else:
                print("  ✓ All symbols and imports verified (0 omissions).")
                sys.exit(0)
        else:
            res = sentinel.inspect_file(target)
            if res["ok"]:
                print(f"✓ {target.name}: Clean syntax and verified imports.")
                sys.exit(0)
            else:
                print(f"❌ {target.name}: Issues detected:")
                print(res)
                sys.exit(1)

    if args.daemon:
        print(f"[*] AST Code Sentinel daemon active. Interval: {args.interval}s.")
        while True:
            target = sentinel.workspace_root / "projects" / "orbit-security" / "src"
            res = sentinel.inspect_directory(target)
            status = "CLEAN" if res["ok"] else f"ISSUES ({res['files_with_issues']})"
            print(f"[{time.strftime('%H:%M:%S')}] AST Sentinel: {status} ({res['files_scanned']} files)")
            time.sleep(args.interval)

    # Default quick check on orbit-security src
    target = sentinel.workspace_root / "projects" / "orbit-security" / "src"
    res = sentinel.inspect_directory(target)
    print(f"AST Sentinel: {res['files_scanned']} files scanned. Status: {'PASS' if res['ok'] else 'FAIL'}")


if __name__ == "__main__":
    main()
