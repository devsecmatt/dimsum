"""Source code analysis: clone repos and extract routes, parameters, and risk indicators."""

from __future__ import annotations

import hashlib
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path

from dimsum.source_analysis.parsers import detect_language, parse_file

logger = logging.getLogger(__name__)

# Max file size to analyze (512 KB)
_MAX_FILE_SIZE = 512 * 1024

# Extensions we analyze
_SOURCE_EXTENSIONS = {".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

# Directories to skip
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv", "env",
    "dist", "build", ".next", ".nuxt", "vendor", ".tox", ".mypy_cache",
}


def clone_repo(repo_url: str, branch: str = "main") -> Path:
    """Shallow clone a git repository to a temporary directory.

    Returns the path to the cloned directory.
    Raises RuntimeError if clone fails.
    """
    tmp_dir = Path(tempfile.mkdtemp(prefix="dimsum_source_"))
    try:
        result = subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", branch, "--single-branch", repo_url, str(tmp_dir / "repo")],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            # Try without --branch in case default branch is not 'main'
            result = subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(tmp_dir / "repo")],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode != 0:
                cleanup_repo(tmp_dir)
                raise RuntimeError(f"Git clone failed: {result.stderr.strip()}")
        return tmp_dir / "repo"
    except subprocess.TimeoutExpired:
        cleanup_repo(tmp_dir)
        raise RuntimeError("Git clone timed out after 120 seconds")


def cleanup_repo(repo_path: Path) -> None:
    """Remove a cloned repository directory."""
    # Walk up to the temp dir if we're inside repo/
    target = repo_path.parent if repo_path.name == "repo" else repo_path
    try:
        shutil.rmtree(target, ignore_errors=True)
    except Exception:
        pass


def analyze_repo(repo_path: Path) -> dict:
    """Walk a repository and analyze all supported source files.

    Returns:
        {
            "files": [{"filepath": ..., "language": ..., "hash": ..., "routes": [...], "parameters": [...], "risk_indicators": [...]}],
            "routes": [...],
            "parameters": [...],
            "risk_indicators": [...],
            "files_analyzed": int,
        }
    """
    all_routes: list[dict] = []
    all_params: list[dict] = []
    all_risks: list[dict] = []
    file_results: list[dict] = []

    for source_file in _walk_source_files(repo_path):
        rel_path = str(source_file.relative_to(repo_path))
        language = detect_language(rel_path)
        if language is None:
            continue

        try:
            content = source_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        file_hash = hashlib.sha256(content.encode()).hexdigest()
        result = parse_file(content, rel_path, language)

        file_results.append({
            "filepath": rel_path,
            "language": language,
            "hash": file_hash,
            "routes": result["routes"],
            "parameters": result["parameters"],
            "risk_indicators": result["risk_indicators"],
        })

        all_routes.extend(result["routes"])
        all_params.extend(result["parameters"])
        all_risks.extend(result["risk_indicators"])

    # Deduplicate parameters by name
    seen_params: set[str] = set()
    unique_params = []
    for p in all_params:
        key = f"{p['name']}:{p.get('source', '')}"
        if key not in seen_params:
            seen_params.add(key)
            unique_params.append(p)

    return {
        "files": file_results,
        "routes": all_routes,
        "parameters": unique_params,
        "risk_indicators": all_risks,
        "files_analyzed": len(file_results),
    }


def _walk_source_files(repo_path: Path):
    """Yield source files in the repo, skipping irrelevant directories."""
    for item in sorted(repo_path.rglob("*")):
        if item.is_dir():
            continue
        # Skip files in excluded directories
        if any(part in _SKIP_DIRS for part in item.relative_to(repo_path).parts):
            continue
        if item.suffix.lower() not in _SOURCE_EXTENSIONS:
            continue
        if item.stat().st_size > _MAX_FILE_SIZE:
            continue
        yield item
