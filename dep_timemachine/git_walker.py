"""Walk git history to find when a dependency first appeared / CVE entered the project."""
from __future__ import annotations

import asyncio
import tempfile
from dataclasses import dataclass
from pathlib import Path

from git import InvalidGitRepositoryError, Repo

from dep_timemachine.osv_client import Vulnerability, query_batch
from dep_timemachine.parsers import Dependency, parse_file

_DEP_FILES = {
    "requirements.txt",
    "pyproject.toml",
    "poetry.lock",
    "package.json",
    "cargo.toml",
    "go.mod",
    "gemfile.lock",
}


@dataclass
class CommitSnapshot:
    sha: str
    author: str
    date: str
    message: str
    dependencies: list[Dependency]


@dataclass
class VulnEntry:
    commit: CommitSnapshot
    dependency: Dependency
    vulnerability: Vulnerability
    introduced_at_commit: bool  # True = first commit where this vuln appeared


def open_repo(path: str) -> Repo:
    try:
        return Repo(path, search_parent_directories=True)
    except InvalidGitRepositoryError as exc:
        raise ValueError(f"Not a git repository: {path}") from exc


def _blobs_for_dep_files(commit) -> dict[str, bytes]:
    """Return {filename: content} for all dep-manifest files in a commit."""
    blobs: dict[str, bytes] = {}
    try:
        tree = commit.tree
        for item in tree.traverse():
            if item.type == "blob" and item.name.lower() in _DEP_FILES:
                try:
                    blobs[item.name.lower()] = item.data_stream.read()
                except Exception:
                    pass
    except Exception:
        pass
    return blobs


def _parse_commit(commit) -> CommitSnapshot:
    blobs = _blobs_for_dep_files(commit)
    deps: list[Dependency] = []
    with tempfile.TemporaryDirectory() as tmp:
        for filename, content in blobs.items():
            p = Path(tmp) / filename
            p.write_bytes(content)
            try:
                deps.extend(parse_file(p))
            except Exception:
                pass
    return CommitSnapshot(
        sha=commit.hexsha[:12],
        author=str(commit.author),
        date=commit.committed_datetime.strftime("%Y-%m-%d"),
        message=commit.message.strip().splitlines()[0][:80],
        dependencies=deps,
    )


def _dep_key(d: Dependency) -> tuple[str, str]:
    return (d.ecosystem, d.name.lower())


async def scan_history(
    repo_path: str,
    max_commits: int = 500,
    target_package: str | None = None,
    progress_callback=None,
) -> list[VulnEntry]:
    """Scan git history for CVE entry points.

    Returns a list of VulnEntry objects sorted from oldest to newest,
    marking the first commit where each vulnerability appeared.
    """
    repo = open_repo(repo_path)
    commits = list(repo.iter_commits("HEAD", max_count=max_commits))
    commits.reverse()  # oldest first

    snapshots: list[CommitSnapshot] = []
    for i, commit in enumerate(commits):
        if progress_callback:
            progress_callback(i + 1, len(commits))
        snapshots.append(_parse_commit(commit))

    # Collect unique (ecosystem, name, version) combos across all commits
    all_packages: set[tuple[str, str, str | None]] = set()
    for snap in snapshots:
        for dep in snap.dependencies:
            if target_package and dep.name.lower() != target_package.lower():
                continue
            all_packages.add((dep.ecosystem, dep.name, dep.version_spec or None))

    if not all_packages:
        return []

    vuln_map = await query_batch(list(all_packages))

    # Track which (ecosystem, name, vuln_id) combos we've already reported
    seen: set[tuple[str, str, str]] = set()
    entries: list[VulnEntry] = []

    for snap in snapshots:
        for dep in snap.dependencies:
            if target_package and dep.name.lower() != target_package.lower():
                continue
            key = (dep.ecosystem, dep.name)
            vulns = vuln_map.get(key, [])
            for vuln in vulns:
                entry_key = (dep.ecosystem, dep.name.lower(), vuln.id)
                first = entry_key not in seen
                seen.add(entry_key)
                if first:
                    entries.append(
                        VulnEntry(
                            commit=snap,
                            dependency=dep,
                            vulnerability=vuln,
                            introduced_at_commit=True,
                        )
                    )

    return entries
