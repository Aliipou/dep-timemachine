"""Parse requirements.txt, pyproject.toml, package.json, Cargo.toml, go.mod."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path


class Dependency:
    __slots__ = ("name", "version_spec", "ecosystem")

    def __init__(self, name: str, version_spec: str, ecosystem: str) -> None:
        self.name = name
        self.version_spec = version_spec
        self.ecosystem = ecosystem

    def __repr__(self) -> str:
        return f"{self.ecosystem}:{self.name}@{self.version_spec}"


def parse_file(path: Path) -> list[Dependency]:
    name = path.name.lower()
    text = path.read_text(encoding="utf-8", errors="ignore")

    if name == "requirements.txt":
        return _parse_requirements(text)
    if name in ("pyproject.toml", "poetry.lock"):
        return _parse_pyproject(text)
    if name == "package.json":
        return _parse_package_json(text)
    if name == "cargo.toml":
        return _parse_cargo(text)
    if name == "go.mod":
        return _parse_go_mod(text)
    if name == "gemfile.lock":
        return _parse_gemfile_lock(text)
    return []


def _parse_requirements(text: str) -> list[Dependency]:
    deps = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "-")):
            continue
        line = re.split(r"[;#]", line)[0].strip()
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~^].*)?$", line)
        if match:
            deps.append(Dependency(match.group(1), (match.group(2) or "").strip(), "pypi"))
    return deps


def _parse_pyproject(text: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    deps = []
    for dep_str in data.get("project", {}).get("dependencies", []):
        match = re.match(r"^([A-Za-z0-9_.\-]+)\s*([><=!~^].*)?$", dep_str.split(";")[0].strip())
        if match:
            deps.append(Dependency(match.group(1), (match.group(2) or "").strip(), "pypi"))
    # poetry
    for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
        if name.lower() == "python":
            continue
        version = spec if isinstance(spec, str) else spec.get("version", "*")
        deps.append(Dependency(name, version, "pypi"))
    return deps


def _parse_package_json(text: str) -> list[Dependency]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return []
    deps = []
    for section in ("dependencies", "devDependencies", "peerDependencies"):
        for name, version in data.get(section, {}).items():
            deps.append(Dependency(name, version, "npm"))
    return deps


def _parse_cargo(text: str) -> list[Dependency]:
    try:
        data = tomllib.loads(text)
    except Exception:
        return []
    deps = []
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        for name, spec in data.get(section, {}).items():
            version = spec if isinstance(spec, str) else spec.get("version", "*")
            deps.append(Dependency(name, version, "crates.io"))
    return deps


def _parse_go_mod(text: str) -> list[Dependency]:
    deps = []
    in_require = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        if in_require or stripped.startswith("require "):
            parts = stripped.replace("require ", "").split()
            if len(parts) >= 2:
                deps.append(Dependency(parts[0], parts[1], "go"))
    return deps


def _parse_gemfile_lock(text: str) -> list[Dependency]:
    deps = []
    in_gem = False
    for line in text.splitlines():
        if line.strip() == "GEM":
            in_gem = True
        elif line.strip() in ("BUNDLED WITH", "PLATFORMS", "DEPENDENCIES"):
            in_gem = False
        elif in_gem:
            match = re.match(r"^\s{4}([a-z][a-z0-9_\-]*)\s+\(([^)]+)\)", line)
            if match:
                deps.append(Dependency(match.group(1), match.group(2), "rubygems"))
    return deps
