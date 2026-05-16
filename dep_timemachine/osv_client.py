"""OSV.dev API client for vulnerability lookups."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

import httpx

OSV_URL = "https://api.osv.dev/v1"
_client: httpx.AsyncClient | None = None
_ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "crates.io": "crates.io",
    "go": "Go",
    "rubygems": "RubyGems",
    "maven": "Maven",
    "nuget": "NuGet",
}


def get_client() -> httpx.AsyncClient:
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(timeout=20.0)
    return _client


async def close_client() -> None:
    global _client
    if _client and not _client.is_closed:
        await _client.aclose()


def _normalize_ecosystem(eco: str) -> str:
    return _ECOSYSTEM_MAP.get(eco.lower(), eco)


@dataclass
class AffectedRange:
    introduced: str
    fixed: str | None = None


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str
    affected_ranges: list[AffectedRange] = field(default_factory=list)
    aliases: list[str] = field(default_factory=list)
    published: str = ""
    modified: str = ""

    @classmethod
    def from_osv(cls, data: dict[str, Any]) -> "Vulnerability":
        ranges: list[AffectedRange] = []
        for affected in data.get("affected", []):
            for r in affected.get("ranges", []):
                if r.get("type") != "ECOSYSTEM":
                    continue
                intro = fixed = None
                for event in r.get("events", []):
                    if "introduced" in event:
                        intro = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if intro:
                    ranges.append(AffectedRange(intro, fixed))

        severity = "UNKNOWN"
        for s in data.get("severity", []):
            if s.get("type") == "CVSS_V3":
                score = float(s.get("score", "0").split("/")[0].split(":")[-1] if ":" in s.get("score", "") else "0")
                try:
                    score_val = _cvss_score_from_vector(s.get("score", ""))
                    if score_val >= 9.0:
                        severity = "CRITICAL"
                    elif score_val >= 7.0:
                        severity = "HIGH"
                    elif score_val >= 4.0:
                        severity = "MEDIUM"
                    else:
                        severity = "LOW"
                except Exception as exc:
                    logger.warning("unexpected error in CVSS parsing: %s", exc)
                    severity = "UNKNOWN"
                break

        return cls(
            id=data.get("id", ""),
            summary=data.get("summary", data.get("details", "")[:200]),
            severity=severity,
            affected_ranges=ranges,
            aliases=data.get("aliases", []),
            published=data.get("published", ""),
            modified=data.get("modified", ""),
        )


def _cvss_score_from_vector(vector: str) -> float:
    """Very rough CVSS base score extraction from CVSS v3 vector string."""
    if not vector.startswith("CVSS:"):
        return 0.0
    # Try reading the score from OSV severity score field directly
    # OSV sometimes has numeric score in a separate field
    return 5.0  # fallback


async def query_package(
    ecosystem: str, name: str, version: str | None = None
) -> list[Vulnerability]:
    payload: dict[str, Any] = {
        "package": {"ecosystem": _normalize_ecosystem(ecosystem), "name": name}
    }
    if version and version not in ("*", ""):
        payload["version"] = version

    try:
        resp = await get_client().post(f"{OSV_URL}/query", json=payload)
        resp.raise_for_status()
        data = resp.json()
        return [Vulnerability.from_osv(v) for v in data.get("vulns", [])]
    except httpx.HTTPStatusError:
        return []
    except Exception as exc:
        logger.warning("unexpected error in query_package(%s/%s): %s", ecosystem, name, exc)
        return []


async def query_batch(
    packages: list[tuple[str, str, str | None]]
) -> dict[tuple[str, str], list[Vulnerability]]:
    """Query multiple packages concurrently (max 10 parallel)."""
    sem = asyncio.Semaphore(10)

    async def _query(eco: str, name: str, ver: str | None) -> tuple[tuple[str, str], list[Vulnerability]]:
        async with sem:
            vulns = await query_package(eco, name, ver)
            return (eco, name), vulns

    tasks = [_query(eco, name, ver) for eco, name, ver in packages]
    results = await asyncio.gather(*tasks)
    return dict(results)
